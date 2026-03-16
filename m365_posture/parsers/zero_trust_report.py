"""Parser for Zero Trust Assessment Report (zerotrustassessment tool output).

Parses the ZeroTrustAssessmentReport.json file which contains:
- Tenant metadata (TenantId, TenantName, Domain, etc.)
- TestResultSummary (pass/total counts per pillar)
- Tests array with full recommendation details
- TenantInfo with configuration snapshots (auth methods, devices, policies, etc.)
"""

from __future__ import annotations

import json
import os
import shutil
import zipfile
from pathlib import Path
from typing import Optional

from ..models import (
    Action, SourceTool, Priority, RiskLevel, UserImpact,
    ImplementationEffort, Workload, ActionStatus,
)

# Map TestPillar values to our workload enum
PILLAR_WORKLOAD_MAP = {
    "identity": Workload.ENTRA.value,
    "devices": Workload.INTUNE.value,
    "data": Workload.PURVIEW.value,
}

# Map TestCategory to workload (more granular)
CATEGORY_WORKLOAD_MAP = {
    "access control": Workload.ENTRA.value,
    "application management": Workload.ENTRA.value,
    "applications management": Workload.ENTRA.value,
    "credential management": Workload.ENTRA.value,
    "external collaboration": Workload.ENTRA.value,
    "identity": Workload.ENTRA.value,
    "identity governance": Workload.ENTRA.value,
    "privileged access": Workload.ENTRA.value,
    "credential management, privileged access": Workload.ENTRA.value,
    "hybrid infrastructure": Workload.ENTRA.value,
    "monitoring": Workload.DEFENDER.value,
    "device": Workload.INTUNE.value,
    "devices": Workload.INTUNE.value,
    "tenant": Workload.GENERAL.value,
    "data": Workload.PURVIEW.value,
}

# Map TestStatus to our ActionStatus
STATUS_MAP = {
    "passed": ActionStatus.COMPLETED.value,
    "failed": ActionStatus.TODO.value,
    "investigate": ActionStatus.TODO.value,
    "skipped": ActionStatus.NOT_APPLICABLE.value,
    "planned": ActionStatus.IN_PLANNING.value,
}

# Map TestRisk to Priority
RISK_PRIORITY_MAP = {
    "high": Priority.HIGH.value,
    "medium": Priority.MEDIUM.value,
    "low": Priority.LOW.value,
}

# Map TestRisk to RiskLevel
RISK_LEVEL_MAP = {
    "high": RiskLevel.HIGH.value,
    "medium": RiskLevel.MEDIUM.value,
    "low": RiskLevel.LOW.value,
}

# Map TestImpact to UserImpact
IMPACT_MAP = {
    "high": UserImpact.HIGH.value,
    "medium": UserImpact.MEDIUM.value,
    "low": UserImpact.LOW.value,
}

# Map TestImplementationCost to ImplementationEffort
EFFORT_MAP = {
    "high": ImplementationEffort.HIGH.value,
    "medium": ImplementationEffort.MEDIUM.value,
    "low": ImplementationEffort.LOW.value,
}


def _extract_urls_from_description(text: str) -> list[str]:
    """Extract markdown URLs from test description text."""
    import re
    return re.findall(r'https?://[^\s\)>"]+', text)


def _score_for_status(status: str) -> tuple[float, float]:
    """Return (score, max_score) based on test status."""
    if status == ActionStatus.COMPLETED.value:
        return 1.0, 1.0
    return 0.0, 1.0


class ZeroTrustReportParser:
    """Parse Zero Trust Assessment Report files (JSON from zerotrustassessment tool).

    Handles:
    - Direct JSON file (ZeroTrustAssessmentReport.json)
    - ZIP file containing the full report directory
    """

    source_tool = SourceTool.ZERO_TRUST_REPORT.value

    def parse_file(self, file_path: str) -> list[Action]:
        """Parse a ZeroTrustAssessmentReport.json file."""
        path = Path(file_path)

        if path.suffix.lower() == ".zip":
            return self._parse_zip(path)
        elif path.suffix.lower() == ".json":
            return self._parse_json(path)
        else:
            raise ValueError(
                f"Unsupported file format: {path.suffix}. "
                "Upload the ZeroTrustAssessmentReport.json or a ZIP of the full report directory."
            )

    def _parse_zip(self, zip_path: Path) -> list[Action]:
        """Extract ZIP and find the report JSON inside."""
        import tempfile
        extract_dir = tempfile.mkdtemp(prefix="zt_report_")
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(extract_dir)

            # Find the report JSON - could be at root or in a subdirectory
            json_file = self._find_report_json(Path(extract_dir))
            if not json_file:
                raise ValueError(
                    "Could not find ZeroTrustAssessmentReport.json in the ZIP. "
                    "Ensure the ZIP contains the report directory."
                )
            actions = self._parse_json(json_file)
            # Store the extract dir path so webapp can access it for HTML/data storage
            self._extract_dir = extract_dir
            return actions
        except zipfile.BadZipFile:
            shutil.rmtree(extract_dir, ignore_errors=True)
            raise ValueError("Invalid ZIP file")

    def _find_report_json(self, root: Path) -> Optional[Path]:
        """Find ZeroTrustAssessmentReport.json in extracted directory."""
        # Check common locations
        for candidate in root.rglob("ZeroTrustAssessmentReport.json"):
            return candidate
        # Also check inside zt-export subdirectory
        for candidate in root.rglob("zt-export/ZeroTrustAssessmentReport.json"):
            return candidate
        return None

    def _parse_json(self, path: Path) -> list[Action]:
        """Parse the main report JSON."""
        with open(path, encoding="utf-8-sig") as f:
            data = json.load(f)

        # Store metadata for later use by webapp
        self.report_metadata = {
            "executed_at": data.get("ExecutedAt", ""),
            "tenant_id": data.get("TenantId", ""),
            "tenant_name": data.get("TenantName", ""),
            "domain": data.get("Domain", ""),
            "account": data.get("Account", ""),
            "tool_version": data.get("CurrentVersion", ""),
            "latest_version": data.get("LatestVersion", ""),
        }

        self.test_result_summary = data.get("TestResultSummary", {})
        self.tenant_info = data.get("TenantInfo", {})

        tests = data.get("Tests", [])
        if not tests:
            raise ValueError("No Tests found in the report JSON")

        actions = []
        for test in tests:
            actions.append(self._test_to_action(test))

        return actions

    def _test_to_action(self, test: dict) -> Action:
        """Convert a single Test entry to an Action."""
        title = test.get("TestTitle", "").strip()
        test_id = str(test.get("TestId", ""))
        status_raw = (test.get("TestStatus") or "").lower()
        risk_raw = (test.get("TestRisk") or "").lower()
        impact_raw = (test.get("TestImpact") or "").lower()
        effort_raw = (test.get("TestImplementationCost") or "").lower()
        pillar = (test.get("TestPillar") or "").lower()
        category = test.get("TestCategory", "")
        sfi_pillar = test.get("TestSfiPillar", "")

        # Map status
        status = STATUS_MAP.get(status_raw, ActionStatus.TODO.value)

        # Score: binary pass/fail
        score, max_score = _score_for_status(status)

        # Map workload: prefer category, fall back to pillar
        workload = Workload.GENERAL.value
        cat_lower = category.lower()
        if cat_lower in CATEGORY_WORKLOAD_MAP:
            workload = CATEGORY_WORKLOAD_MAP[cat_lower]
        elif pillar in PILLAR_WORKLOAD_MAP:
            workload = PILLAR_WORKLOAD_MAP[pillar]

        # Priority from risk
        priority = RISK_PRIORITY_MAP.get(risk_raw, Priority.MEDIUM.value)
        # Boost investigate items to high
        if status_raw == "investigate" and priority != Priority.HIGH.value:
            priority = Priority.HIGH.value

        # Build rich description from TestDescription
        description = test.get("TestDescription", "").strip()

        # TestResult contains the actual findings/evidence
        test_result = test.get("TestResult", "").strip()

        # Extract remediation from description (after "**Remediation action**")
        remediation = ""
        if "**Remediation action**" in description:
            parts = description.split("**Remediation action**", 1)
            remediation = parts[1].strip() if len(parts) > 1 else ""
            # Keep only the explanation part in description
            description = parts[0].strip()

        # Extract reference URLs
        all_text = f"{description} {remediation} {test_result}"
        urls = _extract_urls_from_description(all_text)
        reference_url = urls[0] if urls else ""

        # Handle licence
        licence = test.get("TestMinimumLicense", "") or ""
        if isinstance(licence, list):
            licence = ", ".join(str(l) for l in licence)

        # Skipped reason
        skipped_reason = test.get("SkippedReason", "") or ""
        if skipped_reason and status == ActionStatus.NOT_APPLICABLE.value:
            if not test_result:
                test_result = f"Skipped: {skipped_reason}"

        # Tags from TestTags + TestAppliesTo + pillar
        tags = []
        if test.get("TestTags"):
            tags.extend(t for t in test["TestTags"] if isinstance(t, str))
        if test.get("TestAppliesTo"):
            tags.extend(t for t in test["TestAppliesTo"] if isinstance(t, str) and t not in tags)
        if sfi_pillar:
            tags.append(f"SFI: {sfi_pillar}")
        tags = list(dict.fromkeys(tags))  # dedupe preserving order

        return Action(
            title=title,
            description=description,
            source_tool=self.source_tool,
            source_id=f"ztr_{test_id}",
            workload=workload,
            status=status,
            priority=priority,
            risk_level=RISK_LEVEL_MAP.get(risk_raw, RiskLevel.MEDIUM.value),
            user_impact=IMPACT_MAP.get(impact_raw, UserImpact.LOW.value),
            implementation_effort=EFFORT_MAP.get(effort_raw, ImplementationEffort.MEDIUM.value),
            score=score,
            max_score=max_score,
            score_percentage=round((score / max_score * 100), 1) if max_score > 0 else 0,
            remediation_steps=remediation,
            current_value=test_result,
            category=category,
            subcategory=sfi_pillar,
            required_licence=licence,
            reference_url=reference_url,
            tags=tags,
            raw_data=test,
        )
