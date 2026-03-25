"""Parser for Zero Trust Assessment Report (zerotrustassessment tool output).

Parses the ZeroTrustAssessmentReport.json file which contains:
- Tenant metadata (TenantId, TenantName, Domain, etc.)
- TestResultSummary (pass/total counts per pillar)
- Tests array with full recommendation details
- TenantInfo with configuration snapshots (auth methods, devices, policies, etc.)

The ZT report has its own methodology distinct from Secure Score:
- Tests have a TestStatus: Passed, Failed, Investigate, Planned, Skipped
- Each test has a TestPillar (Identity, Devices), SFI Pillar, and Category
- Tests include TestResult (what was found), TestDescription (what was checked + remediation)
- Each test has a unique TestId for cross-referencing with the HTML report
"""

from __future__ import annotations

import json
import re
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
# "Planned" in ZT means the test is under construction by Microsoft - NOT a user plan
# "Investigate" means manual review is needed
STATUS_MAP = {
    "passed": ActionStatus.COMPLETED.value,
    "failed": ActionStatus.TODO.value,
    "investigate": ActionStatus.TODO.value,
    "skipped": ActionStatus.NOT_APPLICABLE.value,
    "planned": ActionStatus.NOT_APPLICABLE.value,
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


def _extract_urls(text: str) -> list[str]:
    """Extract URLs from text."""
    return re.findall(r'https?://[^\s\)>"]+', text)


def _score_for_status(status: str) -> tuple[float, float]:
    """Return (score, max_score) based on test status."""
    if status == ActionStatus.COMPLETED.value:
        return 1.0, 1.0
    if status == ActionStatus.NOT_APPLICABLE.value:
        return 0.0, 0.0  # N/A tests don't count towards score
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

            json_file = self._find_report_json(Path(extract_dir))
            if not json_file:
                raise ValueError(
                    "Could not find ZeroTrustAssessmentReport.json in the ZIP. "
                    "Ensure the ZIP contains the report directory."
                )
            actions = self._parse_json(json_file)
            self._extract_dir = extract_dir
            return actions
        except zipfile.BadZipFile:
            shutil.rmtree(extract_dir, ignore_errors=True)
            raise ValueError("Invalid ZIP file")

    def _find_report_json(self, root: Path) -> Optional[Path]:
        """Find ZeroTrustAssessmentReport.json in extracted directory."""
        for candidate in root.rglob("ZeroTrustAssessmentReport.json"):
            return candidate
        return None

    def _parse_json(self, path: Path) -> list[Action]:
        """Parse the main report JSON."""
        with open(path, encoding="utf-8-sig") as f:
            data = json.load(f)

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
        status_raw = (test.get("TestStatus") or "").strip()
        status_lower = status_raw.lower()
        risk_raw = (test.get("TestRisk") or "").lower()
        impact_raw = (test.get("TestImpact") or "").lower()
        effort_raw = (test.get("TestImplementationCost") or "").lower()
        pillar = test.get("TestPillar", "") or ""
        category = test.get("TestCategory", "") or ""
        sfi_pillar = test.get("TestSfiPillar", "") or ""

        # Map status
        status = STATUS_MAP.get(status_lower, ActionStatus.TODO.value)

        # Score: pass/fail binary, N/A tests get 0/0
        score, max_score = _score_for_status(status)

        # Map workload: prefer category, fall back to pillar
        workload = Workload.GENERAL.value
        cat_lower = category.lower()
        if cat_lower in CATEGORY_WORKLOAD_MAP:
            workload = CATEGORY_WORKLOAD_MAP[cat_lower]
        elif pillar.lower() in PILLAR_WORKLOAD_MAP:
            workload = PILLAR_WORKLOAD_MAP[pillar.lower()]

        # Priority from risk
        priority = RISK_PRIORITY_MAP.get(risk_raw, Priority.MEDIUM.value)
        # Boost investigate items
        if status_lower == "investigate" and priority != Priority.HIGH.value:
            priority = Priority.HIGH.value

        # --- ZT-specific field mapping ---
        # TestDescription = "What was checked" + remediation action
        full_description = test.get("TestDescription", "").strip()

        # TestResult = the actual findings/evidence from the test
        test_result = test.get("TestResult", "").strip()

        # Split description into "What was checked" and "Remediation action"
        what_was_checked = full_description
        remediation = ""
        if "**Remediation action**" in full_description:
            parts = full_description.split("**Remediation action**", 1)
            what_was_checked = parts[0].strip()
            remediation = parts[1].strip() if len(parts) > 1 else ""

        # For Planned tests with "UnderConstruction", mark clearly
        skipped_reason = test.get("SkippedReason", "") or ""
        if status_lower == "planned":
            if test_result == "Planned for future release.":
                # This test doesn't have real results yet
                test_result = f"[Planned] {skipped_reason or 'Test under construction by Microsoft — not yet available.'}"
            else:
                # This test ran but is marked as planned (partial implementation)
                test_result = f"[Planned - partial] {test_result}"
        elif status_lower == "skipped" and skipped_reason:
            test_result = test_result or f"Skipped: {skipped_reason}"

        # Extract reference URLs from remediation
        urls = _extract_urls(f"{remediation} {what_was_checked}")
        reference_url = urls[0] if urls else ""

        # Handle licence
        licence = test.get("TestMinimumLicense", "") or ""
        if isinstance(licence, list):
            licence = ", ".join(str(l) for l in licence)
        if licence == "None":
            licence = "Free"

        # Tags: preserve original ZT status, pillar, SFI pillar
        tags = []
        # Original ZT test status (Passed/Failed/Investigate/Planned/Skipped)
        if status_raw:
            tags.append(f"ZT: {status_raw}")
        # Pillar
        if pillar:
            tags.append(f"Pillar: {pillar}")
        # SFI Pillar
        if sfi_pillar:
            tags.append(f"SFI: {sfi_pillar}")
        # TestTags
        if test.get("TestTags"):
            for t in test["TestTags"]:
                if isinstance(t, str) and t not in tags:
                    tags.append(t)
        # TestAppliesTo
        if test.get("TestAppliesTo"):
            for t in test["TestAppliesTo"]:
                if isinstance(t, str) and t not in tags:
                    tags.append(t)
        tags = list(dict.fromkeys(tags))  # dedupe

        return Action(
            title=title,
            description=what_was_checked,
            source_tool=self.source_tool,
            source_id=f"ztr_{test_id}",
            reference_id=test_id,  # Preserve TestId for cross-reference
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
            current_value=test_result,  # "Test Result" — what was found
            recommended_value="",  # ZT doesn't have this concept
            category=category,  # TestCategory (e.g. "Access control")
            subcategory=sfi_pillar,  # SFI Pillar
            required_licence=licence,
            reference_url=reference_url,
            tags=tags,
            raw_data=test,
        )
