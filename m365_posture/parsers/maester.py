"""Parser for Maester (maester.dev) test results.

Maester is a Pester-based Microsoft 365 security test framework. Its
``Invoke-Maester`` run writes an interactive HTML report plus a JSON results
file (``test-results.json`` / ``TestResults-*.json``) with this shape:

    {
      "Result": "Failed", "TotalCount": 160, "PassedCount": 120,
      "FailedCount": 30, "SkippedCount": 10,
      "ExecutedAt": "...", "TenantId": "...", "TenantName": "...",
      "Account": "...", "CurrentVersion": "...",
      "Tests": [
        {"Id": "MT.1001", "Title": "...", "Name": "MT.1001: ...",
         "Severity": "High", "Tag": ["MT.1001", "CA", "Security"],
         "Result": "Passed|Failed|Skipped|NotRun|Error",
         "Block": "Conditional Access", "HelpUrl": "https://maester.dev/...",
         "ResultDetail": {"TestResult": "md", "TestDescription": "md"},
         "ErrorRecord": ...}
      ]
    }

Field names vary slightly between Maester versions, so every lookup here is
tolerant of alternates. Accepts the JSON directly or a ZIP of the output
folder (which also preserves the HTML report for in-app viewing).
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import zipfile
from pathlib import Path

from ..models import (
    Action, SourceTool, Priority, RiskLevel, UserImpact,
    ImplementationEffort, Workload, ActionStatus,
)

# Maester test result -> ActionStatus.
# "NotRun" = prerequisites missing / not connected; "Skipped" = excluded.
STATUS_MAP = {
    "passed": ActionStatus.COMPLETED.value,
    "failed": ActionStatus.TODO.value,
    "skipped": ActionStatus.NOT_APPLICABLE.value,
    "notrun": ActionStatus.NOT_APPLICABLE.value,
    "error": ActionStatus.TODO.value,
}

SEVERITY_PRIORITY = {
    "critical": Priority.CRITICAL.value,
    "high": Priority.HIGH.value,
    "medium": Priority.MEDIUM.value,
    "low": Priority.LOW.value,
    "info": Priority.INFORMATIONAL.value,
}

SEVERITY_RISK = {
    "critical": RiskLevel.CRITICAL.value,
    "high": RiskLevel.HIGH.value,
    "medium": RiskLevel.MEDIUM.value,
    "low": RiskLevel.LOW.value,
    "info": RiskLevel.MINIMAL.value,
}

# Keyword -> workload mapping applied to tags, block names and titles.
# Order matters: more specific products first, identity last-but-one,
# General as the fallback.
_WORKLOAD_KEYWORDS = [
    (("copilot", "ai agent", "aiagent", "ai security", "agentic"), Workload.COPILOT.value),
    (("orca", "exchange", "exo", "mailbox", "spf", "dkim", "dmarc",
      "antispam", "anti-spam", "antiphish", "safe link", "safelinks",
      "safe attachment", "safeattachments"), Workload.EXCHANGE.value),
    (("teams",), Workload.TEAMS.value),
    (("onedrive",), Workload.ONEDRIVE.value),
    (("sharepoint", "spo"), Workload.SHAREPOINT.value),
    (("intune", "device compliance", "deviceconfig", "windows update"), Workload.INTUNE.value),
    (("defender", "mdo", "mde", "atp"), Workload.DEFENDER.value),
    (("purview", "dlp", "sensitivity label", "retention", "information protection"), Workload.PURVIEW.value),
    (("powerplatform", "power platform", "powerapps", "power apps"), Workload.POWER_PLATFORM.value),
    (("eidsca", "entra", "aad", "azuread", "conditional access", "conditionalaccess",
      "ca", "identity", "authentication", "mfa", "privileged", "pim", "guest"),
     Workload.ENTRA.value),
]

# Test-ID prefix -> suite name shown as the action category
_SUITE_NAMES = {
    "MT": "Maester",
    "EIDSCA": "EIDSCA",
    "CISA": "CISA SCuBA",
    "CIS": "CIS Benchmark",
    "ORCA": "ORCA",
}

_ID_RE = re.compile(r"^([A-Z]{2,10}(?:\.[A-Za-z0-9]+)*\.\w+)\s*:")
_TAG_ID_RE = re.compile(r"^(MT|EIDSCA|CISA|CIS|ORCA)[.\w]*$")


def _first(d: dict, *keys, default=""):
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return v
    return default


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


class MaesterParser:
    """Parse Maester test results (JSON, or ZIP of the output folder)."""

    source_tool = SourceTool.MAESTER.value

    def __init__(self):
        self.report_metadata: dict = {}
        self.test_summary: dict = {}

    def parse_file(self, file_path: str) -> list[Action]:
        path = Path(file_path)
        suffix = path.suffix.lower()
        if suffix == ".zip":
            return self._parse_zip(path)
        if suffix == ".json":
            return self._parse_json(path)
        raise ValueError(
            f"Unsupported Maester file format: {suffix}. Upload the Maester "
            "output folder as a ZIP, or the test-results JSON file.")

    def _parse_zip(self, zip_path: Path) -> list[Action]:
        import tempfile
        from .zip_safety import safe_extract_zip
        extract_dir = tempfile.mkdtemp(prefix="maester_report_")
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                safe_extract_zip(zf, extract_dir)
            json_file = self._find_results_json(Path(extract_dir))
            if not json_file:
                raise ValueError(
                    "Could not find a Maester test-results JSON in the ZIP. "
                    "Ensure the ZIP contains the Invoke-Maester output folder "
                    "(with test-results.json or TestResults-*.json).")
            actions = self._parse_json(json_file)
            self._extract_dir = extract_dir
            return actions
        except zipfile.BadZipFile:
            shutil.rmtree(extract_dir, ignore_errors=True)
            raise ValueError("Invalid ZIP file")
        except ValueError:
            shutil.rmtree(extract_dir, ignore_errors=True)
            raise

    def _find_results_json(self, root: Path) -> Path | None:
        """Locate the results JSON: known names first, then any JSON that
        contains a Tests array."""
        for pattern in ("test-results.json", "TestResults*.json", "*maester*.json"):
            for candidate in sorted(root.rglob(pattern)):
                return candidate
        for candidate in sorted(root.rglob("*.json")):
            try:
                with open(candidate, encoding="utf-8-sig") as f:
                    head = json.load(f)
                if isinstance(head, dict) and isinstance(head.get("Tests"), list):
                    return candidate
            except (OSError, ValueError):
                continue
        return None

    def _parse_json(self, path: Path) -> list[Action]:
        with open(path, encoding="utf-8-sig") as f:
            data = json.load(f)

        if not isinstance(data, dict) or not isinstance(data.get("Tests"), list):
            raise ValueError(
                "This does not look like a Maester results file "
                "(expected an object with a Tests array).")

        self.report_metadata = {
            "tenant_id": str(_first(data, "TenantId")),
            "tenant_name": str(_first(data, "TenantName")),
            "domain": str(_first(data, "TenantDomain", "Domain")),
            "account": str(_first(data, "Account")),
            "tool_version": str(_first(data, "CurrentVersion", "Version")),
            "executed_at": str(_first(data, "ExecutedAt", "Timestamp")),
        }
        self.test_summary = {
            "total": data.get("TotalCount", len(data["Tests"])),
            "passed": data.get("PassedCount", 0),
            "failed": data.get("FailedCount", 0),
            "skipped": data.get("SkippedCount", 0),
            "result": data.get("Result", ""),
        }

        actions = []
        for test in data["Tests"]:
            if isinstance(test, dict):
                actions.append(self._test_to_action(test))
        if not actions:
            raise ValueError("No tests found in the Maester results file")
        return actions

    def _extract_id(self, test: dict) -> str:
        explicit = str(_first(test, "Id", "TestId")).strip()
        if explicit:
            return explicit
        name = str(_first(test, "Name", "Title"))
        m = _ID_RE.match(name.strip())
        if m:
            return m.group(1)
        for tag in _as_list(test.get("Tag")):
            if isinstance(tag, str) and _TAG_ID_RE.match(tag.strip()):
                return tag.strip()
        # Stable digest fallback (never the salted built-in hash())
        return hashlib.md5(name.encode()).hexdigest()[:10]

    def _resolve_workload(self, *texts: str) -> str:
        # Match whole words so short keys like "ca" cannot fire inside
        # unrelated words (e.g. "certificate").
        for text in texts:
            if not text:
                continue
            words = set(re.findall(r"[a-z0-9]+(?:[ \-][a-z0-9]+)?", text.lower()))
            flat = " " + re.sub(r"[^a-z0-9]+", " ", text.lower()) + " "
            for keywords, workload in _WORKLOAD_KEYWORDS:
                for kw in keywords:
                    if " " in kw or "-" in kw:
                        if kw in flat:
                            return workload
                    elif kw in words:
                        return workload
        return Workload.GENERAL.value

    def _test_to_action(self, test: dict) -> Action:
        test_id = self._extract_id(test)
        name = str(_first(test, "Name", "Title"))
        title = str(_first(test, "Title")) or name
        # Strip a leading "MT.1001: " from the display title
        title = re.sub(r"^[A-Z]{2,10}(?:\.[A-Za-z0-9]+)*\.\w+\s*:\s*", "", title).strip() or name

        result_raw = str(_first(test, "Result", "Outcome")).strip()
        status = STATUS_MAP.get(result_raw.lower(), ActionStatus.TODO.value)

        severity_raw = str(_first(test, "Severity")).strip().lower()
        priority = SEVERITY_PRIORITY.get(severity_raw, Priority.MEDIUM.value)
        risk = SEVERITY_RISK.get(
            severity_raw,
            RiskLevel.HIGH.value if status == ActionStatus.TODO.value else RiskLevel.MEDIUM.value)

        detail = test.get("ResultDetail") or {}
        if not isinstance(detail, dict):
            detail = {}
        description = str(_first(detail, "TestDescription", "Description"))
        test_result = str(_first(detail, "TestResult", "Result"))
        if not test_result and test.get("ErrorRecord"):
            err = test["ErrorRecord"]
            test_result = "; ".join(str(e) for e in _as_list(err))[:2000]

        block = str(_first(test, "Block", "Group"))
        tags = [str(t) for t in _as_list(test.get("Tag")) if t]
        suite = test_id.split(".")[0] if "." in test_id else ""
        category = _SUITE_NAMES.get(suite, suite or "Maester")

        workload = self._resolve_workload(" ".join(tags), block, title)

        if status == ActionStatus.COMPLETED.value:
            score, max_score = 1.0, 1.0
        elif status == ActionStatus.NOT_APPLICABLE.value:
            score, max_score = 0.0, 0.0  # skipped tests don't count
        else:
            score, max_score = 0.0, 1.0

        display_tags = [f"Maester: {result_raw}"] if result_raw else []
        if suite:
            display_tags.append(f"Suite: {category}")
        display_tags.extend(t for t in tags if t not in display_tags)

        return Action(
            title=title,
            description=description,
            source_tool=self.source_tool,
            source_id=f"maester_{test_id}",
            reference_id=test_id,
            workload=workload,
            status=status,
            priority=priority,
            risk_level=risk,
            user_impact=UserImpact.LOW.value,
            implementation_effort=ImplementationEffort.MEDIUM.value,
            score=score,
            max_score=max_score,
            score_percentage=round((score / max_score * 100), 1) if max_score > 0 else 0,
            current_value=test_result,
            category=category,
            subcategory=block,
            reference_url=str(_first(test, "HelpUrl", "HelpURL", "Link")),
            tags=list(dict.fromkeys(display_tags)),
            raw_data={k: v for k, v in test.items() if k != "ScriptBlock"},
        )
