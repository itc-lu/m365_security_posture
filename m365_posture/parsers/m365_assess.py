"""Parser for M365-Assess tool output (https://github.com/Daren9m/M365-Assess)."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from ..models import (
    Action, SourceTool, Priority, RiskLevel, UserImpact,
    ImplementationEffort, Workload, ActionStatus,
)

# M365-Assess module to workload mapping
MODULE_WORKLOAD_MAP = {
    "entra": Workload.ENTRA.value,
    "azuread": Workload.ENTRA.value,
    "aad": Workload.ENTRA.value,
    "exchange": Workload.EXCHANGE.value,
    "exo": Workload.EXCHANGE.value,
    "sharepoint": Workload.SHAREPOINT.value,
    "spo": Workload.SHAREPOINT.value,
    "onedrive": Workload.ONEDRIVE.value,
    "teams": Workload.TEAMS.value,
    "defender": Workload.DEFENDER.value,
    "intune": Workload.INTUNE.value,
    "powerplatform": Workload.POWER_PLATFORM.value,
    "purview": Workload.PURVIEW.value,
}


def _result_to_status(result: str) -> str:
    r = (result or "").lower().strip()
    if r in ("pass", "passed", "compliant", "true"):
        return ActionStatus.COMPLETED.value
    if r in ("fail", "failed", "non-compliant", "false"):
        return ActionStatus.TODO.value
    if r in ("warning", "partial"):
        return ActionStatus.IN_PROGRESS.value
    if r in ("n/a", "not applicable", "informational"):
        return ActionStatus.NOT_APPLICABLE.value
    return ActionStatus.TODO.value


def _severity_to_priority(severity: str) -> str:
    s = (severity or "").lower()
    if "critical" in s:
        return Priority.CRITICAL.value
    if "high" in s:
        return Priority.HIGH.value
    if "medium" in s or "moderate" in s:
        return Priority.MEDIUM.value
    if "low" in s:
        return Priority.LOW.value
    if "info" in s:
        return Priority.INFORMATIONAL.value
    return Priority.MEDIUM.value


class M365AssessParser:
    """Parse M365-Assess tool output (JSON/CSV)."""

    source_tool = SourceTool.M365_ASSESS.value

    def parse_file(self, file_path: str) -> list[Action]:
        path = Path(file_path)
        suffix = path.suffix.lower()

        if suffix == ".json":
            return self._parse_json(path)
        elif suffix == ".csv":
            return self._parse_csv(path)
        else:
            raise ValueError(f"Unsupported M365-Assess file format: {suffix}. Use .json or .csv")

    def _parse_json(self, path: Path) -> list[Action]:
        with open(path) as f:
            data = json.load(f)

        items = data if isinstance(data, list) else data.get("results", data.get("checks", []))
        return [self._item_to_action(item) for item in items]

    def _parse_csv(self, path: Path) -> list[Action]:
        actions = []
        with open(path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                actions.append(self._item_to_action(dict(row)))
        return actions

    def _item_to_action(self, item: dict) -> Action:
        title = (
            item.get("Check", "")
            or item.get("Title", "")
            or item.get("title", "")
            or item.get("Name", "")
            or item.get("name", "")
            or "Unknown M365-Assess Check"
        )
        description = (
            item.get("Description", "")
            or item.get("description", "")
            or item.get("Details", "")
            or ""
        )
        result = (
            item.get("Result", "")
            or item.get("result", "")
            or item.get("Status", "")
            or item.get("status", "")
            or ""
        )
        severity = (
            item.get("Severity", "")
            or item.get("severity", "")
            or item.get("Priority", "")
            or ""
        )
        module = (
            item.get("Module", "")
            or item.get("module", "")
            or item.get("Product", "")
            or item.get("product", "")
            or ""
        )
        remediation = (
            item.get("Remediation", "")
            or item.get("remediation", "")
            or item.get("Recommendation", "")
            or ""
        )
        control_id = (
            item.get("Id", "")
            or item.get("id", "")
            or item.get("CheckId", "")
            or title.replace(" ", "_").lower()[:30]
        )

        # Determine workload from module
        workload = Workload.GENERAL.value
        for key, wl in MODULE_WORKLOAD_MAP.items():
            if key in module.lower():
                workload = wl
                break

        is_pass = result.lower() in ("pass", "passed", "compliant", "true")

        return Action(
            title=title,
            description=description,
            source_tool=self.source_tool,
            source_id=f"m365a_{control_id}",
            workload=workload,
            status=_result_to_status(result),
            priority=_severity_to_priority(severity),
            risk_level=RiskLevel.HIGH.value if not is_pass else RiskLevel.LOW.value,
            user_impact=UserImpact.LOW.value,
            implementation_effort=ImplementationEffort.MEDIUM.value,
            score=1.0 if is_pass else 0.0,
            max_score=1.0,
            score_percentage=100.0 if is_pass else 0.0,
            remediation_steps=remediation,
            current_value=str(item.get("CurrentValue", item.get("currentValue", ""))),
            recommended_value=str(item.get("RecommendedValue", item.get("recommendedValue", ""))),
            category=module,
            reference_url=item.get("ReferenceUrl", item.get("referenceUrl", item.get("Link", ""))),
            raw_data=item,
        )
