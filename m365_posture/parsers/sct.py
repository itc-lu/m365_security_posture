"""Parser for Microsoft Security Compliance Toolkit (SCT) / PolicyAnalyzer output."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from ..models import (
    Action, SourceTool, Priority, RiskLevel, UserImpact,
    ImplementationEffort, Workload, ActionStatus,
)


def _match_to_status(match: str) -> str:
    m = (match or "").lower().strip()
    if m in ("match", "compliant", "pass", "true", "yes"):
        return ActionStatus.COMPLETED.value
    if m in ("mismatch", "non-compliant", "fail", "false", "no"):
        return ActionStatus.TODO.value
    if m in ("missing", "not configured"):
        return ActionStatus.TODO.value
    return ActionStatus.TODO.value


class SCTParser:
    """Parse Microsoft Security Compliance Toolkit / PolicyAnalyzer output."""

    source_tool = SourceTool.SCT.value

    def parse_file(self, file_path: str) -> list[Action]:
        path = Path(file_path)
        suffix = path.suffix.lower()

        if suffix == ".csv":
            return self._parse_csv(path)
        elif suffix == ".json":
            return self._parse_json(path)
        else:
            raise ValueError(f"Unsupported SCT file format: {suffix}. Use .csv or .json")

    def _parse_csv(self, path: Path) -> list[Action]:
        actions = []
        with open(path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                actions.append(self._row_to_action(dict(row)))
        return actions

    def _parse_json(self, path: Path) -> list[Action]:
        with open(path) as f:
            data = json.load(f)

        items = data if isinstance(data, list) else data.get("settings", data.get("policies", []))
        return [self._row_to_action(item) for item in items]

    def _row_to_action(self, item: dict) -> Action:
        setting_name = (
            item.get("Setting", "")
            or item.get("PolicySetting", "")
            or item.get("name", "")
            or item.get("Name", "")
            or "Unknown SCT Setting"
        )
        baseline_value = str(
            item.get("BaselineValue", "")
            or item.get("Baseline", "")
            or item.get("expectedValue", "")
            or ""
        )
        current_value = str(
            item.get("SystemValue", "")
            or item.get("CurrentValue", "")
            or item.get("actualValue", "")
            or ""
        )
        match_result = (
            item.get("MatchResult", "")
            or item.get("Status", "")
            or item.get("Result", "")
            or item.get("Compliant", "")
            or ""
        )
        gpo_name = item.get("GPOName", item.get("PolicyName", item.get("policy", "")))
        category = item.get("Category", item.get("category", ""))
        path = item.get("Path", item.get("RegistryPath", item.get("path", "")))

        description = ""
        if gpo_name:
            description += f"GPO: {gpo_name}\n"
        if path:
            description += f"Path: {path}\n"
        if category:
            description += f"Category: {category}"

        control_id = setting_name.replace(" ", "_").replace("/", "_").lower()[:40]
        is_compliant = match_result.lower() in ("match", "compliant", "pass", "true", "yes")

        return Action(
            title=setting_name,
            description=description.strip(),
            source_tool=self.source_tool,
            source_id=f"sct_{control_id}",
            workload=Workload.GENERAL.value,
            status=_match_to_status(match_result),
            priority=Priority.MEDIUM.value,
            risk_level=RiskLevel.MEDIUM.value if not is_compliant else RiskLevel.LOW.value,
            user_impact=UserImpact.LOW.value,
            implementation_effort=ImplementationEffort.LOW.value,
            score=1.0 if is_compliant else 0.0,
            max_score=1.0,
            score_percentage=100.0 if is_compliant else 0.0,
            current_value=current_value,
            recommended_value=baseline_value,
            category=category or gpo_name or "",
            raw_data=item,
        )
