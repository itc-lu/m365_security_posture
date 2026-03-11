"""Parser for Microsoft Secure Score data (from Graph API JSON export)."""

from __future__ import annotations

import json
from pathlib import Path

from ..models import (
    Action, SourceTool, Priority, RiskLevel, UserImpact,
    ImplementationEffort, Workload, ActionStatus,
)


# Map Secure Score categories to workloads
CATEGORY_WORKLOAD_MAP = {
    "Identity": Workload.ENTRA.value,
    "Data": Workload.PURVIEW.value,
    "Device": Workload.INTUNE.value,
    "Apps": Workload.GENERAL.value,
    "Infrastructure": Workload.GENERAL.value,
}

SCORE_IMPACT_PRIORITY = {
    (7, float("inf")): Priority.CRITICAL.value,
    (4, 7): Priority.HIGH.value,
    (2, 4): Priority.MEDIUM.value,
    (0, 2): Priority.LOW.value,
}


def _map_priority(max_score: float) -> str:
    for (low, high), priority in SCORE_IMPACT_PRIORITY.items():
        if low <= max_score < high:
            return priority
    return Priority.MEDIUM.value


def _map_user_impact(ui: str) -> str:
    ui_lower = (ui or "").lower()
    if "high" in ui_lower:
        return UserImpact.HIGH.value
    if "moderate" in ui_lower or "medium" in ui_lower:
        return UserImpact.MEDIUM.value
    if "low" in ui_lower:
        return UserImpact.LOW.value
    return UserImpact.LOW.value


def _map_effort(difficulty: str) -> str:
    diff_lower = (difficulty or "").lower()
    if "difficult" in diff_lower or "high" in diff_lower:
        return ImplementationEffort.HIGH.value
    if "moderate" in diff_lower or "medium" in diff_lower:
        return ImplementationEffort.MEDIUM.value
    if "easy" in diff_lower or "low" in diff_lower:
        return ImplementationEffort.LOW.value
    return ImplementationEffort.MEDIUM.value


def _determine_status(score: float, max_score: float) -> str:
    if max_score <= 0:
        return ActionStatus.TODO.value
    pct = score / max_score
    if pct >= 1.0:
        return ActionStatus.COMPLETED.value
    if pct > 0:
        return ActionStatus.IN_PROGRESS.value
    return ActionStatus.TODO.value


class SecureScoreParser:
    """Parse Microsoft Secure Score JSON data."""

    source_tool = SourceTool.SECURE_SCORE.value

    def parse_file(self, file_path: str) -> list[Action]:
        path = Path(file_path)
        with open(path) as f:
            data = json.load(f)

        # Handle both direct array and Graph API response format
        if isinstance(data, dict):
            controls = data.get("value", data.get("controlScores", []))
            if "controlScores" not in data and "value" in data:
                # Top-level secureScores response - take the latest
                if controls and isinstance(controls[0], dict) and "controlScores" in controls[0]:
                    controls = controls[0]["controlScores"]
        elif isinstance(data, list):
            controls = data
        else:
            controls = []

        return self._parse_controls(controls, str(path))

    def parse_graph_response(self, data: dict) -> list[Action]:
        """Parse a direct MS Graph API response."""
        if "controlScores" in data:
            controls = data["controlScores"]
        elif "value" in data:
            value = data["value"]
            if value and isinstance(value[0], dict) and "controlScores" in value[0]:
                controls = value[0]["controlScores"]
            else:
                controls = value
        else:
            controls = []
        return self._parse_controls(controls, "graph_api")

    def _parse_controls(self, controls: list[dict], source_file: str) -> list[Action]:
        actions = []
        for ctrl in controls:
            score = float(ctrl.get("score", ctrl.get("currentScore", 0)))
            max_score = float(ctrl.get("maxScore", ctrl.get("scoreInPercentage", 0)))
            if max_score == 0 and "scoreInPercentage" in ctrl:
                max_score = 10  # Default max

            name = ctrl.get("controlName", ctrl.get("name", "Unknown Control"))
            category = ctrl.get("controlCategory", ctrl.get("category", ""))
            description = ctrl.get("description", "")
            remediation = ctrl.get("remediation", ctrl.get("implementationStatus", ""))
            user_impact_str = ctrl.get("userImpact", "")
            difficulty = ctrl.get("implementationCost", ctrl.get("difficulty", ""))

            action = Action(
                title=name,
                description=description,
                source_tool=self.source_tool,
                source_id=f"ss_{name.replace(' ', '_').lower()[:40]}",
                workload=CATEGORY_WORKLOAD_MAP.get(category, Workload.GENERAL.value),
                status=_determine_status(score, max_score),
                priority=_map_priority(max_score),
                risk_level=RiskLevel.MEDIUM.value,
                user_impact=_map_user_impact(user_impact_str),
                implementation_effort=_map_effort(difficulty),
                required_licence=ctrl.get("azureLicenseType", ctrl.get("license", "")),
                score=score,
                max_score=max_score,
                score_percentage=round((score / max_score * 100), 1) if max_score > 0 else 0,
                remediation_steps=remediation,
                category=category,
                reference_url=ctrl.get("actionUrl", ctrl.get("referenceUrl", "")),
                source_report_file=source_file,
                raw_data=ctrl,
            )
            actions.append(action)
        return actions
