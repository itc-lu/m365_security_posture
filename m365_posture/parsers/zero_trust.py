"""Parser for Zero Trust Assessment tool reports."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from ..models import (
    Action, SourceTool, Priority, RiskLevel, UserImpact,
    ImplementationEffort, Workload, ActionStatus,
)

# Zero Trust pillars to workload mapping
PILLAR_WORKLOAD_MAP = {
    "identity": Workload.ENTRA.value,
    "devices": Workload.INTUNE.value,
    "applications": Workload.GENERAL.value,
    "data": Workload.PURVIEW.value,
    "infrastructure": Workload.GENERAL.value,
    "networks": Workload.GENERAL.value,
    "visibility": Workload.DEFENDER.value,
}


def _score_to_status(score: float) -> str:
    if score >= 100:
        return ActionStatus.COMPLETED.value
    if score > 0:
        return ActionStatus.IN_PROGRESS.value
    return ActionStatus.TODO.value


def _score_to_priority(score: float) -> str:
    if score < 25:
        return Priority.CRITICAL.value
    if score < 50:
        return Priority.HIGH.value
    if score < 75:
        return Priority.MEDIUM.value
    return Priority.LOW.value


class ZeroTrustParser:
    """Parse Zero Trust Assessment reports (JSON/CSV)."""

    source_tool = SourceTool.ZERO_TRUST.value

    def parse_file(self, file_path: str) -> list[Action]:
        path = Path(file_path)
        suffix = path.suffix.lower()

        if suffix == ".json":
            return self._parse_json(path)
        elif suffix == ".csv":
            return self._parse_csv(path)
        else:
            raise ValueError(f"Unsupported Zero Trust file format: {suffix}. Use .json or .csv")

    def _parse_json(self, path: Path) -> list[Action]:
        with open(path) as f:
            data = json.load(f)

        actions = []
        # Handle various ZT assessment output formats
        items = data
        if isinstance(data, dict):
            items = (
                data.get("assessments", [])
                or data.get("results", [])
                or data.get("Assessments", [])
                or data.get("controls", [])
                or data.get("value", [])
            )
            # If it's a pillar-based structure
            if not items and any(k.lower() in PILLAR_WORKLOAD_MAP for k in data.keys()):
                for pillar, pillar_data in data.items():
                    if isinstance(pillar_data, list):
                        for item in pillar_data:
                            item["_pillar"] = pillar
                            actions.append(self._item_to_action(item))
                    elif isinstance(pillar_data, dict):
                        controls = pillar_data.get("controls", pillar_data.get("items", []))
                        for item in controls:
                            item["_pillar"] = pillar
                            actions.append(self._item_to_action(item))
                return actions

        if isinstance(items, list):
            for item in items:
                actions.append(self._item_to_action(item))

        return actions

    def _parse_csv(self, path: Path) -> list[Action]:
        actions = []
        with open(path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                actions.append(self._item_to_action(dict(row)))
        return actions

    def _item_to_action(self, item: dict) -> Action:
        title = (
            item.get("title", "")
            or item.get("Title", "")
            or item.get("controlName", "")
            or item.get("Control", "")
            or item.get("name", "")
            or "Unknown ZT Control"
        )
        description = (
            item.get("description", "")
            or item.get("Description", "")
            or item.get("details", "")
            or ""
        )
        pillar = (
            item.get("_pillar", "")
            or item.get("pillar", "")
            or item.get("Pillar", "")
            or item.get("category", "")
            or item.get("Category", "")
            or ""
        )
        score = float(item.get("score", item.get("Score", item.get("percentage", 0))))
        max_score = float(item.get("maxScore", item.get("MaxScore", 100)))

        control_id = (
            item.get("id", "")
            or item.get("Id", "")
            or item.get("controlId", "")
            or title.replace(" ", "_").lower()[:30]
        )

        workload = Workload.GENERAL.value
        for key, wl in PILLAR_WORKLOAD_MAP.items():
            if key in pillar.lower():
                workload = wl
                break

        remediation = (
            item.get("remediation", "")
            or item.get("Remediation", "")
            or item.get("recommendation", "")
            or item.get("Recommendation", "")
            or ""
        )

        return Action(
            title=title,
            description=description,
            source_tool=self.source_tool,
            source_id=f"zt_{control_id}",
            workload=workload,
            status=_score_to_status(score),
            priority=_score_to_priority(score),
            risk_level=RiskLevel.HIGH.value if score < 50 else RiskLevel.MEDIUM.value,
            user_impact=UserImpact.LOW.value,
            implementation_effort=ImplementationEffort.MEDIUM.value,
            score=score,
            max_score=max_score,
            score_percentage=round((score / max_score * 100), 1) if max_score > 0 else 0,
            remediation_steps=remediation,
            current_value=str(item.get("currentValue", item.get("CurrentValue", ""))),
            recommended_value=str(item.get("recommendedValue", item.get("RecommendedValue", ""))),
            category=pillar,
            reference_url=item.get("referenceUrl", item.get("ReferenceUrl", "")),
            raw_data=item,
        )
