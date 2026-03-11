"""Parser for CISA SCuBA (ScubaGear) assessment reports."""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path

from ..models import (
    Action, SourceTool, Priority, RiskLevel, UserImpact,
    ImplementationEffort, Workload, ActionStatus,
)

# SCuBA product to workload mapping
PRODUCT_WORKLOAD_MAP = {
    "aad": Workload.ENTRA.value,
    "entra": Workload.ENTRA.value,
    "exo": Workload.EXCHANGE.value,
    "defender": Workload.DEFENDER.value,
    "sharepoint": Workload.SHAREPOINT.value,
    "onedrive": Workload.ONEDRIVE.value,
    "teams": Workload.TEAMS.value,
    "powerplatform": Workload.POWER_PLATFORM.value,
    "power platform": Workload.POWER_PLATFORM.value,
}


def _map_criticality_to_priority(criticality: str) -> str:
    c = (criticality or "").lower()
    if "shall" in c or "critical" in c:
        return Priority.HIGH.value
    if "should" in c:
        return Priority.MEDIUM.value
    if "may" in c or "informational" in c:
        return Priority.LOW.value
    return Priority.MEDIUM.value


def _scuba_result_to_status(result: str) -> str:
    r = (result or "").lower().strip()
    if r in ("pass", "passed"):
        return ActionStatus.COMPLETED.value
    if r in ("fail", "failed"):
        return ActionStatus.TODO.value
    if r in ("warning", "warn"):
        return ActionStatus.IN_PLANNING.value
    if r in ("n/a", "not applicable"):
        return ActionStatus.NOT_APPLICABLE.value
    if r in ("manual", "manual check"):
        return ActionStatus.TODO.value
    return ActionStatus.TODO.value


class ScubaParser:
    """Parse SCuBA (ScubaGear) report output."""

    source_tool = SourceTool.SCUBA.value

    def parse_file(self, file_path: str) -> list[Action]:
        path = Path(file_path)
        suffix = path.suffix.lower()

        if suffix == ".json":
            return self._parse_json(path)
        elif suffix == ".csv":
            return self._parse_csv(path)
        else:
            raise ValueError(f"Unsupported SCuBA file format: {suffix}. Use .json or .csv")

    def _parse_json(self, path: Path) -> list[Action]:
        with open(path) as f:
            data = json.load(f)

        actions = []
        # ScubaGear JSON structure: {"Results": {"product": [...]}} or flat list
        results = data
        if isinstance(data, dict):
            results = data.get("Results", data.get("results", data))
            if isinstance(results, dict):
                # Nested by product
                for product, items in results.items():
                    if isinstance(items, list):
                        for item in items:
                            action = self._item_to_action(item, product)
                            if action:
                                actions.append(action)
            elif isinstance(results, list):
                for item in results:
                    product = item.get("Product", item.get("product", ""))
                    action = self._item_to_action(item, product)
                    if action:
                        actions.append(action)
        elif isinstance(data, list):
            for item in data:
                product = item.get("Product", item.get("product", ""))
                action = self._item_to_action(item, product)
                if action:
                    actions.append(action)

        return actions

    def _parse_csv(self, path: Path) -> list[Action]:
        actions = []
        with open(path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                action = self._row_to_action(row)
                if action:
                    actions.append(action)
        return actions

    def _item_to_action(self, item: dict, product: str = "") -> Action | None:
        # Normalize field names (ScubaGear uses various conventions)
        control_id = (
            item.get("Control", "")
            or item.get("PolicyId", "")
            or item.get("control_id", "")
            or item.get("Requirement", "")
        )
        if not control_id:
            control_id = item.get("Control ID", str(hash(str(item)))[:8])

        result = (
            item.get("Result", "")
            or item.get("result", "")
            or item.get("Status", "")
            or item.get("ComplianceStatus", "")
        )
        criticality = item.get("Criticality", item.get("criticality", ""))
        details = item.get("Details", item.get("details", ""))
        requirement = item.get("Requirement", item.get("requirement", ""))
        description = item.get("Description", item.get("description", ""))

        product_lower = (product or item.get("Product", "")).lower()
        workload = Workload.GENERAL.value
        for key, wl in PRODUCT_WORKLOAD_MAP.items():
            if key in product_lower:
                workload = wl
                break

        title = requirement or control_id
        if product and not title.lower().startswith(product_lower):
            title = f"[{product.upper()}] {title}"

        return Action(
            title=title,
            description=description or details or "",
            source_tool=self.source_tool,
            source_id=f"scuba_{control_id}",
            workload=workload,
            status=_scuba_result_to_status(result),
            priority=_map_criticality_to_priority(criticality),
            risk_level=RiskLevel.HIGH.value if "fail" in (result or "").lower() else RiskLevel.MEDIUM.value,
            user_impact=UserImpact.LOW.value,
            implementation_effort=ImplementationEffort.MEDIUM.value,
            score=1.0 if (result or "").lower() in ("pass", "passed") else 0.0,
            max_score=1.0,
            score_percentage=100.0 if (result or "").lower() in ("pass", "passed") else 0.0,
            current_value=details or "",
            category=product or "",
            subcategory=criticality or "",
            reference_url=item.get("ReferenceUrl", item.get("reference_url", "")),
            raw_data=item,
        )

    def _row_to_action(self, row: dict) -> Action | None:
        # CSV rows have similar fields
        return self._item_to_action(dict(row), row.get("Product", row.get("product", "")))
