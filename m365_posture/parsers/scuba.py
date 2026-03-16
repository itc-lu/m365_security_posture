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

    def __init__(self):
        # Report metadata populated during parsing of rich ScubaResults JSON
        self.report_metadata: dict = {}
        self.product_summary: dict = {}

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

        # Detect rich ScubaResults format (has MetaData + Results + Summary)
        if isinstance(data, dict) and "MetaData" in data and "Results" in data:
            return self._parse_scuba_results(data)

        # Detect TestResults.json format (flat list with PolicyId + RequirementMet)
        if isinstance(data, list) and data and "PolicyId" in data[0]:
            return self._parse_test_results(data)

        actions = []
        # Generic ScubaGear JSON: {"Results": {"product": [...]}} or flat list
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

    def _parse_scuba_results(self, data: dict) -> list[Action]:
        """Parse the rich ScubaResults JSON (full ScubaGear output with MetaData/Summary/Results)."""
        meta = data.get("MetaData", {})
        self.report_metadata = {
            "tenant_id": meta.get("TenantId", ""),
            "tenant_name": meta.get("DisplayName", ""),
            "domain": meta.get("DomainName", ""),
            "product_suite": meta.get("ProductSuite", ""),
            "products_assessed": meta.get("ProductsAssessed", []),
            "tool": meta.get("Tool", "ScubaGear"),
            "tool_version": meta.get("ToolVersion", ""),
            "timestamp": meta.get("TimestampZulu", ""),
            "report_uuid": meta.get("ReportUUID", ""),
        }

        # Product abbreviation mapping (e.g. "Azure Active Directory" -> "AAD")
        abbrev_map = meta.get("ProductAbbreviationMapping", {})

        # Store per-product summary
        self.product_summary = data.get("Summary", {})

        actions = []
        results = data.get("Results", {})
        for product_abbrev, groups in results.items():
            if not isinstance(groups, list):
                continue
            for group in groups:
                group_name = group.get("GroupName", "")
                group_number = group.get("GroupNumber", "")
                group_url = group.get("GroupReferenceURL", "")
                for control in group.get("Controls", []):
                    action = self._control_to_action(
                        control, product_abbrev, group_name, group_number, group_url
                    )
                    if action:
                        actions.append(action)

        return actions

    def _parse_test_results(self, data: list[dict]) -> list[Action]:
        """Parse TestResults.json format (flat list with PolicyId/RequirementMet)."""
        actions = []
        for item in data:
            policy_id = item.get("PolicyId", "")
            if not policy_id:
                continue

            # Determine product from policy ID prefix (e.g. MS.AAD.1.1v1 -> AAD)
            product = ""
            match = re.match(r"MS\.(\w+)\.", policy_id)
            if match:
                product = match.group(1)

            result = "Pass" if item.get("RequirementMet", False) else "Fail"
            criticality = item.get("Criticality", "")
            details = item.get("ReportDetails", "")

            product_lower = product.lower()
            workload = Workload.GENERAL.value
            for key, wl in PRODUCT_WORKLOAD_MAP.items():
                if key in product_lower:
                    workload = wl
                    break

            title = f"[{product}] {policy_id}"

            actions.append(Action(
                title=title,
                description=details,
                source_tool=self.source_tool,
                source_id=f"scuba_{policy_id}",
                workload=workload,
                status=_scuba_result_to_status(result),
                priority=_map_criticality_to_priority(criticality),
                risk_level=RiskLevel.HIGH.value if result == "Fail" else RiskLevel.MEDIUM.value,
                user_impact=UserImpact.LOW.value,
                implementation_effort=ImplementationEffort.MEDIUM.value,
                score=1.0 if result == "Pass" else 0.0,
                max_score=1.0,
                score_percentage=100.0 if result == "Pass" else 0.0,
                current_value=details,
                category=product,
                subcategory=criticality,
                raw_data=item,
            ))
        return actions

    def _control_to_action(
        self, control: dict, product: str, group_name: str,
        group_number: str, group_url: str,
    ) -> Action | None:
        """Convert a control from the rich Results structure to an Action."""
        control_id = control.get("Control ID", "")
        requirement = control.get("Requirement", "")
        result = control.get("Result", "")
        criticality = control.get("Criticality", "")
        details = control.get("Details", "")

        if not control_id:
            return None

        product_lower = product.lower()
        workload = Workload.GENERAL.value
        for key, wl in PRODUCT_WORKLOAD_MAP.items():
            if key in product_lower:
                workload = wl
                break

        title = requirement or control_id
        if product and not title.lower().startswith(product_lower):
            title = f"[{product}] {title}"

        # Build a richer description with group context
        desc_parts = []
        if group_name:
            desc_parts.append(f"**Group:** {group_number}. {group_name}")
        if details:
            desc_parts.append(f"**Details:** {details}")
        description = "\n\n".join(desc_parts) if desc_parts else details or ""

        return Action(
            title=title,
            description=description,
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
            reference_url=group_url or "",
            raw_data=control,
        )

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
        # "Control ID" (with space) is the standard CSV/JSON field from ScubaGear
        control_id = (
            item.get("Control ID", "")
            or item.get("Control", "")
            or item.get("PolicyId", "")
            or item.get("control_id", "")
        )
        if not control_id:
            control_id = item.get("Requirement", str(hash(str(item)))[:8])

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
        """Parse CSV row. Detects product from Control ID prefix (MS.AAD.* -> AAD)."""
        row_dict = dict(row)
        product = row_dict.get("Product", row_dict.get("product", ""))

        # If no Product column, infer from Control ID (e.g. MS.AAD.1.1v1 -> AAD)
        if not product:
            ctrl_id = row_dict.get("Control ID", "")
            match = re.match(r"MS\.(\w+)\.", ctrl_id)
            if match:
                product = match.group(1)

        return self._item_to_action(row_dict, product)
