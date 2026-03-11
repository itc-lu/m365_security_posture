"""Parser for Microsoft Secure Score data (Graph API JSON or portal CSV export)."""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path

from ..models import (
    Action, SourceTool, Priority, RiskLevel, UserImpact,
    ImplementationEffort, Workload, ActionStatus,
)


# Map Secure Score categories to workloads (EN, DE, FR)
CATEGORY_WORKLOAD_MAP = {
    # English
    "Identity": Workload.ENTRA.value,
    "Data": Workload.PURVIEW.value,
    "Device": Workload.INTUNE.value,
    "Apps": Workload.GENERAL.value,
    "Infrastructure": Workload.GENERAL.value,
    # German
    "Identität": Workload.ENTRA.value,
    "Daten": Workload.PURVIEW.value,
    "Gerät": Workload.INTUNE.value,
    # French
    "Identité": Workload.ENTRA.value,
    "Données": Workload.PURVIEW.value,
    "Appareil": Workload.INTUNE.value,
    "Applications": Workload.GENERAL.value,
}

# Map product names from CSV to workloads
PRODUCT_WORKLOAD_MAP = {
    "exchange online": Workload.EXCHANGE.value,
    "microsoft defender for office": Workload.DEFENDER.value,
    "microsoft defender für office": Workload.DEFENDER.value,
    "microsoft defender pour office": Workload.DEFENDER.value,
    "defender for identity": Workload.DEFENDER.value,
    "defender for cloud apps": Workload.DEFENDER.value,
    "microsoft information protection": Workload.PURVIEW.value,
    "sharepoint": Workload.SHAREPOINT.value,
    "onedrive": Workload.ONEDRIVE.value,
    "teams": Workload.TEAMS.value,
    "intune": Workload.INTUNE.value,
    "entra": Workload.ENTRA.value,
    "azure ad": Workload.ENTRA.value,
}

SCORE_IMPACT_PRIORITY = {
    (7, float("inf")): Priority.CRITICAL.value,
    (4, 7): Priority.HIGH.value,
    (2, 4): Priority.MEDIUM.value,
    (0, 2): Priority.LOW.value,
}

# Multi-language column header mapping to internal field names.
# Each key maps to a canonical field name used in _csv_row_to_action.
_COLUMN_ALIASES: dict[str, str] = {
    # Rank / ID
    "rank": "rank",
    "rang": "rank",
    "classement": "rank",
    # Title / Recommended action
    "recommended action": "title",
    "recommended actions": "title",
    "empfohlene maßnahme": "title",
    "empfohlene massnahme": "title",
    "action recommandée": "title",
    "title": "title",
    "name": "title",
    # Score impact
    "score impact": "score_impact",
    "bewertungsauswirkung": "score_impact",
    "impact du score": "score_impact",
    # Points achieved
    "points achieved": "points",
    "erzielte punkte": "points",
    "points obtenus": "points",
    # Status
    "status": "status",
    # Regressed
    "regressed": "regressed",
    "verschlechtert": "regressed",
    "régressé": "regressed",
    # Has license
    "have license?": "has_license",
    "do you have a license?": "has_license",
    "haben sie eine lizenz?": "has_license",
    "licence disponible ?": "has_license",
    "avez-vous une licence ?": "has_license",
    # Category
    "category": "category",
    "kategorie": "category",
    "catégorie": "category",
    # Product
    "product": "product",
    "produkt": "product",
    "produit": "product",
    # Last sync
    "last synced": "last_sync",
    "letzte synchronisierung": "last_sync",
    "dernière synchronisation": "last_sync",
    # Description (if present in extended export)
    "description": "description",
    "beschreibung": "description",
    # Implementation status
    "implementation status": "implementation_status",
    "implementierungsstatus": "implementation_status",
    "statut de mise en œuvre": "implementation_status",
    # User impact
    "user impact": "user_impact",
    "benutzerauswirkungen": "user_impact",
    "impact utilisateur": "user_impact",
    # Implementation steps / remediation
    "implementation steps": "remediation",
    "next steps": "remediation",
    "nächste schritte": "remediation",
    "prochaines étapes": "remediation",
    "prerequisites": "prerequisites",
    "voraussetzungen": "prerequisites",
    "prérequis": "prerequisites",
}

# Status mapping: portal status text (multi-lang) to ActionStatus
_STATUS_MAP: dict[str, str] = {
    # English
    "to address": ActionStatus.TODO.value,
    "completed": ActionStatus.COMPLETED.value,
    "in progress": ActionStatus.IN_PROGRESS.value,
    "planned": ActionStatus.IN_PLANNING.value,
    "risk accepted": ActionStatus.RISK_ACCEPTED.value,
    "not applicable": ActionStatus.NOT_APPLICABLE.value,
    "resolved through third party": ActionStatus.THIRD_PARTY.value,
    "resolved through alternate mitigation": ActionStatus.THIRD_PARTY.value,
    # German
    "zu behandeln": ActionStatus.TODO.value,
    "abgeschlossen": ActionStatus.COMPLETED.value,
    "in bearbeitung": ActionStatus.IN_PROGRESS.value,
    "geplant": ActionStatus.IN_PLANNING.value,
    "risiko akzeptiert": ActionStatus.RISK_ACCEPTED.value,
    "nicht anwendbar": ActionStatus.NOT_APPLICABLE.value,
    "über drittanbieter aufgelöst": ActionStatus.THIRD_PARTY.value,
    # French
    "à traiter": ActionStatus.TODO.value,
    "terminé": ActionStatus.COMPLETED.value,
    "en cours": ActionStatus.IN_PROGRESS.value,
    "planifié": ActionStatus.IN_PLANNING.value,
    "risque accepté": ActionStatus.RISK_ACCEPTED.value,
    "non applicable": ActionStatus.NOT_APPLICABLE.value,
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


def _parse_points(raw: str) -> tuple[float, float]:
    """Parse points string like '0/9' or '3/8' into (score, max_score)."""
    m = re.match(r"(\d+(?:[.,]\d+)?)\s*/\s*(\d+(?:[.,]\d+)?)", (raw or "").strip())
    if m:
        score = float(m.group(1).replace(",", "."))
        max_score = float(m.group(2).replace(",", "."))
        return score, max_score
    return 0.0, 0.0


def _parse_score_impact(raw: str) -> float:
    """Parse score impact string like '+3.24 %' or '+2,88 %' into a float."""
    m = re.search(r"[+-]?\s*(\d+(?:[.,]\d+)?)", (raw or "").strip())
    if m:
        return float(m.group(1).replace(",", "."))
    return 0.0


def _resolve_workload(category: str, product: str) -> str:
    """Determine workload from category and product name."""
    # Try product first (more specific)
    product_lower = (product or "").lower().strip()
    for key, workload in PRODUCT_WORKLOAD_MAP.items():
        if key in product_lower:
            return workload
    # Fall back to category
    return CATEGORY_WORKLOAD_MAP.get(category, Workload.GENERAL.value)


def _normalize_headers(headers: list[str]) -> dict[str, str]:
    """Map CSV headers to canonical field names using _COLUMN_ALIASES."""
    mapping = {}
    for header in headers:
        normalized = header.strip().lower()
        # Strip BOM if present
        normalized = normalized.lstrip("\ufeff")
        if normalized in _COLUMN_ALIASES:
            mapping[header] = _COLUMN_ALIASES[normalized]
        else:
            # Keep unknown headers as-is for raw_data
            mapping[header] = normalized
    return mapping


class SecureScoreParser:
    """Parse Microsoft Secure Score JSON data or portal CSV export."""

    source_tool = SourceTool.SECURE_SCORE.value

    def parse_file(self, file_path: str) -> list[Action]:
        path = Path(file_path)
        suffix = path.suffix.lower()

        if suffix == ".csv":
            return self._parse_csv(path)

        # Default: JSON
        return self._parse_json(path)

    def _parse_json(self, path: Path) -> list[Action]:
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

    def _parse_csv(self, path: Path) -> list[Action]:
        """Parse a Secure Score CSV export from the M365 portal (any language)."""
        actions = []
        with open(path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            header_map = _normalize_headers(reader.fieldnames or [])
            for row in reader:
                # Build a canonical-key dict from the row
                canonical = {}
                raw = {}
                for orig_key, value in row.items():
                    canon = header_map.get(orig_key, orig_key)
                    canonical[canon] = (value or "").strip()
                    raw[orig_key] = value

                action = self._csv_row_to_action(canonical, raw, str(path))
                if action:
                    actions.append(action)
        return actions

    def _csv_row_to_action(self, row: dict, raw: dict, source_file: str) -> Action | None:
        """Convert a single CSV row (with canonical keys) to an Action."""
        title = row.get("title", "")
        if not title:
            return None

        # Parse points "0/9" -> score=0, max_score=9
        score, max_score = _parse_points(row.get("points", ""))

        # Parse score impact "+3.24 %" -> 3.24
        score_impact = _parse_score_impact(row.get("score_impact", ""))

        # Use score_impact to determine priority when max_score is available
        priority_score = max_score if max_score > 0 else score_impact
        priority = _map_priority(priority_score)

        # Status mapping
        status_raw = row.get("status", "").lower().strip()
        status = _STATUS_MAP.get(status_raw, ActionStatus.TODO.value)
        # If we have score data, let it refine status
        if status == ActionStatus.TODO.value and score > 0 and max_score > 0:
            status = _determine_status(score, max_score)

        # Category and product
        category = row.get("category", "")
        product = row.get("product", "")
        workload = _resolve_workload(category, product)

        # License
        has_license = row.get("has_license", "").lower().strip()
        licence_text = ""
        if has_license in ("nein", "no", "non"):
            licence_text = "Additional license required"
        elif has_license in ("ja", "yes", "oui"):
            licence_text = "Licensed"

        # Description and remediation (from extended exports or manual enrichment)
        description = row.get("description", "")
        implementation_status = row.get("implementation_status", "")
        remediation = row.get("remediation", "")
        prerequisites = row.get("prerequisites", "")
        user_impact_str = row.get("user_impact", "")

        # Build combined remediation text
        remediation_parts = []
        if prerequisites:
            remediation_parts.append(f"Prerequisites:\n{prerequisites}")
        if remediation:
            remediation_parts.append(f"Next steps:\n{remediation}")
        remediation_text = "\n\n".join(remediation_parts)

        # Build combined description
        desc_parts = []
        if description:
            desc_parts.append(description)
        if implementation_status:
            desc_parts.append(f"Implementation status:\n{implementation_status}")
        description_text = "\n\n".join(desc_parts)

        # Rank as source_id
        rank = row.get("rank", "")

        action = Action(
            title=title,
            description=description_text,
            source_tool=self.source_tool,
            source_id=f"ss_{title.replace(' ', '_').lower()[:40]}",
            workload=workload,
            status=status,
            priority=priority,
            risk_level=RiskLevel.MEDIUM.value,
            user_impact=_map_user_impact(user_impact_str),
            implementation_effort=ImplementationEffort.MEDIUM.value,
            required_licence=licence_text,
            score=score,
            max_score=max_score,
            score_percentage=round((score / max_score * 100), 1) if max_score > 0 else 0,
            remediation_steps=remediation_text,
            category=category,
            subcategory=product,
            source_report_file=source_file,
            raw_data=raw,
        )
        return action

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
