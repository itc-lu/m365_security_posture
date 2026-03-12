"""Parser for Microsoft Secure Score data (Graph API JSON or portal CSV export)."""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import TYPE_CHECKING

from ..models import (
    Action, SecureScoreControl, SourceTool, Priority, RiskLevel, UserImpact,
    ImplementationEffort, Workload, ActionStatus,
)

if TYPE_CHECKING:
    from ..database import Database


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

        # For JSON imports that include full control profile data (e.g. controlProfiles),
        # build a profiles map for enrichment
        profiles_map = {}
        profiles = data.get("controlProfiles", []) if isinstance(data, dict) else []
        for p in profiles:
            pid = p.get("id", p.get("controlName", ""))
            if pid:
                profiles_map[pid.lower()] = p

        return self._parse_controls(controls, str(path), profiles_map or None)

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

        # Rank as reference_id
        rank = row.get("rank", "")

        action = Action(
            title=title,
            description=description_text,
            source_tool=self.source_tool,
            source_id=f"ss_{title.replace(' ', '_').lower()[:40]}",
            reference_id=rank,
            workload=workload,
            status=status,
            priority=priority,
            risk_level=RiskLevel.MEDIUM.value,
            user_impact=_map_user_impact(user_impact_str),
            implementation_effort=ImplementationEffort.MEDIUM.value,
            required_licence=licence_text,
            score=score,
            max_score=max_score,
            score_percentage=round((score / max_score * 100), 2) if max_score > 0 else 0,
            remediation_steps=remediation_text,
            category=category,
            subcategory=product,
            source_report_file=source_file,
            raw_data=raw,
        )
        return action

    def parse_graph_response(self, data: dict, profiles_data: dict | list | None = None) -> tuple[list[Action], dict]:
        """Parse a direct MS Graph API response.

        If profiles_data is provided (from secureScoreControlProfiles),
        it will be used to enrich actions with maxScore, description,
        remediation steps, user impact, etc.

        Returns (actions, overall_scores) where overall_scores has
        currentScore and maxScore from the top-level secureScores object.
        """
        overall_scores = {}
        score_entry = None

        if "controlScores" in data:
            controls = data["controlScores"]
            score_entry = data
        elif "value" in data:
            value = data["value"]
            if value and isinstance(value[0], dict) and "controlScores" in value[0]:
                score_entry = value[0]
                controls = score_entry["controlScores"]
            else:
                controls = value
        else:
            controls = []

        # Extract top-level overall scores and metadata from the secureScores object
        if score_entry:
            overall_scores = {
                "currentScore": float(score_entry.get("currentScore", 0)),
                "maxScore": float(score_entry.get("maxScore", 0)),
                "createdDateTime": score_entry.get("createdDateTime", ""),
                "activeUserCount": score_entry.get("activeUserCount", 0),
                "licensedUserCount": score_entry.get("licensedUserCount", 0),
                "enabledServices": score_entry.get("enabledServices", []),
                "averageComparativeScores": score_entry.get("averageComparativeScores", []),
            }

        # Build a lookup from control profiles (by id/controlName and title)
        profiles_map = {}
        if profiles_data:
            profiles_list = profiles_data.get("value", profiles_data) if isinstance(profiles_data, dict) else profiles_data
            if isinstance(profiles_list, list):
                for p in profiles_list:
                    # Index by id (primary key)
                    pid = p.get("id", "")
                    if pid:
                        profiles_map[pid.lower()] = p
                    # Also index by controlName if different from id
                    cname = p.get("controlName", "")
                    if cname and cname.lower() != pid.lower():
                        profiles_map[cname.lower()] = p
                    # Also index by title for fallback matching
                    title = p.get("title", "")
                    if title:
                        profiles_map[title.lower()] = p

        actions = self._parse_controls(controls, "graph_api", profiles_map)

        # Compute sequential Rang (like Microsoft portal): sort by maxScore desc, assign 1..N
        actions.sort(key=lambda a: (a.max_score or 0), reverse=True)
        for i, action in enumerate(actions, start=1):
            action.reference_id = str(i)

        return actions, overall_scores

    def _parse_controls(self, controls: list[dict], source_file: str,
                        profiles_map: dict | None = None) -> list[Action]:
        """Parse controlScores entries, enriching each with its profile data.

        Data sources per field:
        - controlScores[]: controlName, score, controlCategory, description
          (description is tenant-specific implementation status, NOT generic description)
        - secureScoreControlProfiles[]: id (==controlName), maxScore, title,
          description (generic), remediation, prerequisites, userImpact,
          implementationCost, service, actionUrl, threats, tier, actionType,
          remediationImpact, deprecated, rank, azureLicenseType, controlStateUpdates
        """
        profiles_map = profiles_map or {}
        actions = []
        self._unmatched_controls = []
        self._profile_count = len(set(id(v) for v in profiles_map.values())) if profiles_map else 0

        for idx, ctrl in enumerate(controls, start=1):
            name = ctrl.get("controlName", ctrl.get("name", "Unknown Control"))

            # Look up the control profile by id (same as controlName)
            profile = profiles_map.get(name.lower(), {})

            if not profile and profiles_map:
                self._unmatched_controls.append(name)

            # ── Score ──
            # controlScores has: score (current achieved points)
            # Profile has: maxScore (maximum achievable points)
            score = float(ctrl.get("score", 0))
            # maxScore comes exclusively from the profile; controlScores doesn't have it
            profile_max = profile.get("maxScore")
            max_score = float(profile_max) if profile_max is not None else 0.0

            # ── Category ──
            category = ctrl.get("controlCategory", "") or profile.get("controlCategory", "")

            # ── Description ──
            # controlScores.description = tenant-specific implementation details
            # profile.description = static generic description of what the control does
            ctrl_description = ctrl.get("description", "")
            profile_description = profile.get("description", "")
            # Use profile description as main description; ctrl description as current state
            description = profile_description or ctrl_description
            current_value = ctrl_description if (ctrl_description and ctrl_description != description) else ""

            # ── Remediation (from profile only) ──
            remediation_parts = []
            prerequisites = profile.get("prerequisites", "")
            remediation_raw = profile.get("remediation", "")
            if prerequisites:
                remediation_parts.append(f"Prerequisites:\n{prerequisites}")
            if remediation_raw:
                remediation_parts.append(f"Next steps:\n{remediation_raw}")
            remediation = "\n\n".join(remediation_parts)

            # ── User impact and effort (from profile) ──
            user_impact_str = profile.get("userImpact", "")
            difficulty = profile.get("implementationCost", "")

            # ── Product / service (from profile) ──
            product = profile.get("service", "")
            if product:
                product = ", ".join(product.split(";"))

            # ── Workload ──
            # First try service/product for specific workload (e.g. MDO controls)
            workload = Workload.GENERAL.value
            if product:
                workload = _resolve_workload(category, product)
            if workload == Workload.GENERAL.value and category:
                workload = CATEGORY_WORKLOAD_MAP.get(category, Workload.GENERAL.value)

            # ── Reference URL ──
            ref_url = profile.get("actionUrl", "")

            # ── License ──
            licence = profile.get("azureLicenseType", "")

            # ── Rank placeholder (overwritten by sequential Rang after sorting) ──
            rank = idx

            # ── Enrichment fields from profile ──
            threats = profile.get("threats", []) or []
            tier = profile.get("tier", "")
            action_type = profile.get("actionType", "")
            remediation_impact = profile.get("remediationImpact", "")
            deprecated = bool(profile.get("deprecated", False))

            # ── Status from controlStateUpdates ──
            control_states = profile.get("controlStateUpdates", []) or []
            status_override = None
            for cs in control_states:
                state = (cs.get("state") or "").lower()
                if state == "thirdparty":
                    status_override = ActionStatus.THIRD_PARTY.value
                elif state == "ignore" or state == "riskaccepted":
                    status_override = ActionStatus.RISK_ACCEPTED.value

            # ── Determine status from score ──
            if status_override:
                status = status_override
            elif max_score > 0:
                status = _determine_status(score, max_score)
            else:
                status = ActionStatus.TODO.value

            # ── Map tier to risk level ──
            tier_risk = {
                "Core": RiskLevel.HIGH.value,
                "Defense in Depth": RiskLevel.MEDIUM.value,
                "Advanced": RiskLevel.LOW.value,
            }

            action = Action(
                title=profile.get("title") or name,
                description=description,
                source_tool=self.source_tool,
                source_id=name,
                reference_id=str(rank),
                workload=workload,
                status=status,
                priority=_map_priority(max_score),
                risk_level=tier_risk.get(tier, RiskLevel.MEDIUM.value),
                user_impact=_map_user_impact(user_impact_str),
                implementation_effort=_map_effort(difficulty),
                required_licence=licence,
                score=score,
                max_score=max_score,
                score_percentage=round((score / max_score * 100), 2) if max_score > 0 else 0,
                remediation_steps=remediation,
                current_value=current_value,
                category=category,
                subcategory=product,
                reference_url=ref_url,
                source_report_file=source_file,
                raw_data=ctrl,
                threats=threats,
                tier=tier,
                action_type=action_type,
                remediation_impact=remediation_impact,
                deprecated=deprecated,
                tags=threats[:],
            )
            actions.append(action)
        return actions


def enrich_actions_from_controls(db: Database, actions: list[Action]) -> list[Action]:
    """Enrich parsed actions with data from the secure_score_controls reference table.

    Looks up each action by title (including localized variants) and fills in
    missing description, remediation_steps, prerequisites, user_impact, etc.
    Also sets the control_id link.
    """
    for action in actions:
        if action.source_tool != SourceTool.SECURE_SCORE.value:
            continue

        control = db.find_control_by_title(action.title)
        if not control:
            continue

        # Link to reference control
        action.control_id = control["id"]

        # Only fill in fields that are empty (don't overwrite existing data)
        if not action.description:
            action.description = control.get("description", "")

        if not action.remediation_steps:
            parts = []
            prereqs = control.get("prerequisites", "")
            steps = control.get("remediation_steps", "")
            if prereqs:
                parts.append(f"Prerequisites:\n{prereqs}")
            if steps:
                parts.append(f"Next steps:\n{steps}")
            action.remediation_steps = "\n\n".join(parts)

        if not action.reference_url:
            action.reference_url = control.get("reference_url", "")

        # Enrich implementation cost -> effort mapping
        impl_cost = control.get("implementation_cost", "")
        if impl_cost and action.implementation_effort == ImplementationEffort.MEDIUM.value:
            action.implementation_effort = _map_effort(impl_cost)

        # Enrich user impact from control description
        ui_desc = control.get("user_impact_description", "")
        if ui_desc and action.user_impact == UserImpact.LOW.value:
            action.user_impact = _map_user_impact(ui_desc)

    return actions


def load_seed_controls() -> list[SecureScoreControl]:
    """Load built-in seed data for Secure Score controls."""
    seed_path = Path(__file__).parent.parent / "seed_data" / "secure_score_controls.json"
    if not seed_path.exists():
        return []
    with open(seed_path) as f:
        data = json.load(f)
    controls = []
    for entry in data:
        controls.append(SecureScoreControl(
            id=entry["id"],
            title=entry.get("title", ""),
            description=entry.get("description", ""),
            remediation_steps=entry.get("remediation_steps", ""),
            prerequisites=entry.get("prerequisites", ""),
            user_impact_description=entry.get("user_impact_description", ""),
            implementation_cost=entry.get("implementation_cost", ""),
            category=entry.get("category", ""),
            product=entry.get("product", ""),
            reference_url=entry.get("reference_url", ""),
            max_score=entry.get("max_score", 0.0),
            title_variants=entry.get("title_variants", []),
        ))
    return controls


def parse_graph_control_profiles(data: dict | list) -> list[SecureScoreControl]:
    """Parse secureScoreControlProfiles from MS Graph API into reference controls.

    Call with the response from GET /security/secureScoreControlProfiles.
    """
    if isinstance(data, dict):
        profiles = data.get("value", [])
    elif isinstance(data, list):
        profiles = data
    else:
        profiles = []

    controls = []
    for p in profiles:
        ctrl = SecureScoreControl(
            id=p.get("id", p.get("controlName", "")),
            title=p.get("title", p.get("controlName", "")),
            description=p.get("description", ""),
            remediation_steps=p.get("remediation", p.get("implementationStatus", "")),
            prerequisites=p.get("prerequisites", ""),
            user_impact_description=p.get("userImpact", ""),
            implementation_cost=p.get("implementationCost", ""),
            category=p.get("controlCategory", ""),
            product=", ".join(p.get("service", "").split(";")) if p.get("service") else "",
            reference_url=p.get("actionUrl", ""),
            max_score=float(p.get("maxScore", 0)),
        )
        controls.append(ctrl)
    return controls
