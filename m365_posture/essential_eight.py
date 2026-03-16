"""Essential Eight mapping and maturity assessment.

Maps security actions to ASD's Essential Eight controls and maturity levels.
Reference: https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/essential-eight
Reference: https://blueprint.asd.gov.au/security-and-governance/essential-eight/
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from .models import (
    Action, EssentialEightControl, EssentialEightMaturity,
    ActionStatus, SourceTool,
)

# ── Seed data loading ──────────────────────────────────────────────

_E8_DATA: dict | None = None
_MS_DATA: dict | None = None
_ASD_DATA: dict | None = None


def _load_e8_data() -> dict:
    """Load the Essential Eight maturity requirements seed data."""
    global _E8_DATA
    if _E8_DATA is not None:
        return _E8_DATA
    seed_path = Path(__file__).parent / "seed_data" / "essential_eight_maturity.json"
    if seed_path.exists():
        with open(seed_path, "r", encoding="utf-8") as f:
            _E8_DATA = json.load(f)
    else:
        _E8_DATA = {"controls": [], "secure_score_to_e8_mapping": [], "scuba_to_e8_mapping": []}
    return _E8_DATA


def _load_ms_mapping() -> dict:
    """Load the Microsoft E8 compliance mapping data."""
    global _MS_DATA
    if _MS_DATA is not None:
        return _MS_DATA
    seed_path = Path(__file__).parent / "seed_data" / "essential_eight_microsoft_mapping.json"
    if seed_path.exists():
        with open(seed_path, "r", encoding="utf-8") as f:
            _MS_DATA = json.load(f)
    else:
        _MS_DATA = {"controls": []}
    return _MS_DATA


def _get_ms_control_by_name(name: str) -> dict:
    """Get Microsoft mapping data for a control by name."""
    ms = _load_ms_mapping()
    for ctrl in ms.get("controls", []):
        if ctrl.get("control_name") == name:
            return ctrl
    return {}


def _load_asd_blueprint() -> dict:
    """Load the ASD Blueprint E8 reference data."""
    global _ASD_DATA
    if _ASD_DATA is not None:
        return _ASD_DATA
    seed_path = Path(__file__).parent / "seed_data" / "essential_eight_asd_blueprint.json"
    if seed_path.exists():
        with open(seed_path, "r", encoding="utf-8") as f:
            _ASD_DATA = json.load(f)
    else:
        _ASD_DATA = {"controls": {}}
    return _ASD_DATA


# Map E8 control names to ASD Blueprint keys
_ASD_KEY_MAP = {
    "Application Control": "application_control",
    "Patch Applications": "patch_applications",
    "Configure Microsoft Office Macro Settings": "restrict_microsoft_office_macros",
    "User Application Hardening": "user_application_hardening",
    "Restrict Administrative Privileges": "restrict_administrative_privileges",
    "Patch Operating Systems": "patch_operating_systems",
    "Multi-Factor Authentication": "multi_factor_authentication",
    "Regular Backups": "regular_backups",
}


def _get_asd_control(name: str) -> dict:
    """Get ASD Blueprint data for a control."""
    asd = _load_asd_blueprint()
    controls = asd.get("controls", {})
    key = _ASD_KEY_MAP.get(name, "")
    return controls.get(key, {})


def get_e8_controls_data() -> list[dict]:
    """Return the full E8 control definitions with maturity requirements."""
    return _load_e8_data().get("controls", [])


def get_e8_maturity_descriptions() -> dict[str, str]:
    """Return maturity level descriptions."""
    return _load_e8_data().get("maturity_levels", {})


# ── Mapping tables ─────────────────────────────────────────────────

# Keyword-based mapping rules: (keywords_any, keywords_all, control)
E8_MAPPING_RULES: list[tuple[list[str], list[str], str]] = [
    # Application Control
    (
        ["application control", "app control", "applocker", "wdac",
         "application whitelisting", "software restriction",
         "block untrusted applications", "allowed applications",
         "smartscreen", "controlled folder access"],
        [],
        EssentialEightControl.APPLICATION_CONTROL.value,
    ),
    # Patch Applications
    (
        ["patch application", "application update", "software update",
         "application version", "vulnerable application", "app vulnerability",
         "browser update", "office update", "java update", "flash",
         "end of life application", "unsupported application",
         "vulnerability management", "missing patches"],
        [],
        EssentialEightControl.PATCH_APPLICATIONS.value,
    ),
    # Configure Microsoft Office Macro Settings
    (
        ["macro", "vba", "office macro", "macro setting", "macro security",
         "macro execution", "block macro", "disable macro",
         "trusted location", "digitally signed macro",
         "win32 api call"],
        [],
        EssentialEightControl.MACRO_SETTINGS.value,
    ),
    # User Application Hardening
    (
        ["browser hardening", "application hardening", "disable flash",
         "disable java", "block ads", "block javascript", "web browser",
         "office hardening", "ole", "activex", "powershell constrained",
         "attack surface reduction", "asr rule", "safe links",
         "safe attachment", "anti-phish", "antiphish", "smartscreen",
         "internet explorer", "child process", "executable content",
         "code injection"],
        [],
        EssentialEightControl.USER_APP_HARDENING.value,
    ),
    # Restrict Administrative Privileges
    (
        ["admin privilege", "administrative privilege", "privileged access",
         "least privilege", "admin account", "global admin",
         "privileged role", "pim", "pam", "just-in-time",
         "break glass", "emergency access", "admin mfa",
         "separate admin", "tiered admin", "admin workstation",
         "privileged identity", "administrative unit",
         "highly privileged", "role activation"],
        [],
        EssentialEightControl.RESTRICT_ADMIN.value,
    ),
    # Patch Operating Systems
    (
        ["patch os", "operating system update", "os update", "windows update",
         "os vulnerability", "os version", "unsupported os",
         "end of life os", "security update", "cumulative update",
         "firmware update", "windows autopatch", "feature update"],
        [],
        EssentialEightControl.PATCH_OS.value,
    ),
    # Multi-Factor Authentication
    (
        ["mfa", "multi-factor", "multifactor", "two-factor", "2fa",
         "authenticator", "fido", "phishing-resistant", "passwordless",
         "conditional access", "strong authentication",
         "legacy authentication", "basic authentication",
         "modern authentication", "authentication method",
         "security default", "number matching", "passkey",
         "authentication strength", "certificate-based auth"],
        [],
        EssentialEightControl.MFA.value,
    ),
    # Regular Backups
    (
        ["backup", "recovery", "restore", "retention",
         "data protection", "disaster recovery", "business continuity",
         "backup policy", "backup frequency", "immutable storage",
         "versioning", "recycle bin"],
        [],
        EssentialEightControl.REGULAR_BACKUPS.value,
    ),
]

# Build lookup from E8 control id (e.g. "E8-MFA") to control name
_E8_ID_TO_NAME: dict[str, str] = {}
_E8_NAME_TO_ID: dict[str, str] = {}
for _ctrl in (get_e8_controls_data() or []):
    _E8_ID_TO_NAME[_ctrl["id"]] = _ctrl["name"]
    _E8_NAME_TO_ID[_ctrl["name"]] = _ctrl["id"]


# ── Source-specific mapping ────────────────────────────────────────

def _get_secure_score_e8_map() -> dict[str, tuple[str, str]]:
    """Return mapping from Secure Score control ID to (e8_control_name, maturity_level)."""
    data = _load_e8_data()
    result = {}
    for entry in data.get("secure_score_to_e8_mapping", []):
        ctrl_id = entry["e8_control"]
        ctrl_name = _E8_ID_TO_NAME.get(ctrl_id, ctrl_id)
        result[entry["secure_score_id"]] = (ctrl_name, entry["maturity_level"])
    return result


def _get_scuba_e8_map() -> list[tuple[str, str, str]]:
    """Return mapping from SCuBA prefix to (e8_control_name, maturity_level)."""
    data = _load_e8_data()
    result = []
    for entry in data.get("scuba_to_e8_mapping", []):
        ctrl_id = entry["e8_control"]
        ctrl_name = _E8_ID_TO_NAME.get(ctrl_id, ctrl_id)
        result.append((entry["scuba_prefix"], ctrl_name, entry["maturity_level"]))
    return result


_SS_E8_MAP: dict | None = None
_SCUBA_E8_MAP: list | None = None


def _map_by_source(action: Action) -> tuple[str | None, str | None]:
    """Try to map an action using source-specific ID mappings (Secure Score, SCuBA)."""
    global _SS_E8_MAP, _SCUBA_E8_MAP

    # Secure Score mapping by control ID
    if action.source_tool == SourceTool.SECURE_SCORE.value and action.control_id:
        if _SS_E8_MAP is None:
            _SS_E8_MAP = _get_secure_score_e8_map()
        mapping = _SS_E8_MAP.get(action.control_id)
        if mapping:
            return mapping

    # SCuBA mapping by reference_id prefix
    if action.source_tool == SourceTool.SCUBA.value and action.reference_id:
        if _SCUBA_E8_MAP is None:
            _SCUBA_E8_MAP = _get_scuba_e8_map()
        for prefix, ctrl_name, ml in _SCUBA_E8_MAP:
            if action.reference_id.startswith(prefix):
                return ctrl_name, ml

    return None, None


# ── Core mapping logic ─────────────────────────────────────────────

def map_action_to_e8(action: Action) -> tuple[str | None, str | None]:
    """Attempt to map an action to an Essential Eight control.

    Uses source-specific mappings first (Secure Score ID, SCuBA prefix),
    then falls back to keyword-based matching.

    Returns (control_name, maturity_level) or (None, None).
    """
    # Try source-specific mapping first
    control, maturity = _map_by_source(action)
    if control:
        return control, maturity

    # Fall back to keyword matching
    text = f"{action.title} {action.description} {action.remediation_steps}".lower()

    for keywords_any, keywords_all, control in E8_MAPPING_RULES:
        if keywords_all and not all(k in text for k in keywords_all):
            continue
        if any(k in text for k in keywords_any):
            maturity = _estimate_maturity(action, control)
            return control, maturity

    return None, None


def _estimate_maturity(action: Action, control: str) -> str:
    """Estimate the Essential Eight maturity level an action relates to."""
    text = f"{action.title} {action.description} {action.remediation_steps}".lower()

    # Level 3 indicators
    l3_keywords = [
        "phishing-resistant", "fido2", "hardware token", "48 hours",
        "privileged access workstation", "all users and all services",
        "application control on all", "real-time", "continuous monitoring",
        "constrained language mode", "immutable", "worm storage",
        "passkey", "certificate-based auth",
    ]
    if any(k in text for k in l3_keywords):
        return EssentialEightMaturity.LEVEL_3.value

    # Level 2 indicators
    l2_keywords = [
        "all workstations", "all servers", "centrally managed",
        "two weeks", "14 days", "number matching", "all applications",
        "application whitelisting", "constrained language",
        "centrally logged", "non-internet-facing", "weekly scan",
        "access review", "inactivity", "45 days",
    ]
    if any(k in text for k in l2_keywords):
        return EssentialEightMaturity.LEVEL_2.value

    # Level 1 is the baseline
    return EssentialEightMaturity.LEVEL_1.value


def apply_e8_mapping(actions: list[Action]) -> list[Action]:
    """Apply Essential Eight mapping to all actions that don't have one yet."""
    for action in actions:
        if not action.essential_eight_control:
            control, maturity = map_action_to_e8(action)
            if control:
                action.essential_eight_control = control
                action.essential_eight_maturity = maturity
    return actions


# ── Summary and gap analysis ───────────────────────────────────────

def get_e8_summary(actions: list[Action], target_maturity: str = "Maturity Level 3",
                   exclude_na: bool = False) -> dict:
    """Generate an Essential Eight compliance summary with gap analysis.

    Args:
        actions: List of Action objects.
        target_maturity: The target maturity level for gap analysis.
        exclude_na: If True, exclude Not Applicable and Risk Accepted actions.
    """
    e8_data = get_e8_controls_data()
    e8_by_name = {c["name"]: c for c in e8_data}
    ml_descriptions = get_e8_maturity_descriptions()

    # Parse target level number
    target_level_num = _ml_to_num(target_maturity)

    summary = {}
    for control in EssentialEightControl:
        control_actions = [
            a for a in actions if a.essential_eight_control == control.value
        ]

        if exclude_na:
            excluded = {ActionStatus.NOT_APPLICABLE.value, ActionStatus.RISK_ACCEPTED.value}
            filtered_actions = [a for a in control_actions if a.status not in excluded]
        else:
            filtered_actions = control_actions

        total = len(filtered_actions)
        completed = sum(1 for a in filtered_actions if a.status == ActionStatus.COMPLETED.value)

        # Group by maturity level
        maturity_data = {}
        for ml in [EssentialEightMaturity.LEVEL_1, EssentialEightMaturity.LEVEL_2, EssentialEightMaturity.LEVEL_3]:
            ml_actions = [a for a in filtered_actions if a.essential_eight_maturity == ml.value]
            ml_total = len(ml_actions)
            ml_completed = sum(1 for a in ml_actions if a.status == ActionStatus.COMPLETED.value)
            maturity_data[ml.value] = {
                "total": ml_total,
                "completed": ml_completed,
                "percentage": round((ml_completed / ml_total) * 100, 1) if ml_total > 0 else 0,
            }

        # Determine achieved maturity level
        achieved = EssentialEightMaturity.LEVEL_0.value
        for ml in [EssentialEightMaturity.LEVEL_1, EssentialEightMaturity.LEVEL_2, EssentialEightMaturity.LEVEL_3]:
            ml_data = maturity_data.get(ml.value, {})
            if ml_data.get("total", 0) > 0 and ml_data.get("percentage", 0) >= 80:
                achieved = ml.value
            else:
                break

        achieved_num = _ml_to_num(achieved)

        # Gap analysis: what's needed to reach target
        gap_actions = []
        if achieved_num < target_level_num:
            for ml_num in range(max(achieved_num + 1, 1), target_level_num + 1):
                ml_name = _num_to_ml(ml_num)
                ml_actions = [a for a in filtered_actions
                              if a.essential_eight_maturity == ml_name
                              and a.status != ActionStatus.COMPLETED.value]
                for a in ml_actions:
                    gap_actions.append({
                        "id": a.id,
                        "title": a.title,
                        "status": a.status,
                        "maturity": ml_name,
                        "source_tool": a.source_tool,
                        "priority": a.priority,
                    })

        # Get E8 reference data
        ctrl_ref = e8_by_name.get(control.value, {})
        ctrl_id = ctrl_ref.get("id", "")
        m365_products = ctrl_ref.get("m365_products", [])
        m365_features = ctrl_ref.get("m365_features", [])
        objective = ctrl_ref.get("objective", "")

        # Merge Microsoft-specific mapping data
        ms_ctrl = _get_ms_control_by_name(control.value)
        ms_ml_mapping = ms_ctrl.get("maturity_level_mapping", {})
        ms_doc_url = ms_ctrl.get("microsoft_doc_url", "")
        ms_licensing = ms_ctrl.get("licensing", {})
        ms_github = ms_ctrl.get("github_resources", [])

        # ASD Blueprint data
        asd_ctrl = _get_asd_control(control.value)
        asd_url = asd_ctrl.get("url", "")
        asd_technologies = asd_ctrl.get("m365_technologies", [])
        asd_implementation = asd_ctrl.get("implementation_details", {})

        # Get maturity requirements from seed data
        maturity_requirements = {}
        for ml_key, ml_data_ref in ctrl_ref.get("maturity_levels", {}).items():
            reqs = ml_data_ref.get("requirements", [])
            impl = ml_data_ref.get("m365_implementation", "")
            maturity_requirements[ml_key] = {
                "requirements": reqs,
                "m365_implementation": impl,
                "requirement_count": len(reqs),
            }

        # Build Microsoft implementation guidance per maturity level
        ms_guidance = {}
        for ml_key in ["ML1", "ML2", "ML3"]:
            ml_data_ms = ms_ml_mapping.get(ml_key, {})
            if ml_data_ms:
                ms_guidance[ml_key] = {
                    "primary_tool": ml_data_ms.get("primary_tool", ""),
                    "description": ml_data_ms.get("description", ""),
                    "key_configurations": ml_data_ms.get("key_configurations", []),
                    "ism_controls": ml_data_ms.get("ism_controls", []),
                }

        summary[control.value] = {
            "control_id": ctrl_id,
            "objective": objective,
            "m365_products": m365_products,
            "m365_features": m365_features,
            "ms_doc_url": ms_doc_url,
            "ms_licensing": ms_licensing,
            "ms_guidance": ms_guidance,
            "asd_url": asd_url,
            "asd_technologies": asd_technologies,
            "asd_implementation": asd_implementation,
            "total_actions": total,
            "completed_actions": completed,
            "percentage": round((completed / total) * 100, 1) if total > 0 else 0,
            "maturity_levels": maturity_data,
            "maturity_requirements": maturity_requirements,
            "achieved_maturity": achieved,
            "achieved_maturity_num": achieved_num,
            "target_maturity": target_maturity,
            "target_maturity_num": target_level_num,
            "gap_to_target": max(0, target_level_num - achieved_num),
            "gap_actions": gap_actions,
            "gap_action_count": len(gap_actions),
            "actions": [
                {
                    "id": a.id if hasattr(a, 'id') else "",
                    "title": a.title,
                    "status": a.status,
                    "priority": a.priority,
                    "source_tool": a.source_tool,
                    "reference_id": a.reference_id or "",
                    "maturity": a.essential_eight_maturity or "",
                    "workload": a.workload,
                    "score": a.score,
                    "max_score": a.max_score,
                }
                for a in control_actions
            ],
        }

    return {
        "controls": summary,
        "overall": _calc_overall(summary),
        "target_maturity": target_maturity,
        "maturity_descriptions": ml_descriptions,
    }


def _calc_overall(summary: dict) -> dict:
    """Calculate overall E8 statistics."""
    total_actions = sum(d["total_actions"] for d in summary.values())
    total_completed = sum(d["completed_actions"] for d in summary.values())
    controls_mapped = sum(1 for d in summary.values() if d["total_actions"] > 0)

    # Overall achieved maturity = minimum achieved across all controls with data
    achieved_levels = [d["achieved_maturity_num"] for d in summary.values() if d["total_actions"] > 0]
    overall_achieved_num = min(achieved_levels) if achieved_levels else 0
    overall_achieved = _num_to_ml(overall_achieved_num)

    total_gap_actions = sum(d["gap_action_count"] for d in summary.values())

    return {
        "total_actions": total_actions,
        "total_completed": total_completed,
        "overall_percentage": round((total_completed / total_actions) * 100, 1) if total_actions > 0 else 0,
        "controls_mapped": controls_mapped,
        "overall_achieved_maturity": overall_achieved,
        "overall_achieved_num": overall_achieved_num,
        "total_gap_actions": total_gap_actions,
    }


def _ml_to_num(ml: str) -> int:
    """Convert maturity level string to number."""
    if "3" in ml:
        return 3
    if "2" in ml:
        return 2
    if "1" in ml:
        return 1
    return 0


def _num_to_ml(n: int) -> str:
    """Convert maturity level number to string."""
    if n >= 3:
        return EssentialEightMaturity.LEVEL_3.value
    if n == 2:
        return EssentialEightMaturity.LEVEL_2.value
    if n == 1:
        return EssentialEightMaturity.LEVEL_1.value
    return EssentialEightMaturity.LEVEL_0.value
