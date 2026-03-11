"""Essential Eight mapping and maturity assessment.

Maps security actions to ASD's Essential Eight controls and maturity levels.
Reference: https://blueprint.asd.gov.au/security-and-governance/essential-eight/
"""

from __future__ import annotations

from .models import (
    Action, EssentialEightControl, EssentialEightMaturity,
    ActionStatus, Workload,
)


# Keyword-based mapping rules: (keywords_any, keywords_all, control)
E8_MAPPING_RULES: list[tuple[list[str], list[str], str]] = [
    # Application Control
    (
        ["application control", "app control", "applocker", "wdac",
         "application whitelisting", "software restriction",
         "block untrusted applications", "allowed applications"],
        [],
        EssentialEightControl.APPLICATION_CONTROL.value,
    ),
    # Patch Applications
    (
        ["patch application", "application update", "software update",
         "application version", "vulnerable application", "app vulnerability",
         "browser update", "office update", "java update", "flash",
         "end of life application", "unsupported application"],
        [],
        EssentialEightControl.PATCH_APPLICATIONS.value,
    ),
    # Configure Microsoft Office Macro Settings
    (
        ["macro", "vba", "office macro", "macro setting", "macro security",
         "macro execution", "block macro", "disable macro",
         "trusted location", "digitally signed macro"],
        [],
        EssentialEightControl.MACRO_SETTINGS.value,
    ),
    # User Application Hardening
    (
        ["browser hardening", "application hardening", "disable flash",
         "disable java", "block ads", "block javascript", "web browser",
         "office hardening", "ole", "activex", "powershell constrained",
         "attack surface reduction", "asr rule"],
        [],
        EssentialEightControl.USER_APP_HARDENING.value,
    ),
    # Restrict Administrative Privileges
    (
        ["admin privilege", "administrative privilege", "privileged access",
         "least privilege", "admin account", "global admin",
         "privileged role", "pim", "pam", "just-in-time",
         "break glass", "emergency access", "admin mfa",
         "separate admin", "tiered admin", "admin workstation"],
        [],
        EssentialEightControl.RESTRICT_ADMIN.value,
    ),
    # Patch Operating Systems
    (
        ["patch os", "operating system update", "os update", "windows update",
         "os vulnerability", "os version", "unsupported os",
         "end of life os", "security update", "cumulative update",
         "firmware update"],
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
         "security default", "number matching"],
        [],
        EssentialEightControl.MFA.value,
    ),
    # Regular Backups
    (
        ["backup", "recovery", "restore", "retention",
         "data protection", "disaster recovery", "business continuity",
         "backup policy", "backup frequency"],
        [],
        EssentialEightControl.REGULAR_BACKUPS.value,
    ),
]


def map_action_to_e8(action: Action) -> tuple[str | None, str | None]:
    """Attempt to map an action to an Essential Eight control.

    Returns (control, maturity_level) or (None, None).
    """
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
        "privileged access workstation", "all users", "automated",
        "application control on all", "real-time", "continuous",
    ]
    if any(k in text for k in l3_keywords):
        return EssentialEightMaturity.LEVEL_3.value

    # Level 2 indicators
    l2_keywords = [
        "all workstations", "all servers", "centrally managed",
        "two weeks", "14 days", "number matching", "all applications",
        "application whitelisting", "constrained language",
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


def get_e8_summary(actions: list[Action]) -> dict:
    """Generate an Essential Eight compliance summary."""
    summary = {}
    for control in EssentialEightControl:
        control_actions = [
            a for a in actions if a.essential_eight_control == control.value
        ]
        total = len(control_actions)
        completed = sum(1 for a in control_actions if a.status == ActionStatus.COMPLETED.value)

        # Group by maturity level
        maturity_data = {}
        for ml in EssentialEightMaturity:
            ml_actions = [a for a in control_actions if a.essential_eight_maturity == ml.value]
            ml_total = len(ml_actions)
            ml_completed = sum(1 for a in ml_actions if a.status == ActionStatus.COMPLETED.value)
            if ml_total > 0:
                maturity_data[ml.value] = {
                    "total": ml_total,
                    "completed": ml_completed,
                    "percentage": round((ml_completed / ml_total) * 100, 1),
                }

        # Determine achieved maturity level
        achieved = EssentialEightMaturity.LEVEL_0.value
        for ml in [EssentialEightMaturity.LEVEL_1, EssentialEightMaturity.LEVEL_2, EssentialEightMaturity.LEVEL_3]:
            ml_data = maturity_data.get(ml.value, {})
            if ml_data.get("percentage", 0) >= 80:
                achieved = ml.value
            else:
                break

        summary[control.value] = {
            "total_actions": total,
            "completed_actions": completed,
            "percentage": round((completed / total) * 100, 1) if total > 0 else 0,
            "maturity_levels": maturity_data,
            "achieved_maturity": achieved,
        }

    return summary
