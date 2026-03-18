"""Remediation planning engine with impact simulation.

Given a set of actions to implement, calculates:
- Projected score increase per tool and overall
- Which compliance controls/baselines will be satisfied
- Risk reduction estimate
- Effort-to-impact ratio for prioritisation
- Phased rollout recommendations
"""

from __future__ import annotations

from collections import defaultdict
from .models import (
    ActionStatus, Priority, RiskLevel, UserImpact,
    ImplementationEffort, EssentialEightControl,
)
from .database import Database


# Numeric weights for calculations
PRIORITY_WEIGHT = {
    Priority.CRITICAL.value: 5,
    Priority.HIGH.value: 4,
    Priority.MEDIUM.value: 3,
    Priority.LOW.value: 2,
    Priority.INFORMATIONAL.value: 1,
}

RISK_WEIGHT = {
    RiskLevel.CRITICAL.value: 5,
    RiskLevel.HIGH.value: 4,
    RiskLevel.MEDIUM.value: 3,
    RiskLevel.LOW.value: 2,
    RiskLevel.MINIMAL.value: 1,
}

EFFORT_WEIGHT = {
    ImplementationEffort.MINIMAL.value: 1,
    ImplementationEffort.LOW.value: 2,
    ImplementationEffort.MEDIUM.value: 3,
    ImplementationEffort.HIGH.value: 4,
}

IMPACT_WEIGHT = {
    UserImpact.NONE.value: 0,
    UserImpact.LOW.value: 1,
    UserImpact.MEDIUM.value: 2,
    UserImpact.HIGH.value: 3,
}

# Licence tiers for phasing (implement free/included first)
LICENCE_TIERS = {
    "": 0, "included": 0, "free": 0,
    "e3": 1, "business premium": 1,
    "e5": 2, "e5 security": 2, "e5 compliance": 2,
    "p1": 1, "p2": 2, "aad p1": 1, "aad p2": 2,
    "entra id p1": 1, "entra id p2": 2,
    "defender for office 365 p1": 1, "defender for office 365 p2": 2,
    "intune": 1,
}


def _licence_tier(licence: str) -> int:
    """Map a licence string to a numeric tier (0=free, 1=standard, 2=premium)."""
    if not licence:
        return 0
    lc = licence.lower().strip()
    for key, tier in LICENCE_TIERS.items():
        if key and key in lc:
            return tier
    return 1  # Default to standard if unknown


def calculate_action_roi(action: dict) -> float:
    """Calculate Return on Investment score for a single action.

    Higher ROI = higher risk reduction relative to implementation effort.
    Formula: (risk_weight * priority_weight * max_score) / (effort_weight * (1 + impact_weight))
    """
    risk = RISK_WEIGHT.get(action.get("risk_level", "Medium"), 3)
    priority = PRIORITY_WEIGHT.get(action.get("priority", "Medium"), 3)
    max_score = action.get("max_score") or 1
    effort = EFFORT_WEIGHT.get(action.get("implementation_effort", "Medium"), 3)
    impact = IMPACT_WEIGHT.get(action.get("user_impact", "Low"), 1)

    return round((risk * priority * max_score) / (effort * (1 + impact)), 2)


def simulate_plan(db: Database, tenant_name: str, action_ids: list[str]) -> dict:
    """Simulate the impact of implementing a set of actions.

    Returns projected changes to scores, compliance coverage, and risk.
    """
    all_actions = db.get_actions(tenant_name)
    plan_actions = [a for a in all_actions if a["id"] in action_ids]
    non_completed = [a for a in plan_actions if a["status"] != ActionStatus.COMPLETED.value]

    if not non_completed:
        return {"error": "All selected actions are already completed"}

    # Current state
    current_scores = db.get_scores(tenant_name)

    # Projected state: assume all plan actions become Completed
    projected_score_gain = sum(
        (a.get("max_score") or 0) - (a.get("score") or 0)
        for a in non_completed
    )

    # Per-tool impact
    tool_impact = defaultdict(lambda: {"score_gain": 0, "actions_resolved": 0, "controls": []})
    for a in non_completed:
        tool = a["source_tool"]
        tool_impact[tool]["score_gain"] += (a.get("max_score") or 0) - (a.get("score") or 0)
        tool_impact[tool]["actions_resolved"] += 1
        tool_impact[tool]["controls"].append(a["title"])

    # Per-tool projected percentages
    for tool, data in tool_impact.items():
        current_tool = current_scores.get("by_tool", {}).get(tool, {})
        current_pct = current_tool.get("percentage", 0)
        current_max = current_tool.get("max_score", 0)
        if current_max > 0:
            projected_pct = min(100, current_pct + (data["score_gain"] / current_max * 100))
        else:
            projected_pct = 0
        data["current_percentage"] = round(current_pct, 1)
        data["projected_percentage"] = round(projected_pct, 1)
        data["percentage_gain"] = round(projected_pct - current_pct, 1)

    # Per-workload impact
    workload_impact = defaultdict(lambda: {"actions_resolved": 0, "controls": []})
    for a in non_completed:
        wl = a["workload"]
        workload_impact[wl]["actions_resolved"] += 1
        workload_impact[wl]["controls"].append(a["title"])

    # Essential Eight impact
    e8_impact = defaultdict(lambda: {"actions_resolved": 0, "maturity_levels": set()})
    for a in non_completed:
        if a.get("essential_eight_control"):
            ctrl = a["essential_eight_control"]
            e8_impact[ctrl]["actions_resolved"] += 1
            if a.get("essential_eight_maturity"):
                e8_impact[ctrl]["maturity_levels"].add(a["essential_eight_maturity"])
    # Convert sets to lists for JSON
    for ctrl in e8_impact:
        e8_impact[ctrl]["maturity_levels"] = sorted(e8_impact[ctrl]["maturity_levels"])

    # Risk reduction summary
    risk_reduction = defaultdict(int)
    for a in non_completed:
        risk_reduction[a.get("risk_level", "Medium")] += 1

    # Licence requirements
    licences_needed = set()
    for a in non_completed:
        if a.get("required_licence"):
            licences_needed.add(a["required_licence"])

    # Effort breakdown
    effort_breakdown = defaultdict(int)
    for a in non_completed:
        effort_breakdown[a.get("implementation_effort", "Medium")] += 1

    # User impact summary
    user_impact_summary = defaultdict(int)
    for a in non_completed:
        user_impact_summary[a.get("user_impact", "Low")] += 1

    # Overall projected percentage
    current_total_max = current_scores.get("total_max", 0)
    current_pct = current_scores.get("percentage", 0)
    if current_total_max > 0:
        projected_overall_pct = min(
            100, current_pct + (projected_score_gain / current_total_max * 100))
    else:
        projected_overall_pct = 0

    return {
        "actions_count": len(non_completed),
        "already_completed": len(plan_actions) - len(non_completed),
        "current_percentage": round(current_pct, 1),
        "projected_percentage": round(projected_overall_pct, 1),
        "percentage_gain": round(projected_overall_pct - current_pct, 1),
        "projected_score_gain": round(projected_score_gain, 1),
        "by_tool": dict(tool_impact),
        "by_workload": dict(workload_impact),
        "essential_eight_impact": dict(e8_impact),
        "risk_reduction": dict(risk_reduction),
        "licences_needed": sorted(licences_needed),
        "effort_breakdown": dict(effort_breakdown),
        "user_impact_summary": dict(user_impact_summary),
    }


def suggest_phases(db: Database, tenant_name: str, action_ids: list[str],
                   num_phases: int = 3) -> list[dict]:
    """Suggest a phased implementation plan.

    Phases are determined by:
    1. Licence tier (free/included first)
    2. ROI score (highest impact per effort first)
    3. User impact (low impact first within same tier)
    """
    all_actions = db.get_actions(tenant_name)
    plan_actions = [a for a in all_actions if a["id"] in action_ids
                    and a["status"] != ActionStatus.COMPLETED.value]

    if not plan_actions:
        return []

    # Score and sort actions
    for a in plan_actions:
        a["_roi"] = calculate_action_roi(a)
        a["_licence_tier"] = _licence_tier(a.get("required_licence", ""))
        a["_impact"] = IMPACT_WEIGHT.get(a.get("user_impact", "Low"), 1)

    # Sort: licence tier ascending, then ROI descending, then user impact ascending
    plan_actions.sort(key=lambda a: (a["_licence_tier"], -a["_roi"], a["_impact"]))

    # Distribute into phases
    phase_size = max(1, len(plan_actions) // num_phases)
    phases = []
    for i in range(num_phases):
        start = i * phase_size
        if i == num_phases - 1:
            batch = plan_actions[start:]
        else:
            batch = plan_actions[start:start + phase_size]

        if not batch:
            continue

        # Calculate phase metrics
        score_gain = sum((a.get("max_score") or 0) - (a.get("score") or 0) for a in batch)
        licences = set(a.get("required_licence", "") for a in batch if a.get("required_licence"))

        # Clean temp fields
        for a in batch:
            a.pop("_roi", None)
            a.pop("_licence_tier", None)
            a.pop("_impact", None)

        phases.append({
            "phase": i + 1,
            "name": f"Phase {i + 1}" + (
                " - Quick Wins" if i == 0 else
                " - Core Controls" if i == 1 else
                " - Advanced Hardening"
            ),
            "actions": batch,
            "action_count": len(batch),
            "projected_score_gain": round(score_gain, 1),
            "licences_needed": sorted(licences),
            "effort_summary": _effort_summary(batch),
        })

    return phases


def _effort_summary(actions: list[dict]) -> dict:
    """Summarize effort distribution for a set of actions."""
    result = defaultdict(int)
    for a in actions:
        result[a.get("implementation_effort", "Medium")] += 1
    return dict(result)


def get_prioritized_actions(db: Database, tenant_name: str,
                            limit: int = 20) -> list[dict]:
    """Get top actions ranked by ROI (best bang for buck).

    Only includes non-completed actions.
    """
    actions = db.get_actions(tenant_name)
    pending = [a for a in actions if a["status"] not in (
        ActionStatus.COMPLETED.value,
        ActionStatus.NOT_APPLICABLE.value,
        ActionStatus.THIRD_PARTY.value,
    )]

    for a in pending:
        a["roi_score"] = calculate_action_roi(a)

    # Pinned actions come first, then sort by ROI
    pending.sort(key=lambda a: (-a.get("pinned_priority", 0), -a["roi_score"]))
    return pending[:limit]
