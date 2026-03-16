"""Scoring engine - combines scores from multiple source tools into a unified score."""

from __future__ import annotations

from .models import Action, SourceTool, ActionStatus, Workload


def calculate_tool_score(actions: list[Action], source_tool: str) -> dict:
    """Calculate score for a specific source tool."""
    tool_actions = [a for a in actions if a.source_tool == source_tool]
    if not tool_actions:
        return {"score": 0, "max_score": 0, "percentage": 0, "total": 0, "completed": 0}

    total_score = sum(a.score or 0 for a in tool_actions)
    total_max = sum(a.max_score or 0 for a in tool_actions)
    completed = sum(1 for a in tool_actions if a.status == ActionStatus.COMPLETED.value)

    return {
        "score": round(total_score, 2),
        "max_score": round(total_max, 2),
        "percentage": round((total_score / total_max) * 100, 2) if total_max > 0 else 0,
        "total": len(tool_actions),
        "completed": completed,
    }


def calculate_workload_score(actions: list[Action], workload: str) -> dict:
    """Calculate score for a specific workload (Entra, EXO, etc.)."""
    wl_actions = [a for a in actions if a.workload == workload]
    if not wl_actions:
        return {"score": 0, "max_score": 0, "percentage": 0, "total": 0, "completed": 0}

    total_score = sum(a.score or 0 for a in wl_actions)
    total_max = sum(a.max_score or 0 for a in wl_actions)
    completed = sum(1 for a in wl_actions if a.status == ActionStatus.COMPLETED.value)

    return {
        "score": round(total_score, 2),
        "max_score": round(total_max, 2),
        "percentage": round((total_score / total_max) * 100, 2) if total_max > 0 else 0,
        "total": len(wl_actions),
        "completed": completed,
    }


def calculate_total_score(actions: list[Action]) -> dict:
    """Calculate the combined total score across all source tools."""
    if not actions:
        return {
            "total_score": 0,
            "total_max": 0,
            "percentage": 0,
            "total_actions": 0,
            "completed_actions": 0,
            "by_tool": {},
            "by_workload": {},
            "by_status": {},
            "by_priority": {},
        }

    total_score = sum(a.score or 0 for a in actions)
    total_max = sum(a.max_score or 0 for a in actions)

    # By tool
    by_tool = {}
    tools_present = set(a.source_tool for a in actions)
    for tool in tools_present:
        by_tool[tool] = calculate_tool_score(actions, tool)

    # By workload
    by_workload = {}
    workloads_present = set(a.workload for a in actions)
    for wl in workloads_present:
        by_workload[wl] = calculate_workload_score(actions, wl)

    # By status
    by_status = {}
    for a in actions:
        by_status[a.status] = by_status.get(a.status, 0) + 1

    # By priority
    by_priority = {}
    for a in actions:
        by_priority[a.priority] = by_priority.get(a.priority, 0) + 1

    return {
        "total_score": round(total_score, 2),
        "total_max": round(total_max, 2),
        "percentage": round((total_score / total_max) * 100, 2) if total_max > 0 else 0,
        "total_actions": len(actions),
        "completed_actions": sum(1 for a in actions if a.status == ActionStatus.COMPLETED.value),
        "by_tool": by_tool,
        "by_workload": by_workload,
        "by_status": by_status,
        "by_priority": by_priority,
    }


def compare_tenants(tenant_scores: dict[str, dict]) -> dict:
    """Compare scores across multiple tenants.

    Args:
        tenant_scores: dict of {tenant_name: calculate_total_score() result}

    Returns:
        Comparison data structure.
    """
    if len(tenant_scores) < 2:
        return {"error": "Need at least 2 tenants to compare"}

    tenants = list(tenant_scores.keys())
    comparison = {
        "tenants": tenants,
        "overall": {},
        "by_tool": {},
        "by_workload": {},
        "by_status": {},
    }

    # Overall comparison
    for tenant, scores in tenant_scores.items():
        comparison["overall"][tenant] = {
            "percentage": scores["percentage"],
            "total_actions": scores["total_actions"],
            "completed_actions": scores["completed_actions"],
        }

    # By tool comparison
    all_tools = set()
    for scores in tenant_scores.values():
        all_tools.update(scores.get("by_tool", {}).keys())

    for tool in all_tools:
        comparison["by_tool"][tool] = {}
        for tenant, scores in tenant_scores.items():
            tool_data = scores.get("by_tool", {}).get(tool, {})
            comparison["by_tool"][tool][tenant] = {
                "percentage": tool_data.get("percentage", 0),
                "total": tool_data.get("total", 0),
                "completed": tool_data.get("completed", 0),
            }

    # By workload comparison
    all_workloads = set()
    for scores in tenant_scores.values():
        all_workloads.update(scores.get("by_workload", {}).keys())

    for wl in all_workloads:
        comparison["by_workload"][wl] = {}
        for tenant, scores in tenant_scores.items():
            wl_data = scores.get("by_workload", {}).get(wl, {})
            comparison["by_workload"][wl][tenant] = {
                "percentage": wl_data.get("percentage", 0),
                "total": wl_data.get("total", 0),
                "completed": wl_data.get("completed", 0),
            }

    # By status comparison
    all_statuses = set()
    for scores in tenant_scores.values():
        all_statuses.update(scores.get("by_status", {}).keys())

    for status in all_statuses:
        comparison["by_status"][status] = {}
        for tenant, scores in tenant_scores.items():
            comparison["by_status"][status][tenant] = scores.get("by_status", {}).get(status, 0)

    return comparison
