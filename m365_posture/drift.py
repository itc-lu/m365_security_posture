"""Drift detection engine.

After each import, compares the new state with the previous snapshot to detect:
- Score regressions (things got worse)
- Score improvements (things got better)
- New findings (newly discovered issues)
- Resolved findings (issues no longer present)
"""

from __future__ import annotations

from .database import Database


def detect_drift(db: Database, tenant_name: str, source_tool: str = None) -> dict:
    """Compare current scores against the most recent snapshot.

    Call this AFTER a new import and snapshot have been taken.

    Returns:
        {
            score_delta: float,
            regressions: [{action_id, title, old_score, new_score, delta}],
            improvements: [{action_id, title, old_score, new_score, delta}],
            new_findings: [{action_id, title, status, score}],
            resolved_findings: [{action_id, title}],
            summary: str
        }
    """
    snapshots = db.get_score_snapshots(tenant_name, limit=2)

    if len(snapshots) < 2:
        return {
            "score_delta": 0,
            "regressions": [],
            "improvements": [],
            "new_findings": [],
            "resolved_findings": [],
            "summary": "Not enough snapshots for drift detection (need at least 2 imports)",
            "has_drift": False,
        }

    current = snapshots[0]   # most recent
    previous = snapshots[1]  # previous

    score_delta = round(current["percentage"] - previous["percentage"], 2)

    # Compare per-tool scores
    regressions = []
    improvements = []

    current_tools = current.get("by_tool", {})
    previous_tools = previous.get("by_tool", {})

    all_tools = set(list(current_tools.keys()) + list(previous_tools.keys()))
    if source_tool:
        all_tools = {t for t in all_tools if t == source_tool}

    for tool in all_tools:
        cur = current_tools.get(tool, {})
        prev = previous_tools.get(tool, {})
        cur_pct = cur.get("percentage", 0)
        prev_pct = prev.get("percentage", 0)
        delta = round(cur_pct - prev_pct, 2)

        if delta < -0.5:  # More than 0.5% regression
            regressions.append({
                "scope": tool,
                "type": "tool_score",
                "old_value": prev_pct,
                "new_value": cur_pct,
                "delta": delta,
            })
        elif delta > 0.5:
            improvements.append({
                "scope": tool,
                "type": "tool_score",
                "old_value": prev_pct,
                "new_value": cur_pct,
                "delta": delta,
            })

    # Compare per-workload scores
    current_wl = current.get("by_workload", {})
    previous_wl = previous.get("by_workload", {})

    for wl in set(list(current_wl.keys()) + list(previous_wl.keys())):
        cur = current_wl.get(wl, {})
        prev = previous_wl.get(wl, {})
        cur_pct = cur.get("percentage", 0)
        prev_pct = prev.get("percentage", 0)
        delta = round(cur_pct - prev_pct, 2)

        if delta < -0.5:
            regressions.append({
                "scope": wl,
                "type": "workload_score",
                "old_value": prev_pct,
                "new_value": cur_pct,
                "delta": delta,
            })
        elif delta > 0.5:
            improvements.append({
                "scope": wl,
                "type": "workload_score",
                "old_value": prev_pct,
                "new_value": cur_pct,
                "delta": delta,
            })

    # Detect new/resolved findings by comparing action counts per status
    current_status = current.get("by_status", {})
    previous_status = previous.get("by_status", {})

    new_todos = (current_status.get("ToDo", 0) - previous_status.get("ToDo", 0))
    resolved = (current_status.get("Completed", 0) - previous_status.get("Completed", 0))

    # Get actual new and resolved actions from the change log
    changelog = db.get_tenant_change_log(tenant_name, limit=200)
    prev_ts = previous["timestamp"]

    new_findings = []
    resolved_findings = []

    # Check import history for new actions since last snapshot
    import_history = db.get_import_history(tenant_name)
    recent_imports = [h for h in import_history if h["timestamp"] > prev_ts]
    for imp in recent_imports:
        if imp.get("new_actions", 0) > 0:
            new_findings.append({
                "scope": imp["source_tool"],
                "type": "new_actions",
                "count": imp["new_actions"],
                "file": imp.get("file_path", ""),
            })

    # Check for status changes since last snapshot
    recent_changes = [c for c in changelog if c["timestamp"] > prev_ts]
    for change in recent_changes:
        if change.get("new_status") == "Completed" and change.get("old_status") != "Completed":
            resolved_findings.append({
                "action_id": change.get("action_id", ""),
                "title": change.get("action_title", ""),
                "old_status": change.get("old_status", ""),
            })

    # Build summary
    parts = []
    if score_delta > 0:
        parts.append(f"Score improved by {score_delta:+.1f}%")
    elif score_delta < 0:
        parts.append(f"Score regressed by {score_delta:+.1f}%")
    else:
        parts.append("Score unchanged")

    if regressions:
        parts.append(f"{len(regressions)} area(s) regressed")
    if improvements:
        parts.append(f"{len(improvements)} area(s) improved")
    if new_findings:
        total_new = sum(f.get("count", 1) for f in new_findings)
        parts.append(f"{total_new} new finding(s)")
    if resolved_findings:
        parts.append(f"{len(resolved_findings)} finding(s) resolved")

    summary = ". ".join(parts)

    result = {
        "score_delta": score_delta,
        "previous_percentage": previous["percentage"],
        "current_percentage": current["percentage"],
        "previous_snapshot_id": previous["id"],
        "current_snapshot_id": current["id"],
        "previous_timestamp": previous["timestamp"],
        "current_timestamp": current["timestamp"],
        "regressions": regressions,
        "improvements": improvements,
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "summary": summary,
        "has_drift": bool(regressions or improvements or new_findings or resolved_findings),
    }

    # Save drift report if there's meaningful drift
    if result["has_drift"]:
        db.save_drift_report(
            tenant_name=tenant_name,
            source_tool=source_tool or "all",
            previous_snapshot_id=previous["id"],
            current_snapshot_id=current["id"],
            score_before=previous["percentage"],
            score_after=current["percentage"],
            regressions=regressions,
            improvements=improvements,
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            summary=summary,
        )

    return result
