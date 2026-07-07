"""Scoring engine - combines per-tool scores into a unified percentage."""

from __future__ import annotations


# Per-tool weights for the combined overall percentage. Defaults to 1.0 for any
# tool not listed. Adjust here to bias the headline score toward frameworks
# whose individual checks represent more work (e.g. SCuBA).
TOOL_WEIGHTS: dict[str, float] = {}


def combined_percentage(by_tool: dict, weights: dict | None = None) -> float:
    """Combine per-tool percentages into a single overall percentage.

    Each source tool contributes its own 0-100% score, then the values are
    averaged with optional per-tool weights. Tools without scoring data
    (max_score == 0) are excluded so adding a new framework doesn't dilute
    the result with zeros.

    This avoids the headline being dominated by whichever tool happens to
    expose the largest raw point pool (e.g. Microsoft Secure Score's
    ~1300 points vs SCuBA's ~130 binary points).
    """
    weights = weights if weights is not None else TOOL_WEIGHTS
    weighted_sum = 0.0
    weight_total = 0.0
    for tool, data in by_tool.items():
        max_s = data.get("max_score", 0) or 0
        if max_s <= 0:
            continue
        pct = (data.get("score", 0) / max_s) * 100
        w = weights.get(tool, 1.0)
        weighted_sum += pct * w
        weight_total += w
    return round(weighted_sum / weight_total, 2) if weight_total > 0 else 0.0
