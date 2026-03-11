"""HTML report generator for M365 Security Posture dashboards."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from .models import Action, ActionStatus, Priority, Workload, SourceTool
from .scoring import calculate_total_score, compare_tenants
from .essential_eight import get_e8_summary, EssentialEightControl


def _status_color(status: str) -> str:
    return {
        ActionStatus.COMPLETED.value: "#22c55e",
        ActionStatus.IN_PROGRESS.value: "#3b82f6",
        ActionStatus.IN_PLANNING.value: "#a855f7",
        ActionStatus.TODO.value: "#ef4444",
        ActionStatus.RISK_ACCEPTED.value: "#f59e0b",
        ActionStatus.NOT_APPLICABLE.value: "#6b7280",
        ActionStatus.THIRD_PARTY.value: "#06b6d4",
    }.get(status, "#6b7280")


def _priority_color(priority: str) -> str:
    return {
        Priority.CRITICAL.value: "#dc2626",
        Priority.HIGH.value: "#ea580c",
        Priority.MEDIUM.value: "#ca8a04",
        Priority.LOW.value: "#16a34a",
        Priority.INFORMATIONAL.value: "#6b7280",
    }.get(priority, "#6b7280")


def _pct_color(pct: float) -> str:
    if pct >= 80:
        return "#22c55e"
    if pct >= 60:
        return "#84cc16"
    if pct >= 40:
        return "#f59e0b"
    if pct >= 20:
        return "#f97316"
    return "#ef4444"


def _render_gauge(pct: float, label: str, size: int = 120) -> str:
    color = _pct_color(pct)
    r = size // 2 - 8
    circ = 2 * 3.14159 * r
    dash = circ * pct / 100
    return f'''<div class="gauge" style="text-align:center">
  <svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">
    <circle cx="{size//2}" cy="{size//2}" r="{r}" fill="none" stroke="#e5e7eb" stroke-width="8"/>
    <circle cx="{size//2}" cy="{size//2}" r="{r}" fill="none" stroke="{color}" stroke-width="8"
      stroke-dasharray="{dash:.1f} {circ:.1f}" stroke-linecap="round"
      transform="rotate(-90 {size//2} {size//2})"/>
    <text x="{size//2}" y="{size//2}" text-anchor="middle" dy="6" font-size="18" font-weight="bold" fill="#1f2937">{pct:.0f}%</text>
  </svg>
  <div style="font-size:12px;color:#6b7280;margin-top:4px">{label}</div>
</div>'''


CSS = '''
:root { --bg: #f9fafb; --card: #ffffff; --text: #1f2937; --muted: #6b7280; --border: #e5e7eb; }
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }
.container { max-width: 1400px; margin: 0 auto; padding: 20px; }
h1 { font-size: 24px; margin-bottom: 4px; }
h2 { font-size: 18px; margin: 24px 0 12px; border-bottom: 2px solid var(--border); padding-bottom: 6px; }
h3 { font-size: 15px; margin: 16px 0 8px; }
.subtitle { color: var(--muted); font-size: 14px; margin-bottom: 20px; }
.grid { display: grid; gap: 16px; }
.grid-2 { grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); }
.grid-3 { grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); }
.grid-4 { grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); }
.card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
.card-header { font-weight: 600; font-size: 14px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }
.stat { font-size: 32px; font-weight: 700; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; color: white; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { text-align: left; padding: 8px 12px; background: #f3f4f6; border-bottom: 2px solid var(--border); font-weight: 600; position: sticky; top: 0; cursor: pointer; }
td { padding: 8px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
tr:hover { background: #f9fafb; }
.bar-bg { background: #e5e7eb; border-radius: 4px; height: 8px; width: 100%; }
.bar-fill { height: 8px; border-radius: 4px; transition: width 0.3s; }
.gauges { display: flex; gap: 24px; flex-wrap: wrap; justify-content: center; padding: 16px 0; }
.filter-bar { display: flex; gap: 8px; flex-wrap: wrap; margin: 12px 0; }
.filter-btn { padding: 4px 12px; border: 1px solid var(--border); border-radius: 16px; background: white; cursor: pointer; font-size: 12px; }
.filter-btn.active { background: #1f2937; color: white; border-color: #1f2937; }
.detail-panel { display: none; background: #f8fafc; border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin: 8px 0; }
.detail-panel.open { display: block; }
.history-item { padding: 4px 0; border-bottom: 1px solid #f3f4f6; font-size: 12px; }
.search-box { width: 100%; padding: 8px 12px; border: 1px solid var(--border); border-radius: 6px; font-size: 14px; margin-bottom: 12px; }
.tabs { display: flex; border-bottom: 2px solid var(--border); margin-bottom: 16px; }
.tab { padding: 8px 16px; cursor: pointer; border-bottom: 2px solid transparent; margin-bottom: -2px; font-weight: 500; color: var(--muted); }
.tab.active { border-bottom-color: #3b82f6; color: #3b82f6; }
.tab-content { display: none; }
.tab-content.active { display: block; }
@media print { .filter-bar, .search-box, .tabs { display: none; } .tab-content { display: block !important; } }
'''

JS = '''
function filterTable(tableId, column, value) {
  const table = document.getElementById(tableId);
  if (!table) return;
  const rows = table.querySelectorAll('tbody tr');
  const btns = table.closest('.card').querySelectorAll('.filter-btn[data-col="'+column+'"]');
  btns.forEach(b => b.classList.toggle('active', b.dataset.val === value || value === 'all'));
  rows.forEach(row => {
    if (value === 'all') { row.style.display = ''; return; }
    const cell = row.cells[column];
    row.style.display = cell && cell.textContent.trim() === value ? '' : 'none';
  });
}
function searchTable(tableId, query) {
  const table = document.getElementById(tableId);
  if (!table) return;
  const q = query.toLowerCase();
  table.querySelectorAll('tbody tr').forEach(row => {
    row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}
function toggleDetail(id) {
  const el = document.getElementById('detail-'+id);
  if (el) el.classList.toggle('open');
}
function switchTab(tabGroup, tabName) {
  document.querySelectorAll('[data-tabgroup="'+tabGroup+'"] .tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tabName));
  document.querySelectorAll('[data-tabgroup="'+tabGroup+'"] .tab-content').forEach(c => c.classList.toggle('active', c.id === tabGroup+'-'+tabName));
}
function sortTable(tableId, col) {
  const table = document.getElementById(tableId);
  const tbody = table.querySelector('tbody');
  const rows = Array.from(tbody.rows);
  const dir = table.dataset.sortDir === 'asc' ? 'desc' : 'asc';
  table.dataset.sortDir = dir;
  rows.sort((a,b) => {
    let va = a.cells[col].textContent.trim(), vb = b.cells[col].textContent.trim();
    let na = parseFloat(va), nb = parseFloat(vb);
    if (!isNaN(na) && !isNaN(nb)) return dir==='asc' ? na-nb : nb-na;
    return dir==='asc' ? va.localeCompare(vb) : vb.localeCompare(va);
  });
  rows.forEach(r => tbody.appendChild(r));
}
'''


def generate_dashboard(
    actions: list[Action],
    tenant_name: str,
    output_path: str,
    comparison_data: dict = None,
) -> str:
    """Generate a full HTML dashboard report."""
    scores = calculate_total_score(actions)
    e8 = get_e8_summary(actions)
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    html = [f'''<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>M365 Security Posture - {tenant_name}</title>
<style>{CSS}</style></head><body>
<div class="container">
<h1>M365 Security Posture Dashboard</h1>
<p class="subtitle">Tenant: <strong>{tenant_name}</strong> | Generated: {ts} | Actions: {scores["total_actions"]}</p>
''']

    # Overview gauges
    html.append('<div class="gauges">')
    html.append(_render_gauge(scores["percentage"], "Overall Score", 140))
    for tool, data in scores["by_tool"].items():
        html.append(_render_gauge(data["percentage"], tool, 110))
    html.append('</div>')

    # Tabs
    html.append('<div data-tabgroup="main"><div class="tabs">')
    for tab_id, tab_label in [("overview", "Overview"), ("actions", "Actions"), ("e8", "Essential Eight"), ("workloads", "Workloads"), ("history", "History")]:
        active = " active" if tab_id == "overview" else ""
        html.append(f'<div class="tab{active}" data-tab="{tab_id}" onclick="switchTab(\'main\',\'{tab_id}\')">{tab_label}</div>')
    if comparison_data:
        html.append('<div class="tab" data-tab="compare" onclick="switchTab(\'main\',\'compare\')">Comparison</div>')
    html.append('</div>')

    # Overview tab
    html.append('<div class="tab-content active" id="main-overview">')
    html.append(_render_overview(scores))
    html.append('</div>')

    # Actions tab
    html.append('<div class="tab-content" id="main-actions">')
    html.append(_render_actions_table(actions))
    html.append('</div>')

    # E8 tab
    html.append('<div class="tab-content" id="main-e8">')
    html.append(_render_e8(e8, actions))
    html.append('</div>')

    # Workloads tab
    html.append('<div class="tab-content" id="main-workloads">')
    html.append(_render_workloads(scores))
    html.append('</div>')

    # History tab
    html.append('<div class="tab-content" id="main-history">')
    html.append(_render_history(actions))
    html.append('</div>')

    # Comparison tab
    if comparison_data:
        html.append('<div class="tab-content" id="main-compare">')
        html.append(_render_comparison(comparison_data))
        html.append('</div>')

    html.append('</div>')  # close tabgroup

    html.append(f'<script>{JS}</script></div></body></html>')

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        f.write("\n".join(html))
    return str(path)


def _render_overview(scores: dict) -> str:
    parts = ['<div class="grid grid-4">']

    cards = [
        ("Total Actions", str(scores["total_actions"]), ""),
        ("Completed", str(scores["completed_actions"]), _pct_color(scores["percentage"])),
        ("Overall Score", f'{scores["percentage"]:.0f}%', _pct_color(scores["percentage"])),
        ("Remaining", str(scores["total_actions"] - scores["completed_actions"]), ""),
    ]
    for label, value, color in cards:
        style = f' style="color:{color}"' if color else ""
        parts.append(f'<div class="card"><div class="card-header">{label}</div><div class="stat"{style}>{value}</div></div>')

    parts.append('</div>')

    # Status breakdown
    parts.append('<h2>Status Distribution</h2><div class="grid grid-3">')
    for status, count in sorted(scores.get("by_status", {}).items(), key=lambda x: -x[1]):
        color = _status_color(status)
        pct = (count / scores["total_actions"] * 100) if scores["total_actions"] > 0 else 0
        parts.append(f'''<div class="card">
            <div style="display:flex;justify-content:space-between;align-items:center">
              <span><span class="badge" style="background:{color}">{status}</span></span>
              <strong>{count}</strong>
            </div>
            <div class="bar-bg" style="margin-top:8px"><div class="bar-fill" style="width:{pct:.0f}%;background:{color}"></div></div>
        </div>''')
    parts.append('</div>')

    # Priority breakdown
    parts.append('<h2>Priority Distribution</h2><div class="grid grid-3">')
    for priority, count in sorted(scores.get("by_priority", {}).items(), key=lambda x: -x[1]):
        color = _priority_color(priority)
        parts.append(f'''<div class="card">
            <div style="display:flex;justify-content:space-between;align-items:center">
              <span class="badge" style="background:{color}">{priority}</span>
              <strong>{count}</strong>
            </div>
        </div>''')
    parts.append('</div>')

    return "\n".join(parts)


def _render_actions_table(actions: list[Action]) -> str:
    parts = []
    parts.append('<input class="search-box" placeholder="Search actions..." oninput="searchTable(\'actions-table\',this.value)">')

    # Filter buttons
    statuses = sorted(set(a.status for a in actions))
    parts.append('<div class="filter-bar">')
    parts.append('<button class="filter-btn active" data-col="3" data-val="all" onclick="filterTable(\'actions-table\',3,\'all\')">All</button>')
    for s in statuses:
        parts.append(f'<button class="filter-btn" data-col="3" data-val="{s}" onclick="filterTable(\'actions-table\',3,\'{s}\')">{s}</button>')
    parts.append('</div>')

    parts.append('<div style="overflow-x:auto"><table id="actions-table">')
    parts.append('<thead><tr>')
    for i, col in enumerate(["ID", "Title", "Source", "Status", "Priority", "Workload", "Score", "E8 Control"]):
        parts.append(f'<th onclick="sortTable(\'actions-table\',{i})">{col}</th>')
    parts.append('</tr></thead><tbody>')

    for a in actions:
        sc = f"{a.score_percentage:.0f}%" if a.score_percentage is not None else "-"
        e8 = a.essential_eight_control or "-"
        parts.append(f'''<tr onclick="toggleDetail('{a.id}')" style="cursor:pointer">
          <td>{a.id}</td>
          <td><strong>{_esc(a.title[:80])}</strong></td>
          <td>{a.source_tool}</td>
          <td><span class="badge" style="background:{_status_color(a.status)}">{a.status}</span></td>
          <td><span class="badge" style="background:{_priority_color(a.priority)}">{a.priority}</span></td>
          <td>{a.workload}</td>
          <td>{sc}</td>
          <td>{e8}</td>
        </tr>
        <tr><td colspan="8" style="padding:0">
          <div class="detail-panel" id="detail-{a.id}">
            <div class="grid grid-2">
              <div>
                <h3>Details</h3>
                <p><strong>Description:</strong> {_esc(a.description[:500])}</p>
                <p><strong>Source ID:</strong> {a.source_id}</p>
                <p><strong>Risk Level:</strong> {a.risk_level}</p>
                <p><strong>User Impact:</strong> {a.user_impact}</p>
                <p><strong>Impl. Effort:</strong> {a.implementation_effort}</p>
                <p><strong>Required Licence:</strong> {a.required_licence or "N/A"}</p>
                <p><strong>Category:</strong> {a.category}</p>
                {"<p><strong>Reference:</strong> <a href='" + a.reference_url + "' target='_blank'>Link</a></p>" if a.reference_url else ""}
              </div>
              <div>
                <h3>Configuration</h3>
                <p><strong>Current:</strong></p><pre style="background:#f3f4f6;padding:8px;border-radius:4px;font-size:12px;overflow-x:auto">{_esc(a.current_value or "N/A")}</pre>
                <p><strong>Recommended:</strong></p><pre style="background:#f3f4f6;padding:8px;border-radius:4px;font-size:12px;overflow-x:auto">{_esc(a.recommended_value or "N/A")}</pre>
                <h3>Remediation</h3>
                <p>{_esc(a.remediation_steps or "No remediation steps available.")}</p>
                <p><strong>Planned Date:</strong> {a.planned_date or "Not set"}</p>
                <p><strong>Responsible:</strong> {a.responsible or "Not assigned"}</p>
              </div>
            </div>
            {_render_action_history(a)}
          </div>
        </td></tr>''')

    parts.append('</tbody></table></div>')
    return "\n".join(parts)


def _render_action_history(action: Action) -> str:
    if not action.history:
        return ""
    parts = ['<h3>Change History</h3>']
    for entry in reversed(action.history):
        ts = entry.get("timestamp", "")[:19]
        changes = []
        if entry.get("old_status") and entry.get("new_status"):
            changes.append(f'Status: {entry["old_status"]} → {entry["new_status"]}')
        if entry.get("old_score") is not None and entry.get("new_score") is not None:
            changes.append(f'Score: {entry["old_score"]} → {entry["new_score"]}')
        if entry.get("source_report"):
            changes.append(f'Source: {entry["source_report"]}')
        if entry.get("notes"):
            changes.append(entry["notes"])
        parts.append(f'<div class="history-item"><strong>{ts}</strong> - {"; ".join(changes)}</div>')
    return "\n".join(parts)


def _render_e8(e8_summary: dict, actions: list[Action]) -> str:
    parts = ['<h2>Essential Eight Compliance</h2>']
    parts.append('<div class="gauges">')
    for control, data in e8_summary.items():
        parts.append(_render_gauge(data["percentage"], control[:20], 100))
    parts.append('</div>')

    parts.append('<div class="grid grid-2">')
    for control, data in e8_summary.items():
        achieved = data.get("achieved_maturity", "Maturity Level 0")
        parts.append(f'''<div class="card">
          <div class="card-header">{control}</div>
          <div style="display:flex;justify-content:space-between;align-items:center">
            <span><strong>{data["completed_actions"]}/{data["total_actions"]}</strong> actions completed</span>
            <span class="badge" style="background:{_pct_color(data['percentage'])}">{achieved}</span>
          </div>
          <div class="bar-bg" style="margin-top:8px"><div class="bar-fill" style="width:{data['percentage']:.0f}%;background:{_pct_color(data['percentage'])}"></div></div>
        </div>''')
    parts.append('</div>')

    # ASD Blueprint reference
    parts.append('''<div class="card" style="margin-top:16px">
      <div class="card-header">ASD Blueprint Reference</div>
      <p>Mapped to <a href="https://blueprint.asd.gov.au/security-and-governance/essential-eight/" target="_blank">ASD's Blueprint for Secure Cloud - Essential Eight</a></p>
      <p style="font-size:12px;color:var(--muted)">Maturity levels: Level 0 (not implemented) → Level 1 (partly aligned) → Level 2 (mostly aligned) → Level 3 (fully aligned)</p>
    </div>''')

    return "\n".join(parts)


def _render_workloads(scores: dict) -> str:
    parts = ['<h2>Workload Scores</h2>']
    parts.append('<div class="gauges">')
    for wl, data in scores.get("by_workload", {}).items():
        parts.append(_render_gauge(data["percentage"], wl, 100))
    parts.append('</div>')

    parts.append('<div class="grid grid-2">')
    for wl, data in sorted(scores.get("by_workload", {}).items(), key=lambda x: x[1]["percentage"]):
        parts.append(f'''<div class="card">
          <div class="card-header">{wl}</div>
          <div style="display:flex;justify-content:space-between"><span>{data["completed"]}/{data["total"]} completed</span><strong>{data["percentage"]:.0f}%</strong></div>
          <div class="bar-bg" style="margin-top:8px"><div class="bar-fill" style="width:{data['percentage']:.0f}%;background:{_pct_color(data['percentage'])}"></div></div>
        </div>''')
    parts.append('</div>')
    return "\n".join(parts)


def _render_history(actions: list[Action]) -> str:
    # Collect all history entries across all actions
    all_entries = []
    for a in actions:
        for entry in a.history:
            all_entries.append({**entry, "action_title": a.title, "action_id": a.id})

    all_entries.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    parts = ['<h2>Change History Timeline</h2>']
    if not all_entries:
        parts.append('<p style="color:var(--muted)">No history entries yet. Import reports to track changes over time.</p>')
        return "\n".join(parts)

    parts.append('<table><thead><tr><th>Date</th><th>Action</th><th>Change</th><th>Source</th></tr></thead><tbody>')
    for entry in all_entries[:200]:
        ts = entry.get("timestamp", "")[:19]
        change = ""
        if entry.get("old_status") and entry.get("new_status"):
            change = f'{entry["old_status"]} → {entry["new_status"]}'
        elif entry.get("old_score") is not None:
            change = f'Score: {entry["old_score"]} → {entry["new_score"]}'
        source = entry.get("source_report", "")
        parts.append(f'<tr><td>{ts}</td><td>{_esc(entry.get("action_title", "")[:60])}</td><td>{change}</td><td>{_esc(source[:40])}</td></tr>')
    parts.append('</tbody></table>')
    return "\n".join(parts)


def _render_comparison(comparison: dict) -> str:
    tenants = comparison.get("tenants", [])
    parts = ['<h2>Tenant Comparison</h2>']

    # Overall comparison
    parts.append('<div class="grid grid-' + str(len(tenants)) + '">')
    for tenant in tenants:
        data = comparison["overall"].get(tenant, {})
        pct = data.get("percentage", 0)
        parts.append(f'''<div class="card" style="text-align:center">
          <div class="card-header">{tenant}</div>
          {_render_gauge(pct, f'{data.get("completed_actions",0)}/{data.get("total_actions",0)} completed', 120)}
        </div>''')
    parts.append('</div>')

    # Tool comparison table
    parts.append('<h3>By Source Tool</h3><table><thead><tr><th>Tool</th>')
    for t in tenants:
        parts.append(f'<th>{t}</th>')
    parts.append('</tr></thead><tbody>')
    for tool, tenant_data in comparison.get("by_tool", {}).items():
        parts.append(f'<tr><td><strong>{tool}</strong></td>')
        for t in tenants:
            td = tenant_data.get(t, {})
            parts.append(f'<td>{td.get("percentage",0):.0f}% ({td.get("completed",0)}/{td.get("total",0)})</td>')
        parts.append('</tr>')
    parts.append('</tbody></table>')

    # Workload comparison table
    parts.append('<h3>By Workload</h3><table><thead><tr><th>Workload</th>')
    for t in tenants:
        parts.append(f'<th>{t}</th>')
    parts.append('</tr></thead><tbody>')
    for wl, tenant_data in comparison.get("by_workload", {}).items():
        parts.append(f'<tr><td><strong>{wl}</strong></td>')
        for t in tenants:
            td = tenant_data.get(t, {})
            parts.append(f'<td>{td.get("percentage",0):.0f}% ({td.get("completed",0)}/{td.get("total",0)})</td>')
        parts.append('</tr>')
    parts.append('</tbody></table>')

    return "\n".join(parts)


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
