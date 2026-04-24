"""Single-page application HTML for M365 Security Posture Manager."""


def get_spa_html() -> str:
    return _SPA_HTML


_SPA_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>M365 Security Posture Manager</title>
<style>
:root {
  --bg: #f1f5f9; --bg-card: #fff; --bg-sidebar: #0f172a; --bg-sidebar-hover: #1e293b;
  --text: #1e293b; --text-light: #64748b; --text-sidebar: #cbd5e1;
  --primary: #3b82f6; --primary-dark: #2563eb; --primary-light: #dbeafe;
  --success: #10b981; --success-light: #d1fae5;
  --warning: #f59e0b; --warning-light: #fef3c7;
  --danger: #ef4444; --danger-light: #fee2e2;
  --purple: #8b5cf6; --purple-light: #ede9fe;
  --cyan: #06b6d4; --gray: #6b7280;
  --border: #e2e8f0; --shadow: 0 1px 3px rgba(0,0,0,.1);
  --radius: 8px; --sidebar-w: 250px;
}
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:var(--bg); color:var(--text); }
a { color:var(--primary); text-decoration:none; }

/* Layout */
.sidebar { position:fixed; top:0; left:0; width:var(--sidebar-w); height:100vh; background:var(--bg-sidebar); color:var(--text-sidebar); display:flex; flex-direction:column; z-index:100; transition:transform .3s; }
.sidebar .logo { padding:20px; font-size:16px; font-weight:700; color:#fff; border-bottom:1px solid #1e293b; display:flex; align-items:center; gap:10px; }
.sidebar .logo svg { width:28px; height:28px; }
.sidebar nav { flex:1; overflow-y:auto; padding:8px; }
.sidebar nav a { display:flex; align-items:center; gap:10px; padding:10px 14px; border-radius:6px; color:var(--text-sidebar); font-size:14px; margin-bottom:2px; transition:background .15s; }
.sidebar nav a:hover, .sidebar nav a.active { background:var(--bg-sidebar-hover); color:#fff; }
.sidebar nav a svg { width:18px; height:18px; flex-shrink:0; }
.sidebar .tenant-indicator { padding:12px 16px; border-top:1px solid #1e293b; font-size:12px; }
.sidebar .tenant-indicator .name { color:#fff; font-weight:600; font-size:13px; }

.main { margin-left:var(--sidebar-w); min-height:100vh; }
.topbar { background:var(--bg-card); border-bottom:1px solid var(--border); padding:12px 24px; display:flex; justify-content:space-between; align-items:center; position:sticky; top:0; z-index:50; }
.topbar h1 { font-size:20px; font-weight:600; }
.topbar .actions { display:flex; gap:8px; align-items:center; }
.content { padding:24px; }

/* Cards */
.card { background:var(--bg-card); border:1px solid var(--border); border-radius:var(--radius); padding:20px; box-shadow:var(--shadow); }
.card-header { font-size:15px; font-weight:600; margin-bottom:12px; display:flex; justify-content:space-between; align-items:center; }
.grid { display:grid; gap:16px; }
.grid-2 { grid-template-columns:1fr 1fr; }
.grid-3 { grid-template-columns:1fr 1fr 1fr; }
.grid-4 { grid-template-columns:1fr 1fr 1fr 1fr; }
@media(max-width:1200px){ .grid-4{grid-template-columns:1fr 1fr;} .grid-3{grid-template-columns:1fr 1fr;} }
@media(max-width:768px){ .grid-2,.grid-3,.grid-4{grid-template-columns:1fr;} .sidebar{transform:translateX(-100%);} .main{margin-left:0;} }

/* Stat cards */
.stat-card { text-align:center; }
.stat-card .value { font-size:32px; font-weight:700; color:var(--primary); }
.stat-card .label { font-size:13px; color:var(--text-light); margin-top:4px; }

/* Buttons */
.btn { display:inline-flex; align-items:center; gap:6px; padding:8px 16px; border-radius:6px; border:1px solid var(--border); background:var(--bg-card); color:var(--text); font-size:13px; font-weight:500; cursor:pointer; transition:all .15s; }
.btn:hover { border-color:var(--primary); color:var(--primary); }
.btn-primary { background:var(--primary); color:#fff; border-color:var(--primary); }
.btn-primary:hover { background:var(--primary-dark); }
.btn-success { background:var(--success); color:#fff; border-color:var(--success); }
.btn-danger { background:var(--danger); color:#fff; border-color:var(--danger); }
.btn-danger:hover { background:#dc2626; }
.btn-sm { padding:5px 10px; font-size:12px; }
.btn-group { display:flex; gap:4px; }

/* Forms */
input, select, textarea { width:100%; padding:8px 12px; border:1px solid var(--border); border-radius:6px; font-size:14px; font-family:inherit; background:var(--bg-card); color:var(--text); }
input:focus, select:focus, textarea:focus { outline:none; border-color:var(--primary); box-shadow:0 0 0 3px var(--primary-light); }
label { display:block; font-size:13px; font-weight:500; margin-bottom:4px; color:var(--text-light); }
.form-group { margin-bottom:14px; }
.form-row { display:flex; gap:12px; }
.form-row > * { flex:1; }

/* Table */
.table-wrap { overflow-x:auto; }
table { width:100%; border-collapse:collapse; font-size:13px; }
th { text-align:left; padding:10px 12px; background:var(--bg); border-bottom:2px solid var(--border); font-weight:600; color:var(--text-light); font-size:12px; text-transform:uppercase; letter-spacing:.5px; cursor:pointer; white-space:nowrap; user-select:none; }
th:hover { color:var(--primary); }
td { padding:10px 12px; border-bottom:1px solid var(--border); }
tr:hover td { background:var(--primary-light); }
tr.selected td { background:#dbeafe; }

/* Badges */
.badge { display:inline-block; padding:3px 8px; border-radius:4px; font-size:11px; font-weight:600; }
.badge-success { background:var(--success-light); color:#065f46; }
.badge-warning { background:var(--warning-light); color:#92400e; }
.badge-danger { background:var(--danger-light); color:#991b1b; }
.badge-info { background:var(--primary-light); color:#1e40af; }
.badge-purple { background:var(--purple-light); color:#5b21b6; }
.badge-gray { background:#f1f5f9; color:#475569; }
.badge-cyan { background:#cffafe; color:#155e75; }

/* Sortable table headers */
th.sort-asc::after, th.sort-desc::after { margin-left:4px; font-size:10px; opacity:.6; }
th.sort-asc::after { content:"▲"; }
th.sort-desc::after { content:"▼"; }
thead th[style*="cursor"] { transition:background .15s; }
thead th[style*="cursor"]:hover { background:var(--primary-light); }

/* Modal */
.modal-overlay { display:none; position:fixed; inset:0; background:rgba(0,0,0,.5); z-index:200; justify-content:center; align-items:flex-start; padding:40px 20px; overflow-y:auto; }
.modal-overlay.open { display:flex; }
.modal { background:var(--bg-card); border-radius:12px; width:100%; max-width:700px; box-shadow:0 20px 60px rgba(0,0,0,.3); }
.modal-header { padding:16px 20px; border-bottom:1px solid var(--border); display:flex; justify-content:space-between; align-items:center; }
.modal-header h2 { font-size:17px; }
.modal-close { background:none; border:none; font-size:22px; cursor:pointer; color:var(--text-light); padding:4px; }
.modal-body { padding:20px; max-height:65vh; overflow-y:auto; }
.modal-footer { padding:14px 20px; border-top:1px solid var(--border); display:flex; justify-content:flex-end; gap:8px; }

/* Gauge */
.gauge { position:relative; width:120px; height:120px; display:inline-block; }
.gauge svg { transform:rotate(-90deg); }
.gauge .track { fill:none; stroke:#e2e8f0; stroke-width:10; }
.gauge .fill { fill:none; stroke-width:10; stroke-linecap:round; transition:stroke-dashoffset .8s ease; }
.gauge .pct { position:absolute; inset:0; display:flex; flex-direction:column; align-items:center; justify-content:center; font-size:22px; font-weight:700; }
.gauge .pct small { font-size:11px; color:var(--text-light); font-weight:400; }

/* Tabs */
.tabs { display:flex; gap:0; border-bottom:2px solid var(--border); margin-bottom:16px; }
.tabs .tab { padding:10px 18px; cursor:pointer; font-size:14px; font-weight:500; color:var(--text-light); border-bottom:2px solid transparent; margin-bottom:-2px; transition:all .15s; }
.tabs .tab:hover { color:var(--text); }
.tabs .tab.active { color:var(--primary); border-bottom-color:var(--primary); }

/* Upload */
.upload-zone { border:2px dashed var(--border); border-radius:var(--radius); padding:40px; text-align:center; cursor:pointer; transition:all .2s; }
.upload-zone:hover, .upload-zone.drag-over { border-color:var(--primary); background:var(--primary-light); }
.upload-zone .icon { font-size:36px; margin-bottom:8px; }

/* Progress bar */
.progress { height:8px; background:var(--border); border-radius:4px; overflow:hidden; }
.progress .bar { height:100%; border-radius:4px; transition:width .5s ease; }

/* Filter bar */
.filter-bar { display:flex; gap:8px; flex-wrap:wrap; margin-bottom:16px; align-items:center; }
.filter-bar input[type=text] { max-width:250px; }
.filter-bar select { max-width:180px; }

/* Toast */
.toast-container { position:fixed; top:16px; right:16px; z-index:300; display:flex; flex-direction:column; gap:8px; }
.toast { padding:12px 16px; border-radius:8px; background:var(--bg-card); border:1px solid var(--border); box-shadow:0 4px 12px rgba(0,0,0,.15); font-size:14px; animation:slideIn .3s ease; min-width:280px; }
.toast.success { border-left:4px solid var(--success); }
.toast.error { border-left:4px solid var(--danger); }
.toast.info { border-left:4px solid var(--primary); }
@keyframes slideIn { from{transform:translateX(100%);opacity:0;} to{transform:translateX(0);opacity:1;} }

/* Phase card */
.phase-card { border-left:4px solid var(--primary); padding-left:16px; }
.phase-card.phase-1 { border-left-color:var(--success); }
.phase-card.phase-2 { border-left-color:var(--warning); }
.phase-card.phase-3 { border-left-color:var(--purple); }
.phase-card table { table-layout:fixed; width:100%; }
.phase-card th, .phase-card td { overflow:hidden; text-overflow:ellipsis; }

/* Correlation badge */
.corr-badge { display:inline-flex; gap:4px; align-items:center; padding:2px 8px; border-radius:12px; font-size:11px; background:var(--purple-light); color:#5b21b6; }

/* Detail panel */
.detail-panel { background:#f8fafc; border:1px solid var(--border); border-radius:var(--radius); padding:16px; margin:8px 0; }
.detail-panel .field { margin-bottom:8px; }
.detail-panel .field-label { font-size:11px; text-transform:uppercase; letter-spacing:.5px; color:var(--text-light); }
.detail-panel .field-value { font-size:14px; margin-top:2px; white-space:pre-line; }
.detail-panel pre { background:#1e293b; color:#e2e8f0; padding:12px; border-radius:6px; font-size:12px; overflow-x:auto; white-space:pre-wrap; }

/* Tenant switcher dropdown in sidebar */
.tenant-indicator { cursor:pointer; position:relative; transition:background .15s; }
.tenant-indicator:hover { background:var(--bg-sidebar-hover); }
.tenant-indicator .switch-hint { font-size:10px; color:#64748b; margin-top:2px; opacity:0; transition:opacity .15s; }
.tenant-indicator:hover .switch-hint { opacity:1; }
.tenant-dropdown { display:none; position:absolute; bottom:100%; left:0; right:0; background:#1e293b; border:1px solid #334155; border-radius:8px 8px 0 0; max-height:240px; overflow-y:auto; box-shadow:0 -4px 16px rgba(0,0,0,.3); }
.tenant-dropdown.open { display:block; }
.tenant-dropdown .td-item { padding:10px 16px; font-size:13px; color:#cbd5e1; cursor:pointer; display:flex; justify-content:space-between; align-items:center; transition:background .1s; }
.tenant-dropdown .td-item:hover { background:#334155; color:#fff; }
.tenant-dropdown .td-item.active { color:#3b82f6; font-weight:600; }
.tenant-dropdown .td-item .td-check { font-size:14px; }

/* Action detail tabs */
.action-tabs { display:flex; gap:0; border-bottom:2px solid var(--border); margin-bottom:16px; }
.action-tabs .atab { padding:8px 16px; cursor:pointer; font-size:13px; font-weight:500; color:var(--text-light); border-bottom:2px solid transparent; margin-bottom:-2px; transition:all .15s; }
.action-tabs .atab:hover { color:var(--text); }
.action-tabs .atab.active { color:var(--primary); border-bottom-color:var(--primary); }
.action-tab-content { display:none; }
.action-tab-content.active { display:block; }

/* Action detail sidebar (right column) */
.action-detail-layout { display:grid; grid-template-columns:1fr 280px; gap:20px; }
@media(max-width:900px) { .action-detail-layout { grid-template-columns:1fr; } }
.action-sidebar-card { background:var(--bg-card); border:1px solid var(--border); border-radius:var(--radius); padding:16px; }
.action-sidebar-card .sidebar-field { margin-bottom:12px; }
.action-sidebar-card .sidebar-field .field-label { font-size:11px; text-transform:uppercase; letter-spacing:.5px; color:var(--text-light); margin-bottom:2px; }
.action-sidebar-card .sidebar-field .field-value { font-size:13px; }

/* Score bar for action detail */
.score-bar-wrap { margin:8px 0; }
.score-bar { height:10px; background:var(--border); border-radius:5px; overflow:hidden; position:relative; }
.score-bar .bar { height:100%; border-radius:5px; background:var(--primary); transition:width .5s; }
.score-label { font-size:20px; font-weight:700; text-align:right; color:var(--text); }

/* Trend chart */
.trend-chart { width:100%; height:200px; position:relative; }
.trend-chart svg { width:100%; height:100%; }
.trend-chart .line { fill:none; stroke:var(--primary); stroke-width:2; }
.trend-chart .area { fill:var(--primary-light); opacity:.3; }
.trend-chart .dot { fill:var(--primary); r:4; cursor:pointer; }
.trend-chart .dot:hover { r:6; fill:var(--primary-dark); }
.trend-chart .grid-line { stroke:var(--border); stroke-width:1; stroke-dasharray:4; }
.trend-chart .axis-label { font-size:10px; fill:var(--text-light); }

/* Drift indicators */
.drift-positive { color:var(--success); font-weight:600; }
.drift-negative { color:var(--danger); font-weight:600; }
.drift-neutral { color:var(--text-light); }
.drift-card { border-left:4px solid var(--border); }
.drift-card.regression { border-left-color:var(--danger); }
.drift-card.improvement { border-left-color:var(--success); }
.drift-banner { padding:12px 16px; border-radius:var(--radius); margin-bottom:16px; display:flex; align-items:center; gap:12px; }
.drift-banner.positive { background:#d1fae5; border:1px solid #6ee7b7; }
.drift-banner.negative { background:#fee2e2; border:1px solid #fca5a5; }
.drift-banner.neutral { background:#f1f5f9; border:1px solid var(--border); }
.drift-banner .delta { font-size:24px; font-weight:700; }

/* Dependency lines */
.dep-tag { display:inline-flex; align-items:center; gap:4px; padding:2px 8px; border-radius:12px; font-size:11px; background:#fef3c7; color:#92400e; margin:2px; }
.dep-tag.blocked { background:#fee2e2; color:#991b1b; }

/* Risk acceptance card */
.risk-card { border-left:4px solid var(--warning); padding:16px; }
.risk-card.expired { border-left-color:var(--danger); background:#fff5f5; }
.risk-card.upcoming { border-left-color:var(--warning); background:#fffbeb; }

/* Compliance family */
.compliance-family { border:1px solid var(--border); border-radius:var(--radius); margin-bottom:12px; overflow:hidden; }
.compliance-family-header { padding:12px 16px; background:var(--bg); cursor:pointer; display:flex; justify-content:space-between; align-items:center; font-weight:600; font-size:14px; }
.compliance-family-body { padding:0 16px 12px; }

.hidden { display:none !important; }
.text-center { text-align:center; }
.mb-16 { margin-bottom:16px; }
.mb-8 { margin-bottom:8px; }
.mt-16 { margin-top:16px; }
.gap-8 { gap:8px; }
.flex { display:flex; }
.items-center { align-items:center; }
.justify-between { justify-content:space-between; }
.flex-1 { flex:1; }
</style>
</head>
<body>

<!-- Sidebar -->
<div class="sidebar" id="sidebar">
  <div class="logo">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
    M365 Posture
  </div>
  <nav>
    <a href="#dashboard" data-page="dashboard" class="active">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
      Dashboard
    </a>
    <a href="#tenants" data-page="tenants">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z"/><polyline points="9,22 9,12 15,12 15,22"/></svg>
      Tenants
    </a>
    <a href="#actions" data-page="actions">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9,11 12,14 22,4"/><path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/></svg>
      Actions
    </a>
    <a href="#import" data-page="import">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17,8 12,3 7,8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
      Import
    </a>
    <a href="#plans" data-page="plans">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14,2 14,8 20,8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
      Plans
    </a>
    <a href="#people" data-page="people">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></svg>
      People
    </a>
    <a href="#correlations" data-page="correlations">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
      Correlations
    </a>
    <a href="#e8" data-page="e8">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
      Essential Eight
    </a>
    <a href="#compliance" data-page="compliance">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2"/><rect x="9" y="3" width="6" height="4" rx="1"/><path d="M9 14l2 2 4-4"/></svg>
      Compliance
    </a>
    <a href="#risks" data-page="risks">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
      Risk Register
    </a>
    <a href="#trending" data-page="trending">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22,12 18,12 15,21 9,3 6,12 2,12"/></svg>
      Trending
    </a>
    <a href="#export" data-page="export">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7,10 12,15 17,10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
      Export
    </a>
    <a href="#history" data-page="history">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12,6 12,12 16,14"/></svg>
      History
    </a>
  </nav>
  <div class="tenant-indicator" id="tenant-indicator" onclick="toggleTenantDropdown(event)">
    <div class="tenant-dropdown" id="tenant-dropdown"></div>
    <div style="color:var(--text-sidebar)">Active Tenant</div>
    <div class="name" id="active-tenant-name">None</div>
    <div class="switch-hint">Click to switch</div>
  </div>
</div>

<!-- Main content -->
<div class="main">
  <div class="topbar">
    <h1 id="page-title">Dashboard</h1>
    <div class="actions" id="topbar-actions"></div>
  </div>
  <div class="content" id="content"></div>
</div>

<!-- Toast container -->
<div class="toast-container" id="toasts"></div>

<!-- Modal -->
<div class="modal-overlay" id="modal-overlay">
  <div class="modal">
    <div class="modal-header">
      <h2 id="modal-title"></h2>
      <button class="modal-close" onclick="closeModal()">&times;</button>
    </div>
    <div class="modal-body" id="modal-body"></div>
    <div class="modal-footer" id="modal-footer"></div>
  </div>
</div>

<script>
// ── API Client ──
const api = {
  async _handle(r) {
    const data = await r.json().catch(()=>({error:'Invalid response'}));
    if(!r.ok && !data.error) data.error = `HTTP ${r.status}`;
    return data;
  },
  async get(url) { const r = await fetch(url); return this._handle(r); },
  async post(url, data) {
    const r = await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data)});
    return this._handle(r);
  },
  async put(url, data) {
    const r = await fetch(url, {method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data)});
    return this._handle(r);
  },
  async del(url) { const r = await fetch(url, {method:'DELETE'}); return this._handle(r); },
  async upload(url, formData) { const r = await fetch(url, {method:'POST', body:formData}); return this._handle(r); },
  async download(url, data) {
    const r = await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data)});
    return r;
  }
};

// ── State ──
let state = { activeTenant:null, tenants:[], enums:{}, currentPage:'dashboard' };

// ── Utils ──
function toast(msg, type='info') {
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.textContent = msg;
  document.getElementById('toasts').appendChild(t);
  setTimeout(() => t.remove(), 4000);
}

function statusBadge(s) {
  const m = {'Completed':'success','In Progress':'info','In Planning':'purple','Warning':'warning','ToDo':'danger','Risk Accepted':'warning','Not Applicable':'gray','Third Party':'cyan'};
  return `<span class="badge badge-${m[s]||'gray'}">${s}</span>`;
}

function priorityBadge(p) {
  const m = {'Critical':'danger','High':'warning','Medium':'info','Low':'success','Informational':'gray'};
  return `<span class="badge badge-${m[p]||'gray'}">${p}</span>`;
}

function ztStatusBadge(a) {
  // Show the original ZT test status from tags
  const ztTag = (a.tags||[]).find(t => t.startsWith('ZT: '));
  const ztStatus = ztTag ? ztTag.replace('ZT: ', '') : '';
  const m = {'Passed':'success','Failed':'danger','Investigate':'warning','Planned':'purple','Skipped':'gray'};
  return ztStatus ? `<span class="badge badge-${m[ztStatus]||'gray'}">${ztStatus}</span>` : '';
}

function pctColor(p) {
  if(p>=80) return 'var(--success)';
  if(p>=60) return '#84cc16';
  if(p>=40) return 'var(--warning)';
  if(p>=20) return '#f97316';
  return 'var(--danger)';
}

function mdToHtml(text) {
  // Convert markdown links [text](url) to clickable HTML, bold **text**, and headings
  if(!text) return '';
  let s = text.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  // Markdown links: [label](url)
  s = s.replace(/\[([^\]]+)\]\((https?:\/\/[^)]+)\)/g, '<a href="$2" target="_blank" onclick="event.stopPropagation()">$1</a>');
  // Bare URLs not already in an <a> tag
  s = s.replace(/(?<!href=")(https?:\/\/[^\s<"&]+)/g, '<a href="$1" target="_blank" onclick="event.stopPropagation()">$1</a>');
  // Bold **text**
  s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  // Headings
  s = s.replace(/^### (.+)$/gm, '<h4 style="margin:8px 0 4px">$1</h4>');
  s = s.replace(/^## (.+)$/gm, '<h3 style="margin:10px 0 6px">$1</h3>');
  // List items
  s = s.replace(/^- (.+)$/gm, '&bull; $1');
  return s;
}

function gauge(pct, size=120, label='') {
  const r=45, c=2*Math.PI*r, off=c-(pct/100)*c;
  return `<div class="gauge" style="width:${size}px;height:${size}px">
    <svg width="${size}" height="${size}" viewBox="0 0 100 100">
      <circle class="track" cx="50" cy="50" r="${r}"/>
      <circle class="fill" cx="50" cy="50" r="${r}" stroke="${pctColor(pct)}" stroke-dasharray="${c}" stroke-dashoffset="${off}"/>
    </svg>
    <div class="pct">${pct.toFixed(2)}%<small>${label}</small></div>
  </div>`;
}

function progressBar(pct, color=null, h=8) {
  const c = color || pctColor(pct);
  return `<div class="progress" style="height:${h}px"><div class="bar" style="width:${Math.min(100,pct)}%;background:${c}"></div></div>`;
}

function selectOptions(values, selected='') {
  return values.map(v => `<option value="${v}" ${v===selected?'selected':''}>${v}</option>`).join('');
}

function openModal(title, bodyHtml, footerHtml='') {
  document.getElementById('modal-title').textContent = title;
  document.getElementById('modal-body').innerHTML = bodyHtml;
  document.getElementById('modal-footer').innerHTML = footerHtml;
  document.getElementById('modal-overlay').classList.add('open');
}

function closeModal() { document.getElementById('modal-overlay').classList.remove('open'); }

// ── Sortable Tables ──
let _sortState = {}; // tableId -> {col, dir}
function makeSortable(table) {
  if(!table || !table.querySelector('thead')) return;
  const headers = table.querySelectorAll('thead th');
  headers.forEach((th, colIdx) => {
    // Skip checkbox columns
    if(th.querySelector('input[type="checkbox"]')) return;
    th.style.cursor = 'pointer';
    th.style.userSelect = 'none';
    th.style.whiteSpace = 'nowrap';
    th.addEventListener('click', (e) => {
      e.stopPropagation();
      sortTable(table, colIdx, th);
    });
  });
}
function sortTable(table, colIdx, th) {
  const tid = table.id || 'tbl_' + Math.random().toString(36).slice(2,6);
  if(!table.id) table.id = tid;
  const prev = _sortState[tid];
  const dir = (prev && prev.col === colIdx && prev.dir === 'asc') ? 'desc' : 'asc';
  _sortState[tid] = {col: colIdx, dir};
  // Update header indicators
  table.querySelectorAll('thead th').forEach(h => { h.classList.remove('sort-asc','sort-desc'); });
  th.classList.add(dir === 'asc' ? 'sort-asc' : 'sort-desc');
  const tbody = table.querySelector('tbody');
  if(!tbody) return;
  const allRows = Array.from(tbody.querySelectorAll('tr'));
  // Collapse all expanded detail rows before sorting
  allRows.forEach(r => {
    if(r.id && r.id.startsWith('detail-')) r.classList.add('hidden');
  });
  // Only sort main rows (skip detail rows entirely)
  const mainRows = allRows.filter(r => !r.id || !r.id.startsWith('detail-'));
  const detailMap = {};
  allRows.filter(r => r.id && r.id.startsWith('detail-')).forEach(r => {
    detailMap[r.id.replace('detail-','')] = r;
  });
  mainRows.sort((a, b) => {
    let aVal = (a.children[colIdx]?.textContent || '').trim();
    let bVal = (b.children[colIdx]?.textContent || '').trim();
    const aNum = parseFloat(aVal.replace(/[,%]/g,''));
    const bNum = parseFloat(bVal.replace(/[,%]/g,''));
    if(!isNaN(aNum) && !isNaN(bNum)) {
      return dir === 'asc' ? aNum - bNum : bNum - aNum;
    }
    return dir === 'asc' ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
  });
  mainRows.forEach(r => {
    tbody.appendChild(r);
    const key = (r.id||'').replace('row-','');
    if(detailMap[key]) tbody.appendChild(detailMap[key]);
  });
}
// Auto-apply to all tables after any render
function applySort() {
  document.querySelectorAll('table:not([data-sortable])').forEach(t => {
    t.setAttribute('data-sortable', '1');
    makeSortable(t);
  });
}

// ── Router ──
async function navigate(page) {
  state.currentPage = page;
  document.querySelectorAll('.sidebar nav a').forEach(a => a.classList.toggle('active', a.dataset.page===page));
  const titles = {dashboard:'Dashboard',tenants:'Tenants',actions:'Actions',import:'Import Data',plans:'Remediation Plans',people:'People & Assignments',correlations:'Action Correlations',e8:'Essential Eight',scuba:'SCuBA Baseline Conformance',compliance:'Compliance Frameworks',risks:'Risk Register',trending:'Score Trending',export:'Export',history:'Import History'};
  document.getElementById('page-title').textContent = titles[page]||page;
  document.getElementById('topbar-actions').innerHTML = '';

  if(page !== 'dashboard') _dashData = {};
  const render = {dashboard:renderDashboard,tenants:renderTenants,actions:renderActions,import:renderImport,plans:renderPlans,people:renderPeople,correlations:renderCorrelations,e8:renderE8,scuba:renderScuba,compliance:renderCompliance,risks:renderRisks,trending:renderTrending,export:renderExport,history:renderHistory};
  if(render[page]) await render[page]();
  setTimeout(applySort, 50);
}

window.addEventListener('hashchange', () => navigate(location.hash.slice(1)||'dashboard'));

// ── Init ──
async function init() {
  state.enums = await api.get('/api/enums');
  state.tenants = await api.get('/api/tenants');
  const active = await api.get('/api/active-tenant');
  state.activeTenant = active && active.name ? active : (state.tenants[0]||null);
  updateTenantIndicator();
  navigate(location.hash.slice(1)||'dashboard');
}

function updateTenantIndicator() {
  const el = document.getElementById('active-tenant-name');
  el.textContent = state.activeTenant ? (state.activeTenant.display_name || state.activeTenant.name) : 'None';
}

function toggleTenantDropdown(e) {
  e.stopPropagation();
  const dd = document.getElementById('tenant-dropdown');
  if(dd.classList.contains('open')) { dd.classList.remove('open'); return; }
  // Build dropdown items
  let items = state.tenants.map(t => {
    const isActive = state.activeTenant && state.activeTenant.name === t.name;
    return `<div class="td-item ${isActive?'active':''}" onclick="switchTenant('${t.name}');event.stopPropagation()">
      <span>${t.display_name||t.name}</span>
      ${isActive?'<span class="td-check">&#10003;</span>':''}
    </div>`;
  }).join('');
  if(!items) items = '<div class="td-item" style="color:#64748b">No tenants</div>';
  dd.innerHTML = items;
  dd.classList.add('open');
}

async function switchTenant(name) {
  document.getElementById('tenant-dropdown').classList.remove('open');
  await api.post(`/api/tenants/${name}/activate`);
  const active = await api.get('/api/active-tenant');
  state.activeTenant = active && active.name ? active : null;
  state.tenants = await api.get('/api/tenants');
  updateTenantIndicator();
  toast(`Switched to ${state.activeTenant?.display_name||name}`, 'success');
  navigate(state.currentPage);
}

// Close dropdown when clicking elsewhere
document.addEventListener('click', () => {
  document.getElementById('tenant-dropdown')?.classList.remove('open');
});

function requireTenant() {
  if(!state.activeTenant) { toast('No active tenant. Add one first.','error'); navigate('tenants'); return false; }
  return true;
}

// ── Dashboard ──
// Store dashboard data for source filter switching
let _dashData = {};
let _dashExcludeNA = false;

async function renderDashboard(sourceFilter) {
  const c = document.getElementById('content');
  if(!requireTenant()) return;
  const t = state.activeTenant.name;
  const displayName = state.activeTenant.display_name || state.activeTenant.name;

  // Topbar: tenant switcher, compare button, PDF download
  let tenantSwitchOpts = state.tenants.map(tn =>
    `<option value="${tn.name}" ${tn.name===t?'selected':''}>${tn.display_name||tn.name}</option>`
  ).join('');
  document.getElementById('topbar-actions').innerHTML = `
    <select id="dash-tenant-switch" onchange="switchTenantFromDashboard(this.value)" style="max-width:200px;font-size:13px">${tenantSwitchOpts}</select>
    ${state.tenants.length>=2?'<button class="btn btn-sm" onclick="showDashboardCompare()">Compare Tenants</button>':''}
    <button class="btn btn-sm btn-primary" onclick="downloadDashboardPDF()">PDF Report</button>`;

  // Fetch data on first load or full refresh; reuse when just switching source filter
  const isFilterSwitch = (sourceFilter !== undefined) && Object.keys(_dashData).length > 0;
  const excludeParam = _dashExcludeNA ? '?exclude_na=1' : '';
  const needsRefresh = !isFilterSwitch || (_dashData.scores && _dashData.scores.exclude_na !== _dashExcludeNA);
  if(!isFilterSwitch || needsRefresh) {
    const [scores, prioritized, snapshots, riskSummary, allActions] = await Promise.all([
      api.get(`/api/tenants/${t}/scores${excludeParam}`),
      api.get(`/api/tenants/${t}/prioritized?limit=10`),
      api.get(`/api/tenants/${t}/snapshots?limit=20`),
      api.get(`/api/tenants/${t}/risk-summary`),
      api.get(`/api/tenants/${t}/actions`),
    ]);
    _dashData = {scores, prioritized, snapshots, riskSummary, allActions};
  }

  const {scores, prioritized, snapshots, riskSummary, allActions} = _dashData;
  const sf = sourceFilter || '';

  // Filter actions by source if selected
  const filteredActions = sf ? allActions.filter(a => a.source_tool === sf) : allActions;

  // Compute filtered scores
  let dispScore, dispMax, dispPct, dispTotal, dispCompleted;
  if(sf) {
    const toolData = scores.by_tool?.[sf];
    if(toolData) {
      dispScore = toolData.score;
      dispMax = toolData.max_score;
      dispPct = toolData.percentage;
      dispTotal = toolData.total;
      dispCompleted = toolData.completed;
    } else {
      dispScore = 0; dispMax = 0; dispPct = 0; dispTotal = 0; dispCompleted = 0;
    }
  } else {
    dispScore = scores.total_score;
    dispMax = scores.total_max;
    dispPct = scores.percentage;
    dispTotal = scores.total_actions;
    dispCompleted = scores.completed_actions;
  }

  // Build source filter options
  const sourceTools = Object.keys(scores.by_tool||{});
  const sourceOpts = [`<option value="">All Sources (Overall)</option>`].concat(
    sourceTools.map(s => `<option value="${s}" ${sf===s?'selected':''}>${s}</option>`)
  ).join('');

  // Tool gauge cards
  let toolCards = '';
  for(const [tool, d] of Object.entries(scores.by_tool||{})) {
    const isActive = sf === tool;
    toolCards += `<div class="card stat-card" style="${isActive?'border:2px solid var(--primary);':''}cursor:pointer" onclick="renderDashboard('${tool}')">
      <div class="card-header">${tool}</div>${gauge(d.percentage, 100)}
      <div class="label">${d.score}/${d.max_score} pts &middot; ${d.completed}/${d.total} actions</div>
    </div>`;
  }

  // Workload bars (filtered by source if selected)
  let wlBars = '';
  if(sf) {
    // Compute per-workload scores for filtered actions
    const wlMap = {};
    filteredActions.forEach(a => {
      if(!wlMap[a.workload]) wlMap[a.workload] = {score:0, max_score:0, total:0, completed:0};
      wlMap[a.workload].score += a.score||0;
      wlMap[a.workload].max_score += a.max_score||0;
      wlMap[a.workload].total++;
      if(a.status==='Completed') wlMap[a.workload].completed++;
    });
    for(const [wl, d] of Object.entries(wlMap)) {
      const pct = d.max_score > 0 ? (d.score/d.max_score*100) : 0;
      const color = pct >= 80 ? 'var(--success)' : pct >= 40 ? 'var(--warning)' : 'var(--danger)';
      wlBars += `<div class="mb-8"><div class="flex justify-between mb-8"><span style="font-size:13px">${wl}</span><span style="font-size:13px;font-weight:600">${pct.toFixed(2)}%</span></div>${progressBar(pct, color)}</div>`;
    }
  } else {
    for(const [wl, d] of Object.entries(scores.by_workload||{})) {
      const color = d.percentage >= 80 ? 'var(--success)' : d.percentage >= 40 ? 'var(--warning)' : 'var(--danger)';
      wlBars += `<div class="mb-8"><div class="flex justify-between mb-8"><span style="font-size:13px">${wl}</span><span style="font-size:13px;font-weight:600">${d.percentage.toFixed(2)}%</span></div>${progressBar(d.percentage, color)}</div>`;
    }
  }

  // Status pills (filtered)
  let statusPills = '';
  if(sf) {
    const stMap = {};
    filteredActions.forEach(a => { stMap[a.status] = (stMap[a.status]||0)+1; });
    for(const [s, n] of Object.entries(stMap)) statusPills += `${statusBadge(s)} <strong>${n}</strong>&nbsp;&nbsp;`;
  } else {
    for(const [s, n] of Object.entries(scores.by_status||{})) statusPills += `${statusBadge(s)} <strong>${n}</strong>&nbsp;&nbsp;`;
  }

  // Build lookup of full action objects for detail expansion
  const _allActionsMap = {};
  (allActions||[]).forEach(a => _allActionsMap[a.id] = a);

  let topActions = prioritized.filter(a => !sf || a.source_tool === sf).slice(0,10).map(a => {
    const full = _allActionsMap[a.id] || a;
    return `<tr onclick="toggleActionDetail('dash-${a.id}')" style="cursor:pointer">
    <td>${a.title}</td><td>${priorityBadge(a.priority)}</td><td>${statusBadge(a.status)}</td><td>${a.roi_score}</td>
    <td style="white-space:nowrap">
      <button class="btn btn-sm" onclick="unpinDashAction('${a.id}');event.stopPropagation()" title="${a.pinned_priority?'Unpin from dashboard':'Remove from list'}" style="padding:2px 6px;font-size:11px">${a.pinned_priority?'&#9733;':'&times;'}</button>
    </td>
  </tr>
  <tr id="detail-dash-${a.id}" class="hidden"><td colspan="5" style="padding:0">${actionDetailHtml(full)}</td></tr>`;
  }).join('');

  // Mini trend sparkline
  let trendHtml = '';
  if(snapshots.length >= 2) {
    const pts = snapshots.slice().reverse();
    const delta = pts[pts.length-1].percentage - pts[pts.length-2].percentage;
    const cls = delta > 0 ? 'drift-positive' : delta < 0 ? 'drift-negative' : 'drift-neutral';
    trendHtml = `<div class="card stat-card"><div class="value ${cls}">${delta>=0?'+':''}${delta.toFixed(2)}%</div><div class="label">Last Change</div><div style="margin-top:8px">${miniSparkline(pts.map(p=>p.percentage))}</div></div>`;
  } else {
    trendHtml = `<div class="card stat-card"><div class="value drift-neutral">--</div><div class="label">Last Change</div><div style="font-size:12px;color:var(--text-light);margin-top:8px">Import data twice to see trends</div></div>`;
  }

  // Risk summary alert
  let riskAlert = '';
  if(riskSummary.expired?.length > 0) {
    riskAlert = `<div class="drift-banner negative mb-16"><span style="font-size:20px">&#9888;</span><div><strong>${riskSummary.expired.length} expired risk acceptance(s)</strong> require review. <a href="#risks" style="text-decoration:underline">View Risk Register</a></div></div>`;
  }
  if(riskSummary.upcoming_reviews?.length > 0) {
    riskAlert += `<div class="drift-banner neutral mb-16"><span style="font-size:20px">&#128197;</span><div><strong>${riskSummary.upcoming_reviews.length} risk review(s)</strong> due within 30 days. <a href="#risks" style="text-decoration:underline">View</a></div></div>`;
  }

  const today = new Date().toLocaleDateString('en-US', {year:'numeric',month:'long',day:'numeric'});
  const scoreLabel = sf ? sf : 'Overall Security Score';
  const pointsLabel = dispScore != null && dispMax ? `${dispScore}/${dispMax} points` : scoreLabel;

  c.innerHTML = `${riskAlert}
    <div class="card mb-16" style="background:linear-gradient(135deg,#0f172a,#1e3a5f);color:#fff;padding:24px">
      <div class="flex justify-between items-center">
        <div>
          <div style="font-size:24px;font-weight:700">${displayName}</div>
          <div style="font-size:13px;opacity:.7;margin-top:4px">${state.activeTenant.tenant_id||'No Tenant ID'} &middot; ${today}</div>
        </div>
        <div style="text-align:right">
          <div style="font-size:42px;font-weight:800">${(dispPct||0).toFixed(2)}%</div>
          <div style="font-size:12px;opacity:.7">${pointsLabel}</div>
        </div>
      </div>
    </div>
    <div class="mb-16" style="display:flex;align-items:center;gap:12px">
      <label style="font-size:13px;font-weight:600;margin:0;width:auto">Score Source:</label>
      <select id="dash-source-filter" onchange="renderDashboard(this.value)" style="max-width:280px">${sourceOpts}</select>
      ${sf?`<button class="btn btn-sm" onclick="renderDashboard('')">Show All</button>`:''}
      ${sf==='SCuBA (CISA)'?`<button class="btn btn-sm" onclick="navigate('scuba')" style="margin-left:4px">SCuBA Dashboard</button>`:''}
      <label style="display:flex;align-items:center;gap:5px;font-size:12px;margin-left:auto;cursor:pointer" title="Exclude Not Applicable and Risk Accepted actions from score calculations">
        <input type="checkbox" id="dash-exclude-na" ${_dashExcludeNA?'checked':''} onchange="_dashExcludeNA=this.checked;_dashData={};renderDashboard(document.getElementById('dash-source-filter')?.value||'')">
        Exclude N/A &amp; Risk Accepted
      </label>
      ${scores.excluded_count?`<span style="font-size:11px;color:var(--text-light)">(${scores.excluded_count} excluded)</span>`:''}
    </div>
    <div id="dashboard-report">
    <div class="grid grid-4 mb-16">
      <div class="card stat-card"><div class="value">${(dispPct||0).toFixed(2)}%</div><div class="label">${sf?sf+' Score':'Overall Score'}</div></div>
      <div class="card stat-card"><div class="value">${dispTotal||0}</div><div class="label">Total Actions</div></div>
      <div class="card stat-card"><div class="value">${dispCompleted||0}</div><div class="label">Completed</div></div>
      ${trendHtml}
    </div>
    <div class="grid grid-2 mb-16">
      <div class="card"><div class="card-header">Score by Source Tool</div><div class="grid grid-2">${toolCards}</div></div>
      <div class="card"><div class="card-header">Score by Workload${sf?' ('+sf+')':''}</div>${wlBars||'<div style="color:var(--text-light);padding:8px">No workload data</div>'}</div>
    </div>
    <div class="card mb-16"><div class="card-header">Status Distribution${sf?' ('+sf+')':''}</div><div style="padding:8px">${statusPills||'No data'}</div></div>
    <div class="card"><div class="card-header">Top Priority Actions (by ROI) <button class="btn btn-sm" onclick="showPinActionModal()" style="font-size:11px">+ Add</button></div>
      <div class="table-wrap"><table><thead><tr><th>Title</th><th>Priority</th><th>Status</th><th>ROI</th><th style="width:40px"></th></tr></thead><tbody>${topActions||'<tr><td colspan="5" class="text-center">No pending actions</td></tr>'}</tbody></table></div>
    </div>
    </div>`;
}

async function switchTenantFromDashboard(name) {
  await api.post(`/api/tenants/${name}/activate`);
  const active = await api.get('/api/active-tenant');
  state.activeTenant = active && active.name ? active : null;
  state.tenants = await api.get('/api/tenants');
  updateTenantIndicator();
  renderDashboard();
}

function showDashboardCompare() {
  let checks = state.tenants.map(t => {
    return `<label style="display:flex;gap:10px;align-items:center;font-size:14px;padding:8px 0;cursor:pointer;border-bottom:1px solid var(--border)"><input type="checkbox" value="${t.name}" class="dash-cmp" ${t.is_active?'checked':''} style="width:18px;height:18px;flex-shrink:0"> <span>${t.display_name||t.name}</span></label>`;
  }).join('');
  openModal('Compare', `
    <div class="action-tabs" style="margin:0 0 16px">
      <div class="atab active" onclick="switchCmpTab('tenants',this)">Compare Tenants</div>
      <div class="atab" onclick="switchCmpTab('snapshot',this)">Compare with Snapshot</div>
    </div>
    <div id="cmp-tab-tenants">
      <p style="margin-bottom:12px;color:var(--text-light)">Select 2 or more tenants to compare side by side.</p>
      <div style="display:flex;flex-direction:column">${checks}</div>
    </div>
    <div id="cmp-tab-snapshot" class="hidden">
      <p style="margin-bottom:12px;color:var(--text-light)">Compare the current state of a tenant against a historical snapshot.</p>
      <div class="form-group"><label>Tenant</label><select id="snap-cmp-tenant">${state.tenants.map(t=>'<option value="'+t.name+'"'+(t.is_active?' selected':'')+'>'+( t.display_name||t.name)+'</option>').join('')}</select></div>
      <div class="form-group"><label>Snapshot</label><select id="snap-cmp-id"><option value="">Loading snapshots...</option></select></div>
    </div>`,
    `<button class="btn" onclick="closeModal()">Cancel</button>
     <button class="btn btn-primary" id="cmp-btn-tenants" onclick="doDashboardCompare()">Compare Tenants</button>
     <button class="btn btn-primary hidden" id="cmp-btn-snapshot" onclick="doSnapshotCompare()">Compare with Snapshot</button>`);
  // Trigger snapshot loading after modal is open
  setTimeout(()=>loadSnapshotsForCompare(), 50);
}

function switchCmpTab(tab, el) {
  el.parentElement.querySelectorAll('.atab').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');
  document.getElementById('cmp-tab-tenants').classList.toggle('hidden', tab!=='tenants');
  document.getElementById('cmp-tab-snapshot').classList.toggle('hidden', tab!=='snapshot');
  document.getElementById('cmp-btn-tenants').classList.toggle('hidden', tab!=='tenants');
  document.getElementById('cmp-btn-snapshot').classList.toggle('hidden', tab!=='snapshot');
}

async function loadSnapshotsForCompare() {
  const sel = document.getElementById('snap-cmp-tenant');
  const snapSel = document.getElementById('snap-cmp-id');
  if(!sel || !snapSel) return;

  async function refresh() {
    const name = sel.value;
    snapSel.innerHTML = '<option value="">Loading...</option>';
    const snaps = await api.get(`/api/tenants/${name}/snapshots?limit=50`);
    if(!snaps.length) {
      snapSel.innerHTML = '<option value="">No snapshots available</option>';
      return;
    }
    snapSel.innerHTML = snaps.map(s => {
      const dt = s.timestamp?.substring(0,16).replace('T',' ') || '';
      const trigger = s.trigger ? ' ('+s.trigger+')' : '';
      return `<option value="${s.id}">${dt}${trigger} — ${(s.percentage||0).toFixed(1)}%</option>`;
    }).join('');
  }

  sel.addEventListener('change', refresh);
  await refresh();
}

async function doSnapshotCompare() {
  const tenantName = document.getElementById('snap-cmp-tenant')?.value;
  const snapshotId = parseInt(document.getElementById('snap-cmp-id')?.value);
  if(!tenantName || !snapshotId) return toast('Select a tenant and snapshot','error');
  closeModal();
  document.getElementById('topbar-actions').innerHTML = '';

  const r = await api.post(`/api/tenants/${tenantName}/compare-snapshot`, {snapshot_id: snapshotId});
  const labels = r.labels || ['Current', 'Snapshot'];
  const c = document.getElementById('content');

  let rows = labels.map(l => {
    const d = r.overall[l]||{};
    const delta = l === labels[0] ? '' : (() => {
      const cur = r.overall[labels[0]]?.percentage||0;
      const snap = d.percentage||0;
      const diff = cur - snap;
      if(Math.abs(diff) < 0.01) return '';
      return diff > 0 ? ' <span style="color:var(--success);font-size:12px">&#9650; +'+diff.toFixed(1)+'%</span>'
                       : ' <span style="color:var(--danger);font-size:12px">&#9660; '+diff.toFixed(1)+'%</span>';
    })();
    return `<tr><td><strong>${l}</strong></td><td>${gauge(d.percentage||0,80)}${delta}</td><td>${d.total_actions||0}</td><td>${d.completed_actions||0}</td></tr>`;
  }).join('');

  let toolRows = Object.entries(r.by_tool||{}).map(([tool, data]) => {
    let cells = labels.map(l => {
      const pct = (data[l]?.percentage||0).toFixed(2);
      return `<td>${pct}%</td>`;
    }).join('');
    return `<tr><td>${tool}</td>${cells}</tr>`;
  }).join('');

  let wlRows = Object.entries(r.by_workload||{}).map(([wl, data]) => {
    let cells = labels.map(l => {
      const pct = (data[l]?.percentage||0).toFixed(2);
      return `<td>${pct}%</td>`;
    }).join('');
    return `<tr><td>${wl}</td>${cells}</tr>`;
  }).join('');

  const tenantDisplay = state.tenants.find(t=>t.name===tenantName)?.display_name || tenantName;

  // Action differences between current and snapshot
  const actionDiffs = r.action_diffs || [];
  const sameCount = r.actions_same || 0;
  let snapActionRows = actionDiffs.slice(0,200).map((a, idx) => {
    const snapCell = a.snapshot
      ? `<td>${statusBadge(a.snapshot.status)}</td>`
      : '<td style="color:var(--text-light);font-style:italic;font-size:12px">Did not exist</td>';
    const curCell = `<td><a href="#" onclick="toggleCompareActionDetail('${tenantName}','${a.current.id}','snap-detail-${idx}');event.preventDefault()" style="text-decoration:none;cursor:pointer" title="Click to view details">${statusBadge(a.current.status)}</a></td>`;
    return `<tr><td style="font-size:12px">${a.title}</td>${snapCell}${curCell}</tr>
      <tr id="snap-detail-${idx}" class="hidden"><td colspan="3" style="padding:0"><div id="snap-detail-content-${idx}" style="padding:12px;background:var(--bg-hover)"></div></td></tr>`;
  }).join('');

  c.innerHTML = `
    <div class="flex justify-between items-center mb-16">
      <h2 style="font-size:18px;font-weight:600">Snapshot Comparison: ${tenantDisplay}</h2>
      <div class="flex gap-8">
        <button class="btn btn-sm btn-primary" onclick="downloadComparisonPDF()">PDF Report</button>
        <button class="btn btn-sm" onclick="renderDashboard()">Back to Dashboard</button>
      </div>
    </div>
    <div id="comparison-report">
    <div class="card mb-16"><div class="card-header">Overall</div>
      <table><thead><tr><th>State</th><th>Score</th><th>Total</th><th>Completed</th></tr></thead><tbody>${rows}</tbody></table></div>
    <div class="grid grid-2 mb-16">
      <div class="card"><div class="card-header">By Source Tool</div>
        <table><thead><tr><th>Tool</th>${labels.map(l=>`<th>${l}</th>`).join('')}</tr></thead><tbody>${toolRows||'<tr><td colspan="99">No data</td></tr>'}</tbody></table></div>
      <div class="card"><div class="card-header">By Workload</div>
        <table><thead><tr><th>Workload</th>${labels.map(l=>`<th>${l}</th>`).join('')}</tr></thead><tbody>${wlRows||'<tr><td colspan="99">No data</td></tr>'}</tbody></table></div>
    </div>
    <div class="card mb-16">
      <div class="card-header">Action Changes <span class="badge badge-danger">${r.actions_differing||0} changed</span> <span class="badge badge-success">${sameCount} unchanged</span></div>
      <div style="font-size:13px;color:var(--text-light);margin-bottom:8px">Actions whose status changed since the snapshot, or new actions added after the snapshot. Click current status to view details.</div>
      ${snapActionRows ? `
        <div class="table-wrap" style="max-height:500px;overflow-y:auto">
          <table><thead><tr><th>Action</th><th>${labels[1]}</th><th>${labels[0]}</th></tr></thead>
          <tbody>${snapActionRows}</tbody></table>
        </div>` : '<div style="padding:20px;text-align:center;color:var(--text-light)">No changes found - all actions have the same status as the snapshot.</div>'}
    </div>
    </div>`;
}

async function doDashboardCompare() {
  const tenants = [...document.querySelectorAll('.dash-cmp:checked')].map(c=>c.value);
  if(tenants.length < 2) return toast('Select at least 2 tenants','error');
  closeModal();
  // Hide dashboard topbar buttons during comparison
  document.getElementById('topbar-actions').innerHTML = '';
  const [r, actionCmp] = await Promise.all([
    api.post('/api/compare', {tenants}),
    api.post('/api/compare-actions', {tenants})
  ]);
  const c = document.getElementById('content');

  let rows = tenants.map(t => {
    const d = r.overall[t]||{};
    return `<tr><td><strong>${t}</strong></td><td>${gauge(d.percentage||0,80)}</td><td>${d.total_actions||0}</td><td>${d.completed_actions||0}</td></tr>`;
  }).join('');

  let toolRows = Object.entries(r.by_tool||{}).map(([tool, data]) => {
    let cells = tenants.map(t => `<td>${(data[t]?.percentage||0).toFixed(2)}%</td>`).join('');
    return `<tr><td>${tool}</td>${cells}</tr>`;
  }).join('');

  let wlRows = Object.entries(r.by_workload||{}).map(([wl, data]) => {
    let cells = tenants.map(t => `<td>${(data[t]?.percentage||0).toFixed(2)}%</td>`).join('');
    return `<tr><td>${wl}</td>${cells}</tr>`;
  }).join('');

  // Action-level comparison
  const diffActions = (actionCmp.actions||[]).filter(a => a.differs);
  const sameActions = (actionCmp.actions||[]).filter(a => !a.differs);
  let actionDiffRows = diffActions.slice(0,100).map((a, idx) => {
    let cells = tenants.map(t => {
      const d = a.tenants[t];
      if(!d) return '<td style="color:var(--text-light);font-style:italic;font-size:12px">Missing</td>';
      return `<td><a href="#" onclick="toggleCompareActionDetail('${t}','${d.id}','cmp-detail-${idx}');event.preventDefault()" style="text-decoration:none;cursor:pointer" title="Click to view details for ${t}">${statusBadge(d.status)}</a></td>`;
    }).join('');
    return `<tr><td style="font-size:12px">${a.title}</td>${cells}</tr>
      <tr id="cmp-detail-${idx}" class="hidden"><td colspan="${tenants.length+1}" style="padding:0"><div id="cmp-detail-content-${idx}" style="padding:12px;background:var(--bg-hover)"></div></td></tr>`;
  }).join('');

  c.innerHTML = `
    <div class="flex justify-between items-center mb-16">
      <h2 style="font-size:18px;font-weight:600">Tenant Comparison</h2>
      <div class="flex gap-8">
        <button class="btn btn-sm btn-primary" onclick="downloadComparisonPDF()">PDF Report</button>
        <button class="btn btn-sm" onclick="renderDashboard()">Back to Dashboard</button>
      </div>
    </div>
    <div id="comparison-report">
    <div class="card mb-16"><div class="card-header">Overall</div>
      <table><thead><tr><th>Tenant</th><th>Score</th><th>Total</th><th>Completed</th></tr></thead><tbody>${rows}</tbody></table></div>
    <div class="grid grid-2 mb-16">
      <div class="card"><div class="card-header">By Source Tool</div>
        <table><thead><tr><th>Tool</th>${tenants.map(t=>`<th>${t}</th>`).join('')}</tr></thead><tbody>${toolRows||'<tr><td colspan="99">No data</td></tr>'}</tbody></table></div>
      <div class="card"><div class="card-header">By Workload</div>
        <table><thead><tr><th>Workload</th>${tenants.map(t=>`<th>${t}</th>`).join('')}</tr></thead><tbody>${wlRows||'<tr><td colspan="99">No data</td></tr>'}</tbody></table></div>
    </div>
    <div class="card mb-16">
      <div class="card-header">Action Differences <span class="badge badge-danger">${actionCmp.differing||0} differ</span> <span class="badge badge-success">${sameActions.length} same</span></div>
      <div style="font-size:13px;color:var(--text-light);margin-bottom:8px">Actions where status differs between tenants, or action exists in one but not the other.</div>
      ${actionDiffRows ? `
        <div class="table-wrap" style="max-height:500px;overflow-y:auto">
          <table><thead><tr><th>Action</th>${tenants.map(t=>`<th>${t}</th>`).join('')}</tr></thead>
          <tbody>${actionDiffRows}</tbody></table>
        </div>` : '<div style="padding:20px;text-align:center;color:var(--text-light)">No differences found - all actions have the same status across tenants.</div>'}
    </div>
    </div>`;
}

function downloadComparisonPDF() {
  const today = new Date().toLocaleDateString('en-US', {year:'numeric',month:'long',day:'numeric'});
  const reportEl = document.getElementById('comparison-report');
  if(!reportEl) { toast('Comparison not loaded','error'); return; }

  const printWin = window.open('','_blank','width=900,height=700');
  printWin.document.write(`<!DOCTYPE html><html><head><title>Tenant Comparison Report</title>
    <style>
      * { margin:0; padding:0; box-sizing:border-box; }
      body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; color:#1e293b; padding:40px; font-size:13px; }
      .report-header { text-align:center; margin-bottom:32px; padding-bottom:24px; border-bottom:3px solid #3b82f6; }
      .report-header h1 { font-size:24px; color:#0f172a; }
      .report-header .subtitle { color:#64748b; font-size:13px; margin-top:8px; }
      .card { background:#fff; border:1px solid #e2e8f0; border-radius:8px; padding:16px; margin-bottom:16px; break-inside:avoid; }
      .card-header { font-size:14px; font-weight:600; margin-bottom:12px; }
      .grid-2 { display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:16px; }
      table { width:100%; border-collapse:collapse; font-size:12px; }
      th { text-align:left; padding:6px 8px; background:#f1f5f9; border-bottom:2px solid #e2e8f0; font-size:11px; text-transform:uppercase; }
      td { padding:6px 8px; border-bottom:1px solid #e2e8f0; }
      .badge { display:inline-block; padding:2px 8px; border-radius:4px; font-size:10px; font-weight:600; }
      .badge-success { background:#d1fae5; color:#065f46; }
      .badge-warning { background:#fef3c7; color:#92400e; }
      .badge-danger { background:#fee2e2; color:#991b1b; }
      .badge-info { background:#dbeafe; color:#1e40af; }
      .badge-purple { background:#ede9fe; color:#5b21b6; }
      .badge-gray { background:#f1f5f9; color:#475569; }
      .gauge svg { transform:rotate(-90deg); }
      .gauge .track { fill:none; stroke:#e2e8f0; stroke-width:10; }
      .gauge .fill { fill:none; stroke-width:10; stroke-linecap:round; }
      .gauge { position:relative; width:80px; height:80px; display:inline-block; }
      .gauge .pct { position:absolute; inset:0; display:flex; flex-direction:column; align-items:center; justify-content:center; font-size:16px; font-weight:700; }
      a { color:inherit; text-decoration:none; }
      .table-wrap { max-height:none !important; overflow:visible !important; }
      .mb-16 { margin-bottom:16px; }
      .footer { text-align:center; margin-top:32px; padding-top:16px; border-top:1px solid #e2e8f0; color:#64748b; font-size:11px; }
      @media print { body { padding:20px; } }
    </style></head><body>
    <div class="report-header">
      <h1>Tenant Comparison Report</h1>
      <div class="subtitle">${today}</div>
    </div>
    ${reportEl.innerHTML}
    <div class="footer">Generated by M365 Security Posture Manager &middot; ${today}</div>
    <scr`+`ipt>setTimeout(()=>{window.print();},400);<\/scr`+`ipt>
  </body></html>`);
  printWin.document.close();
}

let _cmpExpandedRow = null;
async function toggleCompareActionDetail(tenantName, actionId, rowId) {
  const row = document.getElementById(rowId);
  const contentEl = document.getElementById(rowId.replace('cmp-detail-','cmp-detail-content-').replace('snap-detail-','snap-detail-content-'));
  if(!row || !contentEl) return;

  // Collapse previously expanded row
  if(_cmpExpandedRow && _cmpExpandedRow !== rowId) {
    document.getElementById(_cmpExpandedRow)?.classList.add('hidden');
  }

  // Toggle this row - collapse if same tenant already shown
  if(!row.classList.contains('hidden') && contentEl.dataset.loadedTenant === tenantName) {
    row.classList.add('hidden');
    _cmpExpandedRow = null;
    return;
  }

  contentEl.innerHTML = '<div style="padding:16px;text-align:center;color:var(--text-light)">Loading action details...</div>';
  row.classList.remove('hidden');
  _cmpExpandedRow = rowId;

  try {
    const a = await api.get(`/api/actions/${actionId}`);
    contentEl.dataset.loadedTenant = tenantName;

    // Reuse the full action detail panel with all tabs (General, Implementation, Notes, History)
    contentEl.innerHTML = `
      <div style="padding:8px 0 4px;margin-bottom:4px;border-bottom:1px solid var(--border)">
        <span class="badge badge-info" style="font-size:12px">${tenantName}</span>
        <strong style="font-size:14px;margin-left:8px">${a.title}</strong>
      </div>
      ${actionDetailHtml(a)}`;
    // Load dependencies for this action
    loadActionDeps(actionId);
  } catch(e) {
    contentEl.innerHTML = '<div style="padding:16px;color:var(--danger)">Failed to load action details.</div>';
  }
}

// ── PDF Report Download ──
function downloadDashboardPDF() {
  const displayName = state.activeTenant?.display_name || state.activeTenant?.name || 'Unknown';
  const today = new Date().toLocaleDateString('en-US', {year:'numeric',month:'long',day:'numeric'});
  // Use print-specific styling to generate a clean PDF via browser print dialog
  const reportEl = document.getElementById('dashboard-report');
  if(!reportEl) { toast('Dashboard not loaded','error'); return; }

  const printWin = window.open('','_blank','width=900,height=700');
  printWin.document.write(`<!DOCTYPE html><html><head><title>Security Posture Report - ${displayName}</title>
    <style>
      * { margin:0; padding:0; box-sizing:border-box; }
      body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; color:#1e293b; padding:40px; }
      .report-header { text-align:center; margin-bottom:32px; padding-bottom:24px; border-bottom:3px solid #3b82f6; }
      .report-header h1 { font-size:28px; color:#0f172a; }
      .report-header .subtitle { color:#64748b; font-size:14px; margin-top:8px; }
      .report-header .score { font-size:56px; font-weight:800; color:#3b82f6; margin-top:16px; }
      .card { background:#fff; border:1px solid #e2e8f0; border-radius:8px; padding:16px; margin-bottom:16px; break-inside:avoid; }
      .card-header { font-size:14px; font-weight:600; margin-bottom:12px; }
      .grid { display:grid; gap:12px; }
      .grid-2 { grid-template-columns:1fr 1fr; }
      .grid-4 { grid-template-columns:1fr 1fr 1fr 1fr; }
      .stat-card { text-align:center; padding:16px; }
      .stat-card .value { font-size:28px; font-weight:700; color:#3b82f6; }
      .stat-card .label { font-size:12px; color:#64748b; margin-top:4px; }
      table { width:100%; border-collapse:collapse; font-size:12px; }
      th { text-align:left; padding:8px; background:#f1f5f9; border-bottom:2px solid #e2e8f0; font-size:11px; text-transform:uppercase; }
      td { padding:8px; border-bottom:1px solid #e2e8f0; }
      .badge { display:inline-block; padding:2px 8px; border-radius:4px; font-size:10px; font-weight:600; }
      .badge-success { background:#d1fae5; color:#065f46; }
      .badge-warning { background:#fef3c7; color:#92400e; }
      .badge-danger { background:#fee2e2; color:#991b1b; }
      .badge-info { background:#dbeafe; color:#1e40af; }
      .badge-purple { background:#ede9fe; color:#5b21b6; }
      .badge-gray { background:#f1f5f9; color:#475569; }
      .progress { height:8px; background:#e2e8f0; border-radius:4px; overflow:hidden; }
      .progress .bar { height:100%; border-radius:4px; }
      .gauge svg { transform:rotate(-90deg); }
      .gauge .track { fill:none; stroke:#e2e8f0; stroke-width:10; }
      .gauge .fill { fill:none; stroke-width:10; stroke-linecap:round; }
      .gauge { position:relative; width:100px; height:100px; display:inline-block; }
      .gauge .pct { position:absolute; inset:0; display:flex; flex-direction:column; align-items:center; justify-content:center; font-size:18px; font-weight:700; }
      .footer { text-align:center; margin-top:32px; padding-top:16px; border-top:1px solid #e2e8f0; color:#64748b; font-size:11px; }
      @media print { body { padding:20px; } .report-header { margin-bottom:20px; padding-bottom:16px; } }
    </style></head><body>
    <div class="report-header">
      <h1>M365 Security Posture Report</h1>
      <div class="subtitle">${displayName} &middot; ${today}</div>
    </div>
    ${reportEl.innerHTML}
    <div class="footer">Generated by M365 Security Posture Manager &middot; ${today}</div>
    <scr`+`ipt>setTimeout(()=>{window.print();},400);<\/scr`+`ipt>
  </body></html>`);
  printWin.document.close();
}

async function unpinDashAction(actionId) {
  // Set to -1 to explicitly hide from dashboard priority list
  await api.put(`/api/actions/${actionId}`, {pinned_priority: -1});
  _dashData = {};
  renderDashboard(document.getElementById('dash-source-filter')?.value||'');
}

async function showPinActionModal() {
  const t = state.activeTenant.name;
  const actions = await api.get(`/api/tenants/${t}/actions`);
  const pending = actions.filter(a => !['Completed','Not Applicable','Third Party'].includes(a.status) && !a.pinned_priority);
  let rows = pending.slice(0,50).map(a => `<tr>
    <td><input type="checkbox" value="${a.id}" class="pin-cb"></td>
    <td>${a.title.substring(0,50)}</td><td>${priorityBadge(a.priority)}</td><td>${statusBadge(a.status)}</td>
  </tr>`).join('');
  openModal('Pin Actions to Dashboard', `
    <div style="font-size:13px;color:var(--text-light);margin-bottom:8px">Select actions to pin to the Top Priority list.</div>
    <div style="max-height:400px;overflow-y:auto">
      <table><thead><tr><th><input type="checkbox" onchange="document.querySelectorAll('.pin-cb').forEach(c=>c.checked=this.checked)"></th><th>Title</th><th>Priority</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table>
    </div>`,
    '<button class="btn" onclick="closeModal()">Cancel</button><button class="btn btn-primary" onclick="pinSelectedActions()">Pin Selected</button>');
}

async function pinSelectedActions() {
  const ids = [...document.querySelectorAll('.pin-cb:checked')].map(c=>c.value);
  if(!ids.length) return toast('Select at least one action','error');
  for(const id of ids) await api.post(`/api/actions/${id}/pin`);
  closeModal();
  toast(ids.length + ' action(s) pinned','success');
  _dashData = {};
  renderDashboard(document.getElementById('dash-source-filter')?.value||'');
}

// ── Tenants ──
async function renderTenants() {
  state.tenants = await api.get('/api/tenants');
  const active = await api.get('/api/active-tenant');
  state.activeTenant = active && active.name ? active : null;
  updateTenantIndicator();

  document.getElementById('topbar-actions').innerHTML = '<button class="btn btn-primary" onclick="showAddTenant()">+ Add Tenant</button>';

  let cards = state.tenants.map(t => `
    <div class="card" style="${t.is_active?'border-left:4px solid var(--primary)':''}">
      <div class="card-header">${t.display_name||t.name} ${t.is_active?'<span class="badge badge-info">Active</span>':''}</div>
      <div style="font-size:13px;color:var(--text-light);margin-bottom:8px">${t.tenant_id||'No tenant ID'}</div>
      <div style="font-size:14px;margin-bottom:12px">${t.action_count||0} actions</div>
      <div class="btn-group">
        ${!t.is_active?`<button class="btn btn-sm btn-primary" onclick="activateTenant('${t.name}')">Activate</button>`:''}
        <button class="btn btn-sm" onclick="showEditTenant('${t.name}')">Edit</button>
        <button class="btn btn-sm btn-danger" onclick="deleteTenant('${t.name}')">Delete</button>
      </div>
    </div>`).join('');

  // Migration status
  const migStatus = await api.get('/api/admin/migration-status');
  const migHtml = migStatus.migrated
    ? `<div style="color:var(--success);font-size:13px">&#10003; Migrated to per-tenant databases on ${migStatus.migrated_at?.substring(0,10)}<br><span style="color:var(--text-light)">${migStatus.tenant_db_count} tenant database(s): ${(migStatus.tenants||[]).join(', ')}</span></div>`
    : `<div style="font-size:13px;color:var(--text-light);margin-bottom:8px">Currently using a single database for all tenants. Migrating to per-tenant databases improves isolation, performance, and prepares for encryption.</div>
       <button class="btn btn-sm btn-primary" onclick="migrateDatabase()">Migrate to Per-Tenant Databases</button>
       <div id="migration-result" style="margin-top:8px"></div>`;

  document.getElementById('content').innerHTML = (cards ? `<div class="grid grid-3">${cards}</div>` : '<div class="card text-center" style="padding:60px"><h3>No tenants yet</h3><p style="color:var(--text-light);margin:12px 0">Add your first tenant to get started</p><button class="btn btn-primary" onclick="showAddTenant()">+ Add Tenant</button></div>')
    + `<div class="card mt-16"><div class="card-header">Database Administration</div>${migHtml}</div>`;
}

async function migrateDatabase() {
  if(!confirm('This will migrate to per-tenant databases. The original database will be backed up. Continue?')) return;
  const el = document.getElementById('migration-result');
  el.innerHTML = '<div style="color:var(--text-light)">Migrating... this may take a moment.</div>';
  const r = await api.post('/api/admin/migrate-database');
  if(r.error) {
    el.innerHTML = `<div style="color:var(--danger)">${r.error}</div>`;
    return;
  }
  if(r.success) {
    let details = Object.entries(r.tenants||{}).map(([t,d]) =>
      `<div style="font-size:12px;padding:2px 0"><strong>${t}</strong>: ${d.actions||0} actions, ${d.plans||0} plans, ${d.snapshots||0} snapshots</div>`
    ).join('');
    el.innerHTML = `<div style="color:var(--success);font-weight:600">&#10003; Migration complete!</div>
      <div style="font-size:12px;color:var(--text-light)">Backup saved to: ${r.backup}</div>
      ${details}
      <div style="font-size:12px;color:var(--warning);margin-top:8px">Restart the application to use per-tenant databases.</div>`;
  }
}

function showAddTenant() {
  openModal('Add Tenant', `
    <div class="form-group"><label>Name (short, no spaces)</label><input id="t-name" placeholder="contoso"></div>
    <div class="form-group"><label>Display Name</label><input id="t-display" placeholder="Contoso Ltd"></div>
    <div class="form-group"><label>Azure AD Tenant ID</label><input id="t-tid" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"></div>
    <div class="form-group"><label>Client ID (optional)</label><input id="t-cid"></div>
    <div class="form-group"><label>Client Secret (optional)</label><input id="t-secret" type="password"></div>
    <div class="form-group"><label>Notes</label><textarea id="t-notes" rows="2"></textarea></div>`,
    '<button class="btn" onclick="closeModal()">Cancel</button><button class="btn btn-primary" onclick="addTenant()">Add Tenant</button>');
}

async function addTenant() {
  const data = {name:document.getElementById('t-name').value.trim(), display_name:document.getElementById('t-display').value.trim(), tenant_id:document.getElementById('t-tid').value.trim(), client_id:document.getElementById('t-cid').value.trim(), client_secret:document.getElementById('t-secret').value.trim(), notes:document.getElementById('t-notes').value.trim()};
  if(!data.name) return toast('Name is required','error');
  const r = await api.post('/api/tenants', data);
  if(r.error) return toast(r.error,'error');
  closeModal(); toast('Tenant added','success'); renderTenants();
}

async function showEditTenant(name) {
  const t = await api.get(`/api/tenants/${name}`);
  openModal('Edit Tenant: '+name, `
    <div class="form-group"><label>Display Name</label><input id="te-display" value="${t.display_name||''}"></div>
    <div class="form-group"><label>Azure AD Tenant ID</label><input id="te-tid" value="${t.tenant_id||''}"></div>
    <div class="form-group"><label>Client ID</label><input id="te-cid" value="${t.client_id||''}"></div>
    <div class="form-group"><label>Client Secret</label><input id="te-secret" type="password" value="${t.client_secret||''}"></div>
    <div class="form-group"><label>Notes</label><textarea id="te-notes" rows="2">${t.notes||''}</textarea></div>`,
    `<button class="btn" onclick="closeModal()">Cancel</button><button class="btn btn-primary" onclick="updateTenant('${name}')">Save</button>`);
}

async function updateTenant(name) {
  const data = {display_name:document.getElementById('te-display').value.trim(), tenant_id:document.getElementById('te-tid').value.trim(), client_id:document.getElementById('te-cid').value.trim(), client_secret:document.getElementById('te-secret').value.trim(), notes:document.getElementById('te-notes').value.trim()};
  await api.put(`/api/tenants/${name}`, data);
  closeModal(); toast('Tenant updated','success'); renderTenants();
}

async function activateTenant(name) {
  await api.post(`/api/tenants/${name}/activate`);
  state.activeTenant = await api.get('/api/active-tenant');
  updateTenantIndicator();
  toast('Switched to '+name,'success');
  renderTenants();
}

async function deleteTenant(name) {
  if(!confirm(`Delete tenant "${name}" and all its data?`)) return;
  await api.del(`/api/tenants/${name}`);
  state.activeTenant = await api.get('/api/active-tenant');
  updateTenantIndicator();
  toast('Tenant deleted','success');
  renderTenants();
}

// ── Actions ──
let actionsSort = {col:'priority', dir:1};
let expandedAction = null;

async function renderActions() {
  if(!requireTenant()) return;
  const t = state.activeTenant.name;
  document.getElementById('topbar-actions').innerHTML = '<button class="btn btn-primary" onclick="showAddAction()">+ Add Action</button>';

  const c = document.getElementById('content');
  c.innerHTML = `
    <div class="filter-bar">
      <input type="text" id="f-search" placeholder="Search actions..." oninput="filterActions()">
      <select id="f-status" onchange="filterActions()"><option value="">All Statuses</option>${selectOptions(state.enums.statuses)}</select>
      <select id="f-workload" onchange="filterActions()"><option value="">All Workloads</option>${selectOptions(state.enums.workloads)}</select>
      <select id="f-source" onchange="filterActions()"><option value="">All Sources</option>${selectOptions(state.enums.source_tools)}</select>
      <select id="f-priority" onchange="filterActions()"><option value="">All Priorities</option>${selectOptions(state.enums.priorities)}</select>
      <select id="f-freshness" onchange="filterActions()"><option value="">All Items</option><option value="new-7d">New (last 7 days)</option><option value="new-30d">New (last 30 days)</option><option value="stale-30d">Stale (not seen 30d+)</option><option value="stale-90d">Stale (not seen 90d+)</option><option value="never-imported">Never in a report</option></select>
    </div>
    <div class="filter-bar" id="zt-filters" style="display:none;margin-top:-8px;padding-top:0">
      <select id="f-pillar" onchange="applyZtFilters()"><option value="">All Pillars</option><option value="Identity">Identity</option><option value="Devices">Devices</option></select>
      <select id="f-zt-status" onchange="applyZtFilters()"><option value="">All ZT Statuses</option><option value="Failed">Failed</option><option value="Passed">Passed</option><option value="Investigate">Investigate</option><option value="Planned">Planned</option><option value="Skipped">Skipped</option></select>
      <select id="f-sfi" onchange="applyZtFilters()"><option value="">All SFI Pillars</option></select>
    </div>
    <div class="card"><div class="table-wrap" id="actions-table"></div></div>`;
  await filterActions();
}

let _actionPlanMap = {};

async function filterActions() {
  const t = state.activeTenant.name;
  const params = new URLSearchParams();
  const s = document.getElementById('f-search')?.value; if(s) params.set('search', s);
  const st = document.getElementById('f-status')?.value; if(st) params.set('status', st);
  const wl = document.getElementById('f-workload')?.value; if(wl) params.set('workload', wl);
  const src = document.getElementById('f-source')?.value; if(src) params.set('source_tool', src);
  const pr = document.getElementById('f-priority')?.value; if(pr) params.set('priority', pr);

  const [actions, planMap] = await Promise.all([
    api.get(`/api/tenants/${t}/actions?${params}`),
    api.get(`/api/tenants/${t}/action-plans`)
  ]);
  _actionPlanMap = planMap || {};

  // Show ZT filter row if ZT Report actions exist
  const hasZT = actions.some(a => a.source_tool === 'Zero Trust Report');
  const ztFilters = document.getElementById('zt-filters');
  if(ztFilters) {
    ztFilters.style.display = hasZT ? 'flex' : 'none';
    if(hasZT) {
      // Populate SFI pillar options dynamically
      const sfiEl = document.getElementById('f-sfi');
      const currentSfi = sfiEl?.value || '';
      const sfiValues = [...new Set(actions.filter(a=>a.subcategory).map(a=>a.subcategory))].sort();
      sfiEl.innerHTML = '<option value="">All SFI Pillars</option>' + sfiValues.map(v => `<option value="${v}"${v===currentSfi?' selected':''}>${v}</option>`).join('');
    }
  }

  _allFetchedActions = actions;
  applyZtFilters();
}

let _allFetchedActions = [];
function applyZtFilters() {
  let actions = _allFetchedActions;
  const pillar = document.getElementById('f-pillar')?.value;
  const ztStatus = document.getElementById('f-zt-status')?.value;
  const sfi = document.getElementById('f-sfi')?.value;
  const freshness = document.getElementById('f-freshness')?.value;

  if(pillar) actions = actions.filter(a => (a.tags||[]).some(t => t === 'Pillar: '+pillar));
  if(ztStatus) actions = actions.filter(a => (a.tags||[]).some(t => t === 'ZT: '+ztStatus));
  if(sfi) actions = actions.filter(a => a.subcategory === sfi);

  // Freshness filter based on created_at and last_seen_in_report
  if(freshness) {
    const now = new Date();
    if(freshness === 'new-7d') {
      const cutoff = new Date(now - 7*86400000).toISOString();
      actions = actions.filter(a => a.created_at && a.created_at >= cutoff);
    } else if(freshness === 'new-30d') {
      const cutoff = new Date(now - 30*86400000).toISOString();
      actions = actions.filter(a => a.created_at && a.created_at >= cutoff);
    } else if(freshness === 'stale-30d') {
      const cutoff = new Date(now - 30*86400000).toISOString();
      actions = actions.filter(a => a.last_seen_in_report && a.last_seen_in_report < cutoff);
    } else if(freshness === 'stale-90d') {
      const cutoff = new Date(now - 90*86400000).toISOString();
      actions = actions.filter(a => a.last_seen_in_report && a.last_seen_in_report < cutoff);
    } else if(freshness === 'never-imported') {
      actions = actions.filter(a => !a.last_seen_in_report);
    }
  }

  renderActionsTable(actions);
}

let _actionsData = [];
let _actionsSortCol = null;
let _actionsSortDir = 'asc';

function renderActionsTable(actions) {
  _actionsData = actions;
  _actionsSortCol = null;
  _actionsSortDir = 'asc';
  _renderActionsTableSorted();
}

function sortActionsBy(colIdx) {
  if(_actionsSortCol === colIdx) {
    _actionsSortDir = _actionsSortDir === 'asc' ? 'desc' : 'asc';
  } else {
    _actionsSortCol = colIdx;
    _actionsSortDir = 'asc';
  }
  // Sort keys by column index (matching header order: checkbox,ID,Ref,Title,Status,Priority,Workload,Source,Score,Plan)
  const keys = [null,'id','reference_id','title','status','priority','workload','source_tool','_score','_plan'];
  const key = keys[colIdx];
  if(!key) return;
  const sorted = [..._actionsData].sort((a,b) => {
    let aVal, bVal;
    if(key === '_score') {
      aVal = a.score != null ? a.score : -1;
      bVal = b.score != null ? b.score : -1;
    } else if(key === '_plan') {
      aVal = (_actionPlanMap[a.id]||[]).length;
      bVal = (_actionPlanMap[b.id]||[]).length;
    } else if(key === 'reference_id') {
      aVal = (a[key]||'').toString().toLowerCase();
      bVal = (b[key]||'').toString().toLowerCase();
    } else {
      aVal = (a[key]||'').toString().toLowerCase();
      bVal = (b[key]||'').toString().toLowerCase();
    }
    if(typeof aVal === 'number') return _actionsSortDir === 'asc' ? aVal - bVal : bVal - aVal;
    return _actionsSortDir === 'asc' ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
  });
  _actionsData = sorted;
  _renderActionsTableSorted();
}

function _renderActionsTableSorted() {
  const actions = _actionsData;
  const el = document.getElementById('actions-table');
  if(!actions.length) { el.innerHTML = '<div class="text-center" style="padding:40px;color:var(--text-light)">No actions found</div>'; return; }

  let rows = actions.map(a => {
    const scoreDisplay = a.score != null && a.max_score != null ? `${a.score}/${a.max_score}` : '-';
    const plans = _actionPlanMap[a.id] || [];
    const planBadge = plans.length ? `<span class="badge badge-info" title="${plans.map(p=>p.plan_name).join(', ')}" style="font-size:10px;cursor:help">&#128203; ${plans.length}</span>` : '<span style="color:var(--text-light);font-size:11px">—</span>';
    return `
    <tr onclick="toggleActionDetail('${a.id}')" style="cursor:pointer" id="row-${a.id}">
      <td onclick="event.stopPropagation()"><input type="checkbox" class="action-cb" value="${a.id}"></td>
      <td><code style="font-size:11px">${a.id}</code></td>
      <td style="font-size:12px"><code>${a.reference_id||'-'}</code></td>
      <td style="max-width:300px">${a.title.substring(0,70)}${a.correlation_group_id?'<span class="corr-badge" title="Correlated">&#128279;</span>':''}</td>
      <td>${statusBadge(a.status)}</td>
      <td>${priorityBadge(a.priority)}</td>
      <td style="font-size:12px">${a.workload}</td>
      <td style="font-size:12px">${a.source_tool}</td>
      <td>${scoreDisplay}</td>
      <td>${planBadge}</td>
    </tr>
    <tr id="detail-${a.id}" class="hidden"><td colspan="10" style="padding:0">${actionDetailHtml(a)}</td></tr>`;
  }).join('');

  // Build sort indicators for headers
  const cols = ['','ID','Ref','Title','Status','Priority','Workload','Source','Score','Plan'];
  const headers = cols.map((c,i) => {
    if(i===0) return '<th onclick="event.stopPropagation()"><input type="checkbox" id="select-all-actions" onchange="toggleSelectAllActions(this)"></th>';
    const arrow = _actionsSortCol===i ? (_actionsSortDir==='asc'?' ▲':' ▼') : '';
    return `<th style="cursor:pointer;user-select:none;white-space:nowrap" onclick="event.stopPropagation();sortActionsBy(${i})">${c}${arrow}</th>`;
  }).join('');

  el.innerHTML = `<div id="batch-actions" style="display:none;padding:8px 0;margin-bottom:8px;gap:8px">
    <button class="btn btn-primary btn-sm" onclick="showAddToPlan()">Add to Plan</button>
    <button class="btn btn-sm" onclick="showBatchStatus()">Set Status</button>
    <button class="btn btn-danger btn-sm" onclick="batchDeleteActions()">Delete Selected</button>
    <span id="batch-count" style="font-size:12px;color:var(--text-light);margin-left:8px"></span>
  </div>
  <table><thead><tr>${headers}</tr></thead><tbody>${rows}</tbody></table>
    <div style="padding:8px;font-size:12px;color:var(--text-light)">${actions.length} actions</div>`;

  // Wire up checkbox change listeners
  el.querySelectorAll('.action-cb').forEach(cb => cb.addEventListener('change', updateBatchBar));
}

function toggleSelectAllActions(master) {
  document.querySelectorAll('.action-cb').forEach(cb => cb.checked = master.checked);
  updateBatchBar();
}

function updateBatchBar() {
  const checked = document.querySelectorAll('.action-cb:checked');
  const bar = document.getElementById('batch-actions');
  const count = document.getElementById('batch-count');
  if(checked.length > 0) {
    bar.style.display = 'flex';
    bar.style.alignItems = 'center';
    count.textContent = checked.length + ' selected';
  } else {
    bar.style.display = 'none';
  }
}

async function batchDeleteActions() {
  const ids = Array.from(document.querySelectorAll('.action-cb:checked')).map(cb => cb.value);
  if(!ids.length) return;
  if(!confirm('Delete ' + ids.length + ' selected actions?')) return;
  const r = await api.post('/api/actions/batch-delete', {action_ids: ids});
  if(r.error) return toast(r.error, 'error');
  toast(r.deleted + ' actions deleted', 'success');
  filterActions();
}

function showBatchStatus() {
  const ids = Array.from(document.querySelectorAll('.action-cb:checked')).map(cb => cb.value);
  if(!ids.length) return toast('No actions selected','error');
  const opts = state.enums.statuses.map(s => `<option value="${s}">${s}</option>`).join('');
  openModal(`Set Status for ${ids.length} Action(s)`, `
    <div class="form-group"><label>New Status</label><select id="batch-status-val">${opts}</select></div>
    <div class="form-group"><label>Changed By</label><input id="batch-status-by" placeholder="Your name"></div>`,
    `<button class="btn" onclick="closeModal()">Cancel</button><button class="btn btn-primary" onclick="submitBatchStatus()">Apply</button>`);
  window._batchStatusIds = ids;
}

async function submitBatchStatus() {
  const status = document.getElementById('batch-status-val').value;
  const changed_by = document.getElementById('batch-status-by').value;
  const r = await api.post('/api/actions/batch-status', {action_ids:window._batchStatusIds, status, changed_by});
  if(r.error) return toast(r.error,'error');
  closeModal();
  toast(r.updated + ' actions updated to ' + status, 'success');
  filterActions();
}

let _addToPlanIds = [];

async function showAddToPlan(actionIds) {
  if(!actionIds) {
    actionIds = Array.from(document.querySelectorAll('.action-cb:checked')).map(cb => cb.value);
  }
  if(!actionIds.length) return toast('No actions selected', 'error');
  _addToPlanIds = actionIds;

  const t = state.activeTenant.name;
  const plans = await api.get(`/api/tenants/${t}/plans`);
  const hasPlans = plans.length > 0;

  // Store plan existing items for dedup at submit time
  const planData = [];
  for(const p of plans) {
    try {
      const full = await api.get(`/api/plans/${p.id}`);
      planData.push({...p, existingActionIds: (full?.items||[]).map(i => i.action_id)});
    } catch(e) {
      planData.push({...p, existingActionIds: []});
    }
  }
  window._atpPlanData = planData;

  let planOptions = planData.map(p => {
    const dupes = _addToPlanIds.filter(id => p.existingActionIds.includes(id)).length;
    const dupeNote = dupes ? ` - ${dupes} already in plan` : '';
    return `<option value="${p.id}">${p.name} (${p.item_count} actions, ${p.status})${dupeNote}</option>`;
  }).join('');

  openModal(`Add ${_addToPlanIds.length} Action${_addToPlanIds.length>1?'s':''} to Plan`, `
    <div style="margin-bottom:12px">
      <div style="margin-bottom:8px">
        <input type="radio" name="plan-mode" id="pm-existing" value="existing" ${hasPlans?'checked':''} ${!hasPlans?'disabled':''}
          onchange="document.getElementById('existing-plan-section').style.display='';document.getElementById('new-plan-section').style.display='none'">
        <span onclick="document.getElementById('pm-existing').click()" style="font-size:14px;cursor:pointer;margin-left:4px">Add to existing plan</span>
      </div>
      <div id="existing-plan-section" style="${hasPlans?'':'display:none;'}padding-left:24px;margin-bottom:12px">
        <select id="atp-plan-id" style="width:100%">${planOptions||'<option>No plans available</option>'}</select>
      </div>
    </div>
    <div>
      <div style="margin-bottom:8px">
        <input type="radio" name="plan-mode" id="pm-new" value="new" ${!hasPlans?'checked':''}
          onchange="document.getElementById('new-plan-section').style.display='';document.getElementById('existing-plan-section').style.display='none'">
        <span onclick="document.getElementById('pm-new').click()" style="font-size:14px;cursor:pointer;margin-left:4px">Create new plan</span>
      </div>
      <div id="new-plan-section" style="${hasPlans?'display:none;':''}padding-left:24px">
        <div class="form-group"><span style="display:block;font-size:13px;font-weight:500;margin-bottom:4px;color:var(--text-light)">Plan Name</span><input id="atp-new-name" placeholder="e.g. Q1 2026 Security Uplift"></div>
        <div class="form-group"><span style="display:block;font-size:13px;font-weight:500;margin-bottom:4px;color:var(--text-light)">Description</span><textarea id="atp-new-desc" rows="2"></textarea></div>
        <div style="display:flex;gap:8px">
          <div class="form-group" style="flex:1"><span style="display:block;font-size:13px;font-weight:500;margin-bottom:4px;color:var(--text-light)">Responsible</span><input id="atp-new-responsible" placeholder="e.g. John Smith"></div>
          <div class="form-group" style="flex:1"><span style="display:block;font-size:13px;font-weight:500;margin-bottom:4px;color:var(--text-light)">Priority</span><select id="atp-new-priority">${['Critical','High','Medium','Low'].map(p=>'<option'+(p==='Medium'?' selected':'')+'>'+p+'</option>').join('')}</select></div>
        </div>
        <div style="display:flex;gap:8px">
          <div class="form-group" style="flex:1"><span style="display:block;font-size:13px;font-weight:500;margin-bottom:4px;color:var(--text-light)">Start Date</span><input id="atp-new-start" type="date"></div>
          <div class="form-group" style="flex:1"><span style="display:block;font-size:13px;font-weight:500;margin-bottom:4px;color:var(--text-light)">End Date</span><input id="atp-new-end" type="date"></div>
        </div>
        <div class="form-group"><span style="display:block;font-size:13px;font-weight:500;margin-bottom:4px;color:var(--text-light)">Effort</span><select id="atp-new-effort"><option value="Small">Small (within a day)</option><option value="Medium" selected>Medium (within a week)</option><option value="Large">Large (within a month)</option></select></div>
      </div>
    </div>`,
    `<button class="btn" onclick="closeModal()">Cancel</button>
     <button class="btn btn-primary" onclick="addToPlanSubmit()">Add to Plan</button>`);
}

async function addToPlanSubmit() {
  const actionIds = _addToPlanIds;
  if(!actionIds.length) return toast('No actions to add', 'error');
  const mode = document.querySelector('input[name="plan-mode"]:checked')?.value;
  const t = state.activeTenant.name;

  if(mode === 'new') {
    const name = document.getElementById('atp-new-name').value;
    if(!name) return toast('Plan name required', 'error');
    const r = await api.post(`/api/tenants/${t}/plans`, {
      name, description: document.getElementById('atp-new-desc').value, action_ids: actionIds,
      responsible_person: document.getElementById('atp-new-responsible')?.value||'',
      priority: document.getElementById('atp-new-priority')?.value||'Medium',
      start_date: document.getElementById('atp-new-start')?.value||null,
      end_date: document.getElementById('atp-new-end')?.value||null,
      implementation_effort: document.getElementById('atp-new-effort')?.value||'Medium'
    });
    if(r.error) return toast(r.error, 'error');
    closeModal();
    toast(`Plan created with ${actionIds.length} action${actionIds.length>1?'s':''}`, 'success');
  } else {
    const planId = document.getElementById('atp-plan-id').value;
    if(!planId) return toast('Select a plan', 'error');
    // Filter out actions already in the plan
    const planInfo = (window._atpPlanData||[]).find(p => p.id === planId);
    const existingList = planInfo ? planInfo.existingActionIds : [];
    const newIds = actionIds.filter(id => !existingList.includes(id));
    const dupes = actionIds.length - newIds.length;

    if(!newIds.length) {
      closeModal();
      return toast('All selected actions are already in this plan', 'error');
    }

    let added = 0;
    for(const aid of newIds) {
      const r = await api.post(`/api/plans/${planId}/items`, {action_id: aid});
      if(!r.error) added++;
    }
    closeModal();
    const dupeMsg = dupes ? ` (${dupes} already in plan, skipped)` : '';
    toast(`${added} action${added>1?'s':''} added to plan${dupeMsg}`, 'success');
  }
}

function actionDetailHtml(a) {
  const hist = (a.history||[]).map(h => {
    let desc = [];
    if(h.old_status) desc.push(`${h.old_status} → ${h.new_status}`);
    if(h.old_score!=null) desc.push(`Score: ${h.old_score} → ${h.new_score}`);
    return `<div style="font-size:12px;padding:2px 0"><code>${(h.timestamp||'').substring(0,19)}</code> ${desc.join('; ')} ${h.changed_by?'by '+h.changed_by:''}</div>`;
  }).join('');

  // Risk acceptance info
  let riskHtml = '';
  if(a.status === 'Risk Accepted') {
    const isExpired = a.risk_expiry_date && new Date(a.risk_expiry_date) < new Date();
    riskHtml = `<div class="risk-card ${isExpired?'expired':''} mb-16">
      <div class="field-label">Risk Acceptance</div>
      <div class="grid grid-2 mt-16">
        <div class="field"><div class="field-label">Owner</div><div class="field-value">${a.risk_owner||'Not specified'}</div></div>
        <div class="field"><div class="field-label">Accepted</div><div class="field-value">${a.risk_accepted_at?.substring(0,10)||'Unknown'}</div></div>
        <div class="field"><div class="field-label">Review Date</div><div class="field-value">${a.risk_review_date||'Not set'}</div></div>
        <div class="field"><div class="field-label">Expiry Date</div><div class="field-value">${isExpired?'<span class="badge badge-danger">EXPIRED</span> ':''}${a.risk_expiry_date||'No expiry'}</div></div>
      </div>
      <div class="field mt-16"><div class="field-label">Justification</div><div class="field-value">${a.risk_justification||'None provided'}</div></div>
    </div>`;
  }

  // Score bar
  const scorePct = a.max_score > 0 ? Math.round(a.score / a.max_score * 100) : 0;
  const scoreDisplay = a.score != null ? `${a.score} / ${a.max_score}` : 'N/A';

  // Source badge color
  const isZTR = a.source_tool === 'Zero Trust Report';
  const isSCuBA = a.source_tool === 'SCuBA (CISA)';
  const srcColors = {'Microsoft Secure Score':'badge-info', 'SCuBA (CISA)':'badge-purple', 'Zero Trust Assessment':'badge-cyan', 'Zero Trust Report':'badge-cyan', 'Manual':'badge-gray'};
  const srcBadge = `<span class="badge ${srcColors[a.source_tool]||'badge-gray'}">${a.source_tool}</span>`;

  // Remediation steps - split into structured parts if possible
  let prerequisitesHtml = '';
  let stepsHtml = '';
  const remText = a.remediation_steps || '';
  if(remText.includes('Prerequisites:') && remText.includes('Next steps:')) {
    const parts = remText.split('Next steps:');
    const prereq = parts[0].replace('Prerequisites:', '').trim();
    const steps = parts[1]?.trim() || '';
    prerequisitesHtml = prereq ? `<div class="field mb-16"><div class="field-label">Prerequisites</div><div class="field-value">${isZTR?mdToHtml(prereq):prereq}</div></div>` : '';
    stepsHtml = steps ? `<div class="field mb-16"><div class="field-label">Next Steps</div><div class="field-value">${isZTR?mdToHtml(steps):steps}</div></div>` : '';
  } else if(remText) {
    stepsHtml = `<div class="field mb-16"><div class="field-label">Remediation Steps</div><div class="field-value">${isZTR?mdToHtml(remText):remText}</div></div>`;
  }

  const uid = a.id.replace(/[^a-zA-Z0-9]/g,'');

  return `<div class="detail-panel">
    <div class="flex justify-between items-center mb-16">
      <div class="flex gap-8">
        <button class="btn btn-sm" onclick="showEditAction('${a.id}');event.stopPropagation()">Edit</button>
        <button class="btn btn-sm btn-primary" onclick="showAddToPlan(['${a.id}']);event.stopPropagation()">Add to Plan</button>
        ${a.status!=='Risk Accepted'?`<button class="btn btn-sm" style="background:var(--warning-light);border-color:var(--warning);color:#92400e" onclick="showAcceptRisk('${a.id}');event.stopPropagation()">Accept Risk</button>`:''}
        <button class="btn btn-sm" onclick="showAddDependency('${a.id}');event.stopPropagation()">+ Dependency</button>
        <button class="btn btn-sm btn-danger" onclick="deleteAction('${a.id}');event.stopPropagation()">Delete</button>
      </div>
      <div>${srcBadge} ${statusBadge(a.status)}</div>
    </div>
    ${riskHtml}
    <div class="action-tabs">
      <div class="atab active" onclick="switchActionTab('${uid}','general',this);event.stopPropagation()">General</div>
      <div class="atab" onclick="switchActionTab('${uid}','implementation',this);event.stopPropagation()">Implementation</div>
      <div class="atab" onclick="switchActionTab('${uid}','notes',this);event.stopPropagation()">Notes${a.notes?' *':''}</div>
      <div class="atab" onclick="switchActionTab('${uid}','links',this);loadActionLinks('${a.id}','${uid}');event.stopPropagation()">Links & People</div>
      ${hist?`<div class="atab" onclick="switchActionTab('${uid}','history',this);event.stopPropagation()">History (${a.history.length})</div>`:''}
    </div>
    <!-- General Tab -->
    <div class="action-tab-content active" id="atab-${uid}-general">
      <div class="action-detail-layout">
        <div>
          ${isZTR ? `
          ${a.description?`<div class="field mb-16"><div class="field-label">What was checked</div><div class="field-value">${mdToHtml(a.description)}</div></div>`:''}
          ${a.current_value?`<div class="field mb-16"><div class="field-label">Test Result</div><div class="field-value" style="white-space:pre-wrap;font-family:inherit">${mdToHtml(a.current_value)}</div></div>`:''}
          ` : `
          ${a.description?`<div class="field mb-16"><div class="field-label">Description</div><div class="field-value">${a.description}</div></div>`:'<div class="field mb-16"><div class="field-label">Description</div><div class="field-value" style="color:var(--text-light);font-style:italic">No description available. Seed control data or import from Graph API to populate.</div></div>'}
          ${a.remediation_impact?`<div class="field mb-16"><div class="field-label">Remediation Impact</div><div class="field-value">${a.remediation_impact}</div></div>`:''}
          ${a.threats&&a.threats.length?`<div class="field mb-16"><div class="field-label">Threats Mitigated</div><div class="field-value">${a.threats.map(t=>'<span class="badge badge-info" style="margin:2px">'+t+'</span>').join(' ')}</div></div>`:''}
          ${a.current_value?`<div class="field mb-16"><div class="field-label">Current Configuration</div><pre>${a.current_value}</pre></div>`:''}
          ${a.recommended_value?`<div class="field mb-16"><div class="field-label">Recommended Configuration</div><pre>${a.recommended_value}</pre></div>`:''}
          `}
          <div id="deps-${a.id}" class="mb-8"></div>
        </div>
        <div>
          <div class="action-sidebar-card">
            ${isZTR ? `
            <div class="sidebar-field"><div class="field-label">Test ID</div><div class="field-value" style="font-family:monospace;font-weight:600">${a.reference_id||'N/A'}</div></div>
            <div class="sidebar-field"><div class="field-label">ZT Status</div><div class="field-value">${ztStatusBadge(a)}</div></div>
            <div class="sidebar-field"><div class="field-label">Pillar</div><div class="field-value">${(a.tags||[]).filter(t=>t.startsWith('Pillar:')).map(t=>t.replace('Pillar: ','')).join(', ')||'N/A'}</div></div>
            <div class="sidebar-field"><div class="field-label">SFI Pillar</div><div class="field-value">${a.subcategory||'N/A'}</div></div>
            ` : isSCuBA ? `
            <div class="sidebar-field"><div class="field-label">Control ID</div><div class="field-value" style="font-family:monospace;font-weight:600;font-size:14px">${a.reference_id||a.source_id?.replace('scuba_','')||'N/A'}</div></div>
            <div class="sidebar-field">
              <div class="field-label">Result</div>
              <div class="field-value">${statusBadge(a.status)}</div>
            </div>
            <div class="sidebar-field"><div class="field-label">Product</div><div class="field-value">${a.category||'N/A'}</div></div>
            <div class="sidebar-field"><div class="field-label">Criticality</div><div class="field-value">${_scubaCritBadge(a.subcategory)}</div></div>
            ${(()=>{const g=(a.tags||[]).filter(t=>t.startsWith('Group:')).map(t=>t.replace('Group:','')).join('');return g?'<div class="sidebar-field"><div class="field-label">Group</div><div class="field-value">'+g+'</div></div>':'';})()}
            ` : `
            <div class="sidebar-field">
              <div class="field-label">Score</div>
              <div class="score-label">${scoreDisplay}</div>
              <div class="score-bar-wrap"><div class="score-bar"><div class="bar" style="width:${scorePct}%;background:${pctColor(scorePct)}"></div></div></div>
            </div>
            `}
            ${!isZTR && !isSCuBA ? `<div class="sidebar-field"><div class="field-label">Category</div><div class="field-value">${a.category||'N/A'}</div></div>
            <div class="sidebar-field"><div class="field-label">Product</div><div class="field-value">${a.subcategory||'N/A'}</div></div>` : ''}
            <div class="sidebar-field"><div class="field-label">Priority</div><div class="field-value">${priorityBadge(a.priority)}</div></div>
            <div class="sidebar-field"><div class="field-label">Risk Level</div><div class="field-value">${a.risk_level}</div></div>
            <div class="sidebar-field"><div class="field-label">User Impact</div><div class="field-value">${a.user_impact}</div></div>
            <div class="sidebar-field"><div class="field-label">Impl. Effort</div><div class="field-value">${a.implementation_effort}</div></div>
            <div class="sidebar-field"><div class="field-label">Licence</div><div class="field-value">${a.required_licence||'N/A'}</div></div>
            ${a.tier?`<div class="sidebar-field"><div class="field-label">Tier</div><div class="field-value">${a.tier}</div></div>`:''}
            ${a.action_type?`<div class="sidebar-field"><div class="field-label">Action Type</div><div class="field-value">${a.action_type}</div></div>`:''}
            ${a.deprecated?`<div class="sidebar-field"><div class="field-label">Status</div><div class="field-value"><span class="badge badge-danger">Deprecated</span></div></div>`:''}
            ${a.responsible?`<div class="sidebar-field"><div class="field-label">Responsible</div><div class="field-value">${a.responsible}</div></div>`:''}
            ${a.planned_date?`<div class="sidebar-field"><div class="field-label">Planned Date</div><div class="field-value">${a.planned_date}</div></div>`:''}
            ${a.essential_eight_control?`<div class="sidebar-field"><div class="field-label">E8 Control</div><div class="field-value">${a.essential_eight_control}</div></div>`:''}
            ${a.essential_eight_maturity?`<div class="sidebar-field"><div class="field-label">E8 Maturity</div><div class="field-value">${a.essential_eight_maturity}</div></div>`:''}
            ${a.notes?`<div class="sidebar-field"><div class="field-label">Notes</div><div class="field-value" style="font-size:12px;white-space:pre-wrap">${a.notes}</div></div>`:''}
          </div>
        </div>
      </div>
    </div>
    <!-- Implementation Tab -->
    <div class="action-tab-content" id="atab-${uid}-implementation">
      ${prerequisitesHtml}
      ${stepsHtml}
      ${!prerequisitesHtml && !stepsHtml ? '<div style="color:var(--text-light);font-style:italic;padding:16px 0">No implementation details available. Seed control reference data or import from Graph API to populate.</div>' : ''}
      ${a.reference_url?`<div class="field mb-16"><div class="field-label">Reference Documentation</div><div class="field-value"><a href="${a.reference_url}" target="_blank" onclick="event.stopPropagation()">${a.reference_url}</a></div></div>`:''}
      <div class="grid grid-4 mb-16">
        <div class="field"><div class="field-label">E8 Control</div><div class="field-value">${a.essential_eight_control||'N/A'}</div></div>
        <div class="field"><div class="field-label">E8 Maturity</div><div class="field-value">${a.essential_eight_maturity||'N/A'}</div></div>
        <div class="field"><div class="field-label">Source ID</div><div class="field-value"><code style="font-size:11px">${a.source_id||'N/A'}</code></div></div>
        <div class="field"><div class="field-label">Reference ID</div><div class="field-value"><code style="font-size:11px">${a.reference_id||'N/A'}</code></div></div>
      </div>
    </div>
    <!-- Notes Tab -->
    <div class="action-tab-content" id="atab-${uid}-notes">
      <div style="margin-bottom:12px">
        <textarea id="notes-${uid}" rows="6" style="width:100%;padding:8px;border:1px solid var(--border);border-radius:var(--radius);font-family:inherit;font-size:13px;resize:vertical" placeholder="Add your notes here..." onclick="event.stopPropagation()">${a.notes||''}</textarea>
      </div>
      <button class="btn btn-sm btn-primary" onclick="saveActionNotes('${a.id}','${uid}');event.stopPropagation()">Save Notes</button>
    </div>
    <!-- Links & People Tab -->
    <div class="action-tab-content" id="atab-${uid}-links">
      <div class="grid grid-2" style="gap:20px">
        <div>
          <div style="font-weight:600;margin-bottom:8px;font-size:13px">Responsible Persons</div>
          <div id="action-persons-${uid}" style="margin-bottom:8px"><span style="color:var(--text-light);font-size:12px">Loading...</span></div>
          <button class="btn btn-sm" onclick="showAssignPerson('${a.id}','${uid}');event.stopPropagation()">+ Assign Person</button>
        </div>
        <div>
          <div style="font-weight:600;margin-bottom:8px;font-size:13px">Linked Actions (Cross-Tool)</div>
          <div id="action-links-${uid}" style="margin-bottom:8px"><span style="color:var(--text-light);font-size:12px">Loading...</span></div>
          <button class="btn btn-sm" onclick="showLinkAction('${a.id}','${uid}');event.stopPropagation()">+ Link Action</button>
        </div>
      </div>
      ${a.last_seen_in_report?`<div style="margin-top:16px;padding-top:12px;border-top:1px solid var(--border)"><span style="font-size:12px;color:var(--text-light)">Last seen in report: <strong>${a.last_seen_in_report?.substring(0,10)||'Never'}</strong></span>
      ${a.import_suggested_status?` &middot; <span style="font-size:12px;color:var(--warning)">Import wanted status: <strong>${a.import_suggested_status}</strong> (protected)</span>`:''}</div>`:''}
    </div>
    <!-- History Tab -->
    ${hist?`<div class="action-tab-content" id="atab-${uid}-history">${hist}</div>`:''}
  </div>`;
}

function switchActionTab(uid, tab, el) {
  // Toggle active tab button
  el.parentElement.querySelectorAll('.atab').forEach(t => t.classList.remove('active'));
  el.classList.add('active');
  // Toggle content
  const parent = el.closest('.detail-panel');
  parent.querySelectorAll('.action-tab-content').forEach(c => c.classList.remove('active'));
  const target = document.getElementById(`atab-${uid}-${tab}`);
  if(target) target.classList.add('active');
}

function toggleActionDetail(id) {
  const el = document.getElementById('detail-'+id);
  if(expandedAction && expandedAction!==id) document.getElementById('detail-'+expandedAction)?.classList.add('hidden');
  el.classList.toggle('hidden');
  expandedAction = el.classList.contains('hidden') ? null : id;
  if(!el.classList.contains('hidden')) loadActionDeps(id);
}

async function loadActionLinks(actionId, uid) {
  const [persons, links] = await Promise.all([
    api.get(`/api/actions/${actionId}/persons`),
    api.get(`/api/actions/${actionId}/links`),
  ]);

  // Render persons
  const personsEl = document.getElementById(`action-persons-${uid}`);
  if(personsEl) {
    if(persons.length === 0) {
      personsEl.innerHTML = '<div style="color:var(--text-light);font-size:12px">No persons assigned</div>';
    } else {
      personsEl.innerHTML = persons.map(p =>
        `<div style="display:flex;align-items:center;gap:6px;padding:4px 0;font-size:12px">
          <span style="background:var(--primary);color:#fff;width:24px;height:24px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:600">${p.name.charAt(0).toUpperCase()}</span>
          <span><strong>${p.name}</strong>${p.role?' &middot; '+p.role:''}</span>
          <button class="btn btn-sm" onclick="unassignPerson('${actionId}','${p.id}','${uid}');event.stopPropagation()" style="padding:1px 4px;font-size:10px;color:var(--danger);margin-left:auto">&times;</button>
        </div>`
      ).join('');
    }
  }

  // Render links
  const linksEl = document.getElementById(`action-links-${uid}`);
  if(linksEl) {
    if(links.length === 0) {
      linksEl.innerHTML = '<div style="color:var(--text-light);font-size:12px">No linked actions</div>';
    } else {
      linksEl.innerHTML = links.map(l =>
        `<div style="display:flex;align-items:center;gap:6px;padding:4px 0;font-size:12px;border-bottom:1px solid var(--bg-hover)">
          <span style="font-size:10px;color:var(--text-light)">${l.source_tool}</span>
          <span>${l.title}</span>
          ${statusBadge(l.status)}
          <button class="btn btn-sm" onclick="unlinkAction('${actionId}','${l.id}','${uid}');event.stopPropagation()" style="padding:1px 4px;font-size:10px;color:var(--danger);margin-left:auto">&times;</button>
        </div>`
      ).join('');
    }
  }
}

async function showAssignPerson(actionId, uid) {
  const persons = await api.get('/api/responsible-persons');
  if(!persons.length) {
    toast('No persons registered. Add people first in the People page.','error');
    return;
  }
  const opts = persons.map(p => `<option value="${p.id}">${p.name}${p.role?' ('+p.role+')':''}</option>`).join('');
  openModal('Assign Person', `
    <div class="form-group"><label>Person</label><select id="assign-person-select">${opts}</select></div>`,
    `<button class="btn" onclick="closeModal()">Cancel</button>
     <button class="btn btn-primary" onclick="doAssignPerson('${actionId}','${uid}')">Assign</button>`);
}

async function doAssignPerson(actionId, uid) {
  const personId = document.getElementById('assign-person-select').value;
  await api.post(`/api/actions/${actionId}/persons`, {person_id: personId});
  closeModal(); toast('Person assigned','success');
  loadActionLinks(actionId, uid);
}

async function unassignPerson(actionId, personId, uid) {
  await api.del(`/api/actions/${actionId}/persons/${personId}`);
  toast('Person unassigned','success');
  loadActionLinks(actionId, uid);
}

async function showLinkAction(actionId, uid) {
  if(!state.activeTenant) return;
  const actions = await api.get(`/api/tenants/${state.activeTenant.name}/actions`);
  const other = actions.filter(a => a.id !== actionId).slice(0, 200);
  const opts = other.map(a => `<option value="${a.id}">[${a.source_tool}] ${a.title.substring(0,60)}</option>`).join('');
  openModal('Link Action', `
    <p style="font-size:12px;color:var(--text-light);margin-bottom:8px">Link this action to another action from a different tool to indicate they address the same recommendation.</p>
    <div class="form-group"><label>Target Action</label><select id="link-action-select" style="max-width:100%">${opts}</select></div>`,
    `<button class="btn" onclick="closeModal()">Cancel</button>
     <button class="btn btn-primary" onclick="doLinkAction('${actionId}','${uid}')">Link</button>`);
}

async function doLinkAction(actionId, uid) {
  const targetId = document.getElementById('link-action-select').value;
  await api.post(`/api/actions/${actionId}/links`, {target_action_id: targetId});
  closeModal(); toast('Actions linked','success');
  loadActionLinks(actionId, uid);
}

async function unlinkAction(sourceId, targetId, uid) {
  await api.del(`/api/actions/${sourceId}/links/${targetId}`);
  toast('Link removed','success');
  loadActionLinks(sourceId, uid);
}

function showAddAction() {
  openModal('Add Manual Action', `
    <div class="form-group"><label>Title</label><input id="a-title"></div>
    <div class="form-row"><div class="form-group"><label>Status</label><select id="a-status">${selectOptions(state.enums.statuses,'ToDo')}</select></div>
    <div class="form-group"><label>Priority</label><select id="a-priority">${selectOptions(state.enums.priorities,'Medium')}</select></div></div>
    <div class="form-row"><div class="form-group"><label>Workload</label><select id="a-workload">${selectOptions(state.enums.workloads,'General')}</select></div>
    <div class="form-group"><label>Risk Level</label><select id="a-risk">${selectOptions(state.enums.risk_levels,'Medium')}</select></div></div>
    <div class="form-group"><label>Description</label><textarea id="a-desc" rows="3"></textarea></div>
    <div class="form-group"><label>Remediation Steps</label><textarea id="a-remed" rows="3"></textarea></div>`,
    '<button class="btn" onclick="closeModal()">Cancel</button><button class="btn btn-primary" onclick="addAction()">Create</button>');
}

async function addAction() {
  const data = {title:document.getElementById('a-title').value, status:document.getElementById('a-status').value, priority:document.getElementById('a-priority').value, workload:document.getElementById('a-workload').value, risk_level:document.getElementById('a-risk').value, description:document.getElementById('a-desc').value, remediation_steps:document.getElementById('a-remed').value, source_tool:'Manual'};
  if(!data.title) return toast('Title required','error');
  const r = await api.post(`/api/tenants/${state.activeTenant.name}/actions`, data);
  if(r.error) return toast(r.error,'error');
  closeModal(); toast('Action created','success'); filterActions();
}

async function showEditAction(id) {
  const a = await api.get(`/api/actions/${id}`);
  openModal('Edit Action: '+a.title.substring(0,40), `
    <div class="form-group"><label>Title</label><input id="ae-title" value="${a.title.replace(/"/g,'&quot;')}"></div>
    <div class="form-row"><div class="form-group"><label>Status</label><select id="ae-status">${selectOptions(state.enums.statuses,a.status)}</select></div>
    <div class="form-group"><label>Priority</label><select id="ae-priority">${selectOptions(state.enums.priorities,a.priority)}</select></div></div>
    <div class="form-row"><div class="form-group"><label>Workload</label><select id="ae-workload">${selectOptions(state.enums.workloads,a.workload)}</select></div>
    <div class="form-group"><label>Risk Level</label><select id="ae-risk">${selectOptions(state.enums.risk_levels,a.risk_level)}</select></div></div>
    <div class="form-row"><div class="form-group"><label>User Impact</label><select id="ae-impact">${selectOptions(state.enums.user_impacts,a.user_impact)}</select></div>
    <div class="form-group"><label>Impl. Effort</label><select id="ae-effort">${selectOptions(state.enums.implementation_efforts,a.implementation_effort)}</select></div></div>
    <div class="form-row"><div class="form-group"><label>Responsible</label><input id="ae-responsible" value="${a.responsible||''}"></div>
    <div class="form-group"><label>Planned Date</label><input id="ae-date" type="date" value="${a.planned_date||''}"></div></div>
    <div class="form-row"><div class="form-group"><label>E8 Control</label><select id="ae-e8ctrl"><option value="">— None —</option>${(state.enums.e8_controls||[]).map(c=>'<option'+(c===a.essential_eight_control?' selected':'')+'>'+c+'</option>').join('')}</select></div>
    <div class="form-group"><label>E8 Maturity</label><select id="ae-e8ml"><option value="">— Auto —</option>${(state.enums.e8_maturities||[]).filter(m=>m!=='Level 0').map(m=>'<option'+(m===a.essential_eight_maturity?' selected':'')+'>'+m+'</option>').join('')}</select></div></div>
    <div class="form-group"><label>Notes</label><textarea id="ae-notes" rows="2">${a.notes||''}</textarea></div>
    ${a.max_score != null ? `<div class="form-row"><div class="form-group"><label>Score</label><input id="ae-score" type="number" min="0" step="any" value="${a.score??''}"></div><div class="form-group"><label>Max Score</label><input id="ae-maxscore" type="number" min="0" step="any" value="${a.max_score??''}"></div></div>` : ''}
    <div class="form-group"><label>Changed By</label><input id="ae-by" placeholder="Your name"></div>`,
    `<button class="btn" onclick="closeModal()">Cancel</button><button class="btn btn-primary" onclick="updateAction('${id}')">Save</button>`);
}

async function updateAction(id) {
  const data = {title:document.getElementById('ae-title').value, status:document.getElementById('ae-status').value, priority:document.getElementById('ae-priority').value, workload:document.getElementById('ae-workload').value, risk_level:document.getElementById('ae-risk').value, user_impact:document.getElementById('ae-impact').value, implementation_effort:document.getElementById('ae-effort').value, responsible:document.getElementById('ae-responsible').value, planned_date:document.getElementById('ae-date').value||null, essential_eight_control:document.getElementById('ae-e8ctrl').value||null, essential_eight_maturity:document.getElementById('ae-e8ml').value||null, notes:document.getElementById('ae-notes').value, changed_by:document.getElementById('ae-by').value};
  const scoreEl = document.getElementById('ae-score');
  const maxEl = document.getElementById('ae-maxscore');
  if(scoreEl) {
    const s = parseFloat(scoreEl.value);
    const m = parseFloat(maxEl.value);
    if(!isNaN(s)) data.score = s;
    if(!isNaN(m)) { data.max_score = m; data.score_percentage = m > 0 ? Math.round(s/m*100*100)/100 : 0; }
  }
  await api.put(`/api/actions/${id}`, data);
  closeModal(); toast('Action updated','success'); filterActions();
}

async function saveActionNotes(id, uid) {
  const notes = document.getElementById('notes-'+uid)?.value || '';
  await api.put(`/api/actions/${id}`, {notes});
  toast('Notes saved','success');
}

async function deleteAction(id) {
  if(!confirm('Delete this action?')) return;
  await api.del(`/api/actions/${id}`);
  toast('Action deleted','success'); filterActions();
}

// ── Import ──
async function renderImport() {
  if(!requireTenant()) return;
  const t = state.activeTenant.name;
  const c = document.getElementById('content');

  // Check Graph API auth status
  const graphStatus = await api.get(`/api/tenants/${t}/graph/status`);
  const hasCredentials = state.activeTenant.tenant_id && state.activeTenant.client_id;

  let graphSection = '';
  if(!hasCredentials) {
    graphSection = `
      <div class="card mb-16">
        <div class="card-header">Import from Microsoft Graph API</div>
        <div style="padding:16px 0;color:var(--text-light)">
          <p style="margin-bottom:8px">To import directly from Microsoft Graph, configure your tenant with:</p>
          <ol style="margin-left:20px;font-size:13px;line-height:1.8">
            <li>Register an app in <strong>Entra ID > App registrations</strong></li>
            <li>Add API permission: <strong>Microsoft Graph > SecurityEvents.Read.All</strong></li>
            <li>Either: add a <strong>Client Secret</strong> and grant <strong>admin consent</strong> for <strong>application</strong> permissions,<br>
                or: set <strong>Allow public client flows = Yes</strong> and use <strong>delegated</strong> permissions with device code</li>
            <li>Set the <strong>Tenant ID</strong>, <strong>Client ID</strong>, and optionally <strong>Client Secret</strong> on your tenant configuration</li>
          </ol>
          <button class="btn btn-sm mt-16" onclick="navigate('tenants')">Go to Tenant Settings</button>
        </div>
      </div>`;
  } else if(graphStatus.authenticated) {
    const mins = Math.round((graphStatus.expires_in||0)/60);
    graphSection = `
      <div class="card mb-16">
        <div class="card-header flex justify-between items-center">
          <span>Import from Microsoft Graph API</span>
          <span class="badge badge-success">Authenticated (${mins}m remaining)</span>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button class="btn btn-primary" onclick="graphImportScores()">Import Secure Scores</button>
          <button class="btn" onclick="graphFetchControls()">Update Control Reference Data</button>
        </div>
        <div id="graph-result" style="margin-top:12px"></div>
      </div>`;
  } else {
    const hasSecret = !!(state.activeTenant.client_secret);
    graphSection = `
      <div class="card mb-16">
        <div class="card-header">Import from Microsoft Graph API</div>
        ${hasSecret ? `
        <p style="font-size:13px;color:var(--text-light);margin-bottom:12px">Client secret detected. Use app-only auth (requires <strong>application</strong> permission SecurityEvents.Read.All with admin consent), or sign in interactively.</p>
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">
          <button class="btn btn-primary" id="graph-client-auth-btn" onclick="startClientAuth()">Sign in with Client Secret</button>
          <button class="btn" onclick="startInteractiveAuth()">Sign in with Browser</button>
          <button class="btn" id="graph-auth-btn" onclick="startGraphAuth()">Sign in with Device Code</button>
        </div>
        ` : `
        <p style="font-size:13px;color:var(--text-light);margin-bottom:12px">Authenticate with your Microsoft account to import Secure Score data directly. Uses Global Reader permissions. No secrets stored.</p>
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">
          <button class="btn btn-primary" onclick="startInteractiveAuth()">Sign in with Browser (Recommended)</button>
          <button class="btn" id="graph-auth-btn" onclick="startGraphAuth()">Sign in with Device Code</button>
        </div>
        `}
        <div id="graph-auth-status" style="margin-top:12px"></div>
      </div>`;
  }

  c.innerHTML = `
    ${graphSection}
    <div class="card mb-16">
      <div class="card-header">Import from File</div>
      <div class="form-group"><label>Source Tool</label>
        <select id="imp-source" onchange="onSourceChange()">${selectOptions(state.enums.import_sources)}</select></div>
      <div id="imp-source-hint" style="font-size:12px;color:var(--text-light);margin:-8px 0 8px 0;display:none"></div>
      <div class="upload-zone" id="upload-zone" onclick="document.getElementById('imp-file').click()" ondrop="handleDrop(event)" ondragover="handleDragOver(event)" ondragleave="handleDragLeave(event)">
        <div class="icon">&#128228;</div>
        <div><strong>Click to upload</strong> or drag and drop</div>
        <div id="upload-hint" style="color:var(--text-light);font-size:13px;margin-top:4px">JSON or CSV file</div>
      </div>
      <input type="file" id="imp-file" accept=".json,.csv,.zip" style="display:none" onchange="handleFileSelect(event)">
      <div id="imp-file-name" style="margin-top:8px;font-size:13px"></div>
      <button class="btn btn-primary mt-16" id="imp-btn" onclick="doImport()" disabled>Import</button>
    </div>
    <div id="imp-result"></div>
    <div id="zt-reports-section"></div>`;

  // Load ZT reports if any exist
  loadZtReports(t);
}

// ── Graph API Auth ──
let graphPollTimer = null;

async function startInteractiveAuth() {
  const t = state.activeTenant.name;
  const statusEl = document.getElementById('graph-auth-status');
  statusEl.innerHTML = '<div style="color:var(--text-light)">Starting interactive authentication...</div>';

  const r = await api.post(`/api/tenants/${t}/graph/interactive-auth`);
  if(r.error) {
    statusEl.innerHTML = `<div style="color:var(--danger)">${r.error}</div>`;
    return;
  }

  // Open the auth URL in a new window
  window.open(r.auth_url, '_blank', 'width=600,height=700');
  statusEl.innerHTML = `
    <div class="card" style="padding:12px">
      <p>&#128274; <strong>Sign in with your browser</strong></p>
      <p style="font-size:12px;color:var(--text-light);margin-top:4px">A new window should have opened. Sign in with an account that has <strong>Global Reader</strong> (or Security Reader) permissions.</p>
      <p style="font-size:12px;color:var(--text-light);margin-top:8px">Waiting for authentication to complete...</p>
    </div>`;

  // Poll for completion
  for(let i=0; i<60; i++) {
    await new Promise(r => setTimeout(r, 3000));
    const status = await api.get(`/api/tenants/${t}/graph/interactive-status`);
    if(status.authenticated) {
      statusEl.innerHTML = `
        <div style="color:var(--success);font-weight:600">&#10003; Authenticated (expires in ${Math.floor(status.expires_in/60)} min)</div>
        <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">
          <button class="btn btn-primary" onclick="graphImportScores()">Import Secure Scores</button>
          <button class="btn" onclick="graphFetchControls()">Fetch Control Profiles</button>
        </div>
        <div id="graph-result" style="margin-top:8px"></div>`;
      return;
    }
    if(status.expired) {
      statusEl.innerHTML = '<div style="color:var(--danger)">Authentication expired. Please try again.</div>';
      return;
    }
  }
  statusEl.innerHTML = '<div style="color:var(--danger)">Authentication timed out. Please try again.</div>';
}

async function startGraphAuth() {
  const t = state.activeTenant.name;
  const btn = document.getElementById('graph-auth-btn');
  const statusEl = document.getElementById('graph-auth-status');
  btn.disabled = true;
  btn.textContent = 'Starting...';

  const r = await api.post(`/api/tenants/${t}/graph/device-code`);
  if(r.error) {
    btn.disabled = false;
    btn.textContent = 'Sign in with Microsoft';
    toast(r.error, 'error');
    return;
  }

  btn.textContent = 'Waiting for authentication...';
  statusEl.innerHTML = `
    <div class="card" style="border-left:4px solid var(--primary);background:#f8fafc">
      <div style="font-size:14px;margin-bottom:12px"><strong>Sign in at:</strong></div>
      <div style="display:flex;gap:12px;align-items:center;margin-bottom:12px">
        <a href="${r.verification_uri}" target="_blank" class="btn btn-primary" style="text-decoration:none">${r.verification_uri}</a>
      </div>
      <div style="font-size:14px;margin-bottom:8px"><strong>Enter code:</strong></div>
      <div style="font-size:28px;font-weight:800;letter-spacing:4px;font-family:monospace;color:var(--primary);user-select:all;cursor:pointer" onclick="navigator.clipboard.writeText('${r.user_code}');toast('Code copied!','success')" title="Click to copy">${r.user_code}</div>
      <div style="font-size:12px;color:var(--text-light);margin-top:8px">Click the code to copy it. Expires in ${Math.round((r.expires_in||900)/60)} minutes.</div>
    </div>`;

  // Start polling
  const interval = (r.interval || 5) * 1000;
  if(graphPollTimer) clearInterval(graphPollTimer);
  graphPollTimer = setInterval(() => pollGraphToken(), interval);
}

async function startClientAuth() {
  const t = state.activeTenant.name;
  const btn = document.getElementById('graph-client-auth-btn');
  btn.disabled = true;
  btn.textContent = 'Authenticating...';

  const r = await api.post(`/api/tenants/${t}/graph/client-auth`);
  if(r.error) {
    btn.disabled = false;
    btn.textContent = 'Sign in with Client Secret';
    toast(r.error, 'error');
    return;
  }

  toast('Authenticated with client credentials!', 'success');
  renderImport();
}

async function pollGraphToken() {
  const t = state.activeTenant.name;
  const r = await api.post(`/api/tenants/${t}/graph/poll-token`);

  if(r.error) {
    clearInterval(graphPollTimer);
    graphPollTimer = null;
    toast(r.error, 'error');
    renderImport();
    return;
  }

  if(r.status === 'authenticated') {
    clearInterval(graphPollTimer);
    graphPollTimer = null;
    toast('Authenticated successfully!', 'success');
    renderImport();
  }
  // If 'pending', keep polling (timer continues)
}

async function graphImportScores() {
  const t = state.activeTenant.name;
  const el = document.getElementById('graph-result');
  el.innerHTML = '<div style="color:var(--text-light)">Importing from Microsoft Graph...</div>';

  const r = await api.post(`/api/tenants/${t}/graph/import-scores`);
  if(r.error) {
    el.innerHTML = `<div style="color:var(--danger)">${r.error}</div>`;
    return;
  }

  toast('Graph API import successful!', 'success');
  const unmatchedHtml = r.unmatched_controls?.length ? `<div style="margin-top:8px;font-size:12px;color:var(--warning)">&#9888; ${r.unmatched_controls.length} control(s) had no profile match (max_score may be inaccurate): ${r.unmatched_controls.slice(0,5).join(', ')}${r.unmatched_controls.length>5?'...':''}</div>` : '';
  el.innerHTML = `
    <div class="grid grid-4" style="margin-top:8px">
      <div class="stat-card card"><div class="value">${r.total_parsed}</div><div class="label">Parsed</div></div>
      <div class="stat-card card"><div class="value" style="color:var(--success)">${r.new_actions}</div><div class="label">New</div></div>
      <div class="stat-card card"><div class="value" style="color:var(--warning)">${r.updated_actions}</div><div class="label">Updated</div></div>
      <div class="stat-card card"><div class="value">${r.snapshot?.percentage?.toFixed(2)||'--'}%</div><div class="label">Score</div></div>
    </div>
    <div style="margin-top:8px;font-size:12px;color:var(--text-light)">Profiles loaded: ${r.profiles_loaded||0}</div>
    ${unmatchedHtml}`;
}

async function graphFetchControls() {
  const t = state.activeTenant.name;
  const el = document.getElementById('graph-result');
  el.innerHTML = '<div style="color:var(--text-light)">Fetching control profiles...</div>';

  const r = await api.post(`/api/tenants/${t}/graph/fetch-controls`);
  if(r.error) {
    el.innerHTML = `<div style="color:var(--danger)">${r.error}</div>`;
    return;
  }

  toast('Control profiles updated!', 'success');
  el.innerHTML = `<div style="margin-top:8px;font-size:13px">Updated <strong>${r.total}</strong> reference profiles (${r.new} new, ${r.updated} updated).<br><span style="color:var(--text-light);font-size:12px">These are template definitions from Microsoft (${r.total} across all M365 services). Your tenant has ${r.total > 72 ? 'fewer' : ''} active controls — use "Import Secure Scores" to import your actual scores.</span></div>`;
}

let selectedFile = null;
function handleFileSelect(e) { selectedFile=e.target.files[0]; if(selectedFile){document.getElementById('imp-file-name').textContent='Selected: '+selectedFile.name; document.getElementById('imp-btn').disabled=false;} }
function handleDragOver(e) { e.preventDefault(); e.currentTarget.classList.add('drag-over'); }
function handleDragLeave(e) { e.currentTarget.classList.remove('drag-over'); }
function handleDrop(e) { e.preventDefault(); e.currentTarget.classList.remove('drag-over'); selectedFile=e.dataTransfer.files[0]; if(selectedFile){document.getElementById('imp-file-name').textContent='Selected: '+selectedFile.name; document.getElementById('imp-btn').disabled=false;} }

async function doImport() {
  if(!selectedFile) return;
  const fd = new FormData();
  fd.append('source', document.getElementById('imp-source').value);
  fd.append('file', selectedFile);
  document.getElementById('imp-btn').disabled=true;
  document.getElementById('imp-btn').textContent='Importing...';
  const r = await api.upload(`/api/tenants/${state.activeTenant.name}/import`, fd);
  document.getElementById('imp-btn').textContent='Import';
  document.getElementById('imp-btn').disabled=false;
  if(r.error) { toast(r.error,'error'); return; }
  toast('Import successful!','success');

  // Drift detection display
  let driftHtml = '';
  const drift = r.drift;
  if(drift && drift.has_drift) {
    const cls = drift.score_delta > 0 ? 'positive' : drift.score_delta < 0 ? 'negative' : 'neutral';
    const deltaCls = drift.score_delta > 0 ? 'drift-positive' : drift.score_delta < 0 ? 'drift-negative' : 'drift-neutral';
    driftHtml = `
      <div class="card mb-16">
        <div class="card-header">Drift Detection</div>
        <div class="drift-banner ${cls}">
          <div class="delta ${deltaCls}">${drift.score_delta>=0?'+':''}${drift.score_delta.toFixed(2)}%</div>
          <div>
            <strong>${drift.summary}</strong><br>
            <span style="font-size:12px;color:var(--text-light)">Compared: ${drift.previous_timestamp?.substring(0,16)} vs ${drift.current_timestamp?.substring(0,16)}</span>
          </div>
        </div>
        ${drift.regressions.length?`<div class="mb-8"><div class="field-label">Regressions</div>${drift.regressions.map(r=>`<div class="drift-card regression card mb-8" style="padding:8px 12px"><strong>${r.scope}</strong>: ${r.old_value.toFixed(2)}% → ${r.new_value.toFixed(2)}% <span class="drift-negative">(${r.delta.toFixed(2)}%)</span></div>`).join('')}</div>`:''}
        ${drift.improvements.length?`<div class="mb-8"><div class="field-label">Improvements</div>${drift.improvements.map(i=>`<div class="drift-card improvement card mb-8" style="padding:8px 12px"><strong>${i.scope}</strong>: ${i.old_value.toFixed(2)}% → ${i.new_value.toFixed(2)}% <span class="drift-positive">(+${i.delta.toFixed(2)}%)</span></div>`).join('')}</div>`:''}
        ${drift.new_findings.length?`<div class="mb-8"><div class="field-label">New Findings</div>${drift.new_findings.map(f=>`<div style="font-size:13px;padding:4px 0">${f.scope}: <strong>${f.count}</strong> new action(s) from ${f.file||'import'}</div>`).join('')}</div>`:''}
        ${drift.resolved_findings.length?`<div class="mb-8"><div class="field-label">Resolved</div>${drift.resolved_findings.map(f=>`<div style="font-size:13px;padding:4px 0">${f.title} (was: ${f.old_status})</div>`).join('')}</div>`:''}
      </div>`;
  }

  // Expired risk acceptances
  let expiredHtml = '';
  if(r.expired_risk_acceptances > 0) {
    expiredHtml = `<div class="drift-banner negative mb-16"><span style="font-size:20px">&#9888;</span><div><strong>${r.expired_risk_acceptances} risk acceptance(s) expired</strong> and reverted to ToDo. <a href="#risks" style="text-decoration:underline">Review</a></div></div>`;
  }

  document.getElementById('imp-result').innerHTML = `${expiredHtml}${driftHtml}
    <div class="card"><div class="card-header">Import Result</div>
      <div class="grid grid-4">
        <div class="stat-card"><div class="value">${r.total_parsed}</div><div class="label">Parsed</div></div>
        <div class="stat-card"><div class="value" style="color:var(--success)">${r.new_actions}</div><div class="label">New</div></div>
        <div class="stat-card"><div class="value" style="color:var(--warning)">${r.updated_actions}</div><div class="label">Updated</div></div>
        <div class="stat-card"><div class="value" style="color:var(--purple)">${r.correlation?.actions_linked||0}</div><div class="label">Correlated</div></div>
      </div>
      ${r.compliance?.total_mappings?`<div style="margin-top:12px;font-size:13px;color:var(--text-light)">Compliance: ${r.compliance.total_mappings} mappings across ${Object.keys(r.compliance.by_framework||{}).join(', ')}</div>`:''}
      ${r.protected_actions?.length ? `<div style="margin-top:12px"><div class="field-label" style="color:var(--primary)">&#128274; Protected Actions (status preserved)</div><div style="font-size:12px;color:var(--text-light);margin-bottom:4px">These actions had their status protected during import (Risk Accepted, Completed, In Progress, Exception).</div><table class="data-table" style="font-size:12px"><thead><tr><th>Title</th><th>Current Status</th><th>Import Wanted</th></tr></thead><tbody>${r.protected_actions.map(d => `<tr><td>${d.title}</td><td>${statusBadge(d.current_status)}</td><td>${statusBadge(d.import_wanted_status)}</td></tr>`).join('')}</tbody></table></div>` : ''}
      ${r.stale_actions?.length ? `<div style="margin-top:12px"><div class="field-label" style="color:var(--warning)">&#9888; Stale Actions (${r.stale_actions.length})</div><div style="font-size:12px;color:var(--text-light);margin-bottom:4px">These actions from the same source tool were not in this import. They may be obsolete.</div><table class="data-table" style="font-size:12px"><thead><tr><th>Title</th><th>Status</th><th>Last Seen</th></tr></thead><tbody>${r.stale_actions.slice(0,20).map(d => `<tr><td>${d.title}</td><td>${statusBadge(d.status)}</td><td>${d.last_seen?.substring(0,10)||'—'}</td></tr>`).join('')}</tbody></table>${r.stale_actions.length>20?`<div style="font-size:11px;color:var(--text-light)">... and ${r.stale_actions.length-20} more</div>`:''}</div>` : ''}
      ${r.updated_details?.length ? `<div style="margin-top:12px"><div class="field-label">Updated Actions (matched existing)</div><table class="data-table" style="font-size:12px"><thead><tr><th>Title</th><th>Source ID</th><th>Matched By</th></tr></thead><tbody>${r.updated_details.map(d => `<tr><td>${d.title}</td><td><code>${d.source_id}</code> ${d.source_id !== d.existing_source_id ? '← <code>'+d.existing_source_id+'</code>':''}</td><td>${d.matched_by}</td></tr>`).join('')}</tbody></table></div>` : ''}
    </div>`;
  selectedFile=null;
  // Reload ZT reports after import
  if(r.zt_report_id) loadZtReports(state.activeTenant.name);
}

function onSourceChange() {
  const src = document.getElementById('imp-source').value;
  const hint = document.getElementById('imp-source-hint');
  const uploadHint = document.getElementById('upload-hint');
  if(src === 'zero-trust-report') {
    hint.style.display = 'block';
    hint.innerHTML = 'Upload the full report directory as a <strong>ZIP file</strong> (containing ZeroTrustAssessmentReport.html and zt-export/), or just the ZeroTrustAssessmentReport.json file.';
    uploadHint.textContent = 'ZIP file (recommended) or JSON file';
  } else if(src === 'scuba') {
    hint.style.display = 'block';
    hint.innerHTML = 'Upload the ScubaGear report directory as a <strong>ZIP file</strong> (containing BaselineReports.html, ScubaResults JSON, etc.), or just the ScubaResults JSON/CSV file.';
    uploadHint.textContent = 'ZIP file (recommended), JSON, or CSV file';
  } else {
    hint.style.display = 'none';
    uploadHint.textContent = 'JSON or CSV file';
  }
  // Reset file selection
  selectedFile = null;
  document.getElementById('imp-file-name').textContent = '';
  document.getElementById('imp-btn').disabled = true;
}

async function loadZtReports(tenantName) {
  const el = document.getElementById('zt-reports-section');
  if(!el) return;
  const reports = await api.get(`/api/tenants/${tenantName}/zt-reports`);
  if(!reports.length) { el.innerHTML = ''; return; }

  const rows = reports.map(r => {
    const date = r.imported_at ? new Date(r.imported_at).toLocaleString() : '';
    const execDate = r.executed_at ? new Date(r.executed_at).toLocaleString() : '';
    const pct = r.total_tests > 0 ? Math.round(r.passed_tests / r.total_tests * 100) : 0;
    const pctColor = pct >= 60 ? 'var(--success)' : pct >= 30 ? 'var(--warning)' : 'var(--danger)';
    const htmlBtn = r.html_path ? `<button class="btn btn-sm" onclick="window.open('/api/zt-reports/${r.id}/html','_blank')">Open Report</button>` : '';
    const summary = r.test_result_summary || {};
    const summaryParts = [];
    if(summary.IdentityTotal) summaryParts.push(`Identity: ${summary.IdentityPassed}/${summary.IdentityTotal}`);
    if(summary.DevicesTotal) summaryParts.push(`Devices: ${summary.DevicesPassed}/${summary.DevicesTotal}`);
    if(summary.DataTotal) summaryParts.push(`Data: ${summary.DataPassed}/${summary.DataTotal}`);
    const summaryText = summaryParts.join(' | ') || '';
    return `<tr>
      <td>${date}</td>
      <td>${execDate}</td>
      <td>${r.report_domain || r.report_tenant_name || ''}</td>
      <td style="color:${pctColor};font-weight:600">${r.passed_tests}/${r.total_tests} (${pct}%)</td>
      <td style="font-size:12px">${summaryText}</td>
      <td>${r.tool_version || ''}</td>
      <td>${htmlBtn} <button class="btn btn-sm" onclick="showZtReportDetail('${r.id}')">Details</button></td>
    </tr>`;
  }).join('');

  el.innerHTML = `
    <div class="card mt-16">
      <div class="card-header">Zero Trust Assessment Reports</div>
      <table class="data-table">
        <thead><tr><th>Imported</th><th>Executed</th><th>Domain</th><th>Pass Rate</th><th>Summary</th><th>Version</th><th>Actions</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

async function showZtReportDetail(reportId) {
  const r = await api.get(`/api/zt-reports/${reportId}`);
  if(r.error) return toast(r.error, 'error');

  const summary = r.test_result_summary || {};
  const ti = r.tenant_info || {};

  // Build tenant overview
  const tenantOverview = ti.TenantOverview || {};
  let overviewHtml = '';
  if(Object.keys(tenantOverview).length) {
    overviewHtml = '<div class="grid grid-4" style="margin:12px 0">' +
      Object.entries(tenantOverview).map(([k,v]) => `<div class="stat-card"><div class="value">${v}</div><div class="label">${k.replace(/([A-Z])/g,' $1').trim()}</div></div>`).join('') +
      '</div>';
  }

  // Build summary stats
  let summaryHtml = '<div class="grid grid-3" style="margin:12px 0">';
  if(summary.IdentityTotal) summaryHtml += `<div class="stat-card"><div class="value">${summary.IdentityPassed}/${summary.IdentityTotal}</div><div class="label">Identity</div></div>`;
  if(summary.DevicesTotal) summaryHtml += `<div class="stat-card"><div class="value">${summary.DevicesPassed}/${summary.DevicesTotal}</div><div class="label">Devices</div></div>`;
  if(summary.DataTotal) summaryHtml += `<div class="stat-card"><div class="value">${summary.DataPassed}/${summary.DataTotal}</div><div class="label">Data</div></div>`;
  summaryHtml += '</div>';

  const htmlBtn = r.html_path ? `<button class="btn btn-primary" onclick="window.open('/api/zt-reports/${r.id}/html','_blank')">Open Full HTML Report</button>` : '';

  openModal('Zero Trust Report Details', `
    <div style="margin-bottom:16px">
      <div class="grid grid-2" style="gap:8px;font-size:13px">
        <div><strong>Domain:</strong> ${r.report_domain||'—'}</div>
        <div><strong>Tenant:</strong> ${r.report_tenant_name||'—'}</div>
        <div><strong>Account:</strong> ${r.report_account||'—'}</div>
        <div><strong>Tool Version:</strong> ${r.tool_version||'—'}</div>
        <div><strong>Executed:</strong> ${r.executed_at ? new Date(r.executed_at).toLocaleString() : '—'}</div>
        <div><strong>Imported:</strong> ${new Date(r.imported_at).toLocaleString()}</div>
      </div>
    </div>
    <div class="field-label">Test Results</div>
    ${summaryHtml}
    <div style="font-size:13px;margin:8px 0">Total: <strong>${r.total_tests}</strong> tests | Passed: <strong style="color:var(--success)">${r.passed_tests}</strong> | Failed: <strong style="color:var(--danger)">${r.failed_tests}</strong></div>
    ${overviewHtml ? '<div class="field-label" style="margin-top:16px">Tenant Overview</div>' + overviewHtml : ''}
    <div style="margin-top:16px">${htmlBtn}</div>`,
    `<button class="btn" onclick="closeModal()">Close</button>`);
}

// ── Plans ──
async function renderPlans() {
  if(!requireTenant()) return;
  const t = state.activeTenant.name;
  const plans = await api.get(`/api/tenants/${t}/plans`);
  document.getElementById('topbar-actions').innerHTML = '<button class="btn btn-primary" onclick="showCreatePlan()">+ New Plan</button>';

  let html = '';
  if(!plans.length) {
    html = '<div class="card text-center" style="padding:60px"><h3>No remediation plans yet</h3><p style="color:var(--text-light);margin:12px 0">Create a plan to simulate and prioritize security improvements</p><button class="btn btn-primary" onclick="showCreatePlan()">+ Create Plan</button></div>';
  } else {
    const statusColors = {Draft:'gray', Active:'success', Completed:'info', Archived:'warning'};
    html = plans.map(p => `
      <div class="card mb-16" style="cursor:pointer" onclick="viewPlan('${p.id}')">
        <div class="flex justify-between items-center">
          <div class="card-header" style="margin:0">${p.name} <span class="badge badge-${statusColors[p.status]||'gray'}">${p.status}</span></div>
          <div class="flex gap-8">
            <button class="btn btn-sm btn-primary" onclick="viewPlan('${p.id}');event.stopPropagation()">Open</button>
            <button class="btn btn-sm btn-danger" onclick="deletePlan('${p.id}');event.stopPropagation()">Delete</button>
          </div>
        </div>
        <p style="font-size:13px;color:var(--text-light);margin:8px 0 4px">${p.description||'No description'}</p>
        <div style="font-size:13px;display:flex;gap:16px;flex-wrap:wrap">
          <span>${p.item_count} actions</span>
          ${p.responsible_person?`<span>&#128100; ${p.responsible_person}</span>`:''}
          ${p.priority?`<span>${priorityBadge(p.priority)}</span>`:''}
          ${p.implementation_effort?`<span>Effort: ${p.implementation_effort}</span>`:''}
          ${p.start_date?`<span>${p.start_date}${p.end_date?' → '+p.end_date:''}</span>`:''}
          <span style="color:var(--text-light)">Created ${p.created_at?.substring(0,10)}</span>
        </div>
      </div>`).join('');
  }
  document.getElementById('content').innerHTML = html;
}

async function showCreatePlan() {
  if(!requireTenant()) return;
  const t = state.activeTenant.name;
  const actions = await api.get(`/api/tenants/${t}/actions?status=ToDo`);
  const inProgress = await api.get(`/api/tenants/${t}/actions?status=In Progress`);
  const allPending = [...actions, ...inProgress];

  let rows = allPending.map(a => `<tr><td><input type="checkbox" value="${a.id}" class="plan-action-cb"></td><td>${a.title.substring(0,50)}</td><td>${priorityBadge(a.priority)}</td><td>${a.workload}</td><td>${a.implementation_effort}</td></tr>`).join('');

  const effortOpts = ['Small','Medium','Large'].map(e => `<option value="${e}"${e==='Medium'?' selected':''}>${e}</option>`).join('');
  const prioOpts = ['Critical','High','Medium','Low'].map(p => `<option value="${p}"${p==='Medium'?' selected':''}>${p}</option>`).join('');

  openModal('Create Remediation Plan', `
    <div class="form-group"><label>Plan Name</label><input id="p-name" placeholder="Q1 2026 Security Uplift"></div>
    <div class="form-group"><label>Description</label><textarea id="p-desc" rows="2"></textarea></div>
    <div class="form-row">
      <div class="form-group"><label>Responsible Person</label><input id="p-responsible" placeholder="e.g. John Smith"></div>
      <div class="form-group"><label>Priority</label><select id="p-priority">${prioOpts}</select></div>
    </div>
    <div class="form-row">
      <div class="form-group"><label>Start Date</label><input id="p-start" type="date"></div>
      <div class="form-group"><label>End Date</label><input id="p-end" type="date"></div>
    </div>
    <div class="form-group"><label>Implementation Effort</label><select id="p-effort">${effortOpts}</select>
      <div style="font-size:11px;color:var(--text-light);margin-top:2px">Small: Within a day &middot; Medium: Within a week &middot; Large: Within a month</div>
    </div>
    <div class="card-header">Select Actions (${allPending.length} pending)</div>
    <div style="max-height:300px;overflow-y:auto">
      <table><thead><tr><th><input type="checkbox" onchange="document.querySelectorAll('.plan-action-cb').forEach(c=>c.checked=this.checked)"></th><th>Title</th><th>Priority</th><th>Workload</th><th>Effort</th></tr></thead><tbody>${rows}</tbody></table>
    </div>`,
    '<button class="btn" onclick="closeModal()">Cancel</button><button class="btn btn-primary" onclick="createPlan()">Create & Simulate</button>');
}

async function createPlan() {
  const name = document.getElementById('p-name').value;
  if(!name) return toast('Name required','error');
  const ids = [...document.querySelectorAll('.plan-action-cb:checked')].map(c=>c.value);
  if(!ids.length) return toast('Select at least one action','error');
  const r = await api.post(`/api/tenants/${state.activeTenant.name}/plans`, {
    name, description:document.getElementById('p-desc').value, action_ids:ids,
    responsible_person:document.getElementById('p-responsible').value,
    priority:document.getElementById('p-priority').value,
    start_date:document.getElementById('p-start').value||null,
    end_date:document.getElementById('p-end').value||null,
    implementation_effort:document.getElementById('p-effort').value
  });
  if(r.error) return toast(r.error,'error');
  closeModal();
  toast('Plan created','success');
  viewPlan(r.id);
}

let _currentPlanId = null;

async function viewPlan(planId) {
  if(!requireTenant()) return;
  _currentPlanId = planId;
  const t = state.activeTenant.name;
  const plan = await api.get(`/api/plans/${planId}`);
  const actionIds = plan.items.map(i => i.action_id);

  let sim = {actions_count:0, percentage_gain:0, current_percentage:0, projected_percentage:0, by_tool:{}, essential_eight_impact:{}, risk_reduction:{}, licences_needed:[], effort_breakdown:{}, user_impact_summary:{}};
  let suggestedPhases = [];
  if(actionIds.length) {
    [sim, suggestedPhases] = await Promise.all([
      api.post(`/api/tenants/${t}/simulate`, {action_ids:actionIds}),
      api.post(`/api/tenants/${t}/suggest-phases`, {action_ids:actionIds, num_phases:3})
    ]);
  }

  // Fetch all actions for detail expansion
  const allActions = await api.get(`/api/tenants/${t}/actions`);
  const actionMap = {};
  allActions.forEach(a => actionMap[a.id] = a);

  let toolImpact = Object.entries(sim.by_tool||{}).map(([tool,d]) => `
    <div class="mb-8"><div class="flex justify-between"><span style="font-size:13px">${tool}</span><span style="font-size:13px;font-weight:600;color:var(--success)">+${d.percentage_gain?.toFixed(2)||0}%</span></div>
    <div class="flex gap-8" style="font-size:12px;color:var(--text-light)">${d.current_percentage?.toFixed(2)}% → ${d.projected_percentage?.toFixed(2)}% (${d.actions_resolved} actions)</div>
    ${progressBar(d.projected_percentage)}</div>`).join('');

  let e8Impact = Object.entries(sim.essential_eight_impact||{}).map(([ctrl,d]) => `
    <div style="font-size:13px;padding:4px 0">${ctrl}: <strong>${d.actions_resolved}</strong> actions → ${d.maturity_levels.join(', ')}</div>`).join('');

  let riskReduction = Object.entries(sim.risk_reduction||{}).map(([level,n]) => `<span class="badge badge-${level==='Critical'||level==='High'?'danger':'warning'}">${n}x ${level}</span>`).join(' ');

  // Phase names
  const phaseNames = {1:'Quick Wins', 2:'Core Controls', 3:'Advanced Hardening'};
  const phaseColors = {1:'var(--success)', 2:'var(--primary)', 3:'var(--warning)'};

  // Group items by phase
  const byPhase = {1:[], 2:[], 3:[]};
  plan.items.forEach(item => {
    const ph = item.phase || 1;
    if(!byPhase[ph]) byPhase[ph] = [];
    byPhase[ph].push(item);
  });

  // Render phase cards with clickable items
  function renderPhaseCard(phaseNum) {
    const items = byPhase[phaseNum] || [];
    const phName = phaseNames[phaseNum];
    const phColor = phaseColors[phaseNum];
    let phaseScore = 0;
    items.forEach(a => { if(a.score && a.max_score && a.status !== 'Completed') phaseScore += a.max_score - (a.score||0); });

    const rows = items.map(a => {
      const full = actionMap[a.action_id] || a;
      const scoreDisplay = a.score != null && a.max_score != null ? a.score+'/'+a.max_score : '-';
      // Phase move dropdown options (other phases)
      const moveOpts = [1,2,3].filter(p=>p!==phaseNum).map(p =>
        `<option value="${p}">${phaseNames[p]}</option>`
      ).join('');
      return `<tr onclick="togglePlanActionDetail('plan-${a.action_id}')" style="cursor:pointer" id="plan-row-${a.action_id}">
        <td>${a.title}</td>
        <td>${statusBadge(a.status||'ToDo')}</td>
        <td>${priorityBadge(a.priority||'Medium')}</td>
        <td style="font-size:12px">${a.workload||''}</td>
        <td style="font-size:12px">${a.implementation_effort||'Medium'}</td>
        <td>${scoreDisplay}</td>
        <td onclick="event.stopPropagation()">
          <select onchange="movePlanItemPhase('${planId}','${a.action_id}',this.value)" style="font-size:11px;padding:2px 4px;border:1px solid var(--border);border-radius:4px;background:var(--bg)">
            <option value="" disabled selected>Move</option>
            ${moveOpts}
          </select>
        </td>
        <td onclick="event.stopPropagation()"><button class="btn btn-sm" onclick="removePlanItem('${planId}','${a.action_id}')" title="Remove" style="padding:2px 6px;font-size:11px;color:var(--danger)">&times;</button></td>
      </tr>
      <tr id="detail-plan-${a.action_id}" class="hidden"><td colspan="8" style="padding:0">${actionDetailHtml(full)}</td></tr>`;
    }).join('');

    return `<div class="card mb-16">
      <div class="flex justify-between items-center" style="border-left:4px solid ${phColor};padding-left:12px">
        <div>
          <div class="card-header" style="margin:0">Phase ${phaseNum} — ${phName}</div>
          <div style="font-size:12px;color:var(--text-light)">${items.length} actions${phaseScore>0?' &middot; Est. score gain: +'+phaseScore.toFixed(0):''}</div>
        </div>
        <span class="badge" style="background:${phColor};color:#fff;font-size:14px">${items.length}</span>
      </div>
      ${items.length ? `<div class="table-wrap" style="margin-top:12px"><table><thead><tr><th>Action</th><th>Status</th><th>Priority</th><th>Workload</th><th>Effort</th><th>Score</th><th style="width:80px">Move to</th><th style="width:40px"></th></tr></thead><tbody>${rows}</tbody></table></div>` : '<div style="padding:16px;text-align:center;color:var(--text-light);font-style:italic">No actions in this phase. Move actions here or add new ones.</div>'}
    </div>`;
  }

  const statusOpts = ['Draft','Active','Completed','Archived'].map(s => `<option value="${s}" ${s===plan.status?'selected':''}>${s}</option>`).join('');

  document.getElementById('content').innerHTML = `
    <button class="btn mb-16" onclick="renderPlans()">&larr; Back to Plans</button>

    <div class="card mb-16">
      <div class="flex justify-between items-center mb-8">
        <h2 style="margin:0">${plan.name}</h2>
        <div class="flex gap-8 items-center">
          <select id="plan-status" onchange="updatePlanStatus('${planId}', this.value)" style="padding:4px 8px;border-radius:4px;border:1px solid var(--border)">${statusOpts}</select>
          <button class="btn btn-sm" onclick="showEditPlan('${planId}')">Edit</button>
          <button class="btn btn-sm" onclick="exportPlanPDF('${planId}')">PDF Report</button>
          <button class="btn btn-sm btn-danger" onclick="deletePlan('${planId}')">Delete</button>
        </div>
      </div>
      <p style="color:var(--text-light);margin:0 0 8px">${plan.description||'No description'}</p>
      <div style="display:flex;gap:24px;font-size:13px;flex-wrap:wrap">
        ${plan.responsible_person?`<div><span style="color:var(--text-light)">Responsible:</span> <strong>${plan.responsible_person}</strong></div>`:''}
        ${plan.priority?`<div><span style="color:var(--text-light)">Priority:</span> ${priorityBadge(plan.priority)}</div>`:''}
        ${plan.implementation_effort?`<div><span style="color:var(--text-light)">Effort:</span> <strong>${plan.implementation_effort}</strong>${plan.implementation_effort==='Small'?' (within a day)':plan.implementation_effort==='Medium'?' (within a week)':plan.implementation_effort==='Large'?' (within a month)':''}</div>`:''}
        ${plan.start_date?`<div><span style="color:var(--text-light)">Start:</span> ${plan.start_date}</div>`:''}
        ${plan.end_date?`<div><span style="color:var(--text-light)">End:</span> ${plan.end_date}</div>`:''}
      </div>
    </div>

    <div class="grid grid-4 mb-16">
      <div class="card stat-card"><div class="value">${sim.actions_count}</div><div class="label">Actions to Implement</div></div>
      <div class="card stat-card"><div class="value" style="color:var(--success)">+${sim.percentage_gain?.toFixed(2)}%</div><div class="label">Projected Score Gain</div></div>
      <div class="card stat-card">${gauge(sim.current_percentage||0, 100, 'Current')}</div>
      <div class="card stat-card">${gauge(sim.projected_percentage||0, 100, 'Projected')}</div>
    </div>

    <div class="flex justify-between items-center mb-8">
      <h3 style="margin:0">Phased Rollout</h3>
      <div class="flex gap-8">
        <button class="btn btn-sm" onclick="autoAssignPhases('${planId}')" title="Auto-assign actions to phases based on ROI, effort, and licence requirements">Auto-assign Phases</button>
        <button class="btn btn-sm btn-primary" onclick="showAddActionsToPlan('${planId}')">+ Add Actions</button>
      </div>
    </div>
    ${renderPhaseCard(1)}
    ${renderPhaseCard(2)}
    ${renderPhaseCard(3)}

    <div class="grid grid-2 mb-16">
      <div class="card"><div class="card-header">Impact by Source Tool</div>${toolImpact||'<div style="color:var(--text-light)">No data</div>'}</div>
      <div class="card">
        <div class="card-header">Risk Reduction</div><div class="mb-8">${riskReduction||'<span style="color:var(--text-light)">N/A</span>'}</div>
        <div class="card-header mt-16">Essential Eight Impact</div>${e8Impact||'<div style="color:var(--text-light)">No E8 mapped actions</div>'}
        <div class="card-header mt-16">Licences Required</div><div style="font-size:13px">${sim.licences_needed?.join(', ')||'None'}</div>
        <div class="card-header mt-16">Effort Breakdown</div><div style="font-size:13px">${Object.entries(sim.effort_breakdown||{}).map(([e,n])=>`${n}x ${e}`).join(', ')||'N/A'}</div>
        <div class="card-header mt-16">User Impact</div><div style="font-size:13px">${Object.entries(sim.user_impact_summary||{}).map(([e,n])=>`${n}x ${e}`).join(', ')||'N/A'}</div>
      </div>
    </div>`;
  setTimeout(applySort, 50);
}

let _planExpandedAction = null;
function togglePlanActionDetail(id) {
  const el = document.getElementById('detail-'+id);
  if(!el) return;
  if(_planExpandedAction && _planExpandedAction!==id) {
    const prev = document.getElementById('detail-'+_planExpandedAction);
    if(prev) prev.classList.add('hidden');
  }
  el.classList.toggle('hidden');
  _planExpandedAction = el.classList.contains('hidden') ? null : id;
}

async function movePlanItemPhase(planId, actionId, newPhase) {
  await api.put(`/api/plans/${planId}/items/${actionId}`, {phase: parseInt(newPhase)});
  toast('Moved to Phase ' + newPhase, 'success');
  viewPlan(planId);
}

async function autoAssignPhases(planId) {
  const t = state.activeTenant.name;
  const plan = await api.get(`/api/plans/${planId}`);
  const actionIds = plan.items.map(i => i.action_id);
  if(!actionIds.length) return toast('No actions in plan','error');

  const phases = await api.post(`/api/tenants/${t}/suggest-phases`, {action_ids:actionIds, num_phases:3});

  // Update each item's phase based on suggestion
  for(let phIdx=0; phIdx<phases.length; phIdx++) {
    const ph = phases[phIdx];
    for(const a of ph.actions) {
      await api.put(`/api/plans/${planId}/items/${a.id}`, {phase: phIdx+1});
    }
  }
  toast('Phases auto-assigned based on ROI analysis','success');
  viewPlan(planId);
}

async function updatePlanStatus(planId, status) {
  await api.put(`/api/plans/${planId}`, {status});
  toast('Plan status updated to ' + status, 'success');
}

async function showEditPlan(planId) {
  const plan = await api.get(`/api/plans/${planId}`);
  const effortOpts = ['Small','Medium','Large'].map(e => `<option value="${e}"${e===(plan.implementation_effort||'Medium')?' selected':''}>${e}</option>`).join('');
  const prioOpts = ['Critical','High','Medium','Low'].map(p => `<option value="${p}"${p===(plan.priority||'Medium')?' selected':''}>${p}</option>`).join('');

  openModal('Edit Plan', `
    <div class="form-group"><label>Plan Name</label><input id="ep-name" value="${(plan.name||'').replace(/"/g,'&quot;')}"></div>
    <div class="form-group"><label>Description</label><textarea id="ep-desc" rows="3">${plan.description||''}</textarea></div>
    <div class="form-row">
      <div class="form-group"><label>Responsible Person</label><input id="ep-responsible" value="${plan.responsible_person||''}"></div>
      <div class="form-group"><label>Priority</label><select id="ep-priority">${prioOpts}</select></div>
    </div>
    <div class="form-row">
      <div class="form-group"><label>Start Date</label><input id="ep-start" type="date" value="${plan.start_date||''}"></div>
      <div class="form-group"><label>End Date</label><input id="ep-end" type="date" value="${plan.end_date||''}"></div>
    </div>
    <div class="form-group"><label>Implementation Effort</label><select id="ep-effort">${effortOpts}</select>
      <div style="font-size:11px;color:var(--text-light);margin-top:2px">Small: Within a day &middot; Medium: Within a week &middot; Large: Within a month</div>
    </div>`,
    `<button class="btn" onclick="closeModal()">Cancel</button>
     <button class="btn btn-primary" onclick="submitEditPlan('${planId}')">Save</button>`);
}

async function submitEditPlan(planId) {
  const name = document.getElementById('ep-name').value;
  if(!name) return toast('Name required', 'error');
  await api.put(`/api/plans/${planId}`, {
    name, description: document.getElementById('ep-desc').value,
    responsible_person: document.getElementById('ep-responsible').value,
    priority: document.getElementById('ep-priority').value,
    start_date: document.getElementById('ep-start').value||null,
    end_date: document.getElementById('ep-end').value||null,
    implementation_effort: document.getElementById('ep-effort').value
  });
  closeModal();
  toast('Plan updated', 'success');
  viewPlan(planId);
}

async function removePlanItem(planId, actionId) {
  if(!confirm('Remove this action from the plan?')) return;
  await api.del(`/api/plans/${planId}/items/${actionId}`);
  toast('Action removed from plan', 'success');
  viewPlan(planId);
}

async function showAddActionsToPlan(planId) {
  const t = state.activeTenant.name;
  const plan = await api.get(`/api/plans/${planId}`);
  const existingIds = new Set(plan.items.map(i => i.action_id));

  const actions = await api.get(`/api/tenants/${t}/actions?status=ToDo`);
  const inProgress = await api.get(`/api/tenants/${t}/actions?status=In Progress`);
  const available = [...actions, ...inProgress].filter(a => !existingIds.has(a.id));

  if(!available.length) {
    return openModal('Add Actions to Plan', '<div style="padding:20px;text-align:center;color:var(--text-light)">All pending actions are already in this plan.</div>',
      '<button class="btn" onclick="closeModal()">Close</button>');
  }

  let rows = available.map(a => `<tr><td><input type="checkbox" value="${a.id}" class="plan-add-cb"></td><td>${a.title}</td><td>${priorityBadge(a.priority)}</td><td>${a.workload}</td><td>${a.implementation_effort}</td></tr>`).join('');

  openModal('Add Actions to Plan', `
    <div style="font-size:13px;color:var(--text-light);margin-bottom:8px">${available.length} actions available (already in plan excluded)</div>
    <div class="form-group"><label>Add to Phase</label>
      <select id="plan-add-phase">
        <option value="1">Phase 1 — Quick Wins</option>
        <option value="2">Phase 2 — Core Controls</option>
        <option value="3">Phase 3 — Advanced Hardening</option>
      </select>
    </div>
    <div style="max-height:350px;overflow-y:auto">
      <table><thead><tr><th><input type="checkbox" onchange="document.querySelectorAll('.plan-add-cb').forEach(c=>c.checked=this.checked)"></th><th>Title</th><th>Priority</th><th>Workload</th><th>Effort</th></tr></thead><tbody>${rows}</tbody></table>
    </div>`,
    `<button class="btn" onclick="closeModal()">Cancel</button>
     <button class="btn btn-primary" onclick="submitAddActionsToPlan('${planId}')">Add Selected</button>`);
}

async function submitAddActionsToPlan(planId) {
  const ids = [...document.querySelectorAll('.plan-add-cb:checked')].map(c => c.value);
  if(!ids.length) return toast('Select at least one action', 'error');
  const phase = parseInt(document.getElementById('plan-add-phase')?.value || '1');
  for(const aid of ids) {
    await api.post(`/api/plans/${planId}/items`, {action_id: aid, phase: phase});
  }
  closeModal();
  toast(ids.length + ' action' + (ids.length>1?'s':'') + ' added', 'success');
  viewPlan(planId);
}

async function exportPlanPDF(planId) {
  const t = state.activeTenant.name;
  const [plan, sim] = await Promise.all([
    api.get(`/api/plans/${planId}`),
    api.post(`/api/tenants/${t}/simulate`, {action_ids: (await api.get(`/api/plans/${planId}`)).items.map(i=>i.action_id)}).catch(()=>({}))
  ]);
  const tenant = state.activeTenant;
  const today = new Date().toLocaleDateString('en-US', {year:'numeric',month:'long',day:'numeric'});

  // Group by priority
  const byPriority = {};
  (plan.items||[]).forEach(a => { const p=a.priority||'Medium'; if(!byPriority[p]) byPriority[p]=[]; byPriority[p].push(a); });
  // Group by workload
  const byWorkload = {};
  (plan.items||[]).forEach(a => { const w=a.workload||'General'; if(!byWorkload[w]) byWorkload[w]=[]; byWorkload[w].push(a); });
  // Status counts
  const statusCounts = {};
  (plan.items||[]).forEach(a => { statusCounts[a.status||'ToDo'] = (statusCounts[a.status||'ToDo']||0)+1; });

  let actionRows = (plan.items||[]).map((a,i) => `<tr>
    <td>${i+1}</td><td>${a.title||''}</td><td>${a.status||''}</td><td>${a.priority||''}</td>
    <td>${a.workload||''}</td><td>${a.implementation_effort||''}</td>
    <td>${a.responsible||''}</td>
    <td>${a.score!=null?a.score+'/'+a.max_score:'—'}</td>
  </tr>`).join('');

  const w = window.open('', '_blank');
  w.document.write(`<!DOCTYPE html><html><head><title>${plan.name} - Plan Report</title>
  <style>
    body{font-family:Arial,sans-serif;margin:40px;color:#1e293b;font-size:13px}
    h1{font-size:22px;margin-bottom:4px} h2{font-size:16px;margin-top:24px;border-bottom:2px solid #3b82f6;padding-bottom:4px}
    .meta{color:#64748b;font-size:12px;margin-bottom:20px}
    .kpi-row{display:flex;gap:16px;margin:16px 0}
    .kpi{flex:1;border:1px solid #e2e8f0;border-radius:8px;padding:12px;text-align:center}
    .kpi .val{font-size:24px;font-weight:700;color:#3b82f6} .kpi .lbl{font-size:11px;color:#64748b;margin-top:4px}
    table{width:100%;border-collapse:collapse;margin:8px 0} th,td{border:1px solid #e2e8f0;padding:6px 8px;text-align:left;font-size:12px}
    th{background:#f1f5f9;font-weight:600} tr:nth-child(even){background:#f8fafc}
    .badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}
    .green{color:#10b981} .red{color:#ef4444} .yellow{color:#f59e0b}
    @media print{body{margin:20px}}
  </style></head><body>
  <h1>${plan.name}</h1>
  <div class="meta">${tenant.display_name||tenant.name} &middot; ${today} &middot; Status: ${plan.status}</div>
  ${plan.description?`<p style="margin:12px 0 0;color:#475569">${plan.description}</p>`:''}

  <h2>Plan Details</h2>
  <table>
    <tbody>
      ${plan.responsible_person?`<tr><td style="width:180px;font-weight:600">Responsible</td><td>${plan.responsible_person}</td></tr>`:''}
      ${plan.start_date?`<tr><td style="font-weight:600">Start Date</td><td>${plan.start_date}</td></tr>`:''}
      ${plan.end_date?`<tr><td style="font-weight:600">End Date</td><td>${plan.end_date}</td></tr>`:''}
      ${plan.start_date&&plan.end_date?`<tr><td style="font-weight:600">Duration</td><td>${Math.ceil((new Date(plan.end_date)-new Date(plan.start_date))/(1000*60*60*24))} days</td></tr>`:''}
      <tr><td style="font-weight:600">Implementation Effort</td><td>${(()=>{const efforts={};(plan.items||[]).forEach(a=>{const e=a.implementation_effort||'Unknown';efforts[e]=(efforts[e]||0)+1;});return Object.entries(efforts).map(([e,n])=>e+': '+n).join(', ')||'N/A';})()}</td></tr>
    </tbody>
  </table>

  <h2>Key Performance Indicators</h2>
  <div class="kpi-row">
    <div class="kpi"><div class="val">${plan.items?.length||0}</div><div class="lbl">Total Actions</div></div>
    <div class="kpi"><div class="val green">+${(sim.percentage_gain||0).toFixed(1)}%</div><div class="lbl">Projected Score Gain</div></div>
    <div class="kpi"><div class="val">${(sim.current_percentage||0).toFixed(1)}%</div><div class="lbl">Current Score</div></div>
    <div class="kpi"><div class="val green">${(sim.projected_percentage||0).toFixed(1)}%</div><div class="lbl">Projected Score</div></div>
  </div>

  <h2>Status Breakdown</h2>
  <div class="kpi-row">${Object.entries(statusCounts).map(([s,n])=>`<div class="kpi"><div class="val">${n}</div><div class="lbl">${s}</div></div>`).join('')}</div>

  <h2>By Priority</h2>
  <table><thead><tr><th>Priority</th><th>Count</th><th>Actions</th></tr></thead><tbody>
  ${Object.entries(byPriority).map(([p,acts])=>`<tr><td>${p}</td><td>${acts.length}</td><td style="font-size:11px">${acts.map(a=>a.title?.substring(0,40)).join(', ')}</td></tr>`).join('')}
  </tbody></table>

  <h2>By Workload</h2>
  <table><thead><tr><th>Workload</th><th>Count</th></tr></thead><tbody>
  ${Object.entries(byWorkload).map(([w,acts])=>`<tr><td>${w}</td><td>${acts.length}</td></tr>`).join('')}
  </tbody></table>

  <h2>All Planned Actions</h2>
  <table><thead><tr><th>#</th><th>Title</th><th>Status</th><th>Priority</th><th>Workload</th><th>Effort</th><th>Responsible</th><th>Score</th></tr></thead>
  <tbody>${actionRows}</tbody></table>

  <div style="margin-top:30px;font-size:11px;color:#64748b;border-top:1px solid #e2e8f0;padding-top:8px">
    Generated by M365 Security Posture Manager &middot; ${today}
  </div>
  </body></html>`);
  w.document.close();
  setTimeout(()=>w.print(), 500);
}

async function deletePlan(id) {
  if(!confirm('Delete this plan?')) return;
  await api.del(`/api/plans/${id}`);
  toast('Plan deleted','success'); renderPlans();
}

// ── People & Assignments ──
let _peopleView = 'list'; // 'list' or 'kanban'
let _peopleFilter = '';

async function renderPeople() {
  const c = document.getElementById('content');
  const [persons, allActions] = await Promise.all([
    api.get('/api/responsible-persons'),
    requireTenant() ? api.get(`/api/tenants/${state.activeTenant.name}/actions`) : Promise.resolve([]),
  ]);
  const assignments = requireTenant() ? await api.get(`/api/tenants/${state.activeTenant.name}/action-persons`) : {};
  // Build reverse map: person_id -> [actions]
  const personActions = {};
  persons.forEach(p => personActions[p.id] = []);
  for(const [aid, plist] of Object.entries(assignments)) {
    const action = allActions.find(a => a.id === aid);
    if(!action) continue;
    for(const p of plist) {
      if(!personActions[p.id]) personActions[p.id] = [];
      personActions[p.id].push(action);
    }
  }
  // Unassigned actions
  const assignedIds = new Set(Object.keys(assignments));
  const unassigned = allActions.filter(a => !assignedIds.has(a.id));

  // Plans map
  let plansMap = {};
  if(requireTenant()) {
    try {
      const plans = await api.get(`/api/tenants/${state.activeTenant.name}/plans`);
      for(const p of plans) for(const pa of (p.actions||[])) {
        if(!plansMap[pa.action_id]) plansMap[pa.action_id] = [];
        plansMap[pa.action_id].push(p.name);
      }
    } catch(e) {}
  }

  const personList = persons.map(p => {
    const acts = personActions[p.id] || [];
    const todo = acts.filter(a=>a.status==='ToDo').length;
    const prog = acts.filter(a=>a.status==='In Progress').length;
    const done = acts.filter(a=>a.status==='Completed').length;
    return `<tr>
      <td><strong>${p.name}</strong></td>
      <td style="font-size:12px">${p.email||'—'}</td>
      <td style="font-size:12px">${p.role||'—'}</td>
      <td style="font-size:12px">${p.department||'—'}</td>
      <td>${acts.length}</td>
      <td><span class="badge badge-danger">${todo}</span> <span class="badge badge-warning">${prog}</span> <span class="badge badge-success">${done}</span></td>
      <td>
        <button class="btn btn-sm" onclick="editPerson('${p.id}','${p.name.replace(/'/g,"\\'")}','${(p.email||'').replace(/'/g,"\\'")}','${(p.role||'').replace(/'/g,"\\'")}','${(p.department||'').replace(/'/g,"\\'")}')">Edit</button>
        <button class="btn btn-sm" onclick="deletePerson('${p.id}')" style="color:var(--danger)">Del</button>
      </td>
    </tr>`;
  }).join('');

  // Kanban: columns per person + unassigned
  const filterLower = _peopleFilter.toLowerCase();
  const kanbanCols = persons.map(p => {
    let acts = (personActions[p.id]||[]);
    if(filterLower) acts = acts.filter(a => a.title.toLowerCase().includes(filterLower) || a.status.toLowerCase().includes(filterLower) || a.source_tool.toLowerCase().includes(filterLower));
    const cards = acts.map(a => {
      const planBadge = plansMap[a.id] ? `<div style="font-size:10px;color:var(--primary);margin-top:4px">&#128203; ${plansMap[a.id].join(', ')}</div>` : '';
      return `<div style="padding:8px;background:var(--bg);border:1px solid var(--border);border-radius:6px;margin-bottom:6px;cursor:pointer" onclick="navigate('actions');setTimeout(()=>toggleActionDetail('${a.id}'),300)">
        <div style="font-size:12px;font-weight:500">${a.title}</div>
        <div style="margin-top:4px;display:flex;gap:4px;flex-wrap:wrap">${statusBadge(a.status)} ${priorityBadge(a.priority)}</div>
        <div style="font-size:10px;color:var(--text-light);margin-top:4px">${a.source_tool} &middot; ${a.workload}</div>
        ${planBadge}
      </div>`;
    }).join('');
    return `<div style="min-width:280px;max-width:320px;flex-shrink:0">
      <div style="font-weight:600;margin-bottom:8px;padding:6px 10px;background:var(--bg-hover);border-radius:6px;display:flex;justify-content:space-between;align-items:center">
        <span>${p.name}</span>
        <span class="badge" style="background:var(--primary);color:#fff">${acts.length}</span>
      </div>
      <div style="max-height:calc(100vh - 260px);overflow-y:auto">${cards||'<div style="color:var(--text-light);font-size:12px;padding:8px;text-align:center">No actions</div>'}</div>
    </div>`;
  }).join('');

  // Unassigned column
  let unassignedFiltered = unassigned;
  if(filterLower) unassignedFiltered = unassigned.filter(a => a.title.toLowerCase().includes(filterLower) || a.status.toLowerCase().includes(filterLower));
  const unassignedCards = unassignedFiltered.slice(0,50).map(a => {
    return `<div style="padding:8px;background:var(--bg);border:1px solid var(--border);border-radius:6px;margin-bottom:6px;font-size:12px">
      <div style="font-weight:500">${a.title}</div>
      <div style="margin-top:4px">${statusBadge(a.status)} ${priorityBadge(a.priority)}</div>
    </div>`;
  }).join('');

  c.innerHTML = `
    <div class="flex justify-between items-center mb-16">
      <div class="flex gap-8">
        <button class="btn btn-sm ${_peopleView==='list'?'btn-primary':''}" onclick="_peopleView='list';renderPeople()">List</button>
        <button class="btn btn-sm ${_peopleView==='kanban'?'btn-primary':''}" onclick="_peopleView='kanban';renderPeople()">Kanban</button>
      </div>
      <div class="flex gap-8">
        ${_peopleView==='kanban'?`<input class="form-control" style="width:200px" placeholder="Filter actions..." value="${_peopleFilter}" oninput="_peopleFilter=this.value;renderPeople()">`:''}
        <button class="btn btn-primary btn-sm" onclick="showAddPerson()">+ Add Person</button>
      </div>
    </div>
    ${_peopleView==='list' ? `
    <div class="card mb-16">
      <div class="card-header">Responsible Persons (${persons.length})</div>
      <div class="table-wrap"><table><thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Department</th><th>Actions</th><th>Status</th><th></th></tr></thead>
      <tbody>${personList||'<tr><td colspan="7" class="text-center">No persons registered. Add your first team member.</td></tr>'}</tbody></table></div>
    </div>` : `
    <div style="display:flex;gap:16px;overflow-x:auto;padding-bottom:16px">
      ${kanbanCols}
      <div style="min-width:280px;max-width:320px;flex-shrink:0">
        <div style="font-weight:600;margin-bottom:8px;padding:6px 10px;background:var(--bg-hover);border-radius:6px;display:flex;justify-content:space-between;align-items:center">
          <span style="color:var(--text-light)">Unassigned</span>
          <span class="badge">${unassigned.length}</span>
        </div>
        <div style="max-height:calc(100vh - 260px);overflow-y:auto">${unassignedCards||'<div style="color:var(--text-light);font-size:12px;padding:8px;text-align:center">All actions assigned</div>'}</div>
        ${unassigned.length>50?`<div style="font-size:11px;color:var(--text-light);text-align:center;margin-top:4px">${unassigned.length-50} more...</div>`:''}
      </div>
    </div>`}`;
}

function showAddPerson() {
  openModal('Add Person', `
    <div class="form-group"><label>Name</label><input id="rp-name" placeholder="Jane Doe"></div>
    <div class="form-group"><label>Email</label><input id="rp-email" placeholder="jane@company.com"></div>
    <div class="form-row">
      <div class="form-group"><label>Role</label><input id="rp-role" placeholder="Security Engineer"></div>
      <div class="form-group"><label>Department</label><input id="rp-department" placeholder="IT Security"></div>
    </div>`,
    `<button class="btn" onclick="closeModal()">Cancel</button><button class="btn btn-primary" onclick="addPerson()">Add</button>`);
}

async function addPerson() {
  const name = document.getElementById('rp-name').value;
  if(!name) return toast('Name is required','error');
  await api.post('/api/responsible-persons', {
    name, email:document.getElementById('rp-email').value,
    role:document.getElementById('rp-role').value,
    department:document.getElementById('rp-department').value
  });
  closeModal(); toast('Person added','success'); renderPeople();
}

function editPerson(id, name, email, role, dept) {
  openModal('Edit Person', `
    <div class="form-group"><label>Name</label><input id="rp-name" value="${name}"></div>
    <div class="form-group"><label>Email</label><input id="rp-email" value="${email}"></div>
    <div class="form-row">
      <div class="form-group"><label>Role</label><input id="rp-role" value="${role}"></div>
      <div class="form-group"><label>Department</label><input id="rp-department" value="${dept}"></div>
    </div>`,
    `<button class="btn" onclick="closeModal()">Cancel</button><button class="btn btn-primary" onclick="updatePerson('${id}')">Save</button>`);
}

async function updatePerson(id) {
  await api.put(`/api/responsible-persons/${id}`, {
    name:document.getElementById('rp-name').value,
    email:document.getElementById('rp-email').value,
    role:document.getElementById('rp-role').value,
    department:document.getElementById('rp-department').value
  });
  closeModal(); toast('Person updated','success'); renderPeople();
}

async function deletePerson(id) {
  if(!confirm('Delete this person? They will be unassigned from all actions.')) return;
  await api.del(`/api/responsible-persons/${id}`);
  toast('Person deleted','success'); renderPeople();
}

// ── Correlations ──
let _corrTab = 'results';

async function renderCorrelations() {
  if(!requireTenant()) return;
  const t = state.activeTenant.name;
  document.getElementById('topbar-actions').innerHTML = '<button class="btn btn-primary" onclick="runCorrelation()">Re-correlate</button>';

  const tabClass = tab => `atab${_corrTab===tab?' active':''}`;

  const tabBar = `<div class="card mb-16" style="padding:0">
    <div class="action-tabs" style="margin:0">
      <div class="${tabClass('results')}" onclick="_corrTab='results';renderCorrelations()">Correlation Results</div>
      <div class="${tabClass('families')}" onclick="_corrTab='families';renderCorrelations()">Manage Control Families</div>
    </div></div>`;

  if(_corrTab === 'families') {
    await renderControlFamilies(tabBar);
    return;
  }

  const corr = await api.get(`/api/tenants/${t}/correlations`);

  if(!corr.length) {
    document.getElementById('content').innerHTML = tabBar + '<div class="card text-center" style="padding:60px"><h3>No correlated actions</h3><p style="color:var(--text-light);margin:12px 0">Import data from multiple tools, then correlations will be detected automatically</p><button class="btn btn-primary" onclick="runCorrelation()">Run Correlation</button></div>';
    return;
  }

  let html = corr.map(g => `
    <div class="card mb-16">
      <div class="flex justify-between items-center">
        <div class="card-header" style="margin:0">${g.canonical_name} <span class="badge badge-${g.overall_status==='Completed'?'success':g.overall_status==='In Progress'?'info':'danger'}">${g.overall_status}</span></div>
        <button class="btn btn-sm" onclick="showAddActionToGroup('${g.group_id}','${g.canonical_name.replace(/'/g,"\\'")}')">+ Add Action</button>
      </div>
      <p style="font-size:13px;color:var(--text-light);margin-bottom:8px">${g.description}</p>
      <div style="font-size:13px;margin-bottom:8px">Found in ${g.source_count} tools: ${g.sources.join(', ')}</div>
      <div class="table-wrap"><table><thead><tr><th>Source</th><th>Title</th><th>Status</th><th>Score</th><th style="width:40px"></th></tr></thead><tbody>
        ${g.actions.map(a=>`<tr><td style="font-size:12px">${a.source_tool}</td><td>${a.title.substring(0,60)}</td><td>${statusBadge(a.status)}</td><td>${a.score!=null?a.score+'/'+a.max_score:'-'}</td><td><button class="btn btn-sm btn-danger" onclick="unlinkActionFromGroup('${a.id}');event.stopPropagation()" title="Remove from group">&times;</button></td></tr>`).join('')}
      </tbody></table></div>
    </div>`).join('');

  document.getElementById('content').innerHTML = `${tabBar}
    <div class="card mb-16"><div class="grid grid-3">
      <div class="stat-card"><div class="value">${corr.length}</div><div class="label">Control Families</div></div>
      <div class="stat-card"><div class="value">${corr.reduce((s,g)=>s+g.action_count,0)}</div><div class="label">Linked Actions</div></div>
      <div class="stat-card"><div class="value">${corr.filter(g=>g.source_count>1).length}</div><div class="label">Cross-tool Links</div></div>
    </div></div>${html}`;
}

async function renderControlFamilies(tabBar) {
  const groups = await api.get('/api/correlation-groups');

  let rows = groups.map(g => {
    const kw = (g.keywords||[]).join(', ');
    return `<tr>
      <td style="font-weight:600">${g.canonical_name}</td>
      <td style="font-size:12px;max-width:200px">${g.description||''}</td>
      <td style="font-size:11px;max-width:400px;word-break:break-word">${kw}</td>
      <td style="white-space:nowrap">
        <button class="btn btn-sm" onclick="editControlFamily('${g.id}')">Edit</button>
        <button class="btn btn-sm btn-danger" onclick="deleteControlFamily('${g.id}','${g.canonical_name.replace(/'/g,"\\'")}')">Delete</button>
      </td>
    </tr>`;
  }).join('');

  document.getElementById('content').innerHTML = `${tabBar}
    <div class="card mb-16">
      <div class="flex justify-between items-center mb-16">
        <div class="card-header" style="margin:0">Control Families (${groups.length})</div>
        <div class="flex gap-8">
          <button class="btn btn-sm" onclick="seedDefaultFamilies()">Seed Defaults</button>
          <button class="btn btn-sm btn-primary" onclick="showAddFamily()">+ Add Family</button>
        </div>
      </div>
      <p style="font-size:13px;color:var(--text-light);margin-bottom:12px">Control families define keyword patterns used to automatically group related actions across tools. Edit keywords to improve matching accuracy.</p>
      <div class="table-wrap"><table><thead><tr><th>Name</th><th>Description</th><th>Keywords</th><th>Actions</th></tr></thead>
      <tbody>${rows||'<tr><td colspan="4" class="text-center">No families defined. Click "Seed Defaults" to load built-in families.</td></tr>'}</tbody></table></div>
    </div>`;
}

async function seedDefaultFamilies() {
  const r = await api.post('/api/correlation-groups/seed-defaults');
  toast(`Seeded ${r.seeded} default families`, 'success');
  renderCorrelations();
}

function showAddFamily() {
  openModal('Add Control Family', `
    <div class="field mb-16"><label class="field-label">Name</label><input id="cf-name" class="form-control" placeholder="e.g. MFA Enforcement"></div>
    <div class="field mb-16"><label class="field-label">Description</label><input id="cf-desc" class="form-control" placeholder="Short description"></div>
    <div class="field mb-16"><label class="field-label">Keywords (comma-separated regex patterns)</label><textarea id="cf-kw" class="form-control" rows="4" placeholder="mfa, multi-factor, authenticator, ..."></textarea></div>`,
    '<button class="btn" onclick="closeModal()">Cancel</button><button class="btn btn-primary" onclick="submitAddFamily()">Save</button>');
}

async function submitAddFamily() {
  const name = document.getElementById('cf-name').value.trim();
  const desc = document.getElementById('cf-desc').value.trim();
  const kw = document.getElementById('cf-kw').value.split(',').map(k=>k.trim()).filter(Boolean);
  if(!name) return toast('Name is required','error');
  if(!kw.length) return toast('Add at least one keyword','error');
  await api.post('/api/correlation-groups', {canonical_name:name, description:desc, keywords:kw});
  closeModal();
  toast('Family created','success');
  renderCorrelations();
}

async function editControlFamily(id) {
  const groups = await api.get('/api/correlation-groups');
  const g = groups.find(x=>x.id===id);
  if(!g) return toast('Family not found','error');
  openModal('Edit Control Family', `
    <div class="field mb-16"><label class="field-label">Name</label><input id="cf-name" class="form-control" value="${g.canonical_name}"></div>
    <div class="field mb-16"><label class="field-label">Description</label><input id="cf-desc" class="form-control" value="${g.description||''}"></div>
    <div class="field mb-16"><label class="field-label">Keywords (comma-separated regex patterns)</label><textarea id="cf-kw" class="form-control" rows="4">${(g.keywords||[]).join(', ')}</textarea></div>`,
    `<button class="btn" onclick="closeModal()">Cancel</button><button class="btn btn-primary" onclick="submitEditFamily('${id}')">Save</button>`);
}

async function submitEditFamily(id) {
  const name = document.getElementById('cf-name').value.trim();
  const desc = document.getElementById('cf-desc').value.trim();
  const kw = document.getElementById('cf-kw').value.split(',').map(k=>k.trim()).filter(Boolean);
  if(!name) return toast('Name is required','error');
  await api.put(`/api/correlation-groups/${id}`, {canonical_name:name, description:desc, keywords:kw});
  closeModal();
  toast('Family updated','success');
  renderCorrelations();
}

async function deleteControlFamily(id, name) {
  if(!confirm(`Delete "${name}"? This will unlink all associated actions.`)) return;
  await api.del(`/api/correlation-groups/${id}`);
  toast('Family deleted','success');
  renderCorrelations();
}

async function runCorrelation() {
  const r = await api.post(`/api/tenants/${state.activeTenant.name}/correlate`);
  toast(`Correlated ${r.actions_linked} actions into ${r.groups_created} new groups`,'success');
  renderCorrelations();
}

async function unlinkActionFromGroup(actionId) {
  if(!confirm('Remove this action from the correlation group?')) return;
  await api.post(`/api/actions/${actionId}/unlink`);
  toast('Action removed from group','success');
  renderCorrelations();
}

async function showAddActionToGroup(groupId, groupName) {
  const t = state.activeTenant.name;
  const actions = await api.get(`/api/tenants/${t}/actions`);
  const uncorrelated = actions.filter(a => !a.correlation_group_id);
  if(!uncorrelated.length) return openModal('Add Action to Group', '<p style="padding:20px;text-align:center;color:var(--text-light)">All actions are already in correlation groups.</p>',
    '<button class="btn" onclick="closeModal()">Close</button>');

  let rows = uncorrelated.map(a => `<tr>
    <td><input type="checkbox" value="${a.id}" class="corr-add-cb"></td>
    <td style="font-size:12px">${a.source_tool}</td>
    <td>${a.title.substring(0,55)}</td>
    <td>${statusBadge(a.status)}</td>
  </tr>`).join('');

  openModal(`Add Actions to "${groupName}"`, `
    <div style="font-size:13px;color:var(--text-light);margin-bottom:8px">${uncorrelated.length} uncorrelated actions available</div>
    <div style="max-height:400px;overflow-y:auto">
      <table><thead><tr><th><input type="checkbox" onchange="document.querySelectorAll('.corr-add-cb').forEach(c=>c.checked=this.checked)"></th><th>Source</th><th>Title</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table>
    </div>`,
    `<button class="btn" onclick="closeModal()">Cancel</button><button class="btn btn-primary" onclick="submitAddActionsToGroup('${groupId}')">Link Selected</button>`);
}

async function submitAddActionsToGroup(groupId) {
  const ids = [...document.querySelectorAll('.corr-add-cb:checked')].map(c=>c.value);
  if(!ids.length) return toast('Select at least one action','error');
  for(const id of ids) {
    await api.post(`/api/actions/${id}/link`, {group_id: groupId});
  }
  closeModal();
  toast(`${ids.length} action(s) linked to group`,'success');
  renderCorrelations();
}

// ── Essential Eight ──
let _e8TargetML = 'Maturity Level 3';
let _e8ExcludeNA = false;

async function renderE8() {
  if(!requireTenant()) return;
  const params = `target=${encodeURIComponent(_e8TargetML)}&exclude_na=${_e8ExcludeNA?'1':'0'}`;
  const e8 = await api.get(`/api/tenants/${state.activeTenant.name}/e8?${params}`);

  const ov = e8.overall || {};
  const controls = e8.controls || {};
  const entries = Object.entries(controls);
  const mlDescs = e8.maturity_descriptions || {};

  // Helper: maturity level color
  function mlColor(ml) {
    if(!ml) return 'var(--text-light)';
    if(ml.includes('0')) return 'var(--danger)';
    if(ml.includes('1')) return 'var(--warning)';
    if(ml.includes('2')) return '#84cc16';
    return 'var(--success)';
  }
  function mlBadge(ml) {
    const n = ml ? ml.replace('Maturity ','') : 'Level 0';
    return `<span class="badge" style="background:${mlColor(ml)};color:#fff">${n}</span>`;
  }

  // ── Spider/Radar chart (SVG) ──
  // Short names for radar chart labels
  const _e8Short = {
    'Application Control':'App Control',
    'Patch Applications':'Patch Apps',
    'Configure Microsoft Office Macro Settings':'Office Macros',
    'User Application Hardening':'App Hardening',
    'Restrict Administrative Privileges':'Admin Privileges',
    'Patch Operating Systems':'Patch OS',
    'Multi-Factor Authentication':'MFA',
    'Regular Backups':'Backups'
  };

  function renderRadarChart(controls) {
    const cx=200,cy=200,r=130;
    const names = Object.keys(controls);
    const n = names.length;
    if(n===0) return '';
    const angleStep = (2*Math.PI)/n;

    // Grid circles
    let grid = '';
    for(let lv=1;lv<=3;lv++){
      const cr = r*(lv/3);
      grid += `<circle cx="${cx}" cy="${cy}" r="${cr}" fill="none" stroke="var(--border)" stroke-width="0.5" stroke-dasharray="3,3"/>`;
      grid += `<text x="${cx+3}" y="${cy-cr+4}" font-size="9" fill="var(--text-light)">ML${lv}</text>`;
    }

    // Axis lines and labels
    let axes = '';
    let labels = '';
    names.forEach((name, i) => {
      const angle = -Math.PI/2 + i*angleStep;
      const x2 = cx + r*Math.cos(angle);
      const y2 = cy + r*Math.sin(angle);
      axes += `<line x1="${cx}" y1="${cy}" x2="${x2}" y2="${y2}" stroke="var(--border)" stroke-width="0.5"/>`;
      const lx = cx + (r+45)*Math.cos(angle);
      const ly = cy + (r+45)*Math.sin(angle);
      const anchor = Math.abs(Math.cos(angle))<0.15?'middle':Math.cos(angle)>0?'start':'end';
      const shortName = _e8Short[name] || name.substring(0,16);
      labels += `<text x="${lx}" y="${ly}" font-size="11" fill="var(--text)" text-anchor="${anchor}" dominant-baseline="middle" font-weight="500">${shortName}</text>`;
    });

    // Compute continuous progress score (0-3) from per-ML completion percentages
    // e.g. ML1=100% + ML2=50% + ML3=0% → 1.5
    function progressScore(d) {
      const mls = d.maturity_levels || {};
      let score = 0;
      for (const ml of ['Maturity Level 1','Maturity Level 2','Maturity Level 3']) {
        const md = mls[ml] || {};
        if (md.total > 0) score += Math.min(md.percentage || 0, 100) / 100;
        else break; // no actions at this level, stop accumulating
      }
      return score;
    }

    // Achieved polygon (continuous progress)
    let achievedPts = names.map((name, i) => {
      const d = controls[name];
      const angle = -Math.PI/2 + i*angleStep;
      const pr = r*(progressScore(d)/3);
      return `${cx+pr*Math.cos(angle)},${cy+pr*Math.sin(angle)}`;
    }).join(' ');

    // Target polygon
    let targetPts = names.map((name, i) => {
      const d = controls[name];
      const angle = -Math.PI/2 + i*angleStep;
      const pr = r*(d.target_maturity_num/3);
      return `${cx+pr*Math.cos(angle)},${cy+pr*Math.sin(angle)}`;
    }).join(' ');

    return `<svg viewBox="0 0 400 400" style="width:100%;max-width:420px;height:auto">
      ${grid}${axes}
      <polygon points="${targetPts}" fill="rgba(59,130,246,0.08)" stroke="var(--primary)" stroke-width="1.5" stroke-dasharray="5,3"/>
      <polygon points="${achievedPts}" fill="rgba(34,197,94,0.2)" stroke="var(--success)" stroke-width="2"/>
      ${labels}
    </svg>`;
  }

  // ── Control cards ──
  let cards = entries.map(([ctrl, d], idx) => {
    const achievedCol = mlColor(d.achieved_maturity);

    // Maturity level progress bars
    let mlBars = ['Maturity Level 1','Maturity Level 2','Maturity Level 3'].map(ml => {
      const md = (d.maturity_levels||{})[ml] || {total:0,completed:0,percentage:0};
      const isTarget = ml === _e8TargetML;
      const short = ml.replace('Maturity ','');
      return `<div class="mb-8">
        <div class="flex justify-between"><span style="font-size:12px;${isTarget?'font-weight:600':''}">${short}${isTarget?' ★':''}</span><span style="font-size:12px">${md.completed}/${md.total}</span></div>
        ${progressBar(md.percentage)}
      </div>`;
    }).join('');

    // M365 products & features
    const products = (d.m365_products||[]).map(p=>`<span class="badge badge-info" style="font-size:10px;margin:1px">${p}</span>`).join(' ');
    const allFeatures = [...new Set([...(d.m365_features||[]), ...(d.asd_technologies||[])])];
    const features = allFeatures.slice(0,8).map(f=>`<div style="font-size:11px;color:var(--text-light);padding:1px 0">• ${f}</div>`).join('');

    // Gap analysis
    let gapSection = '';
    if(d.gap_action_count > 0) {
      const gapRows = (d.gap_actions||[]).slice(0,10).map(a => `<tr>
        <td style="font-size:11px">${a.maturity?.replace('Maturity ','')}</td>
        <td style="font-size:12px">${(a.title||'').substring(0,50)}</td>
        <td>${statusBadge(a.status)}</td>
        <td style="font-size:11px">${a.source_tool||''}</td>
      </tr>`).join('');
      gapSection = `<div style="margin-top:12px;border-top:1px solid var(--border);padding-top:12px">
        <div class="card-header" style="margin:0;font-size:13px;color:var(--danger)">Gap to Target: ${d.gap_action_count} actions needed</div>
        <div class="table-wrap" style="margin-top:8px"><table><thead><tr><th>Level</th><th>Action</th><th>Status</th><th>Source</th></tr></thead><tbody>${gapRows}</tbody></table></div>
        ${d.gap_action_count>10?`<div style="font-size:11px;color:var(--text-light);margin-top:4px">... and ${d.gap_action_count-10} more</div>`:''}
      </div>`;
    }

    // Maturity requirements (from seed data)
    let reqSection = '';
    const reqs = d.maturity_requirements || {};
    if(Object.keys(reqs).length > 0) {
      let reqPanels = ['Maturity Level 1','Maturity Level 2','Maturity Level 3'].map(ml => {
        const r = reqs[ml];
        if(!r || !r.requirements?.length) return '';
        const items = r.requirements.map(req =>
          `<div style="font-size:11px;padding:3px 0;border-bottom:1px solid var(--bg-hover)">
            <code style="font-size:10px;color:var(--primary)">${req.id}</code> ${req.text.substring(0,120)}${req.text.length>120?'...':''}
            ${req.ism?.length?`<span style="color:var(--text-light);font-size:10px"> [${req.ism.join(', ')}]</span>`:''}
          </div>`
        ).join('');
        const implNote = r.m365_implementation ? `<div style="font-size:11px;color:var(--text-light);margin-top:6px;padding:6px;background:var(--bg-hover);border-radius:4px"><strong>M365:</strong> ${r.m365_implementation}</div>` : '';
        return `<div style="margin-bottom:8px">
          <div style="font-size:12px;font-weight:600;margin-bottom:4px">${ml.replace('Maturity ','')} (${r.requirement_count} requirements)</div>
          ${items}${implNote}
        </div>`;
      }).join('');
      reqSection = `<div id="e8-reqs-${idx}" class="hidden" style="margin-top:12px;border-top:1px solid var(--border);padding-top:12px">
        <div class="card-header" style="margin:0 0 8px;font-size:13px">Maturity Requirements (ASD)</div>
        ${reqPanels}
      </div>`;
    }

    // Source tool coverage breakdown
    const sourceBreakdown = {};
    (d.actions||[]).forEach(a => {
      const s = a.source_tool || 'Unknown';
      if(!sourceBreakdown[s]) sourceBreakdown[s] = {total:0,completed:0};
      sourceBreakdown[s].total++;
      if(a.status === 'Completed') sourceBreakdown[s].completed++;
    });
    const sourceBadges = Object.entries(sourceBreakdown).map(([s,c]) =>
      `<span class="badge" style="background:var(--bg-hover);color:var(--text);font-size:10px;margin:1px">${s} <span style="color:var(--success)">${c.completed}</span>/${c.total}</span>`
    ).join(' ');

    // Action table
    let actionRows = (d.actions||[]).map(a => `<tr>
      <td style="font-size:11px;font-family:monospace">${a.reference_id||''}</td>
      <td style="font-size:12px">${a.source_tool||''}</td>
      <td>${(a.title||'').substring(0,55)}</td>
      <td>${statusBadge(a.status)}</td>
      <td>${priorityBadge(a.priority)}</td>
      <td style="font-size:12px">${a.maturity?.replace('Maturity ','')||'—'}</td>
      <td>${a.score!=null?a.score+'/'+a.max_score:'—'}</td>
      <td><button class="btn btn-sm" onclick="event.stopPropagation();removeE8Action('${a.id}')" title="Remove from E8 control" style="padding:2px 6px;font-size:11px;color:var(--danger)">&times;</button></td>
    </tr>`).join('');

    return `<div class="card mb-16">
      <div class="flex justify-between items-center" style="cursor:pointer" onclick="document.getElementById('e8-detail-${idx}').classList.toggle('hidden')">
        <div>
          <div style="display:flex;align-items:center;gap:8px">
            <span class="card-header" style="margin:0;font-size:14px">${ctrl}</span>
            <span style="font-size:11px;color:var(--text-light)">${d.control_id||''}</span>
          </div>
          <div style="font-size:12px;color:var(--text-light);margin-top:4px">
            ${d.completed_actions}/${d.total_actions} actions &middot;
            Achieved: ${mlBadge(d.achieved_maturity)}
            ${d.gap_to_target>0?` &middot; <span style="color:var(--danger)">${d.gap_action_count} gaps to target</span>`:''}
          </div>
          <div style="margin-top:4px">${products}</div>
        </div>
        <div style="flex-shrink:0">${gauge(d.percentage, 80)}</div>
      </div>
      <div id="e8-detail-${idx}" class="hidden" style="margin-top:12px;border-top:1px solid var(--border);padding-top:12px">
        ${d.objective?`<div style="font-size:12px;color:var(--text-light);margin-bottom:12px;font-style:italic">${d.objective}</div>`:''}
        <div class="grid grid-2 mb-16" style="gap:16px">
          <div>
            <div style="font-size:13px;font-weight:600;margin-bottom:8px">Maturity Progress</div>
            ${mlBars}
          </div>
          <div>
            <div style="font-size:13px;font-weight:600;margin-bottom:8px">M365 Features</div>
            ${features||'<div style="color:var(--text-light);font-size:12px">No M365 features mapped</div>'}
          </div>
        </div>
        <div style="margin-bottom:8px;display:flex;gap:8px;flex-wrap:wrap">
          <button class="btn btn-sm" onclick="event.stopPropagation();document.getElementById('e8-reqs-${idx}').classList.toggle('hidden')">ASD Requirements</button>
          <button class="btn btn-sm" onclick="event.stopPropagation();document.getElementById('e8-ms-${idx}').classList.toggle('hidden')">Microsoft Guidance</button>
          ${d.ms_doc_url?`<a class="btn btn-sm" href="${d.ms_doc_url}" target="_blank" onclick="event.stopPropagation()">Microsoft Docs</a>`:''}
          ${d.asd_url?`<a class="btn btn-sm" href="${d.asd_url}" target="_blank" onclick="event.stopPropagation()">ASD Blueprint</a>`:''}
        </div>
        ${reqSection}
        ${(()=>{
          const msg = d.ms_guidance || {};
          if(!Object.keys(msg).length) return '';
          let panels = ['ML1','ML2','ML3'].map(ml => {
            const g = msg[ml];
            if(!g) return '';
            const configs = (g.key_configurations||[]).map(c=>`<div style="font-size:11px;padding:2px 0">• ${typeof c==='string'?c:JSON.stringify(c)}</div>`).join('');
            return '<div style="margin-bottom:10px;padding:8px;background:var(--bg-hover);border-radius:4px">'+
              '<div style="font-size:12px;font-weight:600;margin-bottom:4px">'+ml+': '+g.primary_tool+'</div>'+
              '<div style="font-size:11px;color:var(--text-light);margin-bottom:4px">'+g.description+'</div>'+
              (configs?'<div style="margin-top:4px"><strong style="font-size:11px">Key Configurations:</strong>'+configs+'</div>':'')+
            '</div>';
          }).join('');
          const lic = d.ms_licensing||{};
          const licHtml = Object.keys(lic).length?'<div style="margin-top:8px;font-size:11px"><strong>Licensing:</strong> '+Object.entries(lic).map(([k,v])=>k+': '+(typeof v==='string'?v:JSON.stringify(v))).join(', ')+'</div>':'';
          return '<div id="e8-ms-'+idx+'" class="hidden" style="margin-top:12px;border-top:1px solid var(--border);padding-top:12px">'+
            '<div class="card-header" style="margin:0 0 8px;font-size:13px">Microsoft Implementation Guidance</div>'+
            panels+licHtml+'</div>';
        })()}
        ${gapSection}
        <div style="margin-top:12px;border-top:1px solid var(--border);padding-top:12px">
          <div class="flex justify-between items-center mb-8">
            <div>
              <span style="font-size:13px;font-weight:600">Mapped Actions</span>
              ${sourceBadges ? `<span style="margin-left:8px">${sourceBadges}</span>` : ''}
            </div>
            <button class="btn btn-sm" onclick="showE8AddAction('${ctrl.replace(/'/g,"\\'")}', '${d.control_id||''}')">+ Add Action</button>
          </div>
          ${actionRows ? `<div class="table-wrap"><table><thead><tr><th>Ref</th><th>Source</th><th>Title</th><th>Status</th><th>Priority</th><th>Level</th><th>Score</th><th style="width:40px"></th></tr></thead><tbody>${actionRows}</tbody></table></div>` : '<div style="color:var(--text-light);padding:8px;background:var(--bg-hover);border-radius:6px;text-align:center">No actions mapped to this control. Use the button above to add actions, or import data from Secure Score / SCuBA / Zero Trust.</div>'}
        </div>
      </div>
    </div>`;
  }).join('');

  // ── Maturity summary table ──
  let matSummaryRows = entries.map(([ctrl,d]) => {
    const cells = ['Maturity Level 1','Maturity Level 2','Maturity Level 3'].map(ml => {
      const md = (d.maturity_levels||{})[ml] || {percentage:0,total:0,completed:0};
      const bg = md.percentage>=80?'var(--success)':md.percentage>=50?'var(--warning)':md.percentage>0?'var(--danger)':'var(--bg-hover)';
      const txt = md.total>0?md.completed+'/'+md.total:'-';
      const clr = md.total>0?'#fff':'var(--text-light)';
      return `<td style="text-align:center"><span class="badge" style="background:${bg};color:${clr};min-width:40px">${txt}</span></td>`;
    }).join('');
    return `<tr><td style="font-size:12px">${ctrl}</td><td>${mlBadge(d.achieved_maturity)}</td>${cells}</tr>`;
  }).join('');

  const radarChart = renderRadarChart(controls);

  document.getElementById('content').innerHTML = `
    <div class="flex justify-between items-center mb-16">
      <h2 style="margin:0">Essential Eight Assessment</h2>
      <div style="display:flex;gap:12px;align-items:center">
        <label style="font-size:12px;display:flex;align-items:center;gap:6px">
          <input type="checkbox" ${_e8ExcludeNA?'checked':''} onchange="_e8ExcludeNA=this.checked;renderE8()"> Exclude N/A & Risk Accepted
        </label>
        <select class="input" style="width:auto;font-size:12px" onchange="_e8TargetML=this.value;renderE8()">
          <option ${_e8TargetML==='Maturity Level 1'?'selected':''}>Maturity Level 1</option>
          <option ${_e8TargetML==='Maturity Level 2'?'selected':''}>Maturity Level 2</option>
          <option ${_e8TargetML==='Maturity Level 3'?'selected':''}>Maturity Level 3</option>
        </select>
      </div>
    </div>

    <div class="card mb-16"><div class="grid grid-4">
      <div class="stat-card">${gauge(ov.overall_percentage||0, 100)}<div class="label">Overall E8</div></div>
      <div class="stat-card"><div class="value">${ov.total_actions||0}</div><div class="label">Actions Mapped</div></div>
      <div class="stat-card"><div class="value" style="color:var(--success)">${ov.total_completed||0}</div><div class="label">Completed</div></div>
      <div class="stat-card">
        <div style="display:flex;align-items:center;gap:8px">
          ${mlBadge(ov.overall_achieved_maturity)}
        </div>
        <div class="label" style="margin-top:8px">Overall Achieved</div>
        ${ov.total_gap_actions>0?`<div style="font-size:11px;color:var(--danger);margin-top:2px">${ov.total_gap_actions} gaps to target</div>`:''}
      </div>
    </div></div>

    <div class="grid grid-2 mb-16" style="gap:16px">
      <div class="card" style="display:flex;flex-direction:column;align-items:center;padding:16px">
        ${radarChart}
        <div style="margin-top:12px;font-size:12px;color:var(--text-light);display:flex;gap:16px;justify-content:center">
          <span><span style="display:inline-block;width:12px;height:12px;background:rgba(34,197,94,0.3);border:2px solid var(--success);border-radius:2px;vertical-align:middle;margin-right:4px"></span> Progress</span>
          <span><span style="display:inline-block;width:12px;height:12px;background:rgba(59,130,246,0.08);border:2px dashed var(--primary);border-radius:2px;vertical-align:middle;margin-right:4px"></span> Target</span>
        </div>
      </div>
      <div class="card">
        <div class="card-header" style="font-size:14px">Maturity Summary</div>
        <div class="table-wrap"><table>
          <thead><tr><th>Control</th><th>Achieved</th><th>ML1</th><th>ML2</th><th>ML3</th></tr></thead>
          <tbody>${matSummaryRows}</tbody>
        </table></div>
      </div>
    </div>

    <div class="card mb-16">
      <div class="card-header" style="font-size:14px">Tool Coverage</div>
      <div style="font-size:12px;color:var(--text-light);margin-bottom:8px">Shows which data sources provide actions for each E8 control. Empty cells indicate no actions from that tool.</div>
      <div class="table-wrap"><table>
        <thead><tr><th>Control</th><th>Secure Score</th><th>SCuBA</th><th>Zero Trust</th><th>Manual</th><th>Total</th></tr></thead>
        <tbody>${entries.map(([ctrl,d]) => {
          const src = {};
          (d.actions||[]).forEach(a => { const s = a.source_tool||'?'; src[s] = (src[s]||0)+1; });
          const total = d.total_actions || 0;
          const _tb = (tool) => {
            const c = src[tool] || 0;
            return c > 0 ? '<td style="text-align:center"><span class="badge badge-success" style="min-width:28px">'+c+'</span></td>'
                         : '<td style="text-align:center;color:var(--text-light)">—</td>';
          };
          return '<tr><td style="font-size:12px">'+ctrl+'</td>'+_tb('Secure Score')+_tb('SCuBA')+_tb('Zero Trust')+_tb('Manual')
            +'<td style="text-align:center;font-weight:600">'+(total||'<span style="color:var(--danger)">0</span>')+'</td></tr>';
        }).join('')}</tbody>
      </table></div>
    </div>

    ${cards}

    <div class="card" style="margin-top:16px">
      <div class="card-header">About Essential Eight</div>
      <p style="font-size:13px">The <a href="https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/essential-eight" target="_blank">Essential Eight</a> is a set of baseline mitigation strategies from the Australian Signals Directorate (ASD) designed to protect Microsoft Windows-based internet-connected networks.</p>
      <div class="grid grid-2" style="gap:12px;margin-top:12px">
        ${Object.entries(mlDescs).map(([ml,desc])=>`<div style="font-size:12px"><strong>${ml}:</strong> ${desc}</div>`).join('')}
      </div>
      <div style="margin-top:12px;font-size:12px">
        <a href="https://blueprint.asd.gov.au/security-and-governance/essential-eight/" target="_blank">ASD Blueprint - Essential Eight</a> &middot;
        <a href="https://learn.microsoft.com/en-us/compliance/anz/e8-overview" target="_blank">Microsoft E8 Overview</a>
      </div>
    </div>`;
}

// ── E8 action management ──
function showE8AddAction(controlName, controlId) {
  openModal('Add Action to ' + controlName, `
    <div class="form-group"><label>Title</label><input id="e8a-title" placeholder="e.g. Enable AppLocker on workstations"></div>
    <div class="form-row">
      <div class="form-group"><label>Maturity Level</label>
        <select id="e8a-ml">
          <option value="Maturity Level 1">Maturity Level 1</option>
          <option value="Maturity Level 2">Maturity Level 2</option>
          <option value="Maturity Level 3">Maturity Level 3</option>
        </select>
      </div>
      <div class="form-group"><label>Status</label><select id="e8a-status">${selectOptions(state.enums.statuses,'ToDo')}</select></div>
    </div>
    <div class="form-row">
      <div class="form-group"><label>Priority</label><select id="e8a-priority">${selectOptions(state.enums.priorities,'Medium')}</select></div>
      <div class="form-group"><label>Workload</label><select id="e8a-workload">${selectOptions(state.enums.workloads,'General')}</select></div>
    </div>
    <div class="form-group"><label>Description</label><textarea id="e8a-desc" rows="2"></textarea></div>
    <div class="form-group"><label>Remediation Steps</label><textarea id="e8a-remed" rows="2"></textarea></div>`,
    `<button class="btn" onclick="closeModal()">Cancel</button><button class="btn btn-primary" onclick="e8AddAction('${controlName.replace(/'/g,"\\'")}')">Create</button>`);
}

async function e8AddAction(controlName) {
  const data = {
    title: document.getElementById('e8a-title').value,
    essential_eight_control: controlName,
    essential_eight_maturity: document.getElementById('e8a-ml').value,
    status: document.getElementById('e8a-status').value,
    priority: document.getElementById('e8a-priority').value,
    workload: document.getElementById('e8a-workload').value,
    description: document.getElementById('e8a-desc').value,
    remediation_steps: document.getElementById('e8a-remed').value,
    source_tool: 'Manual'
  };
  if(!data.title) return toast('Title required','error');
  const r = await api.post(`/api/tenants/${state.activeTenant.name}/actions`, data);
  if(r.error) return toast(r.error,'error');
  closeModal(); toast('Action created','success'); renderE8();
}

async function removeE8Action(actionId) {
  if(!confirm('Remove this action from Essential Eight control?')) return;
  await api.put(`/api/actions/${actionId}`, {essential_eight_control:'', essential_eight_maturity:''});
  toast('Action removed from E8 control','success');
  renderE8();
}

// ── SCuBA ──
function _scubaCritBadge(crit) {
  if(!crit) return '';
  const cl = crit.toLowerCase();
  if(cl.includes('shall') && !cl.includes('not-implemented') && !cl.includes('3rd')) return `<span class="badge badge-danger">Shall</span>`;
  if(cl.includes('should')) return `<span class="badge badge-warning">Should</span>`;
  if(cl.includes('3rd')) return `<span class="badge badge-info">3rd Party</span>`;
  if(cl.includes('not-implemented')) return `<span class="badge badge-gray">Not Implemented</span>`;
  return `<span class="badge badge-gray">${crit}</span>`;
}

async function renderScuba() {
  if(!requireTenant()) return;
  const data = await api.get(`/api/tenants/${state.activeTenant.name}/scuba`);
  const reports = await api.get(`/api/tenants/${state.activeTenant.name}/scuba-reports`);

  if(data.total_controls === 0) {
    document.getElementById('content').innerHTML = `<div class="card text-center" style="padding:60px">
      <h3>No SCuBA Data</h3><p style="color:var(--text-light);margin-top:8px">Import a ScubaGear report (ScubaResults JSON or CSV) from the Import page.</p>
      <button class="btn btn-primary" style="margin-top:16px" onclick="navigate('import')">Go to Import</button></div>`;
    return;
  }

  const passRate = data.pass_rate;

  // Product sections with groups
  let pidx = 0;
  let productSections = Object.entries(data.products).map(([prod, pd]) => {
    const prodPct = pd.total > 0 ? Math.round(pd.pass / pd.total * 100) : 0;

    // Group cards within product
    let groupCards = Object.entries(pd.groups || {}).map(([grpName, grp]) => {
      const gi = pidx++;
      const grpPct = grp.total > 0 ? Math.round(grp.pass / grp.total * 100) : 0;

      let rows = (grp.actions || []).map(a => {
        const cid = a.reference_id || a.source_id?.replace('scuba_','') || '';
        return `<tr>
          <td style="font-size:12px;font-family:monospace;white-space:nowrap">${cid}</td>
          <td style="font-size:12px">${(a.title||'').replace(/^\[\w+\]\s*/,'').substring(0,90)}</td>
          <td>${statusBadge(a.status)}</td>
          <td>${_scubaCritBadge(a.subcategory)}</td>
          <td style="font-size:11px;max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${(a.current_value||'').replace(/"/g,'&quot;')}">${a.current_value||''}</td>
        </tr>`;
      }).join('');

      const refLink = grp.reference_url ? `<a href="${grp.reference_url}" target="_blank" onclick="event.stopPropagation()" style="font-size:11px;color:var(--primary)">Baseline</a>` : '';

      return `<div style="margin-bottom:8px;border:1px solid var(--border);border-radius:6px;padding:10px 14px">
        <div class="flex justify-between items-center" style="cursor:pointer" onclick="document.getElementById('scuba-grp-${gi}').classList.toggle('hidden')">
          <div>
            <div style="font-size:13px;font-weight:600">${grpName}</div>
            <div style="font-size:11px;color:var(--text-light);margin-top:2px">
              <span class="badge badge-success" style="font-size:10px">Pass ${grp.pass}</span>
              <span class="badge badge-danger" style="font-size:10px">Fail ${grp.fail}</span>
              ${grp.warning?`<span class="badge badge-warning" style="font-size:10px">Warn ${grp.warning}</span>`:''}
              ${grp.na?`<span class="badge badge-gray" style="font-size:10px">N/A ${grp.na}</span>`:''}
              ${refLink}
            </div>
          </div>
          <div style="font-size:13px;font-weight:600;color:${pctColor(grpPct)}">${grpPct}%</div>
        </div>
        <div id="scuba-grp-${gi}" class="hidden" style="margin-top:8px">
          <div class="table-wrap"><table style="font-size:12px"><thead><tr><th>Control ID</th><th>Requirement</th><th>Result</th><th>Criticality</th><th>Details</th></tr></thead><tbody>${rows}</tbody></table></div>
        </div>
      </div>`;
    }).join('');

    const pi = pidx++;
    return `<div class="card mb-16">
      <div class="flex justify-between items-center" style="cursor:pointer" onclick="document.getElementById('scuba-prod-${pi}').classList.toggle('hidden')">
        <div>
          <div class="card-header" style="margin:0;font-size:16px">${prod}</div>
          <div style="font-size:12px;color:var(--text-light);margin-top:4px">
            ${pd.pass}/${pd.total} passed &middot; ${pd.fail} failed &middot; ${pd.warning} warnings &middot; ${pd.na} N/A
            &middot; ${Object.keys(pd.groups||{}).length} groups
          </div>
        </div>
        <div style="flex-shrink:0">${gauge(prodPct, 80)}</div>
      </div>
      <div id="scuba-prod-${pi}" style="margin-top:12px;border-top:1px solid var(--border);padding-top:12px">
        ${groupCards}
      </div>
    </div>`;
  }).join('');

  // Reports history
  let reportsHtml = '';
  if(reports && reports.length > 0) {
    let rptRows = reports.map(r => {
      const products = (r.products_assessed || []).join(', ');
      const pr = r.total_controls > 0 ? Math.round(r.passed_controls / r.total_controls * 100) : 0;
      const htmlBtn = r.html_path ? `<button class="btn btn-sm" onclick="window.open('/api/scuba-reports/${r.id}/html','_blank')">Open Report</button>` : '';
      return `<tr>
        <td>${r.imported_at?.substring(0,19) || ''}</td>
        <td>${r.executed_at?.substring(0,19) || ''}</td>
        <td>${r.report_tenant_name || ''}</td>
        <td>${r.report_domain || ''}</td>
        <td>${products}</td>
        <td>${r.tool_version || ''}</td>
        <td>${gauge(pr, 60)}</td>
        <td>${r.passed_controls}/${r.total_controls}</td>
        <td class="flex gap-4">${htmlBtn}<button class="btn btn-sm" onclick="showScubaReportDetail('${r.id}')">Details</button></td>
      </tr>`;
    }).join('');
    reportsHtml = `<div class="card mb-16"><div class="card-header">Import History</div>
      <div class="table-wrap"><table><thead><tr><th>Imported</th><th>Executed</th><th>Tenant</th><th>Domain</th><th>Products</th><th>Version</th><th>Pass Rate</th><th>Results</th><th>Actions</th></tr></thead>
      <tbody>${rptRows}</tbody></table></div></div>`;
  }

  document.getElementById('content').innerHTML = `
    <div class="card mb-16"><div class="grid grid-4" style="grid-template-columns: auto 1fr 1fr 1fr 1fr">
      <div class="stat-card">${gauge(passRate, 100)}<div class="label">Pass Rate</div></div>
      <div class="stat-card"><div class="value">${data.total_controls}</div><div class="label">Total Controls</div></div>
      <div class="stat-card"><div class="value" style="color:var(--success)">${data.passed}</div><div class="label">Passed</div></div>
      <div class="stat-card"><div class="value" style="color:var(--danger)">${data.failed}</div><div class="label">Failed</div></div>
      <div class="stat-card"><div class="value" style="color:var(--warning)">${data.warnings}</div><div class="label">Warnings</div></div>
    </div></div>
    ${reportsHtml}
    ${productSections}`;
}

async function showScubaReportDetail(reportId) {
  const r = await api.get(`/api/scuba-reports/${reportId}`);
  if(!r) return;

  let summaryRows = Object.entries(r.product_summary || {}).map(([prod, s]) => {
    const total = (s.Passes||0) + (s.Failures||0) + (s.Warnings||0) + (s.Manual||0) + (s.Errors||0) + (s.Omits||0);
    return `<tr>
      <td><strong>${prod}</strong></td>
      <td style="color:var(--success)">${s.Passes||0}</td>
      <td style="color:var(--danger)">${s.Failures||0}</td>
      <td style="color:var(--warning)">${s.Warnings||0}</td>
      <td>${s.Manual||0}</td>
      <td>${s.Errors||0}</td>
      <td>${total}</td>
    </tr>`;
  }).join('');

  const products = (r.products_assessed || []).join(', ');

  openModal('SCuBA Report Details', `
    <div class="grid grid-2 mb-16" style="gap:16px;font-size:13px">
      <div>
        <div class="mb-8"><strong>Tenant:</strong> ${r.report_tenant_name||'—'}</div>
        <div class="mb-8"><strong>Domain:</strong> ${r.report_domain||'—'}</div>
        <div class="mb-8"><strong>Tenant ID:</strong> <span style="font-family:monospace;font-size:11px">${r.report_tenant_id||'—'}</span></div>
      </div>
      <div>
        <div class="mb-8"><strong>ScubaGear Version:</strong> ${r.tool_version||'—'}</div>
        <div class="mb-8"><strong>Executed:</strong> ${r.executed_at||'—'}</div>
        <div class="mb-8"><strong>Products:</strong> ${products||'—'}</div>
        <div class="mb-8"><strong>Report UUID:</strong> <span style="font-family:monospace;font-size:11px">${r.report_uuid||'—'}</span></div>
      </div>
    </div>
    <div class="card-header" style="margin-bottom:8px">Product Summary</div>
    <table><thead><tr><th>Product</th><th>Passes</th><th>Failures</th><th>Warnings</th><th>Manual</th><th>Errors</th><th>Total</th></tr></thead>
    <tbody>${summaryRows || '<tr><td colspan="7" style="text-align:center;color:var(--text-light)">No summary data</td></tr>'}</tbody></table>
    <div style="margin-top:16px;font-size:12px;color:var(--text-light)">
      <strong>Results:</strong> ${r.passed_controls} passed, ${r.failed_controls} failed, ${r.warning_controls} warnings out of ${r.total_controls} total controls
    </div>
  `);
}

// ── Export ──
let _exportTab = 'quick';

async function renderExport() {
  if(!requireTenant()) return;
  const t = state.activeTenant.name;

  const tabClass = tab => `atab${_exportTab===tab?' active':''}`;
  const tabBar = `<div class="card mb-16" style="padding:0"><div class="action-tabs" style="margin:0">
    <div class="${tabClass('quick')}" onclick="_exportTab='quick';renderExport()">Quick Export</div>
    <div class="${tabClass('templates')}" onclick="_exportTab='templates';renderExport()">GitLab Templates</div>
    <div class="${tabClass('plan-export')}" onclick="_exportTab='plan-export';renderExport()">Export Plan to GitLab</div>
  </div></div>`;

  if(_exportTab === 'templates') {
    await renderGitlabTemplates(tabBar);
    return;
  }
  if(_exportTab === 'plan-export') {
    await renderPlanExport(tabBar);
    return;
  }

  document.getElementById('content').innerHTML = `${tabBar}
    <div class="card">
      <div class="card-header">Quick Export to GitLab</div>
      <div class="form-row">
        <div class="form-group"><label>Format</label><select id="exp-fmt"><option value="csv">CSV (Bulk Import)</option><option value="json">JSON (API)</option><option value="script">Shell Script (glab CLI)</option></select></div>
        <div class="form-group"><label>Filter Status (optional)</label><input id="exp-status" placeholder="ToDo,In Progress"></div>
      </div>
      <div class="form-row">
        <div class="form-group"><label>Project ID (JSON only)</label><input id="exp-pid" type="number"></div>
        <div class="form-group"><label>Project Path (Script only)</label><input id="exp-path" placeholder="GROUP/PROJECT"></div>
      </div>
      <button class="btn btn-primary" onclick="doExport()">Download Export</button>
    </div>`;
}

async function renderGitlabTemplates(tabBar) {
  const t = state.activeTenant.name;
  const templates = await api.get(`/api/tenants/${t}/gitlab-templates`);

  let rows = templates.map(tpl => `<tr>
    <td style="font-weight:600">${tpl.name}</td>
    <td><span class="badge badge-${tpl.template_type==='assessment'?'info':'purple'}">${tpl.template_type}</span></td>
    <td style="font-size:12px;max-width:300px">${tpl.title_template.substring(0,60)||'—'}</td>
    <td style="font-size:11px">${(tpl.labels||[]).join(', ')||'—'}</td>
    <td style="white-space:nowrap">
      <button class="btn btn-sm" onclick="editGitlabTemplate('${tpl.id}')">Edit</button>
      <button class="btn btn-sm btn-danger" onclick="deleteGitlabTemplate('${tpl.id}','${tpl.name.replace(/'/g,"\\'")}')">Delete</button>
    </td>
  </tr>`).join('');

  document.getElementById('content').innerHTML = `${tabBar}
    <div class="card">
      <div class="flex justify-between items-center mb-16">
        <div class="card-header" style="margin:0">GitLab Issue Templates (${templates.length})</div>
        <button class="btn btn-sm btn-primary" onclick="showAddGitlabTemplate()">+ New Template</button>
      </div>
      <p style="font-size:13px;color:var(--text-light);margin-bottom:12px">Define templates per tenant for exporting actions as GitLab issues. Use <code>{{variable}}</code> placeholders in title and body.<br>
      Available variables: <code>action_title</code>, <code>action_status</code>, <code>action_priority</code>, <code>action_workload</code>, <code>action_effort</code>, <code>action_risk_level</code>, <code>action_description</code>, <code>action_remediation</code>, <code>action_current_value</code>, <code>action_reference_url</code>, <code>action_category</code>, <code>action_tags</code>, <code>plan_name</code>, <code>tenant_name</code>, <code>tenant_id</code></p>
      <div class="table-wrap"><table><thead><tr><th>Name</th><th>Type</th><th>Title Template</th><th>Labels</th><th>Actions</th></tr></thead>
      <tbody>${rows||'<tr><td colspan="5" class="text-center">No templates yet. Create one to start exporting.</td></tr>'}</tbody></table></div>
    </div>`;
}

function showAddGitlabTemplate() {
  openModal('New GitLab Template', `
    <div class="form-group"><label>Template Name</label><input id="gt-name" placeholder="e.g. Security Assessment Issue"></div>
    <div class="form-group"><label>Type</label><select id="gt-type"><option value="assessment">Assessment Issue</option><option value="implementation">Implementation Issue</option></select></div>
    <div class="form-group"><label>Issue Title Template</label><input id="gt-title" placeholder="[{{action_priority}}] {{action_title}}"></div>
    <div class="form-group"><label>Issue Body Template</label><textarea id="gt-body" rows="10" style="font-family:monospace;font-size:12px" placeholder="## Description\n{{action_description}}\n\n## Remediation\n{{action_remediation}}\n\n## Details\n- Priority: {{action_priority}}\n- Workload: {{action_workload}}"></textarea></div>
    <div class="form-group"><label>Labels (comma-separated)</label><input id="gt-labels" placeholder="security, assessment, {{action_workload}}"></div>`,
    '<button class="btn" onclick="closeModal()">Cancel</button><button class="btn btn-primary" onclick="submitAddGitlabTemplate()">Create</button>');
}

async function submitAddGitlabTemplate() {
  const name = document.getElementById('gt-name').value.trim();
  if(!name) return toast('Name is required','error');
  const data = {
    name,
    template_type: document.getElementById('gt-type').value,
    title_template: document.getElementById('gt-title').value,
    body_template: document.getElementById('gt-body').value,
    labels: document.getElementById('gt-labels').value.split(',').map(l=>l.trim()).filter(Boolean),
  };
  const r = await api.post(`/api/tenants/${state.activeTenant.name}/gitlab-templates`, data);
  if(r.error) return toast(r.error, 'error');
  closeModal();
  toast('Template created','success');
  renderExport();
}

async function editGitlabTemplate(id) {
  const tpl = await api.get(`/api/gitlab-templates/${id}`);
  if(!tpl||tpl.error) return toast('Template not found','error');
  openModal('Edit GitLab Template', `
    <div class="form-group"><label>Template Name</label><input id="gt-name" value="${tpl.name||''}"></div>
    <div class="form-group"><label>Type</label><select id="gt-type"><option value="assessment" ${tpl.template_type==='assessment'?'selected':''}>Assessment Issue</option><option value="implementation" ${tpl.template_type==='implementation'?'selected':''}>Implementation Issue</option></select></div>
    <div class="form-group"><label>Issue Title Template</label><input id="gt-title" value="${(tpl.title_template||'').replace(/"/g,'&quot;')}"></div>
    <div class="form-group"><label>Issue Body Template</label><textarea id="gt-body" rows="10" style="font-family:monospace;font-size:12px">${tpl.body_template||''}</textarea></div>
    <div class="form-group"><label>Labels (comma-separated)</label><input id="gt-labels" value="${(tpl.labels||[]).join(', ')}"></div>`,
    `<button class="btn" onclick="closeModal()">Cancel</button><button class="btn btn-primary" onclick="submitEditGitlabTemplate('${id}')">Save</button>`);
}

async function submitEditGitlabTemplate(id) {
  const name = document.getElementById('gt-name').value.trim();
  if(!name) return toast('Name is required','error');
  const data = {
    name,
    template_type: document.getElementById('gt-type').value,
    title_template: document.getElementById('gt-title').value,
    body_template: document.getElementById('gt-body').value,
    labels: document.getElementById('gt-labels').value.split(',').map(l=>l.trim()).filter(Boolean),
  };
  const r = await api.put(`/api/gitlab-templates/${id}`, data);
  if(r.error) return toast(r.error, 'error');
  closeModal();
  toast('Template updated','success');
  renderExport();
}

async function deleteGitlabTemplate(id, name) {
  if(!confirm(`Delete template "${name}"?`)) return;
  await api.del(`/api/gitlab-templates/${id}`);
  toast('Template deleted','success');
  renderExport();
}

async function renderPlanExport(tabBar) {
  const t = state.activeTenant.name;
  const [plans, templates] = await Promise.all([
    api.get(`/api/tenants/${t}/plans`),
    api.get(`/api/tenants/${t}/gitlab-templates`),
  ]);

  if(!plans.length) {
    document.getElementById('content').innerHTML = `${tabBar}<div class="card text-center" style="padding:40px"><h3>No plans available</h3><p style="color:var(--text-light)">Create a plan first, then export it using a GitLab template.</p></div>`;
    return;
  }
  if(!templates.length) {
    document.getElementById('content').innerHTML = `${tabBar}<div class="card text-center" style="padding:40px"><h3>No templates defined</h3><p style="color:var(--text-light)">Create a GitLab template first on the "GitLab Templates" tab.</p></div>`;
    return;
  }

  const planOpts = plans.map(p=>`<option value="${p.id}">${p.name} (${p.item_count} actions)</option>`).join('');
  const tplOpts = templates.map(t=>`<option value="${t.id}">${t.name} (${t.template_type})</option>`).join('');

  document.getElementById('content').innerHTML = `${tabBar}
    <div class="card mb-16">
      <div class="card-header">Export Plan as GitLab Issues</div>
      <p style="font-size:13px;color:var(--text-light);margin-bottom:12px">Select a plan and template to generate GitLab issue files. The output can be used to create issues in your GitLab project.</p>
      <div class="form-row">
        <div class="form-group"><label>Plan</label><select id="pe-plan">${planOpts}</select></div>
        <div class="form-group"><label>Template</label><select id="pe-tpl">${tplOpts}</select></div>
      </div>
      <div class="flex gap-8">
        <button class="btn btn-primary" onclick="doExportPlanGitlab()">Generate Issues</button>
        <button class="btn" onclick="previewPlanExport()">Preview</button>
      </div>
    </div>
    <div id="plan-export-result"></div>`;
}

async function previewPlanExport() {
  const t = state.activeTenant.name;
  const planId = document.getElementById('pe-plan').value;
  const tplId = document.getElementById('pe-tpl').value;
  const r = await api.post(`/api/tenants/${t}/plans/${planId}/export-gitlab`, {template_id: tplId});
  if(r.error) return toast(r.error, 'error');

  let preview = r.issues.slice(0,5).map((iss,i) => `
    <div class="card mb-8" style="border-left:3px solid var(--primary)">
      <div style="font-weight:600;margin-bottom:4px">${iss.title}</div>
      <div style="font-size:12px;color:var(--text-light);white-space:pre-wrap;max-height:150px;overflow-y:auto">${iss.body.substring(0,500)}${iss.body.length>500?'...':''}</div>
      ${iss.labels.length ? `<div style="margin-top:4px">${iss.labels.map(l=>'<span class="badge badge-info">'+l+'</span>').join(' ')}</div>` : ''}
    </div>`).join('');

  document.getElementById('plan-export-result').innerHTML = `
    <div class="card"><div class="card-header">Preview (${r.issue_count} issues, showing first 5)</div>${preview}
    ${r.issue_count>5?`<div style="color:var(--text-light);font-size:13px;padding:8px">... and ${r.issue_count-5} more</div>`:''}
    </div>`;
}

async function doExportPlanGitlab() {
  const t = state.activeTenant.name;
  const planId = document.getElementById('pe-plan').value;
  const tplId = document.getElementById('pe-tpl').value;
  const r = await api.post(`/api/tenants/${t}/plans/${planId}/export-gitlab`, {template_id: tplId});
  if(r.error) return toast(r.error, 'error');

  // Download as JSON file
  const blob = new Blob([JSON.stringify(r, null, 2)], {type:'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `gitlab_issues_${r.plan.replace(/[^a-zA-Z0-9]/g,'_')}_${r.template_type}.json`;
  document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
  toast(`Exported ${r.issue_count} issues`,'success');
}

async function doExport() {
  const data = {format:document.getElementById('exp-fmt').value, status_filter:document.getElementById('exp-status').value||null, project_id:parseInt(document.getElementById('exp-pid').value)||null, project_path:document.getElementById('exp-path').value||null};
  const r = await api.download(`/api/tenants/${state.activeTenant.name}/export`, data);
  if(!r.ok) { toast('Export failed','error'); return; }
  const blob = await r.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href=url; a.download=r.headers.get('content-disposition')?.split('filename=')[1]||'export.'+data.format; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
  toast('Export downloaded','success');
}

// ── History ──
async function renderHistory() {
  if(!requireTenant()) return;
  const t = state.activeTenant.name;
  const [imports, changelog] = await Promise.all([api.get(`/api/tenants/${t}/history`), api.get(`/api/tenants/${t}/changelog?limit=50`)]);

  let impRows = imports.map(h => `<tr><td>${h.timestamp?.substring(0,19)}</td><td>${h.source_tool}</td><td>${h.file_path?.split('/').pop()?.split('\\\\').pop()}</td><td>${h.new_actions}</td><td>${h.updated_actions}</td></tr>`).join('');

  let clRows = changelog.map(h => {
    let desc = [];
    if(h.old_status) desc.push(`${h.old_status} → ${h.new_status}`);
    if(h.old_score!=null) desc.push(`Score: ${h.old_score} → ${h.new_score}`);
    return `<tr><td>${h.timestamp?.substring(0,19)}</td><td>${h.action_title||''}</td><td>${h.source_tool||''}</td><td>${desc.join('; ')}</td><td>${h.changed_by||''}</td></tr>`;
  }).join('');

  document.getElementById('content').innerHTML = `
    <div class="tabs"><div class="tab active" onclick="showHistTab(this,'imp-tab')">Imports</div><div class="tab" onclick="showHistTab(this,'cl-tab')">Change Log</div></div>
    <div id="imp-tab" class="card"><div class="table-wrap"><table><thead><tr><th>Date</th><th>Source</th><th>File</th><th>New</th><th>Updated</th></tr></thead><tbody>${impRows||'<tr><td colspan="5" class="text-center">No imports yet</td></tr>'}</tbody></table></div></div>
    <div id="cl-tab" class="card hidden"><div class="table-wrap"><table><thead><tr><th>Date</th><th>Action</th><th>Source</th><th>Change</th><th>By</th></tr></thead><tbody>${clRows||'<tr><td colspan="5" class="text-center">No changes yet</td></tr>'}</tbody></table></div></div>`;
}

function showHistTab(el, tabId) {
  el.parentElement.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');
  document.getElementById('imp-tab').classList.toggle('hidden', tabId!=='imp-tab');
  document.getElementById('cl-tab').classList.toggle('hidden', tabId!=='cl-tab');
}

// ── SVG Sparkline ──
function miniSparkline(values, w=200, h=40) {
  if(!values.length) return '';
  const min = Math.min(...values), max = Math.max(...values);
  const range = max - min || 1;
  const pts = values.map((v,i) => {
    const x = (i/(values.length-1||1))*w;
    const y = h - ((v-min)/range)*h;
    return `${x.toFixed(2)},${y.toFixed(2)}`;
  });
  const area = `${pts.join(' ')} ${w},${h} 0,${h}`;
  return `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" style="display:block">
    <polygon points="${area}" fill="var(--primary-light)" opacity=".4"/>
    <polyline points="${pts.join(' ')}" fill="none" stroke="var(--primary)" stroke-width="2"/>
  </svg>`;
}

// ── Full Trend Chart ──
function trendChart(snapshots, w=800, h=250) {
  if(snapshots.length < 2) return '<div class="text-center" style="padding:40px;color:var(--text-light)">Need at least 2 snapshots to show trend</div>';
  const pts = snapshots.slice().reverse();
  const pcts = pts.map(p=>p.percentage);
  const min = Math.max(0, Math.min(...pcts) - 5);
  const max = Math.min(100, Math.max(...pcts) + 5);
  const range = max - min || 1;
  const pad = {t:20, r:20, b:40, l:50};
  const cw = w-pad.l-pad.r, ch = h-pad.t-pad.b;

  let gridLines = '';
  for(let i=0; i<=4; i++) {
    const y = pad.t + (i/4)*ch;
    const val = max - (i/4)*range;
    gridLines += `<line x1="${pad.l}" y1="${y}" x2="${w-pad.r}" y2="${y}" class="grid-line"/>`;
    gridLines += `<text x="${pad.l-8}" y="${y+4}" text-anchor="end" class="axis-label">${val.toFixed(0)}%</text>`;
  }

  const coords = pts.map((p,i) => {
    const x = pad.l + (i/(pts.length-1||1))*cw;
    const y = pad.t + ((max-p.percentage)/range)*ch;
    return {x, y, p};
  });

  const line = coords.map(c=>`${c.x.toFixed(2)},${c.y.toFixed(2)}`).join(' ');
  const area = line + ` ${coords[coords.length-1].x.toFixed(2)},${pad.t+ch} ${coords[0].x.toFixed(2)},${pad.t+ch}`;
  const dots = coords.map(c=>`<circle cx="${c.x.toFixed(2)}" cy="${c.y.toFixed(2)}" class="dot"><title>${c.p.timestamp?.substring(0,16)}: ${c.p.percentage.toFixed(2)}% (${c.p.trigger||''})</title></circle>`).join('');

  // X-axis labels (show max 8)
  let xLabels = '';
  const step = Math.max(1, Math.floor(pts.length/8));
  for(let i=0; i<pts.length; i+=step) {
    const x = pad.l + (i/(pts.length-1||1))*cw;
    const label = pts[i].timestamp?.substring(5,10)||'';
    xLabels += `<text x="${x}" y="${h-8}" text-anchor="middle" class="axis-label">${label}</text>`;
  }

  return `<div class="trend-chart"><svg viewBox="0 0 ${w} ${h}">
    ${gridLines}${xLabels}
    <polygon points="${area}" class="area"/>
    <polyline points="${line}" class="line"/>
    ${dots}
  </svg></div>`;
}

// ── Score Trending Page ──
async function renderTrending() {
  if(!requireTenant()) return;
  const t = state.activeTenant.name;
  document.getElementById('topbar-actions').innerHTML = '<button class="btn btn-primary" onclick="takeSnapshot()">Take Snapshot</button>';

  const [snapshots, driftReports] = await Promise.all([
    api.get(`/api/tenants/${t}/snapshots?limit=50`),
    api.get(`/api/tenants/${t}/drift?limit=10`),
  ]);

  let chart = trendChart(snapshots);

  // Snapshot table
  let snapRows = snapshots.map(s => {
    const tools = Object.entries(s.by_tool||{}).map(([tool,d])=>`${tool}: ${d.percentage?.toFixed(2)||0}%`).join(', ');
    return `<tr>
      <td><code>${s.timestamp?.substring(0,16)}</code></td>
      <td>${s.trigger||''}</td>
      <td><strong>${s.percentage?.toFixed(2)}%</strong></td>
      <td>${s.total_actions}</td>
      <td>${s.completed_actions}</td>
      <td style="font-size:12px">${tools||'-'}</td>
    </tr>`;
  }).join('');

  // Drift history
  let driftRows = driftReports.map(d => {
    const cls = d.score_delta > 0 ? 'drift-positive' : d.score_delta < 0 ? 'drift-negative' : 'drift-neutral';
    return `<tr>
      <td><code>${d.timestamp?.substring(0,16)}</code></td>
      <td>${d.source_tool}</td>
      <td class="${cls}">${d.score_delta>=0?'+':''}${d.score_delta?.toFixed(2)}%</td>
      <td>${d.score_before?.toFixed(2)}% → ${d.score_after?.toFixed(2)}%</td>
      <td>${d.regressions?.length||0}</td>
      <td>${d.improvements?.length||0}</td>
      <td style="font-size:12px;max-width:200px">${d.summary}</td>
    </tr>`;
  }).join('');

  document.getElementById('content').innerHTML = `
    <div class="card mb-16">
      <div class="card-header">Score Trend Over Time</div>
      ${chart}
    </div>
    <div class="tabs">
      <div class="tab active" onclick="showTrendTab(this,'snap-tab')">Snapshots (${snapshots.length})</div>
      <div class="tab" onclick="showTrendTab(this,'drift-tab')">Drift Reports (${driftReports.length})</div>
    </div>
    <div id="snap-tab" class="card">
      <div class="table-wrap"><table><thead><tr><th>Timestamp</th><th>Trigger</th><th>Score</th><th>Actions</th><th>Completed</th><th>By Tool</th></tr></thead>
      <tbody>${snapRows||'<tr><td colspan="6" class="text-center">No snapshots yet. Import data to create snapshots automatically.</td></tr>'}</tbody></table></div>
    </div>
    <div id="drift-tab" class="card hidden">
      <div class="table-wrap"><table><thead><tr><th>Timestamp</th><th>Source</th><th>Delta</th><th>Score</th><th>Regressions</th><th>Improvements</th><th>Summary</th></tr></thead>
      <tbody>${driftRows||'<tr><td colspan="7" class="text-center">No drift detected yet</td></tr>'}</tbody></table></div>
    </div>`;
}

function showTrendTab(el, tabId) {
  el.parentElement.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');
  document.getElementById('snap-tab').classList.toggle('hidden', tabId!=='snap-tab');
  document.getElementById('drift-tab').classList.toggle('hidden', tabId!=='drift-tab');
}

async function takeSnapshot() {
  const r = await api.post(`/api/tenants/${state.activeTenant.name}/snapshots`, {trigger:'manual'});
  toast(`Snapshot taken: ${r.percentage?.toFixed(2)}%`, 'success');
  renderTrending();
}

// ── Compliance Page ──
async function renderCompliance() {
  if(!requireTenant()) return;
  const t = state.activeTenant.name;
  document.getElementById('topbar-actions').innerHTML = '<button class="btn btn-primary" onclick="mapCompliance()">Re-map All</button>';

  const compliance = await api.get(`/api/tenants/${t}/compliance`);
  const frameworks = Object.keys(compliance);

  if(!frameworks.length) {
    document.getElementById('content').innerHTML = `<div class="card text-center" style="padding:60px">
      <h3>No compliance mappings yet</h3>
      <p style="color:var(--text-light);margin:12px 0">Import assessment data first, then compliance mappings are created automatically.</p>
      <button class="btn btn-primary" onclick="mapCompliance()">Map Compliance Now</button>
    </div>`;
    return;
  }

  // Overall summary across all frameworks
  let totalControls = 0, totalCompleted = 0;
  frameworks.forEach(fw => { totalControls += compliance[fw].total_controls||0; totalCompleted += compliance[fw].completed_controls||0; });
  const overallPct = totalControls > 0 ? Math.round(totalCompleted/totalControls*100) : 0;

  // Framework summary cards
  let fwSummary = frameworks.map(fw => {
    const d = compliance[fw];
    const pct = d.percentage||0;
    return `<div class="stat-card" style="cursor:pointer" onclick="showFrameworkTab(document.querySelector('[data-fw=\\'${fw}\\']'),'fw-${fw}')">
      ${gauge(pct, 80)}<div class="label" style="font-size:12px">${fw}</div>
      <div style="font-size:11px;color:var(--text-light)">${d.completed_controls}/${d.total_controls} controls</div>
    </div>`;
  }).join('');

  // Framework tabs
  let tabs = frameworks.map((fw,i) => `<div class="tab ${i===0?'active':''}" data-fw="${fw}" onclick="showFrameworkTab(this,'fw-${fw}')">${fw} (${compliance[fw].percentage||0}%)</div>`).join('');

  let frameworkPanels = frameworks.map((fw, i) => {
    const data = compliance[fw];
    let familiesHtml = '';
    for(const [fam, famData] of Object.entries(data.families||{})) {
      let controlRows = Object.entries(famData.controls||{}).map(([ctrlId, ctrl]) => {
        const statusCls = ctrl.status==='Completed'?'success':ctrl.status==='In Progress'?'info':'danger';
        const actions = ctrl.actions.map(a=>`<div style="font-size:12px;padding:2px 0">${statusBadge(a.status)} ${a.title.substring(0,50)} <span style="color:var(--text-light)">(${a.source_tool||''})</span></div>`).join('');
        return `<tr>
          <td><code style="font-size:12px">${ctrlId}</code></td>
          <td style="font-size:13px">${ctrl.control_name}</td>
          <td><span class="badge badge-${statusCls}">${ctrl.status}</span></td>
          <td style="text-align:center">${ctrl.actions.length}</td>
          <td>${actions}</td>
        </tr>`;
      }).join('');

      const famPct = famData.percentage||0;
      const barColor = famPct >= 80 ? 'var(--success)' : famPct >= 40 ? 'var(--warning)' : 'var(--danger)';

      familiesHtml += `<div class="compliance-family" style="margin-bottom:8px">
        <div class="compliance-family-header" style="cursor:pointer;display:flex;justify-content:space-between;align-items:center;padding:10px 12px;background:var(--bg);border-radius:6px" onclick="this.nextElementSibling.classList.toggle('hidden')">
          <span style="font-weight:600;font-size:14px">${fam}</span>
          <span style="font-size:13px;color:var(--text-light)">${famData.completed}/${famData.total} (${famPct}%)</span>
        </div>
        <div class="compliance-family-body hidden" style="padding:8px 0">
          <div style="margin-bottom:8px">${progressBar(famPct, barColor)}</div>
          <div class="table-wrap"><table><thead><tr><th>Control</th><th>Name</th><th>Status</th><th style="text-align:center">Actions</th><th>Details</th></tr></thead>
          <tbody>${controlRows}</tbody></table></div>
        </div>
      </div>`;
    }

    return `<div id="fw-${fw}" class="card ${i>0?'hidden':''}">
      <div class="grid grid-3 mb-16">
        <div class="stat-card">${gauge(data.percentage, 100)}<div class="label">${fw}</div></div>
        <div class="stat-card"><div class="value">${data.total_controls}</div><div class="label">Total Controls</div></div>
        <div class="stat-card"><div class="value" style="color:var(--success)">${data.completed_controls}</div><div class="label">Completed</div></div>
      </div>
      ${familiesHtml}
    </div>`;
  }).join('');

  document.getElementById('content').innerHTML = `
    <div class="card mb-16"><div class="grid grid-${Math.min(frameworks.length+1, 5)}">
      <div class="stat-card">${gauge(overallPct, 100)}<div class="label">Overall</div></div>
      ${fwSummary}
    </div></div>
    <div class="tabs">${tabs}</div>
    ${frameworkPanels}`;
}

function showFrameworkTab(el, tabId) {
  if(!el) return;
  const tabBar = el.closest('.tabs');
  if(tabBar) tabBar.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');
  // Hide all framework panels (match id starting with fw-)
  document.querySelectorAll('[id^="fw-"].card').forEach(p=>p.classList.add('hidden'));
  document.getElementById(tabId)?.classList.remove('hidden');
}

async function mapCompliance() {
  const r = await api.post(`/api/tenants/${state.activeTenant.name}/compliance/map`);
  toast(`Mapped ${r.total_mappings} controls across ${Object.keys(r.by_framework||{}).length} frameworks`, 'success');
  renderCompliance();
}

// ── Risk Register Page ──
async function renderRisks() {
  if(!requireTenant()) return;
  const t = state.activeTenant.name;
  document.getElementById('topbar-actions').innerHTML = '<button class="btn" onclick="expireRisks()">Check Expirations</button>';

  const summary = await api.get(`/api/tenants/${t}/risk-summary`);

  let expiredCards = summary.expired.map(a => `
    <div class="risk-card expired card mb-8">
      <div class="flex justify-between items-center">
        <div><strong>${a.title?.substring(0,50)}</strong><div style="font-size:12px;color:var(--text-light)">Owner: ${a.risk_owner||'N/A'} | Expired: ${a.risk_expiry_date}</div></div>
        <button class="btn btn-sm btn-danger" onclick="showEditAction('${a.id}')">Review</button>
      </div>
    </div>`).join('');

  let upcomingCards = summary.upcoming_reviews.map(a => `
    <div class="risk-card upcoming card mb-8">
      <div class="flex justify-between items-center">
        <div><strong>${a.title?.substring(0,50)}</strong><div style="font-size:12px;color:var(--text-light)">Owner: ${a.risk_owner||'N/A'} | Review by: ${a.risk_review_date}</div></div>
        <button class="btn btn-sm" onclick="showEditAction('${a.id}')">Review</button>
      </div>
    </div>`).join('');

  let acceptedRows = summary.accepted.map(a => `<tr>
    <td>${a.title?.substring(0,45)}</td>
    <td>${a.risk_owner||'N/A'}</td>
    <td style="font-size:12px">${a.risk_justification?.substring(0,60)||'N/A'}</td>
    <td>${a.risk_accepted_at?.substring(0,10)||'N/A'}</td>
    <td>${a.risk_expiry_date||'No expiry'}</td>
    <td>${a.risk_review_date||'Not set'}</td>
    <td><button class="btn btn-sm" onclick="showEditAction('${a.id}')">View</button></td>
  </tr>`).join('');

  document.getElementById('content').innerHTML = `
    <div class="grid grid-3 mb-16">
      <div class="card stat-card"><div class="value">${summary.total_accepted}</div><div class="label">Accepted Risks</div></div>
      <div class="card stat-card"><div class="value" style="color:var(--danger)">${summary.expired.length}</div><div class="label">Expired</div></div>
      <div class="card stat-card"><div class="value" style="color:var(--warning)">${summary.upcoming_reviews.length}</div><div class="label">Reviews Due (30d)</div></div>
    </div>
    ${summary.expired.length?`<div class="card mb-16"><div class="card-header" style="color:var(--danger)">Expired Risk Acceptances</div>${expiredCards}</div>`:''}
    ${summary.upcoming_reviews.length?`<div class="card mb-16"><div class="card-header" style="color:var(--warning)">Upcoming Reviews</div>${upcomingCards}</div>`:''}
    <div class="card"><div class="card-header">All Accepted Risks</div>
      <div class="table-wrap"><table><thead><tr><th>Title</th><th>Owner</th><th>Justification</th><th>Accepted</th><th>Expiry</th><th>Review</th><th></th></tr></thead>
      <tbody>${acceptedRows||'<tr><td colspan="7" class="text-center">No accepted risks</td></tr>'}</tbody></table></div>
    </div>`;
}

async function expireRisks() {
  const r = await api.post(`/api/tenants/${state.activeTenant.name}/expire-risks`);
  if(r.expired_count > 0) {
    toast(`${r.expired_count} risk acceptance(s) expired and reverted to ToDo`, 'info');
  } else {
    toast('No expired risk acceptances found', 'info');
  }
  renderRisks();
}

// ── Risk Acceptance Modal ──
function showAcceptRisk(actionId) {
  openModal('Accept Risk', `
    <p style="margin-bottom:12px;color:var(--text-light)">Document the risk acceptance decision. The action will be marked as "Risk Accepted".</p>
    <div class="form-group"><label>Justification (required)</label><textarea id="ra-justification" rows="3" placeholder="Why is this risk being accepted?"></textarea></div>
    <div class="form-group"><label>Risk Owner (required)</label><input id="ra-owner" placeholder="Person responsible for this risk"></div>
    <div class="form-row">
      <div class="form-group"><label>Review Date</label><input id="ra-review" type="date"></div>
      <div class="form-group"><label>Expiry Date (auto-revert to ToDo)</label><input id="ra-expiry" type="date"></div>
    </div>
    <div class="form-group"><label>Your Name</label><input id="ra-by" placeholder="Who is recording this"></div>`,
    `<button class="btn" onclick="closeModal()">Cancel</button><button class="btn" style="background:var(--warning);color:#fff;border-color:var(--warning)" onclick="acceptRisk('${actionId}')">Accept Risk</button>`);
}

async function acceptRisk(actionId) {
  const justification = document.getElementById('ra-justification').value.trim();
  const risk_owner = document.getElementById('ra-owner').value.trim();
  if(!justification) return toast('Justification is required','error');
  if(!risk_owner) return toast('Risk owner is required','error');
  const data = {
    justification, risk_owner,
    review_date: document.getElementById('ra-review').value || null,
    expiry_date: document.getElementById('ra-expiry').value || null,
    changed_by: document.getElementById('ra-by').value || '',
  };
  const r = await api.post(`/api/actions/${actionId}/accept-risk`, data);
  if(r.error) return toast(r.error, 'error');
  closeModal();
  toast('Risk accepted', 'success');
  filterActions();
}

// ── Dependencies ──
async function loadActionDeps(actionId) {
  const el = document.getElementById('deps-'+actionId);
  if(!el) return;
  const deps = await api.get(`/api/actions/${actionId}/dependencies`);
  if(!deps.depends_on.length && !deps.blocks.length) { el.innerHTML = ''; return; }

  let html = '';
  if(deps.depends_on.length) {
    html += `<div class="field-label mb-8">Depends On</div>`;
    html += deps.depends_on.map(d => {
      const blocked = d.status !== 'Completed' && d.status !== 'Risk Accepted';
      return `<span class="dep-tag ${blocked?'blocked':''}">
        ${blocked?'&#128274; ':'&#9989; '}${d.title?.substring(0,35)} (${d.status})
        <button style="background:none;border:none;cursor:pointer;font-size:14px;color:#999" onclick="removeDep('${actionId}','${d.depends_on_id}');event.stopPropagation()">&times;</button>
      </span>`;
    }).join('');
  }
  if(deps.blocks.length) {
    html += `<div class="field-label mb-8 ${deps.depends_on.length?'mt-16':''}">Blocks</div>`;
    html += deps.blocks.map(d => `<span class="dep-tag">${d.title?.substring(0,35)} (${d.status})</span>`).join('');
  }
  el.innerHTML = `<div class="mb-16">${html}</div>`;
}

function showAddDependency(actionId) {
  // Load actions to select from
  (async () => {
    const actions = await api.get(`/api/tenants/${state.activeTenant.name}/actions`);
    const otherActions = actions.filter(a => a.id !== actionId);
    let options = otherActions.map(a => `<option value="${a.id}">${a.title.substring(0,60)} [${a.status}]</option>`).join('');
    openModal('Add Dependency', `
      <p style="margin-bottom:12px;color:var(--text-light)">Select an action that must be completed before this one can proceed.</p>
      <div class="form-group"><label>Depends On</label><select id="dep-target">${options}</select></div>
      <div class="form-group"><label>Notes (optional)</label><input id="dep-notes" placeholder="Why this dependency exists"></div>`,
      `<button class="btn" onclick="closeModal()">Cancel</button><button class="btn btn-primary" onclick="addDependency('${actionId}')">Add Dependency</button>`);
  })();
}

async function addDependency(actionId) {
  const depends_on_id = document.getElementById('dep-target').value;
  const notes = document.getElementById('dep-notes').value;
  const r = await api.post(`/api/actions/${actionId}/dependencies`, {depends_on_id, notes});
  if(r.error) return toast(r.error, 'error');
  closeModal();
  toast('Dependency added', 'success');
  loadActionDeps(actionId);
}

async function removeDep(actionId, dependsOnId) {
  await api.del(`/api/actions/${actionId}/dependencies/${dependsOnId}`);
  toast('Dependency removed', 'success');
  loadActionDeps(actionId);
}

// Boot
init();
</script>
</body>
</html>"""
