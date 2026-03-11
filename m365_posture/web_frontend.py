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
.phase-card { border-left:4px solid var(--primary); }
.phase-card.phase-1 { border-left-color:var(--success); }
.phase-card.phase-2 { border-left-color:var(--warning); }
.phase-card.phase-3 { border-left-color:var(--purple); }

/* Correlation badge */
.corr-badge { display:inline-flex; gap:4px; align-items:center; padding:2px 8px; border-radius:12px; font-size:11px; background:var(--purple-light); color:#5b21b6; }

/* Detail panel */
.detail-panel { background:#f8fafc; border:1px solid var(--border); border-radius:var(--radius); padding:16px; margin:8px 0; }
.detail-panel .field { margin-bottom:8px; }
.detail-panel .field-label { font-size:11px; text-transform:uppercase; letter-spacing:.5px; color:var(--text-light); }
.detail-panel .field-value { font-size:14px; margin-top:2px; }
.detail-panel pre { background:#1e293b; color:#e2e8f0; padding:12px; border-radius:6px; font-size:12px; overflow-x:auto; white-space:pre-wrap; }

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
    <a href="#correlations" data-page="correlations">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
      Correlations
    </a>
    <a href="#e8" data-page="e8">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
      Essential Eight
    </a>
    <a href="#compare" data-page="compare">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
      Compare
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
  <div class="tenant-indicator" id="tenant-indicator">
    <div style="color:var(--text-sidebar)">Active Tenant</div>
    <div class="name" id="active-tenant-name">None</div>
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
  async get(url) { const r = await fetch(url); return r.json(); },
  async post(url, data) {
    const r = await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data)});
    return r.json();
  },
  async put(url, data) {
    const r = await fetch(url, {method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data)});
    return r.json();
  },
  async del(url) { const r = await fetch(url, {method:'DELETE'}); return r.json(); },
  async upload(url, formData) { const r = await fetch(url, {method:'POST', body:formData}); return r.json(); },
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
  const m = {'Completed':'success','In Progress':'info','In Planning':'purple','ToDo':'danger','Risk Accepted':'warning','Not Applicable':'gray','Third Party':'cyan'};
  return `<span class="badge badge-${m[s]||'gray'}">${s}</span>`;
}

function priorityBadge(p) {
  const m = {'Critical':'danger','High':'warning','Medium':'info','Low':'success','Informational':'gray'};
  return `<span class="badge badge-${m[p]||'gray'}">${p}</span>`;
}

function pctColor(p) {
  if(p>=80) return 'var(--success)';
  if(p>=60) return '#84cc16';
  if(p>=40) return 'var(--warning)';
  if(p>=20) return '#f97316';
  return 'var(--danger)';
}

function gauge(pct, size=120, label='') {
  const r=45, c=2*Math.PI*r, off=c-(pct/100)*c;
  return `<div class="gauge" style="width:${size}px;height:${size}px">
    <svg width="${size}" height="${size}" viewBox="0 0 100 100">
      <circle class="track" cx="50" cy="50" r="${r}"/>
      <circle class="fill" cx="50" cy="50" r="${r}" stroke="${pctColor(pct)}" stroke-dasharray="${c}" stroke-dashoffset="${off}"/>
    </svg>
    <div class="pct">${Math.round(pct)}%<small>${label}</small></div>
  </div>`;
}

function progressBar(pct, h=8) {
  return `<div class="progress" style="height:${h}px"><div class="bar" style="width:${Math.min(100,pct)}%;background:${pctColor(pct)}"></div></div>`;
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

// ── Router ──
async function navigate(page) {
  state.currentPage = page;
  document.querySelectorAll('.sidebar nav a').forEach(a => a.classList.toggle('active', a.dataset.page===page));
  const titles = {dashboard:'Dashboard',tenants:'Tenants',actions:'Actions',import:'Import Data',plans:'Remediation Plans',correlations:'Action Correlations',e8:'Essential Eight',compare:'Compare Tenants',export:'Export',history:'Import History'};
  document.getElementById('page-title').textContent = titles[page]||page;
  document.getElementById('topbar-actions').innerHTML = '';

  const render = {dashboard:renderDashboard,tenants:renderTenants,actions:renderActions,import:renderImport,plans:renderPlans,correlations:renderCorrelations,e8:renderE8,compare:renderCompare,export:renderExport,history:renderHistory};
  if(render[page]) await render[page]();
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

function requireTenant() {
  if(!state.activeTenant) { toast('No active tenant. Add one first.','error'); navigate('tenants'); return false; }
  return true;
}

// ── Dashboard ──
async function renderDashboard() {
  const c = document.getElementById('content');
  if(!requireTenant()) return;
  const t = state.activeTenant.name;
  const [scores, prioritized] = await Promise.all([api.get(`/api/tenants/${t}/scores`), api.get(`/api/tenants/${t}/prioritized?limit=10`)]);

  let toolCards = '';
  for(const [tool, d] of Object.entries(scores.by_tool||{})) {
    toolCards += `<div class="card stat-card"><div class="card-header">${tool}</div>${gauge(d.percentage, 100)}<div class="label">${d.completed}/${d.total} actions</div></div>`;
  }

  let wlBars = '';
  for(const [wl, d] of Object.entries(scores.by_workload||{})) {
    wlBars += `<div class="mb-8"><div class="flex justify-between mb-8"><span style="font-size:13px">${wl}</span><span style="font-size:13px;font-weight:600">${d.percentage.toFixed(1)}%</span></div>${progressBar(d.percentage)}</div>`;
  }

  let statusPills = '';
  for(const [s, n] of Object.entries(scores.by_status||{})) {
    statusPills += `${statusBadge(s)} <strong>${n}</strong>&nbsp;&nbsp;`;
  }

  let topActions = prioritized.slice(0,10).map(a => `<tr><td>${a.title.substring(0,60)}</td><td>${priorityBadge(a.priority)}</td><td>${statusBadge(a.status)}</td><td>${a.roi_score}</td></tr>`).join('');

  c.innerHTML = `
    <div class="grid grid-4 mb-16">
      <div class="card stat-card"><div class="value">${scores.percentage?.toFixed(1)||0}%</div><div class="label">Overall Score</div></div>
      <div class="card stat-card"><div class="value">${scores.total_actions||0}</div><div class="label">Total Actions</div></div>
      <div class="card stat-card"><div class="value">${scores.completed_actions||0}</div><div class="label">Completed</div></div>
      <div class="card stat-card"><div class="value">${scores.total_actions ? Math.round((scores.total_actions-scores.completed_actions)/scores.total_actions*100) : 0}%</div><div class="label">Remaining</div></div>
    </div>
    <div class="grid grid-2 mb-16">
      <div class="card"><div class="card-header">Score by Source Tool</div><div class="grid grid-2">${toolCards}</div></div>
      <div class="card"><div class="card-header">Score by Workload</div>${wlBars}</div>
    </div>
    <div class="card mb-16"><div class="card-header">Status Distribution</div><div style="padding:8px">${statusPills}</div></div>
    <div class="card"><div class="card-header">Top Priority Actions (by ROI)</div>
      <div class="table-wrap"><table><thead><tr><th>Title</th><th>Priority</th><th>Status</th><th>ROI</th></tr></thead><tbody>${topActions||'<tr><td colspan="4" class="text-center">No pending actions</td></tr>'}</tbody></table></div>
    </div>`;
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

  document.getElementById('content').innerHTML = cards ? `<div class="grid grid-3">${cards}</div>` : '<div class="card text-center" style="padding:60px"><h3>No tenants yet</h3><p style="color:var(--text-light);margin:12px 0">Add your first tenant to get started</p><button class="btn btn-primary" onclick="showAddTenant()">+ Add Tenant</button></div>';
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
    </div>
    <div class="card"><div class="table-wrap" id="actions-table"></div></div>`;
  await filterActions();
}

async function filterActions() {
  const t = state.activeTenant.name;
  const params = new URLSearchParams();
  const s = document.getElementById('f-search')?.value; if(s) params.set('search', s);
  const st = document.getElementById('f-status')?.value; if(st) params.set('status', st);
  const wl = document.getElementById('f-workload')?.value; if(wl) params.set('workload', wl);
  const src = document.getElementById('f-source')?.value; if(src) params.set('source_tool', src);
  const pr = document.getElementById('f-priority')?.value; if(pr) params.set('priority', pr);

  const actions = await api.get(`/api/tenants/${t}/actions?${params}`);
  renderActionsTable(actions);
}

function renderActionsTable(actions) {
  const el = document.getElementById('actions-table');
  if(!actions.length) { el.innerHTML = '<div class="text-center" style="padding:40px;color:var(--text-light)">No actions found</div>'; return; }

  let rows = actions.map(a => `
    <tr onclick="toggleActionDetail('${a.id}')" style="cursor:pointer" id="row-${a.id}">
      <td><code style="font-size:11px">${a.id}</code></td>
      <td style="max-width:300px">${a.title.substring(0,70)}${a.correlation_group_id?'<span class="corr-badge" title="Correlated">&#128279;</span>':''}</td>
      <td>${statusBadge(a.status)}</td>
      <td>${priorityBadge(a.priority)}</td>
      <td style="font-size:12px">${a.workload}</td>
      <td style="font-size:12px">${a.source_tool}</td>
      <td>${a.score!=null?`${a.score}/${a.max_score}`:'-'}</td>
    </tr>
    <tr id="detail-${a.id}" class="hidden"><td colspan="7" style="padding:0">${actionDetailHtml(a)}</td></tr>`).join('');

  el.innerHTML = `<table><thead><tr><th>ID</th><th>Title</th><th>Status</th><th>Priority</th><th>Workload</th><th>Source</th><th>Score</th></tr></thead><tbody>${rows}</tbody></table>
    <div style="padding:8px;font-size:12px;color:var(--text-light)">${actions.length} actions</div>`;
}

function actionDetailHtml(a) {
  const hist = (a.history||[]).map(h => {
    let desc = [];
    if(h.old_status) desc.push(`${h.old_status} → ${h.new_status}`);
    if(h.old_score!=null) desc.push(`Score: ${h.old_score} → ${h.new_score}`);
    return `<div style="font-size:12px;padding:2px 0"><code>${(h.timestamp||'').substring(0,19)}</code> ${desc.join('; ')} ${h.changed_by?'by '+h.changed_by:''}</div>`;
  }).join('');

  return `<div class="detail-panel">
    <div class="flex gap-8 mb-16">
      <button class="btn btn-sm" onclick="showEditAction('${a.id}');event.stopPropagation()">Edit</button>
      <button class="btn btn-sm btn-danger" onclick="deleteAction('${a.id}');event.stopPropagation()">Delete</button>
    </div>
    <div class="grid grid-3 mb-16">
      <div class="field"><div class="field-label">Risk Level</div><div class="field-value">${a.risk_level}</div></div>
      <div class="field"><div class="field-label">User Impact</div><div class="field-value">${a.user_impact}</div></div>
      <div class="field"><div class="field-label">Impl. Effort</div><div class="field-value">${a.implementation_effort}</div></div>
      <div class="field"><div class="field-label">E8 Control</div><div class="field-value">${a.essential_eight_control||'N/A'}</div></div>
      <div class="field"><div class="field-label">E8 Maturity</div><div class="field-value">${a.essential_eight_maturity||'N/A'}</div></div>
      <div class="field"><div class="field-label">Licence</div><div class="field-value">${a.required_licence||'N/A'}</div></div>
      <div class="field"><div class="field-label">Responsible</div><div class="field-value">${a.responsible||'Not assigned'}</div></div>
      <div class="field"><div class="field-label">Planned Date</div><div class="field-value">${a.planned_date||'Not set'}</div></div>
      <div class="field"><div class="field-label">Category</div><div class="field-value">${a.category||'N/A'}</div></div>
    </div>
    ${a.description?`<div class="field mb-8"><div class="field-label">Description</div><div class="field-value">${a.description}</div></div>`:''}
    ${a.current_value?`<div class="field mb-8"><div class="field-label">Current Value</div><pre>${a.current_value}</pre></div>`:''}
    ${a.recommended_value?`<div class="field mb-8"><div class="field-label">Recommended Value</div><pre>${a.recommended_value}</pre></div>`:''}
    ${a.remediation_steps?`<div class="field mb-8"><div class="field-label">Remediation Steps</div><div class="field-value">${a.remediation_steps}</div></div>`:''}
    ${a.reference_url?`<div class="field mb-8"><div class="field-label">Reference</div><div class="field-value"><a href="${a.reference_url}" target="_blank">${a.reference_url}</a></div></div>`:''}
    ${hist?`<div class="field"><div class="field-label">History (${a.history.length})</div>${hist}</div>`:''}
  </div>`;
}

function toggleActionDetail(id) {
  const el = document.getElementById('detail-'+id);
  if(expandedAction && expandedAction!==id) document.getElementById('detail-'+expandedAction)?.classList.add('hidden');
  el.classList.toggle('hidden');
  expandedAction = el.classList.contains('hidden') ? null : id;
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
    <div class="form-group"><label>Notes</label><textarea id="ae-notes" rows="2">${a.notes||''}</textarea></div>
    <div class="form-group"><label>Changed By</label><input id="ae-by" placeholder="Your name"></div>`,
    `<button class="btn" onclick="closeModal()">Cancel</button><button class="btn btn-primary" onclick="updateAction('${id}')">Save</button>`);
}

async function updateAction(id) {
  const data = {title:document.getElementById('ae-title').value, status:document.getElementById('ae-status').value, priority:document.getElementById('ae-priority').value, workload:document.getElementById('ae-workload').value, risk_level:document.getElementById('ae-risk').value, user_impact:document.getElementById('ae-impact').value, implementation_effort:document.getElementById('ae-effort').value, responsible:document.getElementById('ae-responsible').value, planned_date:document.getElementById('ae-date').value||null, notes:document.getElementById('ae-notes').value, changed_by:document.getElementById('ae-by').value};
  await api.put(`/api/actions/${id}`, data);
  closeModal(); toast('Action updated','success'); filterActions();
}

async function deleteAction(id) {
  if(!confirm('Delete this action?')) return;
  await api.del(`/api/actions/${id}`);
  toast('Action deleted','success'); filterActions();
}

// ── Import ──
async function renderImport() {
  if(!requireTenant()) return;
  const c = document.getElementById('content');
  c.innerHTML = `
    <div class="card mb-16">
      <div class="card-header">Import Assessment Data</div>
      <div class="form-group"><label>Source Tool</label>
        <select id="imp-source">${selectOptions(state.enums.import_sources)}</select></div>
      <div class="upload-zone" id="upload-zone" onclick="document.getElementById('imp-file').click()" ondrop="handleDrop(event)" ondragover="handleDragOver(event)" ondragleave="handleDragLeave(event)">
        <div class="icon">&#128228;</div>
        <div><strong>Click to upload</strong> or drag and drop</div>
        <div style="color:var(--text-light);font-size:13px;margin-top:4px">JSON or CSV file</div>
      </div>
      <input type="file" id="imp-file" accept=".json,.csv" style="display:none" onchange="handleFileSelect(event)">
      <div id="imp-file-name" style="margin-top:8px;font-size:13px"></div>
      <button class="btn btn-primary mt-16" id="imp-btn" onclick="doImport()" disabled>Import</button>
    </div>
    <div id="imp-result"></div>`;
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
  document.getElementById('imp-result').innerHTML = `
    <div class="card"><div class="card-header">Import Result</div>
      <div class="grid grid-4">
        <div class="stat-card"><div class="value">${r.total_parsed}</div><div class="label">Parsed</div></div>
        <div class="stat-card"><div class="value" style="color:var(--success)">${r.new_actions}</div><div class="label">New</div></div>
        <div class="stat-card"><div class="value" style="color:var(--warning)">${r.updated_actions}</div><div class="label">Updated</div></div>
        <div class="stat-card"><div class="value" style="color:var(--purple)">${r.correlation?.actions_linked||0}</div><div class="label">Correlated</div></div>
      </div>
    </div>`;
  selectedFile=null;
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
    html = plans.map(p => `
      <div class="card mb-16">
        <div class="card-header">${p.name} <span class="badge badge-${p.status==='Active'?'success':'gray'}">${p.status}</span></div>
        <p style="font-size:13px;color:var(--text-light);margin-bottom:8px">${p.description||'No description'}</p>
        <div style="font-size:13px">${p.item_count} actions &middot; Created ${p.created_at?.substring(0,10)}</div>
        <div class="btn-group mt-16">
          <button class="btn btn-sm btn-primary" onclick="viewPlan('${p.id}')">Open</button>
          <button class="btn btn-sm btn-danger" onclick="deletePlan('${p.id}')">Delete</button>
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

  openModal('Create Remediation Plan', `
    <div class="form-group"><label>Plan Name</label><input id="p-name" placeholder="Q1 2026 Security Uplift"></div>
    <div class="form-group"><label>Description</label><textarea id="p-desc" rows="2"></textarea></div>
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
  const r = await api.post(`/api/tenants/${state.activeTenant.name}/plans`, {name, description:document.getElementById('p-desc').value, action_ids:ids});
  if(r.error) return toast(r.error,'error');
  closeModal();
  toast('Plan created','success');
  viewPlan(r.id);
}

async function viewPlan(planId) {
  if(!requireTenant()) return;
  const t = state.activeTenant.name;
  const plan = await api.get(`/api/plans/${planId}`);
  const actionIds = plan.items.map(i => i.action_id);
  const [sim, phases] = await Promise.all([
    api.post(`/api/tenants/${t}/simulate`, {action_ids:actionIds}),
    api.post(`/api/tenants/${t}/suggest-phases`, {action_ids:actionIds, num_phases:3})
  ]);

  let toolImpact = Object.entries(sim.by_tool||{}).map(([tool,d]) => `
    <div class="mb-8"><div class="flex justify-between"><span style="font-size:13px">${tool}</span><span style="font-size:13px;font-weight:600;color:var(--success)">+${d.percentage_gain?.toFixed(1)||0}%</span></div>
    <div class="flex gap-8" style="font-size:12px;color:var(--text-light)">${d.current_percentage?.toFixed(1)}% → ${d.projected_percentage?.toFixed(1)}% (${d.actions_resolved} actions)</div>
    ${progressBar(d.projected_percentage)}</div>`).join('');

  let e8Impact = Object.entries(sim.essential_eight_impact||{}).map(([ctrl,d]) => `
    <div style="font-size:13px;padding:4px 0">${ctrl}: <strong>${d.actions_resolved}</strong> actions → ${d.maturity_levels.join(', ')}</div>`).join('');

  let riskReduction = Object.entries(sim.risk_reduction||{}).map(([level,n]) => `<span class="badge badge-${level==='Critical'||level==='High'?'danger':'warning'}">${n}x ${level}</span>`).join(' ');

  let phaseHtml = phases.map((ph,i) => `
    <div class="card phase-card phase-${i+1} mb-16">
      <div class="card-header">${ph.name} <span class="badge badge-info">${ph.action_count} actions</span></div>
      <div class="grid grid-3 mb-8">
        <div><span style="font-size:12px;color:var(--text-light)">Score Gain</span><div style="font-weight:600;color:var(--success)">+${ph.projected_score_gain}</div></div>
        <div><span style="font-size:12px;color:var(--text-light)">Effort</span><div style="font-size:13px">${Object.entries(ph.effort_summary).map(([e,n])=>`${n}x ${e}`).join(', ')}</div></div>
        <div><span style="font-size:12px;color:var(--text-light)">Licences</span><div style="font-size:13px">${ph.licences_needed.join(', ')||'None required'}</div></div>
      </div>
      <div class="table-wrap"><table><thead><tr><th>Action</th><th>Priority</th><th>Workload</th><th>Effort</th></tr></thead><tbody>
        ${ph.actions.map(a=>`<tr><td>${a.title.substring(0,50)}</td><td>${priorityBadge(a.priority)}</td><td>${a.workload}</td><td>${a.implementation_effort}</td></tr>`).join('')}
      </tbody></table></div>
    </div>`).join('');

  document.getElementById('content').innerHTML = `
    <button class="btn mb-16" onclick="renderPlans()">&larr; Back to Plans</button>
    <h2 style="margin-bottom:4px">${plan.name}</h2>
    <p style="color:var(--text-light);margin-bottom:16px">${plan.description||''}</p>

    <div class="grid grid-4 mb-16">
      <div class="card stat-card"><div class="value">${sim.actions_count}</div><div class="label">Actions to Implement</div></div>
      <div class="card stat-card"><div class="value" style="color:var(--success)">+${sim.percentage_gain?.toFixed(1)}%</div><div class="label">Projected Score Gain</div></div>
      <div class="card stat-card">${gauge(sim.current_percentage||0, 100, 'Current')}</div>
      <div class="card stat-card">${gauge(sim.projected_percentage||0, 100, 'Projected')}</div>
    </div>

    <div class="grid grid-2 mb-16">
      <div class="card"><div class="card-header">Impact by Source Tool</div>${toolImpact||'<div style="color:var(--text-light)">No data</div>'}</div>
      <div class="card">
        <div class="card-header">Risk Reduction</div><div class="mb-8">${riskReduction}</div>
        <div class="card-header mt-16">Essential Eight Impact</div>${e8Impact||'<div style="color:var(--text-light)">No E8 mapped actions</div>'}
        <div class="card-header mt-16">Licences Required</div><div style="font-size:13px">${sim.licences_needed?.join(', ')||'None'}</div>
        <div class="card-header mt-16">Effort Breakdown</div><div style="font-size:13px">${Object.entries(sim.effort_breakdown||{}).map(([e,n])=>`${n}x ${e}`).join(', ')}</div>
        <div class="card-header mt-16">User Impact</div><div style="font-size:13px">${Object.entries(sim.user_impact_summary||{}).map(([e,n])=>`${n}x ${e}`).join(', ')}</div>
      </div>
    </div>

    <h3 class="mb-16">Suggested Phased Rollout</h3>
    ${phaseHtml}`;
}

async function deletePlan(id) {
  if(!confirm('Delete this plan?')) return;
  await api.del(`/api/plans/${id}`);
  toast('Plan deleted','success'); renderPlans();
}

// ── Correlations ──
async function renderCorrelations() {
  if(!requireTenant()) return;
  const t = state.activeTenant.name;
  document.getElementById('topbar-actions').innerHTML = '<button class="btn btn-primary" onclick="runCorrelation()">Re-correlate</button>';
  const corr = await api.get(`/api/tenants/${t}/correlations`);

  if(!corr.length) {
    document.getElementById('content').innerHTML = '<div class="card text-center" style="padding:60px"><h3>No correlated actions</h3><p style="color:var(--text-light);margin:12px 0">Import data from multiple tools, then correlations will be detected automatically</p><button class="btn btn-primary" onclick="runCorrelation()">Run Correlation</button></div>';
    return;
  }

  let html = corr.map(g => `
    <div class="card mb-16">
      <div class="card-header">${g.canonical_name} <span class="badge badge-${g.overall_status==='Completed'?'success':g.overall_status==='In Progress'?'info':'danger'}">${g.overall_status}</span></div>
      <p style="font-size:13px;color:var(--text-light);margin-bottom:8px">${g.description}</p>
      <div style="font-size:13px;margin-bottom:8px">Found in ${g.source_count} tools: ${g.sources.join(', ')}</div>
      <div class="table-wrap"><table><thead><tr><th>Source</th><th>Title</th><th>Status</th><th>Score</th></tr></thead><tbody>
        ${g.actions.map(a=>`<tr><td style="font-size:12px">${a.source_tool}</td><td>${a.title.substring(0,60)}</td><td>${statusBadge(a.status)}</td><td>${a.score!=null?a.score+'/'+a.max_score:'-'}</td></tr>`).join('')}
      </tbody></table></div>
    </div>`).join('');

  document.getElementById('content').innerHTML = `
    <div class="card mb-16"><div class="grid grid-3">
      <div class="stat-card"><div class="value">${corr.length}</div><div class="label">Control Families</div></div>
      <div class="stat-card"><div class="value">${corr.reduce((s,g)=>s+g.action_count,0)}</div><div class="label">Linked Actions</div></div>
      <div class="stat-card"><div class="value">${corr.filter(g=>g.source_count>1).length}</div><div class="label">Cross-tool Links</div></div>
    </div></div>${html}`;
}

async function runCorrelation() {
  const r = await api.post(`/api/tenants/${state.activeTenant.name}/correlate`);
  toast(`Correlated ${r.actions_linked} actions into ${r.groups_created} new groups`,'success');
  renderCorrelations();
}

// ── Essential Eight ──
async function renderE8() {
  if(!requireTenant()) return;
  const e8 = await api.get(`/api/tenants/${state.activeTenant.name}/e8`);

  let cards = Object.entries(e8).map(([ctrl, d]) => {
    let mlBars = Object.entries(d.maturity_levels||{}).map(([ml, md]) =>
      `<div class="mb-8"><div class="flex justify-between"><span style="font-size:12px">${ml}</span><span style="font-size:12px">${md.completed}/${md.total}</span></div>${progressBar(md.percentage)}</div>`
    ).join('');

    return `<div class="card">
      <div class="card-header" style="font-size:14px">${ctrl}</div>
      <div class="text-center mb-8">${gauge(d.percentage, 100)}</div>
      <div style="font-size:13px;text-align:center;margin-bottom:8px">${d.completed_actions}/${d.total_actions} actions</div>
      <div style="font-size:13px;text-align:center;margin-bottom:12px">Achieved: <strong>${d.achieved_maturity}</strong></div>
      ${mlBars}
    </div>`;
  }).join('');

  document.getElementById('content').innerHTML = `<div class="grid grid-4">${cards}</div>`;
}

// ── Compare ──
async function renderCompare() {
  state.tenants = await api.get('/api/tenants');
  if(state.tenants.length < 2) {
    document.getElementById('content').innerHTML = '<div class="card text-center" style="padding:60px"><h3>Need at least 2 tenants</h3></div>';
    return;
  }

  let checks = state.tenants.map(t => `<label style="display:flex;gap:6px;align-items:center;font-size:14px"><input type="checkbox" value="${t.name}" class="cmp-tenant" ${t.is_active?'checked':''}> ${t.display_name||t.name}</label>`).join('');

  document.getElementById('content').innerHTML = `
    <div class="card mb-16"><div class="card-header">Select Tenants to Compare</div>
      <div class="flex gap-8 flex-wrap mb-16">${checks}</div>
      <button class="btn btn-primary" onclick="doCompare()">Compare</button>
    </div><div id="compare-result"></div>`;
}

async function doCompare() {
  const tenants = [...document.querySelectorAll('.cmp-tenant:checked')].map(c=>c.value);
  if(tenants.length < 2) return toast('Select at least 2 tenants','error');
  const r = await api.post('/api/compare', {tenants});

  let overallRows = tenants.map(t => {
    const d = r.overall[t]||{};
    return `<tr><td><strong>${t}</strong></td><td>${gauge(d.percentage||0, 80)}</td><td>${d.total_actions||0}</td><td>${d.completed_actions||0}</td></tr>`;
  }).join('');

  let toolRows = Object.entries(r.by_tool||{}).map(([tool, data]) => {
    let cells = tenants.map(t => `<td>${(data[t]?.percentage||0).toFixed(1)}%</td>`).join('');
    return `<tr><td>${tool}</td>${cells}</tr>`;
  }).join('');

  document.getElementById('compare-result').innerHTML = `
    <div class="card mb-16"><div class="card-header">Overall Comparison</div>
      <table><thead><tr><th>Tenant</th><th>Score</th><th>Total</th><th>Completed</th></tr></thead><tbody>${overallRows}</tbody></table></div>
    <div class="card"><div class="card-header">By Source Tool</div>
      <table><thead><tr><th>Tool</th>${tenants.map(t=>`<th>${t}</th>`).join('')}</tr></thead><tbody>${toolRows}</tbody></table></div>`;
}

// ── Export ──
async function renderExport() {
  if(!requireTenant()) return;
  document.getElementById('content').innerHTML = `
    <div class="card">
      <div class="card-header">Export to GitLab</div>
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

// Boot
init();
</script>
</body>
</html>"""
