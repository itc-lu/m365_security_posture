"""Flask web application - REST API + SPA frontend for M365 Security Posture.

Launch with: m365-posture web [--port 8080] [--no-browser]
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import webbrowser
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, request, send_file, Response, session

from .database import Database
from .models import (
    Action, TenantConfig, ActionStatus, Priority, RiskLevel,
    UserImpact, ImplementationEffort, SourceTool, Workload,
    EssentialEightControl, EssentialEightMaturity, ComplianceFramework,
    GlobalAction, UserRole,
)
from .parsers import load_seed_controls, parse_graph_control_profiles
from .essential_eight import apply_e8_mapping, get_e8_summary
from .compliance import auto_map_compliance
from .correlation import auto_correlate, get_correlation_summary
from .planner import simulate_plan, suggest_phases, get_prioritized_actions
from .gitlab_export import export_to_gitlab_csv, export_to_gitlab_json, generate_gitlab_script
from .graph_api import (
    start_device_code_flow, poll_for_token,
    fetch_control_profiles, client_credentials_token,
    client_credentials_token_cert, thumbprint_from_pem,
    start_interactive_auth, exchange_auth_code,
)
from .import_pipeline import (
    PARSER_MAP, TenantMismatchError, process_file_import,
    import_secure_scores_with_token,
)
from .web_frontend import get_spa_html

# Simple in-memory login rate limiter
_login_attempts: dict = {}


def _check_login_rate_limit(ip: str) -> bool:
    """Returns True if allowed, False if rate-limited. Max 10 attempts per 5 minutes."""
    import time
    now = time.time()
    window = 300  # 5 minutes
    max_attempts = 10
    attempts = _login_attempts.get(ip, [])
    attempts = [t for t in attempts if now - t < window]
    if len(attempts) >= max_attempts:
        return False
    attempts.append(now)
    _login_attempts[ip] = attempts
    return True


# Identifier validators (prevent attribute-context injection in onclick handlers).
# Tenant names are lowercased and space-normalized before validation.
_TENANT_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")


def create_app(db_path: str = None) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024
    _secret = os.environ.get("SECRET_KEY")
    if not _secret:
        import secrets as _secrets_mod
        _secret = _secrets_mod.token_hex(32)
        print(f"[WARNING] SECRET_KEY not set — generated ephemeral key. Set SECRET_KEY env var for production.", flush=True)
    app.config["SECRET_KEY"] = _secret
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "false").lower() == "true"
    app.config["PERMANENT_SESSION_LIFETIME"] = 28800  # 8 hours
    app.json.sort_keys = False
    db = Database(db_path)

    # Seed the Secure Score control reference table on first run so imported
    # actions carry descriptions and remediation steps even before a Graph
    # API fetch refreshes them.
    with db._conn() as conn:
        _has_controls = conn.execute(
            "SELECT COUNT(*) AS c FROM secure_score_controls").fetchone()["c"]
    if not _has_controls:
        _seeds = load_seed_controls()
        if _seeds:
            result = db.seed_controls(_seeds)
            print(f"[INFO] Seeded {result['total']} Secure Score reference controls.", flush=True)

    def login_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not session.get("user_id"):
                return jsonify({"error": "Unauthorized", "login_required": True}), 401
            return f(*args, **kwargs)
        return decorated

    def require_role(*roles):
        def decorator(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                if not session.get("user_id"):
                    return jsonify({"error": "Unauthorized", "login_required": True}), 401
                if session.get("role") not in roles:
                    return jsonify({"error": "Forbidden"}), 403
                return f(*args, **kwargs)
            return decorated
        return decorator

    def _json_error(msg, code=400):
        return jsonify({"error": msg}), code

    def _redact_tenant(t: dict) -> dict:
        """Remove client_secret from tenant dict before sending to client."""
        if t and "client_secret" in t:
            t = dict(t)
            t["client_secret"] = "***" if t["client_secret"] else ""
        return t

    # Public endpoints that don't require authentication
    _PUBLIC_ENDPOINTS = {
        "api_auth_login",
        "api_auth_logout",
        "serve_frontend",
        "serve_static",
        "index",
    }

    # Endpoints allowed while user has must_change_password=1
    _PASSWORD_RESET_ALLOWED = {
        "api_auth_login",
        "api_auth_logout",
        "api_auth_me",
        "api_auth_change_password",
        "api_enums",
        "serve_frontend",
        "serve_static",
        "index",
    }

    @app.before_request
    def _require_auth():
        """Enforce authentication on all /api/* routes except the allowlist."""
        if request.endpoint in _PUBLIC_ENDPOINTS:
            return
        if not request.path.startswith("/api/"):
            return
        if "user_id" not in session:
            return jsonify({"error": "Authentication required", "login_required": True}), 401
        # CSRF: state-changing requests must carry X-Requested-With header
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            if request.endpoint not in ("api_auth_login",) and not request.headers.get("X-Requested-With"):
                return jsonify({"error": "CSRF check failed"}), 403
            # Viewers are read-only everywhere except their own auth actions
            if session.get("role") == "viewer" and request.endpoint not in (
                    "api_auth_login", "api_auth_logout", "api_auth_change_password"):
                return jsonify({"error": "Read-only role: viewers cannot modify data"}), 403
        # Force password-change: restrict access until the flag is cleared
        if session.get("must_change_password"):
            if request.endpoint not in _PASSWORD_RESET_ALLOWED:
                return jsonify({"error": "Password change required", "must_change_password": True}), 403

    # ── Serve SPA ──

    @app.route("/")
    def index():
        return Response(get_spa_html(), mimetype="text/html")

    # ── Enum values (for dropdowns) ──

    @app.route("/api/enums")
    def api_enums():
        return jsonify({
            "statuses": [s.value for s in ActionStatus],
            "priorities": [p.value for p in Priority],
            "risk_levels": [r.value for r in RiskLevel],
            "user_impacts": [u.value for u in UserImpact],
            "implementation_efforts": [e.value for e in ImplementationEffort],
            "source_tools": [s.value for s in SourceTool],
            "workloads": [w.value for w in Workload],
            "e8_controls": [c.value for c in EssentialEightControl],
            "e8_maturities": [m.value for m in EssentialEightMaturity],
            "import_sources": list(PARSER_MAP.keys()),
            "compliance_frameworks": [f.value for f in ComplianceFramework],
        })

    # ── Tenant endpoints ──

    @app.route("/api/tenants", methods=["GET"])
    def api_list_tenants():
        return jsonify([_redact_tenant(t) for t in db.list_tenants()])

    @app.route("/api/tenants", methods=["POST"])
    def api_create_tenant():
        data = request.get_json()
        if not data or not data.get("name"):
            return _json_error("name is required")
        name = data["name"].strip().lower().replace(" ", "-")
        if not _TENANT_NAME_RE.match(name):
            return _json_error("Tenant name must be 1-63 chars, start alphanumeric, letters/digits/._- only")
        existing = db.get_tenant(name)
        if existing:
            return _json_error(f"Tenant '{name}' already exists")
        config = TenantConfig(
            tenant_id=data.get("tenant_id", ""),
            tenant_name=name,
            display_name=data.get("display_name", name),
            client_id=data.get("client_id", ""),
            client_secret=data.get("client_secret", ""),
            certificate_path=data.get("certificate_path", ""),
            certificate_thumbprint=data.get("certificate_thumbprint", ""),
            use_interactive=data.get("use_interactive", False),
            notes=data.get("notes", ""),
        )
        tenant = db.create_tenant(name, config)
        return jsonify(tenant), 201

    @app.route("/api/tenants/<name>", methods=["GET"])
    def api_get_tenant(name):
        tenant = db.get_tenant(name)
        if not tenant:
            return _json_error("Tenant not found", 404)
        return jsonify(_redact_tenant(tenant))

    @app.route("/api/tenants/<name>", methods=["PUT"])
    def api_update_tenant(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        data = request.get_json() or {}
        # Only admins may update client_secret
        if "client_secret" in data and session.get("role") != "admin":
            return _json_error("Admin role required to update client_secret", 403)
        tenant = db.update_tenant(name, **data)
        # Invalidate any cached Graph auth tokens for this tenant when the
        # credentials they were obtained against may have changed -- otherwise
        # a subsequent import would silently reuse a token tied to the old
        # tenant_id / client_id.
        cred_keys = {"tenant_id", "client_id", "client_secret",
                     "certificate_path", "certificate_thumbprint"}
        if cred_keys & set(data.keys()):
            _device_flows.pop(name, None)
            _interactive_flows.pop(name, None)
        return jsonify(_redact_tenant(tenant))

    @app.route("/api/tenants/<name>", methods=["DELETE"])
    @require_role("admin")
    def api_delete_tenant(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        db.delete_tenant(name)
        db.audit("tenant.delete", actor=session.get("username"),
                 entity_type="tenant", entity_id=name)
        return jsonify({"deleted": True})

    @app.route("/api/tenants/<name>/activate", methods=["POST"])
    def api_activate_tenant(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        # The active tenant is per user session. The DB flag is only kept as
        # the fallback default for fresh sessions — a tenant switch in one
        # session must never retarget another user's (or tab's) imports.
        session["active_tenant"] = name
        db.set_active_tenant(name)
        return jsonify({"active": name})

    @app.route("/api/active-tenant", methods=["GET"])
    def api_active_tenant():
        selected = session.get("active_tenant")
        if selected:
            tenant = db.get_tenant(selected)
            if tenant:
                return jsonify(_redact_tenant(tenant))
        return jsonify(_redact_tenant(db.get_active_tenant() or {}))

    # ── Global dashboard (all tenants) ──

    @app.route("/api/global-dashboard", methods=["GET"])
    def api_global_dashboard():
        """Fleet overview: per-tenant scores, adjusted scores, 7/30-day
        progress, tool/workload breakdowns and status distribution, plus
        aggregate totals. Feeds the landing page and the management report."""
        def _progress(snapshots, current_pct, days):
            cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
            older = [s for s in snapshots if s["timestamp"] <= cutoff]
            baseline = older[0] if older else (snapshots[-1] if snapshots else None)
            if not baseline or baseline.get("percentage") is None:
                return None
            return round(current_pct - baseline["percentage"], 2)

        tenants_out = []
        for t in db.list_tenants():
            name = t["name"]
            scores = db.get_scores(name)
            adj = db.get_scores(name, exclude_na=True, exclude_ra=True)
            snapshots = db.get_score_snapshots(name, limit=200)
            pct = scores.get("percentage", 0)
            by_status = scores.get("by_status", {})
            tenants_out.append({
                "name": name,
                "display_name": t.get("display_name") or name,
                "tenant_id": t.get("tenant_id", ""),
                "percentage": pct,
                "adj_percentage": adj.get("percentage", 0),
                "total_actions": scores.get("total_actions", 0),
                "completed_actions": scores.get("completed_actions", 0),
                "progress_7d": _progress(snapshots, pct, 7),
                "progress_30d": _progress(snapshots, pct, 30),
                "snapshot_count": len(snapshots),
                "by_tool": scores.get("by_tool", {}),
                "by_workload": scores.get("by_workload", {}),
                "by_status": by_status,
                "risk_accepted": by_status.get("Risk Accepted", 0),
                "not_applicable": by_status.get("Not Applicable", 0),
                "blocked_count": len(db.get_blocked_actions(name)),
            })

        with_actions = [t for t in tenants_out if t["total_actions"] > 0]
        totals = {
            "tenant_count": len(tenants_out),
            "avg_percentage": round(sum(t["percentage"] for t in with_actions) / len(with_actions), 2) if with_actions else 0,
            "avg_adj_percentage": round(sum(t["adj_percentage"] for t in with_actions) / len(with_actions), 2) if with_actions else 0,
            "total_actions": sum(t["total_actions"] for t in tenants_out),
            "completed_actions": sum(t["completed_actions"] for t in tenants_out),
            "risk_accepted": sum(t["risk_accepted"] for t in tenants_out),
            "blocked": sum(t["blocked_count"] for t in tenants_out),
        }
        return jsonify({"tenants": tenants_out, "totals": totals,
                        "generated_at": datetime.utcnow().isoformat()})

    # ── Action endpoints ──

    @app.route("/api/tenants/<name>/actions", methods=["GET"])
    def api_list_actions(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        filters = {}
        for key in ("status", "workload", "source_tool", "priority",
                     "essential_eight_control", "correlation_group_id", "search"):
            val = request.args.get(key)
            if val:
                filters[key] = val
        # Workload-scoped access: derive allowed workloads from session user
        allowed_workloads = None
        user_id = session.get("user_id")
        if user_id:
            accesses = db.get_user_tenant_access(user_id)
            for acc in accesses:
                if acc.get("tenant_name") == name:
                    wl = acc.get("workloads")
                    if wl:
                        import json as _json
                        allowed_workloads = _json.loads(wl) if isinstance(wl, str) else wl
                    break
        actions = db.get_actions(name, filters, allowed_workloads=allowed_workloads)
        return jsonify(actions)

    @app.route("/api/tenants/<name>/actions", methods=["POST"])
    def api_create_action(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        data = request.get_json()
        if not data or not data.get("title"):
            return _json_error("title is required")
        action = db.create_action(name, data)
        return jsonify(action), 201

    @app.route("/api/actions/<action_id>", methods=["GET"])
    def api_get_action(action_id):
        action = db.get_action(action_id)
        if not action:
            return _json_error("Action not found", 404)
        return jsonify(action)

    @app.route("/api/actions/<action_id>", methods=["PUT"])
    def api_update_action(action_id):
        data = request.get_json() or {}
        changed_by = data.pop("changed_by", "")
        action = db.update_action(action_id, data, changed_by)
        if not action:
            return _json_error("Action not found", 404)
        return jsonify(action)

    @app.route("/api/actions/<action_id>", methods=["DELETE"])
    def api_delete_action(action_id):
        action = db.get_action(action_id)
        if not action:
            return _json_error("Action not found", 404)
        db.delete_action(action_id)
        return jsonify({"deleted": True})

    @app.route("/api/actions/batch-delete", methods=["POST"])
    def api_batch_delete_actions():
        data = request.get_json() or {}
        action_ids = data.get("action_ids", [])
        if not action_ids:
            return _json_error("action_ids is required")
        deleted = 0
        for aid in action_ids:
            if db.get_action(aid):
                db.delete_action(aid)
                deleted += 1
        return jsonify({"deleted": deleted, "total_requested": len(action_ids)})

    @app.route("/api/actions/<action_id>/implementation", methods=["PUT"])
    def api_update_action_implementation(action_id):
        """Save implementation steps either globally (default) or only for
        this tenant. Body: {implementation_steps, scope: 'global'|'tenant'}.
        Requires the action to be linked to a global action."""
        data = request.get_json() or {}
        action = db.get_action(action_id)
        if not action:
            return _json_error("Action not found", 404)
        ga_id = action.get("global_action_id")
        if not ga_id:
            return _json_error("Action is not linked to a global action; promote it in Control Plane first", 400)
        scope = (data.get("scope") or "global").lower()
        steps = data.get("implementation_steps", "")
        actor = session.get("username") or data.get("changed_by", "")
        if scope == "tenant":
            db.set_implementation_override(action["tenant_name"], ga_id, steps, actor)
        elif scope == "global":
            db.update_global_action(ga_id, implementation_steps=steps)
            # If a tenant override was masking the global value, drop it so the
            # newly-saved global value takes effect immediately.
            db.clear_implementation_override(action["tenant_name"], ga_id)
        else:
            return _json_error("scope must be 'global' or 'tenant'", 400)
        return jsonify(db.get_action(action_id))

    @app.route("/api/actions/<action_id>/peers", methods=["GET"])
    def api_action_peers(action_id):
        """Cross-tool peers for an action: other tenant actions correlated via
        correlation group or explicit link. Includes a status_differs flag so
        the UI can mark peers whose status disagrees."""
        return jsonify(db.get_action_peers(action_id))

    @app.route("/api/actions/<action_id>/peers/sync", methods=["POST"])
    def api_sync_peer_status(action_id):
        """Copy the current action's status to all differing peers (or a subset
        of peer IDs supplied in the request body as {peer_ids: [...]})."""
        action = db.get_action(action_id)
        if not action:
            return _json_error("Action not found", 404)
        data = request.get_json(silent=True) or {}
        peer_ids = data.get("peer_ids")  # None => all differing peers
        peers = db.get_action_peers(action_id)
        targets = [p for p in peers if p["status_differs"]]
        if peer_ids is not None:
            peer_id_set = set(peer_ids)
            targets = [p for p in targets if p["id"] in peer_id_set]
        changed_by = session.get("username") or data.get("changed_by", "peer-sync")
        updated = 0
        for p in targets:
            db.update_action(p["id"], {"status": action["status"]}, changed_by=changed_by)
            updated += 1
        return jsonify({"updated": updated, "status": action["status"]})

    @app.route("/api/tenants/<name>/peer-disagreements", methods=["GET"])
    def api_tenant_peer_disagreements(name):
        """Map of action_id -> count of correlated peers whose status differs.
        Used by the actions list to render a peer-disagreement indicator."""
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        return jsonify(db.get_peer_disagreements_for_tenant(name))

    @app.route("/api/actions/<action_id>/implementation-override", methods=["DELETE"])
    def api_clear_action_implementation_override(action_id):
        """Drop the per-tenant override and revert to the global value."""
        action = db.get_action(action_id)
        if not action:
            return _json_error("Action not found", 404)
        ga_id = action.get("global_action_id")
        if not ga_id:
            return _json_error("Action is not linked to a global action", 400)
        removed = db.clear_implementation_override(action["tenant_name"], ga_id)
        if not removed:
            return _json_error("No override to remove", 404)
        return jsonify(db.get_action(action_id))

    # ── Import endpoint ──

    @app.route("/api/tenants/<name>/import", methods=["POST"])
    def api_import(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)

        source = request.form.get("source")
        if source not in PARSER_MAP:
            return _json_error(f"Invalid source. Valid: {', '.join(PARSER_MAP.keys())}")

        file = request.files.get("file")
        if not file:
            return _json_error("No file uploaded")

        # Save to temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(file.filename).suffix) as tmp:
            file.save(tmp)
            tmp_path = tmp.name

        force_tenant = request.form.get("force") == "1"
        try:
            result = process_file_import(db, name, source, tmp_path, file.filename,
                                         force_tenant=force_tenant)
            db.audit("import.file", actor=session.get("username"),
                     entity_type="tenant", entity_id=name,
                     detail=f"{source}:{file.filename}"
                            + (" (tenant check overridden)" if force_tenant else ""))
            return jsonify(result)
        except TenantMismatchError as e:
            return jsonify({"error": e.payload["message"], **e.payload}), 409
        except Exception as e:
            return _json_error(f"Import failed: {str(e)}")
        finally:
            os.unlink(tmp_path)

    # ── Import status conflicts (DB status vs. last imported status) ──

    @app.route("/api/tenants/<name>/import-status-conflicts", methods=["GET"])
    def api_import_status_conflicts(name):
        """Actions whose protected status differs from what the last import
        reported. The user decides per item (or in bulk) which side wins."""
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        return jsonify(db.get_import_status_conflicts(name))

    @app.route("/api/tenants/<name>/import-status-conflicts/resolve", methods=["POST"])
    def api_resolve_import_status_conflicts(name):
        """Resolve import/DB status conflicts.

        Body: {"resolution": "use_import"|"keep_mine",
               "action_ids": [...]}          # omit action_ids to resolve all
        - use_import: set the action status to the status the import reported.
        - keep_mine:  keep the DB status and dismiss the conflict.
        """
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        data = request.get_json() or {}
        resolution = data.get("resolution")
        if resolution not in ("use_import", "keep_mine"):
            return _json_error("resolution must be 'use_import' or 'keep_mine'")
        changed_by = session.get("username") or data.get("changed_by", "import-sync")
        result = db.resolve_import_status_conflicts(
            name, resolution, data.get("action_ids"), changed_by)
        return jsonify(result)

    # ── Zero Trust Report endpoints ──

    @app.route("/api/tenants/<name>/zt-reports", methods=["GET"])
    def api_zt_reports(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        reports = db.get_zt_reports(name)
        # Don't send the full tenant_info blob in list view
        for r in reports:
            r.pop("tenant_info", None)
        return jsonify(reports)

    @app.route("/api/zt-reports/<report_id>", methods=["GET"])
    def api_zt_report_detail(report_id):
        report = db.get_zt_report(report_id)
        if not report:
            return _json_error("Report not found", 404)
        return jsonify(report)

    @app.route("/api/zt-reports/<report_id>", methods=["DELETE"])
    def api_zt_report_delete(report_id):
        """Remove a stored ZT report record and its files (imported actions
        are kept — clean those up via the Actions page if needed)."""
        report = db.get_zt_report(report_id)
        if not report:
            return _json_error("Report not found", 404)
        db.delete_zt_report(report_id)
        db.audit("zt_report.delete", actor=session.get("username"),
                 entity_type="tenant", entity_id=report.get("tenant_name"),
                 detail=report_id)
        return jsonify({"deleted": True})

    @app.route("/api/zt-reports/<report_id>/html", methods=["GET"])
    def api_zt_report_html(report_id):
        report = db.get_zt_report(report_id)
        if not report:
            return _json_error("Report not found", 404)
        html_path = report.get("html_path", "")
        if not html_path or not Path(html_path).exists():
            return _json_error("HTML report file not found", 404)
        return send_file(html_path, mimetype="text/html")

    # ── Scores endpoint ──

    @app.route("/api/tenants/<name>/scores", methods=["GET"])
    def api_scores(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        exclude_na = request.args.get("exclude_na", "").lower() in ("1", "true", "yes")
        exclude_ra = request.args.get("exclude_ra", "").lower() in ("1", "true", "yes")
        return jsonify(db.get_scores(name, exclude_na=exclude_na, exclude_ra=exclude_ra))

    # ── Essential Eight endpoint ──

    @app.route("/api/tenants/<name>/e8", methods=["GET"])
    def api_e8(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        target = request.args.get("target", "Maturity Level 3")
        exclude_na = request.args.get("exclude_na", "0") == "1"
        actions = db.get_actions(name)
        action_objects = [Action.from_dict(a) for a in actions]
        action_objects = apply_e8_mapping(action_objects)
        summary = get_e8_summary(action_objects, target_maturity=target, exclude_na=exclude_na)
        return jsonify(summary)

    # ── SCuBA endpoints ──

    @app.route("/api/tenants/<name>/scuba", methods=["GET"])
    def api_scuba_summary(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        actions = db.get_actions(name)
        scuba_actions = [a for a in actions if a.get("source_tool") == SourceTool.SCUBA.value]

        def _count_status(status, counters):
            if status == ActionStatus.COMPLETED.value:
                counters["pass"] += 1
            elif status == ActionStatus.TODO.value:
                counters["fail"] += 1
            elif status == ActionStatus.IN_PLANNING.value:
                counters["warning"] += 1
            elif status == ActionStatus.NOT_APPLICABLE.value:
                counters["na"] += 1

        def _action_summary(a):
            tags = a.get("tags") or []
            if isinstance(tags, str):
                import json as _j
                try:
                    tags = _j.loads(tags)
                except Exception:
                    tags = []
            group_tag = next((t.replace("Group:", "") for t in tags if t.startswith("Group:")), "")
            return {
                "id": a.get("id"), "title": a.get("title"),
                "status": a.get("status"), "priority": a.get("priority"),
                "source_id": a.get("source_id"), "reference_id": a.get("reference_id", ""),
                "current_value": a.get("current_value", ""),
                "subcategory": a.get("subcategory", ""),
                "reference_url": a.get("reference_url", ""),
                "notes": a.get("notes", ""),
                "group": group_tag,
            }

        # Group by product → group
        products = {}
        for a in scuba_actions:
            prod = a.get("category", "") or "Unknown"
            if prod not in products:
                products[prod] = {"total": 0, "pass": 0, "fail": 0, "warning": 0, "na": 0, "groups": {}}
            products[prod]["total"] += 1
            status = a.get("status", "")
            _count_status(status, products[prod])

            summary = _action_summary(a)
            group_name = summary["group"] or "Ungrouped"
            if group_name not in products[prod]["groups"]:
                products[prod]["groups"][group_name] = {
                    "total": 0, "pass": 0, "fail": 0, "warning": 0, "na": 0,
                    "reference_url": a.get("reference_url", ""),
                    "actions": [],
                }
            grp = products[prod]["groups"][group_name]
            grp["total"] += 1
            _count_status(status, grp)
            grp["actions"].append(summary)

        total = len(scuba_actions)
        passed = sum(p["pass"] for p in products.values())
        failed = sum(p["fail"] for p in products.values())
        warnings = sum(p["warning"] for p in products.values())
        na_count = sum(p["na"] for p in products.values())

        return jsonify({
            "total_controls": total,
            "passed": passed,
            "failed": failed,
            "warnings": warnings,
            "na": na_count,
            "pass_rate": round(passed / total * 100, 1) if total else 0,
            "products": products,
        })

    @app.route("/api/tenants/<name>/scuba-reports", methods=["GET"])
    def api_scuba_reports(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        return jsonify(db.get_scuba_reports(name))

    @app.route("/api/scuba-reports/<report_id>", methods=["GET"])
    def api_scuba_report_detail(report_id):
        report = db.get_scuba_report(report_id)
        if not report:
            return _json_error("Report not found", 404)
        return jsonify(report)

    @app.route("/api/scuba-reports/<report_id>", methods=["DELETE"])
    def api_scuba_report_delete(report_id):
        """Remove a stored SCuBA report record and its files (imported
        actions are kept — clean those up via the Actions page if needed)."""
        report = db.get_scuba_report(report_id)
        if not report:
            return _json_error("Report not found", 404)
        db.delete_scuba_report(report_id)
        db.audit("scuba_report.delete", actor=session.get("username"),
                 entity_type="tenant", entity_id=report.get("tenant_name"),
                 detail=report_id)
        return jsonify({"deleted": True})

    @app.route("/api/scuba-reports/<report_id>/html", methods=["GET"])
    @app.route("/api/scuba-reports/<report_id>/html/<path:subpath>", methods=["GET"])
    def api_scuba_report_html(report_id, subpath=None):
        report = db.get_scuba_report(report_id)
        if not report:
            return _json_error("Report not found", 404)
        html_path = report.get("html_path", "")
        if not html_path or not Path(html_path).exists():
            return _json_error("HTML report file not found", 404)
        report_root = Path(html_path).parent

        if subpath:
            # Serve sub-pages (e.g. IndividualReports/AADReport.html)
            target = report_root / subpath
            try:
                target.resolve().relative_to(report_root.resolve())
            except ValueError:
                return _json_error("Invalid path", 400)
            if not target.exists():
                return _json_error("File not found", 404)
            # For non-HTML files, serve directly
            if target.suffix.lower() not in (".html", ".htm"):
                import mimetypes
                mime = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
                return send_file(str(target), mimetype=mime)
            serve_path = str(target)
            # Compute base href relative to this sub-page
            rel = Path(subpath).parent
            depth = len(rel.parts) if str(rel) != "." else 0
            base_href = f"/api/scuba-reports/{report_id}/html/" + ("../" * depth if depth else "")
        else:
            serve_path = html_path
            base_href = f"/api/scuba-reports/{report_id}/html/"

        # Inject <base> tag so relative links (images, sub-pages) resolve correctly
        with open(serve_path, "r", encoding="utf-8") as f:
            content = f.read()
        base_tag = f'<base href="{base_href}">'
        if "<head>" in content:
            content = content.replace("<head>", f"<head>{base_tag}", 1)
        elif "<HEAD>" in content:
            content = content.replace("<HEAD>", f"<HEAD>{base_tag}", 1)
        else:
            content = base_tag + content
        return Response(content, mimetype="text/html")

    @app.route("/api/scuba-reports/<report_id>/files/<path:filepath>", methods=["GET"])
    def api_scuba_report_files(report_id, filepath):
        """Serve static files (images, CSS) from the SCuBA report directory."""
        report = db.get_scuba_report(report_id)
        if not report:
            return _json_error("Report not found", 404)
        html_path = report.get("html_path", "")
        if not html_path:
            return _json_error("No report directory", 404)
        report_dir = Path(html_path).parent
        full_path = report_dir / filepath
        try:
            full_path.resolve().relative_to(report_dir.resolve())
        except ValueError:
            return _json_error("Invalid path", 400)
        if not full_path.exists():
            return _json_error("File not found", 404)
        import mimetypes
        mime = mimetypes.guess_type(str(full_path))[0] or "application/octet-stream"
        return send_file(str(full_path), mimetype=mime)

    # ── Import history ──

    @app.route("/api/tenants/<name>/history", methods=["GET"])
    def api_history(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        return jsonify(db.get_import_history(name))

    @app.route("/api/tenants/<name>/changelog", methods=["GET"])
    def api_changelog(name):
        limit = request.args.get("limit", 100, type=int)
        return jsonify(db.get_tenant_change_log(name, limit))

    # ── Correlation endpoints ──

    @app.route("/api/tenants/<name>/correlations", methods=["GET"])
    def api_correlations(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        return jsonify(get_correlation_summary(db, name))

    @app.route("/api/tenants/<name>/correlate", methods=["POST"])
    def api_run_correlation(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        result = auto_correlate(db, name)
        return jsonify(result)

    @app.route("/api/tenants/<name>/suggested-links", methods=["GET"])
    def api_suggested_links(name):
        """Cross-tool action pairs that likely represent the same control
        (title similarity), so linking them lets one fix validate all tools."""
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        from .correlation import suggest_action_links
        return jsonify(suggest_action_links(db, name))

    @app.route("/api/tenants/<name>/suggested-links/dismiss", methods=["POST"])
    def api_dismiss_suggested_link(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        data = request.get_json() or {}
        a, b = data.get("action_a_id"), data.get("action_b_id")
        if not a or not b:
            return _json_error("action_a_id and action_b_id required")
        db.dismiss_link_suggestion(name, a, b)
        return jsonify({"dismissed": True})

    @app.route("/api/correlation-groups", methods=["GET"])
    def api_correlation_groups():
        return jsonify(db.list_correlation_groups())

    @app.route("/api/correlation-groups", methods=["POST"])
    def api_create_correlation_group():
        data = request.get_json() or {}
        if not data.get("canonical_name"):
            return _json_error("canonical_name is required")
        group = db.create_correlation_group(
            data["canonical_name"],
            data.get("description", ""),
            data.get("keywords", []),
        )
        return jsonify(group), 201

    @app.route("/api/correlation-groups/<group_id>", methods=["PUT"])
    def api_update_correlation_group(group_id):
        data = request.get_json() or {}
        if not data.get("canonical_name"):
            return _json_error("canonical_name is required")
        group = db.update_correlation_group(
            group_id,
            data["canonical_name"],
            data.get("description", ""),
            data.get("keywords", []),
        )
        return jsonify(group)

    @app.route("/api/correlation-groups/<group_id>", methods=["DELETE"])
    def api_delete_correlation_group(group_id):
        db.delete_correlation_group(group_id)
        return jsonify({"deleted": True})

    @app.route("/api/correlation-groups/seed-defaults", methods=["POST"])
    def api_seed_default_families():
        """Seed the default control families from CONTROL_FAMILIES if DB is empty."""
        from .correlation import CONTROL_FAMILIES
        existing = db.list_correlation_groups()
        existing_names = {g["canonical_name"] for g in existing}
        created = 0
        for canonical_name, description, keywords in CONTROL_FAMILIES:
            if canonical_name not in existing_names:
                db.create_correlation_group(canonical_name, description, keywords)
                created += 1
        return jsonify({"seeded": created})

    @app.route("/api/actions/<action_id>/link", methods=["POST"])
    def api_link_action(action_id):
        data = request.get_json() or {}
        group_id = data.get("group_id")
        if not group_id:
            return _json_error("group_id is required")
        db.link_action_to_group(action_id, group_id)
        return jsonify({"linked": True})

    @app.route("/api/actions/<action_id>/unlink", methods=["POST"])
    def api_unlink_action(action_id):
        db.unlink_action(action_id)
        return jsonify({"unlinked": True})

    # ── Plan endpoints ──

    @app.route("/api/tenants/<name>/plans", methods=["GET"])
    def api_list_plans(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        return jsonify(db.get_plans(name))

    @app.route("/api/tenants/<name>/plans", methods=["POST"])
    def api_create_plan(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        data = request.get_json() or {}
        if not data.get("name"):
            return _json_error("name is required")
        plan = db.create_plan(name, data["name"], data.get("description", ""))

        # Update additional plan metadata if provided
        extra = {}
        for field in ("responsible_person", "start_date", "end_date",
                       "priority", "implementation_effort"):
            if field in data:
                extra[field] = data[field]
        if extra:
            db.update_plan(plan["id"], **extra)

        # If action_ids provided, add them
        action_ids = data.get("action_ids", [])
        for i, aid in enumerate(action_ids):
            db.add_plan_item(plan["id"], aid, phase=1, sequence=i)

        return jsonify(db.get_plan(plan["id"])), 201

    @app.route("/api/plans/<plan_id>", methods=["GET"])
    def api_get_plan(plan_id):
        plan = db.get_plan(plan_id)
        if not plan:
            return _json_error("Plan not found", 404)
        return jsonify(plan)

    @app.route("/api/plans/<plan_id>", methods=["PUT"])
    def api_update_plan(plan_id):
        data = request.get_json() or {}
        plan = db.update_plan(plan_id, **data)
        if not plan:
            return _json_error("Plan not found", 404)
        return jsonify(plan)

    @app.route("/api/plans/<plan_id>", methods=["DELETE"])
    def api_delete_plan(plan_id):
        db.delete_plan(plan_id)
        return jsonify({"deleted": True})

    @app.route("/api/plans/<plan_id>/items", methods=["POST"])
    def api_add_plan_item(plan_id):
        data = request.get_json() or {}
        if not data.get("action_id"):
            return _json_error("action_id is required")
        plan = db.add_plan_item(
            plan_id, data["action_id"],
            phase=data.get("phase", 1),
            sequence=data.get("sequence", 0),
            estimated_days=data.get("estimated_days"),
            notes=data.get("notes", ""),
        )
        return jsonify(plan)

    @app.route("/api/plans/<plan_id>/items/<action_id>", methods=["DELETE"])
    def api_remove_plan_item(plan_id, action_id):
        db.remove_plan_item(plan_id, action_id)
        return jsonify(db.get_plan(plan_id))

    @app.route("/api/plans/<plan_id>/items/<action_id>", methods=["PUT"])
    def api_update_plan_item(plan_id, action_id):
        data = request.get_json() or {}
        db.update_plan_item(plan_id, action_id, **data)
        return jsonify(db.get_plan(plan_id))

    # ── Plan simulation ──

    @app.route("/api/tenants/<name>/simulate", methods=["POST"])
    def api_simulate(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        data = request.get_json() or {}
        action_ids = data.get("action_ids", [])
        if not action_ids:
            return _json_error("action_ids required")
        result = simulate_plan(db, name, action_ids)
        return jsonify(result)

    @app.route("/api/tenants/<name>/suggest-phases", methods=["POST"])
    def api_suggest_phases(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        data = request.get_json() or {}
        action_ids = data.get("action_ids", [])
        num_phases = data.get("num_phases", 3)
        if not action_ids:
            return _json_error("action_ids required")
        phases = suggest_phases(db, name, action_ids, num_phases)
        return jsonify(phases)

    @app.route("/api/tenants/<name>/prioritized", methods=["GET"])
    def api_prioritized(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        limit = request.args.get("limit", 20, type=int)
        return jsonify(get_prioritized_actions(db, name, limit))

    # ── Compare endpoint ──

    @app.route("/api/compare", methods=["POST"])
    def api_compare():
        data = request.get_json() or {}
        tenant_names = data.get("tenants", [])
        if len(tenant_names) < 2:
            return _json_error("At least 2 tenants required")

        result = {"tenants": tenant_names, "overall": {}, "by_tool": {}, "by_workload": {}}
        for name in tenant_names:
            scores = db.get_scores(name)
            result["overall"][name] = {
                "percentage": scores.get("percentage", 0),
                "total_actions": scores.get("total_actions", 0),
                "completed_actions": scores.get("completed_actions", 0),
            }
            for tool, data_t in scores.get("by_tool", {}).items():
                if tool not in result["by_tool"]:
                    result["by_tool"][tool] = {}
                result["by_tool"][tool][name] = data_t
            for wl, data_w in scores.get("by_workload", {}).items():
                if wl not in result["by_workload"]:
                    result["by_workload"][wl] = {}
                result["by_workload"][wl][name] = data_w

        return jsonify(result)

    # ── Action comparison across tenants ──

    @app.route("/api/compare-actions", methods=["POST"])
    def api_compare_actions():
        """Compare individual actions across tenants by matching source_id."""
        data = request.get_json() or {}
        tenant_names = data.get("tenants", [])
        if len(tenant_names) < 2:
            return _json_error("At least 2 tenants required")

        # Gather all actions per tenant, keyed by source_id
        tenant_actions = {}
        for name in tenant_names:
            actions = db.get_actions(name)
            tenant_actions[name] = {a["source_id"]: a for a in actions if a.get("source_id")}

        # Find all unique source_ids across tenants
        all_source_ids = set()
        for actions_map in tenant_actions.values():
            all_source_ids.update(actions_map.keys())

        # Build comparison rows
        rows = []
        for sid in sorted(all_source_ids):
            row = {"source_id": sid, "title": "", "tenants": {}}
            statuses = set()
            for tname in tenant_names:
                a = tenant_actions[tname].get(sid)
                if a:
                    row["tenants"][tname] = {
                        "id": a["id"], "status": a["status"],
                        "priority": a["priority"],
                        "score": a.get("score"), "max_score": a.get("max_score"),
                        "workload": a.get("workload", ""),
                    }
                    if not row["title"]:
                        row["title"] = a["title"]
                    statuses.add(a["status"])
                else:
                    row["tenants"][tname] = None
            # Mark as different if statuses differ or action missing in some tenants
            row["differs"] = len(statuses) > 1 or len(row["tenants"]) != len(
                [v for v in row["tenants"].values() if v is not None]
            )
            rows.append(row)

        # Sort: differing actions first, then by title
        rows.sort(key=lambda r: (0 if r["differs"] else 1, r["title"]))
        return jsonify({"tenants": tenant_names, "actions": rows,
                        "total": len(rows), "differing": sum(1 for r in rows if r["differs"])})

    # ── Snapshot comparison ──

    @app.route("/api/tenants/<name>/compare-snapshot", methods=["POST"])
    def api_compare_snapshot(name):
        """Compare current tenant scores against a historical snapshot."""
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        data = request.get_json() or {}
        snapshot_id = data.get("snapshot_id")
        if not snapshot_id:
            return _json_error("snapshot_id required")

        # Get the snapshot
        snapshots = db.get_score_snapshots(name, limit=500)
        snapshot = next((s for s in snapshots if s["id"] == snapshot_id), None)
        if not snapshot:
            return _json_error("Snapshot not found", 404)

        # Get current scores (full and adjusted)
        current = db.get_scores(name)
        current_adj = db.get_scores(name, exclude_na=True, exclude_ra=True)
        snap_label = "Snapshot (" + snapshot["timestamp"][:10] + ")"
        cur_label = "Current"

        # Snapshot adjusted scores (stored since the adj_scores migration; may be None for old snapshots)
        snap_adj_pct = snapshot.get("adj_percentage")
        snap_has_adj = snap_adj_pct is not None

        result = {
            "tenant": name,
            "snapshot_id": snapshot_id,
            "snapshot_timestamp": snapshot["timestamp"],
            "labels": [cur_label, snap_label],
            "overall": {
                cur_label: {
                    "percentage": current.get("percentage", 0),
                    "total_actions": current.get("total_actions", 0),
                    "completed_actions": current.get("completed_actions", 0),
                    "adj_percentage": current_adj.get("percentage", 0),
                    "adj_total_actions": current_adj.get("total_actions", 0),
                    "adj_completed_actions": current_adj.get("completed_actions", 0),
                    "adj_total_score": current_adj.get("total_score", 0),
                    "adj_total_max": current_adj.get("total_max", 0),
                },
                snap_label: {
                    "percentage": snapshot.get("percentage", 0),
                    "total_actions": snapshot.get("total_actions", 0),
                    "completed_actions": snapshot.get("completed_actions", 0),
                    "adj_percentage": snapshot.get("adj_percentage"),
                    "adj_total_actions": snapshot.get("adj_total_actions"),
                    "adj_completed_actions": snapshot.get("adj_completed_actions"),
                    "adj_total_score": snapshot.get("adj_total_score"),
                    "adj_total_max": snapshot.get("adj_total_max"),
                },
            },
            "snap_has_adj": snap_has_adj,
            "by_tool": {},
            "by_workload": {},
            "adj_by_tool": {},
            "adj_by_workload": {},
        }

        # Merge tool data (full)
        all_tools = set(list(current.get("by_tool", {}).keys()) +
                        list(snapshot.get("by_tool", {}).keys()))
        for tool in sorted(all_tools):
            result["by_tool"][tool] = {
                cur_label: current.get("by_tool", {}).get(tool, {}),
                snap_label: snapshot.get("by_tool", {}).get(tool, {}),
            }

        # Merge tool data (adjusted)
        all_adj_tools = set(list(current_adj.get("by_tool", {}).keys()) +
                            list(snapshot.get("adj_by_tool", {}).keys()))
        for tool in sorted(all_adj_tools):
            result["adj_by_tool"][tool] = {
                cur_label: current_adj.get("by_tool", {}).get(tool, {}),
                snap_label: snapshot.get("adj_by_tool", {}).get(tool, {}),
            }

        # Merge workload data (full)
        all_wl = set(list(current.get("by_workload", {}).keys()) +
                      list(snapshot.get("by_workload", {}).keys()))
        for wl in sorted(all_wl):
            result["by_workload"][wl] = {
                cur_label: current.get("by_workload", {}).get(wl, {}),
                snap_label: snapshot.get("by_workload", {}).get(wl, {}),
            }

        # Merge workload data (adjusted)
        all_adj_wl = set(list(current_adj.get("by_workload", {}).keys()) +
                          list(snapshot.get("adj_by_workload", {}).keys()))
        for wl in sorted(all_adj_wl):
            result["adj_by_workload"][wl] = {
                cur_label: current_adj.get("by_workload", {}).get(wl, {}),
                snap_label: snapshot.get("adj_by_workload", {}).get(wl, {}),
            }

        # Action-level comparison: reconstruct status at snapshot time
        # by reversing history entries that occurred after the snapshot
        snap_ts = snapshot["timestamp"]
        actions = db.get_actions(name)
        action_diffs = []
        same_count = 0
        for a in actions:
            current_status = a["status"]
            # Walk history backwards to find status at snapshot time
            status_at_snap = current_status
            # History entries after snapshot, newest first
            changes_after = sorted(
                [h for h in (a.get("history") or []) if h.get("timestamp", "") > snap_ts],
                key=lambda h: h["timestamp"], reverse=True
            )
            for h in changes_after:
                if h.get("old_status"):
                    status_at_snap = h["old_status"]

            # Actions created after snapshot didn't exist then
            created_after = a.get("created_at", "") > snap_ts if a.get("created_at") else False

            if created_after:
                action_diffs.append({
                    "title": a["title"], "source_id": a.get("source_id", ""),
                    "differs": True,
                    "current": {"id": a["id"], "status": current_status,
                                "priority": a["priority"], "workload": a.get("workload", "")},
                    "snapshot": None,
                })
            elif status_at_snap != current_status:
                action_diffs.append({
                    "title": a["title"], "source_id": a.get("source_id", ""),
                    "differs": True,
                    "current": {"id": a["id"], "status": current_status,
                                "priority": a["priority"], "workload": a.get("workload", "")},
                    "snapshot": {"id": a["id"], "status": status_at_snap,
                                 "priority": a["priority"], "workload": a.get("workload", "")},
                })
            else:
                same_count += 1

        # Sort: differing first, then by title
        action_diffs.sort(key=lambda r: r["title"])
        result["action_diffs"] = action_diffs
        result["actions_same"] = same_count
        result["actions_differing"] = len(action_diffs)

        return jsonify(result)

    # ── Responsible Persons ──

    @app.route("/api/users", methods=["GET"])
    def api_list_users_for_select():
        """Lightweight user list for selectors (responsible/owner pickers).
        Available to any authenticated user; returns only fields needed for
        rendering a dropdown."""
        users = db.list_users()
        return jsonify([
            {
                "id": u.get("id"),
                "username": u.get("username"),
                "display_name": u.get("display_name") or u.get("username"),
                "email": u.get("email", ""),
                "role": u.get("role", ""),
                "is_active": bool(u.get("is_active", True)),
            }
            for u in users
        ])

    # ── Action Links (cross-tool) ──

    @app.route("/api/actions/<action_id>/links", methods=["GET"])
    def api_action_crosslinks(action_id):
        return jsonify(db.get_linked_actions(action_id))

    @app.route("/api/actions/<action_id>/links", methods=["POST"])
    def api_create_crosslink(action_id):
        data = request.get_json() or {}
        target_id = data.get("target_action_id")
        if not target_id:
            return _json_error("target_action_id required")
        db.link_actions(action_id, target_id, data.get("link_type", "related"))
        return jsonify({"ok": True})

    @app.route("/api/actions/<aid>/links/<tid>", methods=["DELETE"])
    def api_delete_crosslink(aid, tid):
        db.unlink_actions(aid, tid)
        return jsonify({"ok": True})

    # ── Batch status update ──

    @app.route("/api/actions/batch-status", methods=["POST"])
    def api_batch_status():
        data = request.get_json() or {}
        action_ids = data.get("action_ids", [])
        status = data.get("status")
        if not action_ids or not status:
            return _json_error("action_ids and status required")
        updated = 0
        for aid in action_ids:
            result = db.update_action(aid, {"status": status},
                                       changed_by=data.get("changed_by", "batch"))
            if result:
                updated += 1
        return jsonify({"updated": updated})

    # ── Plan membership lookup ──

    @app.route("/api/tenants/<name>/action-plans", methods=["GET"])
    def api_action_plans(name):
        """Return a mapping of action_id -> list of plan names for all actions in plans."""
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        plans = db.get_plans(name)
        result = {}
        for p in plans:
            full = db.get_plan(p["id"])
            if full:
                for item in full.get("items", []):
                    aid = item["action_id"]
                    if aid not in result:
                        result[aid] = []
                    result[aid].append({"plan_id": p["id"], "plan_name": p["name"],
                                        "plan_status": p["status"]})
        return jsonify(result)

    # ── GitLab Templates ──

    @app.route("/api/tenants/<name>/gitlab-templates", methods=["GET"])
    def api_list_gitlab_templates(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        return jsonify(db.get_gitlab_templates(name))

    @app.route("/api/tenants/<name>/gitlab-templates", methods=["POST"])
    def api_create_gitlab_template(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        data = request.get_json() or {}
        if not data.get("name"):
            return _json_error("name is required")
        tpl = db.create_gitlab_template(
            name, data["name"], data.get("template_type", "assessment"),
            data.get("title_template", ""), data.get("body_template", ""),
            data.get("labels", []),
        )
        return jsonify(tpl), 201

    @app.route("/api/gitlab-templates/<template_id>", methods=["GET"])
    def api_get_gitlab_template(template_id):
        tpl = db.get_gitlab_template(template_id)
        if not tpl:
            return _json_error("Template not found", 404)
        return jsonify(tpl)

    @app.route("/api/gitlab-templates/<template_id>", methods=["PUT"])
    def api_update_gitlab_template(template_id):
        data = request.get_json() or {}
        tpl = db.update_gitlab_template(template_id, **data)
        if not tpl:
            return _json_error("Template not found", 404)
        return jsonify(tpl)

    @app.route("/api/gitlab-templates/<template_id>", methods=["DELETE"])
    def api_delete_gitlab_template(template_id):
        db.delete_gitlab_template(template_id)
        return jsonify({"deleted": True})

    @app.route("/api/tenants/<name>/plans/<plan_id>/export-gitlab", methods=["POST"])
    def api_export_plan_gitlab(name, plan_id):
        """Export plan actions as GitLab-ready files using tenant's templates."""
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        plan = db.get_plan(plan_id)
        if not plan:
            return _json_error("Plan not found", 404)

        data = request.get_json() or {}
        template_id = data.get("template_id")
        if not template_id:
            return _json_error("template_id is required")
        tpl = db.get_gitlab_template(template_id)
        if not tpl:
            return _json_error("Template not found", 404)

        tenant = db.get_tenant(name)

        # Render each action through the template
        issues = []
        for item in plan.get("items", []):
            # Build variable context for template substitution
            ctx = {
                "action_title": item.get("title", ""),
                "action_status": item.get("status", ""),
                "action_priority": item.get("priority", ""),
                "action_workload": item.get("workload", ""),
                "action_effort": item.get("implementation_effort", ""),
                "action_risk_level": item.get("risk_level", ""),
                "action_user_impact": item.get("user_impact", ""),
                "action_score": f"{item.get('score', 0)}/{item.get('max_score', 0)}",
                "action_source": item.get("source_tool", ""),
                "action_licence": item.get("required_licence", ""),
                "action_id": item.get("action_id", ""),
                "plan_name": plan.get("name", ""),
                "tenant_name": tenant.get("display_name", name),
                "tenant_id": tenant.get("tenant_id", ""),
            }

            # Get full action for description/remediation
            full_action = db.get_action(item.get("action_id", ""))
            if full_action:
                ctx["action_description"] = full_action.get("description", "")
                ctx["action_remediation"] = full_action.get("remediation_steps", "")
                ctx["action_current_value"] = full_action.get("current_value", "")
                ctx["action_recommended_value"] = full_action.get("recommended_value", "")
                ctx["action_reference_url"] = full_action.get("reference_url", "")
                ctx["action_category"] = full_action.get("category", "")
                ctx["action_subcategory"] = full_action.get("subcategory", "")
                ctx["action_tags"] = ", ".join(full_action.get("tags", []))

            # Substitute variables in templates
            title = tpl.get("title_template", "")
            body = tpl.get("body_template", "")
            for k, v in ctx.items():
                title = title.replace(f"{{{{{k}}}}}", str(v or ""))
                body = body.replace(f"{{{{{k}}}}}", str(v or ""))

            issues.append({
                "title": title,
                "body": body,
                "labels": tpl.get("labels", []),
                "action_id": item.get("action_id", ""),
            })

        return jsonify({
            "template": tpl["name"],
            "template_type": tpl["template_type"],
            "plan": plan["name"],
            "issue_count": len(issues),
            "issues": issues,
        })

    # ── Generic table → Excel export ──

    @app.route("/api/export-xlsx", methods=["POST"])
    def api_export_xlsx():
        """Turn posted table data into an Excel file.

        Body: {"filename": "...", "sheet": "...", "headers": [...], "rows": [[...], ...]}
        Used by the 'Export Excel' buttons throughout the UI.
        """
        from .xlsx import make_xlsx
        data = request.get_json() or {}
        headers = data.get("headers") or []
        rows = data.get("rows") or []
        if not headers:
            return _json_error("headers required")
        if len(rows) > 50000:
            return _json_error("Too many rows (max 50000)")
        fname = re.sub(r"[^A-Za-z0-9._-]", "_", data.get("filename") or "export")[:80]
        content = make_xlsx(headers, rows, data.get("sheet") or "Export")
        resp = Response(content, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        resp.headers["Content-Disposition"] = f"attachment; filename={fname}.xlsx"
        return resp

    # ── Data export (raw actions as CSV / JSON / Excel) ──

    _EXPORT_COLUMNS = [
        "id", "title", "status", "priority", "risk_level", "user_impact",
        "implementation_effort", "workload", "source_tool", "source_id",
        "reference_id", "category", "subcategory", "score", "max_score",
        "score_percentage", "required_licence", "essential_eight_control",
        "essential_eight_maturity", "responsible", "planned_date", "notes",
        "risk_owner", "risk_justification", "risk_review_date", "risk_expiry_date",
        "reference_url", "last_seen_in_report", "created_at", "updated_at",
    ]

    @app.route("/api/tenants/<name>/export-actions", methods=["GET"])
    def api_export_actions(name):
        """Download the tenant's actions as CSV or JSON, with optional
        status / source_tool / workload filters."""
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        fmt = request.args.get("format", "csv").lower()
        filters = {}
        for key in ("status", "source_tool", "workload"):
            val = request.args.get(key)
            if val:
                filters[key] = val
        actions = db.get_actions(name, filters)
        stamp = datetime.utcnow().strftime("%Y%m%d")

        if fmt == "json":
            rows = []
            for a in actions:
                row = {k: a.get(k) for k in _EXPORT_COLUMNS}
                row["description"] = a.get("description", "")
                row["implementation_steps"] = a.get("implementation_steps", "")
                row["tags"] = a.get("tags", [])
                rows.append(row)
            resp = Response(json.dumps(rows, indent=2), mimetype="application/json")
            resp.headers["Content-Disposition"] = \
                f"attachment; filename=actions_{name}_{stamp}.json"
            return resp

        if fmt == "csv":
            import csv
            import io as _io
            buf = _io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(_EXPORT_COLUMNS)
            for a in actions:
                writer.writerow([a.get(k) if a.get(k) is not None else "" for k in _EXPORT_COLUMNS])
            resp = Response(buf.getvalue(), mimetype="text/csv")
            resp.headers["Content-Disposition"] = \
                f"attachment; filename=actions_{name}_{stamp}.csv"
            return resp

        if fmt == "xlsx":
            from .xlsx import make_xlsx
            rows = [[a.get(k) for k in _EXPORT_COLUMNS] for a in actions]
            content = make_xlsx(_EXPORT_COLUMNS, rows, "Actions")
            resp = Response(content, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            resp.headers["Content-Disposition"] = \
                f"attachment; filename=actions_{name}_{stamp}.xlsx"
            return resp

        return _json_error("format must be 'csv', 'json' or 'xlsx'")

    # ── Export endpoint ──

    @app.route("/api/tenants/<name>/export", methods=["POST"])
    def api_export(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)

        data = request.get_json() or {}
        fmt = data.get("format", "csv")
        filter_status = data.get("status_filter")
        tenant = db.get_tenant(name)
        display_name = tenant.get("display_name", name)

        actions_data = db.get_actions(name)
        actions = [Action.from_dict(a) for a in actions_data]

        with tempfile.NamedTemporaryFile(delete=False, suffix=f".{fmt}") as tmp:
            tmp_path = tmp.name

        try:
            if fmt == "csv":
                export_to_gitlab_csv(actions, tmp_path, display_name,
                                     filter_status.split(",") if filter_status else None)
                mime = "text/csv"
                fname = f"gitlab_issues_{name}.csv"
            elif fmt == "json":
                project_id = data.get("project_id")
                export_to_gitlab_json(actions, tmp_path, display_name,
                                      project_id=project_id,
                                      filter_status=filter_status.split(",") if filter_status else None)
                mime = "application/json"
                fname = f"gitlab_issues_{name}.json"
            elif fmt == "script":
                project_path = data.get("project_path", "GROUP/PROJECT")
                generate_gitlab_script(actions, tmp_path, display_name,
                                       project_path=project_path,
                                       filter_status=filter_status.split(",") if filter_status else None)
                mime = "text/x-shellscript"
                fname = f"gitlab_issues_{name}.sh"
            else:
                return _json_error(f"Unknown format: {fmt}")

            return send_file(tmp_path, mimetype=mime, as_attachment=True,
                             download_name=fname)
        finally:
            # Cleanup will happen after response
            pass

    # ── Score Trending endpoints ──

    @app.route("/api/tenants/<name>/snapshots", methods=["GET"])
    def api_snapshots(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        limit = request.args.get("limit", 50, type=int)
        return jsonify(db.get_score_snapshots(name, limit))

    @app.route("/api/tenants/<name>/snapshots", methods=["POST"])
    def api_take_snapshot(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        trigger = (request.get_json() or {}).get("trigger", "manual")
        snapshot = db.take_score_snapshot(name, trigger)
        return jsonify(snapshot), 201

    # ── Dependency endpoints ──

    @app.route("/api/actions/<action_id>/dependencies", methods=["GET"])
    def api_get_dependencies(action_id):
        action = db.get_action(action_id)
        if not action:
            return _json_error("Action not found", 404)
        return jsonify(db.get_dependencies(action_id))

    @app.route("/api/actions/<action_id>/dependencies", methods=["POST"])
    def api_add_dependency(action_id):
        data = request.get_json() or {}
        depends_on_id = data.get("depends_on_id")
        if not depends_on_id:
            return _json_error("depends_on_id is required")
        try:
            result = db.add_dependency(
                action_id, depends_on_id,
                data.get("dependency_type", "requires"),
                data.get("notes", ""),
            )
            return jsonify(result), 201
        except ValueError as e:
            return _json_error(str(e))

    @app.route("/api/actions/<action_id>/dependencies/<depends_on_id>", methods=["DELETE"])
    def api_remove_dependency(action_id, depends_on_id):
        db.remove_dependency(action_id, depends_on_id)
        return jsonify({"removed": True})

    @app.route("/api/tenants/<name>/blocked-actions", methods=["GET"])
    def api_blocked_actions(name):
        """Open actions waiting on incomplete dependencies."""
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        return jsonify(db.get_blocked_actions(name))

    # ── Compliance endpoints ──

    @app.route("/api/tenants/<name>/compliance", methods=["GET"])
    def api_compliance(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        framework = request.args.get("framework")
        return jsonify(db.get_compliance_summary(name, framework))

    @app.route("/api/tenants/<name>/compliance/map", methods=["POST"])
    def api_map_compliance(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        data = request.get_json() or {}
        frameworks = data.get("frameworks")
        result = auto_map_compliance(db, name, frameworks)
        return jsonify(result)

    # ── Risk Acceptance endpoints ──

    @app.route("/api/actions/<action_id>/accept-risk", methods=["POST"])
    def api_accept_risk(action_id):
        data = request.get_json() or {}
        justification = data.get("justification", "").strip()
        risk_owner = data.get("risk_owner", "").strip()
        if not justification:
            return _json_error("justification is required")
        if not risk_owner:
            return _json_error("risk_owner is required")
        result = db.accept_risk(
            action_id, justification, risk_owner,
            review_date=data.get("review_date"),
            expiry_date=data.get("expiry_date"),
            changed_by=data.get("changed_by", ""),
        )
        if not result:
            return _json_error("Action not found", 404)
        return jsonify(result)

    @app.route("/api/tenants/<name>/risk-summary", methods=["GET"])
    def api_risk_summary(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        expired = db.get_expired_risk_acceptances(name)
        upcoming = db.get_upcoming_risk_reviews(name, days=30)
        all_accepted = db.get_actions(name, {"status": "Risk Accepted"})
        return jsonify({
            "total_accepted": len(all_accepted),
            "expired": [{"id": a["id"], "title": a["title"],
                         "risk_owner": a.get("risk_owner"),
                         "risk_expiry_date": a.get("risk_expiry_date")} for a in expired],
            "upcoming_reviews": [{"id": a["id"], "title": a["title"],
                                  "risk_owner": a.get("risk_owner"),
                                  "risk_review_date": a.get("risk_review_date")} for a in upcoming],
            "accepted": [{"id": a["id"], "title": a["title"],
                          "risk_owner": a.get("risk_owner"),
                          "risk_justification": a.get("risk_justification"),
                          "risk_expiry_date": a.get("risk_expiry_date"),
                          "risk_review_date": a.get("risk_review_date"),
                          "risk_accepted_at": a.get("risk_accepted_at")} for a in all_accepted],
        })

    @app.route("/api/tenants/<name>/expire-risks", methods=["POST"])
    def api_expire_risks(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        expired = db.expire_risk_acceptances(name)
        return jsonify({"expired_count": len(expired),
                        "expired": [{"id": a["id"], "title": a["title"]} for a in expired]})

    # ── Drift Detection endpoints ──

    @app.route("/api/tenants/<name>/drift", methods=["GET"])
    def api_drift_reports(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        limit = request.args.get("limit", 20, type=int)
        return jsonify(db.get_drift_reports(name, limit))

    # ── Graph API (Device Code Auth) ──

    # In-memory store for pending device code flows (per-tenant)
    _device_flows = {}

    def _method_disabled_error(method):
        return _json_error(
            f"The '{method.replace('_', ' ')}' authentication method is disabled "
            f"for this tenant. Enable it in Control Plane > Tenant Config.", 403)

    @app.route("/api/tenants/<name>/graph/device-code", methods=["POST"])
    def api_graph_device_code(name):
        """Start device code authentication flow for Graph API access."""
        tenant = db.get_tenant(name)
        if not tenant:
            return _json_error("Tenant not found", 404)
        if not db.auth_method_enabled(tenant, "device_code"):
            return _method_disabled_error("device_code")

        tenant_id = tenant.get("tenant_id", "")
        client_id = tenant.get("client_id", "")

        if not tenant_id or not client_id:
            return _json_error(
                "Tenant must have tenant_id and client_id configured. "
                "Register an app in Entra ID (set 'Allow public client flows' = Yes, "
                "add SecurityEvents.Read.All delegated permission) and set the IDs on the tenant."
            )

        try:
            result = start_device_code_flow(tenant_id, client_id)
            # Store the flow for polling
            _device_flows[name] = {
                "device_code": result["device_code"],
                "tenant_id": tenant_id,
                "client_id": client_id,
                "expires_at": datetime.utcnow().timestamp() + result.get("expires_in", 900),
            }
            return jsonify({
                "user_code": result["user_code"],
                "verification_uri": result.get("verification_uri", result.get("verification_url", "")),
                "message": result.get("message", ""),
                "expires_in": result.get("expires_in", 900),
                "interval": result.get("interval", 5),
            })
        except Exception as e:
            return _json_error(f"Device code flow failed: {str(e)}")

    @app.route("/api/tenants/<name>/graph/poll-token", methods=["POST"])
    def api_graph_poll_token(name):
        """Poll for token after user completes device code authentication."""
        flow = _device_flows.get(name)
        if not flow:
            return _json_error("No pending authentication flow. Start with /graph/device-code first.")

        if datetime.utcnow().timestamp() > flow["expires_at"]:
            _device_flows.pop(name, None)
            return _json_error("Device code expired. Please start a new flow.")

        result = poll_for_token(flow["tenant_id"], flow["client_id"], flow["device_code"])

        if "access_token" in result:
            # Store token temporarily, remove device code
            _device_flows[name] = {
                "access_token": result["access_token"],
                "expires_at": datetime.utcnow().timestamp() + result.get("expires_in", 3600),
            }
            return jsonify({"status": "authenticated", "expires_in": result.get("expires_in", 3600)})

        error = result.get("error", "unknown")
        if error == "authorization_pending":
            return jsonify({"status": "pending", "message": "Waiting for user to authenticate..."})
        elif error == "slow_down":
            return jsonify({"status": "pending", "message": "Polling too fast, slowing down..."})
        else:
            _device_flows.pop(name, None)
            return _json_error(result.get("error_description", f"Authentication failed: {error}"))

    @app.route("/api/tenants/<name>/graph/import-scores", methods=["POST"])
    def api_graph_import_scores(name):
        """Import Secure Score data from Graph API using device code auth token."""
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)

        flow = _device_flows.get(name)
        if not flow or "access_token" not in flow:
            return _json_error("Not authenticated. Complete device code flow first.")

        if datetime.utcnow().timestamp() > flow["expires_at"]:
            _device_flows.pop(name, None)
            return _json_error("Token expired. Please re-authenticate.")

        try:
            result = import_secure_scores_with_token(db, name, flow["access_token"])
            return jsonify(result)
        except Exception as e:
            return _json_error(f"Graph API import failed: {str(e)}")

    @app.route("/api/tenants/<name>/graph/fetch-controls", methods=["POST"])
    def api_graph_fetch_controls(name):
        """Fetch control profiles from Graph API to populate reference table."""
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)

        flow = _device_flows.get(name)
        if not flow or "access_token" not in flow:
            return _json_error("Not authenticated. Complete device code flow first.")

        if datetime.utcnow().timestamp() > flow["expires_at"]:
            _device_flows.pop(name, None)
            return _json_error("Token expired. Please re-authenticate.")

        try:
            profiles_data = fetch_control_profiles(flow["access_token"])
            controls = parse_graph_control_profiles(profiles_data)
            result = db.seed_controls(controls)
            return jsonify(result)
        except Exception as e:
            return _json_error(f"Control profiles fetch failed: {str(e)}")

    @app.route("/api/tenants/<name>/graph/status", methods=["GET"])
    def api_graph_status(name):
        """Check if the tenant has an active Graph API session."""
        flow = _device_flows.get(name)
        if not flow:
            return jsonify({"authenticated": False})
        if "access_token" not in flow:
            return jsonify({"authenticated": False, "pending": True})
        if datetime.utcnow().timestamp() > flow["expires_at"]:
            _device_flows.pop(name, None)
            return jsonify({"authenticated": False, "expired": True})
        remaining = int(flow["expires_at"] - datetime.utcnow().timestamp())
        return jsonify({"authenticated": True, "expires_in": remaining})

    @app.route("/api/tenants/<name>/graph/client-auth", methods=["POST"])
    def api_graph_client_auth(name):
        """Authenticate using client credentials (client_id + client_secret).

        This is an app-only flow -- no interactive sign-in required.
        The app registration must have **application** (not delegated) permission
        SecurityEvents.Read.All with admin consent granted.
        """
        tenant = db.get_tenant(name)
        if not tenant:
            return _json_error("Tenant not found", 404)
        if not db.auth_method_enabled(tenant, "client_secret"):
            return _method_disabled_error("client_secret")

        tenant_id = tenant.get("tenant_id", "")
        client_id = tenant.get("client_id", "")
        client_secret = tenant.get("client_secret", "")

        if not tenant_id or not client_id or not client_secret:
            return _json_error(
                "Tenant must have tenant_id, client_id, and client_secret configured."
            )

        try:
            result = client_credentials_token(tenant_id, client_id, client_secret)
            expires_in = result.get("expires_in", 3600)
            _device_flows[name] = {
                "access_token": result["access_token"],
                "expires_at": datetime.utcnow().timestamp() + expires_in,
            }
            return jsonify({
                "status": "authenticated",
                "expires_in": expires_in,
            })
        except Exception as e:
            return _json_error(f"Client credentials auth failed: {str(e)}")

    @app.route("/api/tenants/<name>/graph/cert-auth", methods=["POST"])
    def api_graph_cert_auth(name):
        """Authenticate using client credentials with a certificate.

        Uses the tenant's ``certificate_path`` (PEM file containing the
        private key and certificate). The ``certificate_thumbprint`` is
        optional -- it is derived from the certificate when blank.
        Requires the ``msal`` library.
        """
        tenant = db.get_tenant(name)
        if not tenant:
            return _json_error("Tenant not found", 404)
        if not db.auth_method_enabled(tenant, "certificate"):
            return _method_disabled_error("certificate")

        tenant_id = tenant.get("tenant_id", "")
        client_id = tenant.get("client_id", "")
        cert_path = tenant.get("certificate_path", "")
        thumbprint = tenant.get("certificate_thumbprint", "")

        if not tenant_id or not client_id or not cert_path:
            return _json_error(
                "Tenant must have tenant_id, client_id and certificate_path configured."
            )

        try:
            result = client_credentials_token_cert(
                tenant_id, client_id, cert_path, thumbprint)
            expires_in = result.get("expires_in", 3600)
            _device_flows[name] = {
                "access_token": result["access_token"],
                "expires_at": datetime.utcnow().timestamp() + expires_in,
            }
            return jsonify({
                "status": "authenticated",
                "expires_in": expires_in,
            })
        except Exception as e:
            return _json_error(f"Certificate auth failed: {str(e)}")

    # ── Interactive Browser Auth ──

    _interactive_flows: dict = {}

    @app.route("/api/tenants/<name>/graph/interactive-auth", methods=["POST"])
    def api_graph_interactive_auth(name):
        """Start interactive browser-based OAuth2 with PKCE for Graph API.

        The user signs in with their browser (Global Reader permissions suffice).
        No client secret required.
        """
        tenant = db.get_tenant(name)
        if not tenant:
            return _json_error("Tenant not found", 404)
        if not db.auth_method_enabled(tenant, "interactive"):
            return _method_disabled_error("interactive")

        tenant_id = tenant.get("tenant_id", "")
        client_id = tenant.get("client_id", "")

        if not tenant_id or not client_id:
            return _json_error(
                "Tenant must have tenant_id and client_id configured. "
                "Register an app in Entra ID (set 'Allow public client flows' = Yes, "
                "add SecurityEvents.Read.All delegated permission, "
                "add http://localhost:8400/auth/callback as redirect URI) "
                "and set the IDs on the tenant."
            )

        try:
            auth_data = start_interactive_auth(tenant_id, client_id)
            _interactive_flows[name] = {
                "tenant_id": tenant_id,
                "client_id": client_id,
                "state": auth_data["state"],
                "code_verifier": auth_data["code_verifier"],
                "redirect_uri": auth_data["redirect_uri"],
            }
            return jsonify({
                "auth_url": auth_data["auth_url"],
                "message": "Open the URL in your browser to sign in.",
            })
        except Exception as e:
            return _json_error(f"Interactive auth failed: {str(e)}")

    @app.route("/auth/callback")
    def auth_callback():
        """Handle the OAuth2 redirect callback from Entra ID."""
        code = request.args.get("code")
        state = request.args.get("state")
        error = request.args.get("error")
        error_desc = request.args.get("error_description", "")

        if error:
            return f"""<html><body style="font-family:system-ui;padding:40px">
                <h2 style="color:red">Authentication Failed</h2>
                <p>{error}: {error_desc}</p>
                <p>You can close this window.</p></body></html>"""

        # Find which tenant this callback belongs to
        tenant_name = None
        flow = None
        for tname, fdata in _interactive_flows.items():
            if fdata.get("state") == state:
                tenant_name = tname
                flow = fdata
                break

        if not flow:
            return """<html><body style="font-family:system-ui;padding:40px">
                <h2 style="color:red">Error</h2>
                <p>Unknown auth state. The flow may have expired.</p>
                </body></html>"""

        try:
            token_result = exchange_auth_code(
                flow["tenant_id"], flow["client_id"],
                code, flow["code_verifier"], flow["redirect_uri"])

            expires_in = token_result.get("expires_in", 3600)
            _device_flows[tenant_name] = {
                "access_token": token_result["access_token"],
                "expires_at": datetime.utcnow().timestamp() + expires_in,
            }
            _interactive_flows.pop(tenant_name, None)

            return f"""<html><body style="font-family:system-ui;padding:40px;text-align:center">
                <h2 style="color:green">Authenticated Successfully</h2>
                <p>You are now signed in for tenant <strong>{tenant_name}</strong>.</p>
                <p>Token expires in {expires_in // 60} minutes.</p>
                <p>You can close this window and return to the application.</p>
                <script>window.close()</script></body></html>"""
        except Exception as e:
            return f"""<html><body style="font-family:system-ui;padding:40px">
                <h2 style="color:red">Token Exchange Failed</h2>
                <p>{str(e)}</p></body></html>"""

    @app.route("/api/tenants/<name>/graph/interactive-status", methods=["GET"])
    def api_graph_interactive_status(name):
        """Check if interactive auth has completed."""
        flow = _device_flows.get(name)
        if flow and "access_token" in flow:
            if datetime.utcnow().timestamp() > flow["expires_at"]:
                return jsonify({"authenticated": False, "expired": True})
            remaining = int(flow["expires_at"] - datetime.utcnow().timestamp())
            return jsonify({"authenticated": True, "expires_in": remaining})
        return jsonify({"authenticated": False})

    @app.route("/api/tenants/<name>/graph/logout", methods=["POST"])
    def api_graph_logout(name):
        """Sign out of the tenant's Graph session: discard cached tokens and
        any pending auth flows for this tenant."""
        had_session = name in _device_flows or name in _interactive_flows
        _device_flows.pop(name, None)
        _interactive_flows.pop(name, None)
        db.audit("graph.logout", actor=session.get("username"),
                 entity_type="tenant", entity_id=name)
        return jsonify({"logged_out": had_session})

    @app.route("/api/tenants/<name>/graph/test", methods=["POST"])
    def api_graph_test(name):
        """Test the tenant's app-only Graph credentials without importing.

        Body (optional): {"method": "certificate"|"client_secret"} to test one
        specific method. Without it, every enabled + configured app-only
        method is tried and the first success is reported.
        """
        tenant = db.get_tenant(name)
        if not tenant:
            return _json_error("Tenant not found", 404)
        if not tenant.get("tenant_id") or not tenant.get("client_id"):
            return _json_error("Set Tenant ID and Client ID first.")

        wanted = (request.get_json(silent=True) or {}).get("method")
        if wanted and wanted not in ("certificate", "client_secret"):
            return _json_error("method must be 'certificate' or 'client_secret' "
                               "(device code and interactive are tested by signing in on the Import page)")

        def _try_cert():
            if not tenant.get("certificate_path"):
                raise RuntimeError("No certificate uploaded for this tenant.")
            client_credentials_token_cert(
                tenant["tenant_id"], tenant["client_id"],
                tenant["certificate_path"],
                tenant.get("certificate_thumbprint", ""))

        def _try_secret():
            if not tenant.get("client_secret"):
                raise RuntimeError("No client secret configured for this tenant.")
            client_credentials_token(
                tenant["tenant_id"], tenant["client_id"], tenant["client_secret"])

        attempts = {"certificate": _try_cert, "client_secret": _try_secret}
        methods = [wanted] if wanted else [
            m for m in ("certificate", "client_secret")
            if db.auth_method_enabled(tenant, m)]
        if not methods:
            return _json_error("All app-only authentication methods are disabled for this tenant.")

        errors = []
        for m in methods:
            if not wanted and not db.auth_method_enabled(tenant, m):
                continue
            try:
                attempts[m]()
                return jsonify({"ok": True, "method": m,
                                "enabled": db.auth_method_enabled(tenant, m)})
            except Exception as e:
                errors.append(f"{m.replace('_', ' ')}: {e}")
        return jsonify({"ok": False, "error": " | ".join(errors)}), 400

    @app.route("/api/tenants/<name>/certificate", methods=["POST"])
    @require_role("admin")
    def api_upload_certificate(name):
        """Upload a PEM certificate bundle (private key + certificate) for
        app-only Graph authentication. Stores it under data/certs/ and sets
        certificate_path + derived thumbprint on the tenant."""
        tenant = db.get_tenant(name)
        if not tenant:
            return _json_error("Tenant not found", 404)
        file = request.files.get("file")
        if not file:
            return _json_error("No file uploaded")
        pem_bytes = file.read()
        if len(pem_bytes) > 1024 * 1024:
            return _json_error("Certificate file too large")
        text = pem_bytes.decode("utf-8", errors="ignore")
        if "PRIVATE KEY-----" not in text:
            return _json_error(
                "The PEM file must contain the private key "
                "(a '-----BEGIN PRIVATE KEY-----' or '-----BEGIN RSA PRIVATE KEY-----' block). "
                "Export both key and certificate into one .pem file.")
        if "-----BEGIN CERTIFICATE-----" not in text:
            return _json_error(
                "The PEM file must also contain the certificate "
                "(a '-----BEGIN CERTIFICATE-----' block).")
        thumbprint = thumbprint_from_pem(pem_bytes)
        if not thumbprint:
            return _json_error("Could not read the certificate from the PEM file.")

        certs_dir = Path(db.db_path).parent / "certs"
        certs_dir.mkdir(parents=True, exist_ok=True)
        cert_path = certs_dir / f"{name}.pem"
        cert_path.write_bytes(pem_bytes)
        try:
            os.chmod(cert_path, 0o600)
        except OSError:
            pass

        db.update_tenant(name, certificate_path=str(cert_path),
                         certificate_thumbprint=thumbprint)
        # Cached tokens were obtained against old credentials
        _device_flows.pop(name, None)
        _interactive_flows.pop(name, None)
        db.audit("tenant.certificate_upload", actor=session.get("username"),
                 entity_type="tenant", entity_id=name, detail=thumbprint)
        return jsonify({"ok": True, "certificate_path": str(cert_path),
                        "thumbprint": thumbprint})

    @app.route("/api/tenants/<name>/certificate", methods=["DELETE"])
    @require_role("admin")
    def api_delete_certificate(name):
        """Remove the stored certificate from the tenant configuration."""
        tenant = db.get_tenant(name)
        if not tenant:
            return _json_error("Tenant not found", 404)
        cert_path = tenant.get("certificate_path", "")
        managed_dir = str(Path(db.db_path).parent / "certs")
        if cert_path and cert_path.startswith(managed_dir) and os.path.isfile(cert_path):
            os.unlink(cert_path)
        db.update_tenant(name, certificate_path="", certificate_thumbprint="")
        _device_flows.pop(name, None)
        db.audit("tenant.certificate_delete", actor=session.get("username"),
                 entity_type="tenant", entity_id=name)
        return jsonify({"ok": True})

    # ── Automation: schedules, tool configs, runs ──

    @app.route("/api/tenants/<name>/automation", methods=["GET"])
    def api_automation_overview(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        from .runner import find_pwsh
        ps_cfg = db.get_tool_config(name, "powershell")
        tenant = db.get_tenant(name)
        return jsonify({
            "schedules": db.get_schedules(name),
            "tool_configs": {
                "scuba": db.get_tool_config(name, "scuba"),
                "zero_trust": db.get_tool_config(name, "zero_trust"),
                "powershell": ps_cfg,
            },
            "runs": db.get_tool_runs(name),
            "environment": {
                "pwsh_found": bool(find_pwsh(ps_cfg)),
                "pwsh_path": find_pwsh(ps_cfg) or "",
                "app_credentials": bool(
                    tenant.get("tenant_id") and tenant.get("client_id")
                    and (tenant.get("client_secret") or tenant.get("certificate_path"))),
            },
        })

    @app.route("/api/tenants/<name>/schedules/<task_type>", methods=["PUT"])
    def api_set_schedule(name, task_type):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        data = request.get_json() or {}
        try:
            sched = db.set_schedule(name, task_type,
                                    data.get("frequency", "manual"),
                                    bool(data.get("enabled")))
        except ValueError as e:
            return _json_error(str(e))
        db.audit("schedule.update", actor=session.get("username"),
                 entity_type="tenant", entity_id=name,
                 detail=f"{task_type}={sched['frequency']},enabled={sched['enabled']}")
        return jsonify(sched)

    @app.route("/api/tenants/<name>/tool-config/<tool>", methods=["PUT"])
    def api_set_tool_config(name, tool):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        if tool not in ("scuba", "zero_trust", "powershell"):
            return _json_error("Unknown tool")
        data = request.get_json() or {}
        return jsonify(db.set_tool_config(name, tool, data.get("config", {})))

    @app.route("/api/tenants/<name>/run/<task_type>", methods=["POST"])
    def api_run_task(name, task_type):
        """Start a tool run in the background. Poll /runs for its status."""
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        from .runner import execute_task_async, TASK_TYPES
        if task_type not in TASK_TYPES:
            return _json_error("Unknown task type")
        run_id = execute_task_async(db.db_path, name, task_type, trigger="manual")
        db.audit("tool.run", actor=session.get("username"),
                 entity_type="tenant", entity_id=name, detail=task_type)
        return jsonify({"run_id": run_id, "status": "running"}), 202

    @app.route("/api/tenants/<name>/runs", methods=["GET"])
    def api_tool_runs(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        limit = request.args.get("limit", 30, type=int)
        return jsonify(db.get_tool_runs(name, limit))

    # ── Auth ──

    @app.route("/api/auth/login", methods=["POST"])
    def api_auth_login():
        if not _check_login_rate_limit(request.remote_addr or "unknown"):
            return jsonify({"error": "Too many login attempts. Try again in 5 minutes."}), 429
        data = request.get_json() or {}
        username = data.get("username", "").strip()
        password = data.get("password", "")
        if not username or not password:
            return _json_error("Username and password required")
        user = db.authenticate_user(username, password)
        if not user:
            return _json_error("Invalid credentials", 401)
        session.permanent = True
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        session["must_change_password"] = bool(user.get("must_change_password"))
        return jsonify(user)

    @app.route("/api/auth/logout", methods=["POST"])
    def api_auth_logout():
        session.clear()
        return jsonify({"status": "ok"})

    @app.route("/api/auth/me", methods=["GET"])
    def api_auth_me():
        uid = session.get("user_id")
        if not uid:
            return jsonify({"authenticated": False})
        user = db.get_user(uid)
        if not user:
            session.clear()
            return jsonify({"authenticated": False})
        return jsonify({**user, "authenticated": True})

    @app.route("/api/auth/change-password", methods=["POST"])
    @login_required
    def api_auth_change_password():
        data = request.get_json() or {}
        uid = session["user_id"]
        user = db.get_user_by_username(session["username"], include_hash=True)
        if not user:
            return _json_error("User not found", 404)
        from .database import _verify_password
        if not _verify_password(data.get("current_password", ""), user.get("password_hash", "")):
            return _json_error("Current password is incorrect")
        new_pw = data.get("new_password", "")
        if len(new_pw) < 12:
            return _json_error("Password must be at least 12 characters")
        db.update_user(uid, password=new_pw)
        session["must_change_password"] = False
        db.audit("user.password_change", actor=session.get("username"), entity_type="user", entity_id=uid)
        return jsonify({"status": "ok"})

    # ── Control Plane: Global Actions ──

    @app.route("/api/control-plane/global-actions", methods=["GET"])
    @require_role("admin", "analyst")
    def api_cp_list_global_actions():
        source_tool = request.args.get("source_tool")
        workload = request.args.get("workload")
        review_status = request.args.get("review_status")
        search = request.args.get("search")
        actions = db.list_global_actions(source_tool=source_tool, workload=workload,
                                          review_status=review_status, search=search)
        # Enrich with compliance mapping counts
        with db._conn() as conn:
            counts = {r["global_action_id"]: r["c"] for r in conn.execute(
                "SELECT global_action_id, COUNT(*) as c FROM global_compliance_mappings GROUP BY global_action_id"
            ).fetchall()}
            tenant_counts = {r["global_action_id"]: r["c"] for r in conn.execute(
                "SELECT global_action_id, COUNT(*) as c FROM actions WHERE global_action_id IS NOT NULL GROUP BY global_action_id"
            ).fetchall()}
        for a in actions:
            a["compliance_mapping_count"] = counts.get(a["id"], 0)
            a["tenant_action_count"] = tenant_counts.get(a["id"], 0)
        return jsonify(actions)

    @app.route("/api/control-plane/global-actions", methods=["POST"])
    def api_cp_create_global_action():
        data = request.get_json() or {}
        if not data.get("title"):
            return _json_error("title is required")
        ga = GlobalAction(
            source_tool=data.get("source_tool", "Manual"),
            source_id=data.get("source_id", ""),
            title=data["title"],
            description=data.get("description", ""),
            workload=data.get("workload", "General"),
            category=data.get("category", ""),
            subcategory=data.get("subcategory", ""),
            priority=data.get("priority", "Medium"),
            risk_level=data.get("risk_level", "Medium"),
            user_impact=data.get("user_impact", "Low"),
            implementation_effort=data.get("implementation_effort", "Medium"),
            required_licence=data.get("required_licence", ""),
            score=data.get("score"),
            max_score=data.get("max_score"),
            essential_eight_control=data.get("essential_eight_control"),
            essential_eight_maturity=data.get("essential_eight_maturity"),
            implementation_steps=data.get("implementation_steps", ""),
            risk_explanation=data.get("risk_explanation", ""),
            additional_info=data.get("additional_info", ""),
            reference_url=data.get("reference_url", ""),
            tags=data.get("tags", []),
            review_status=data.get("review_status", "To Review"),
        )
        result = db.create_global_action(ga)
        return jsonify(result), 201

    @app.route("/api/control-plane/global-actions/<ga_id>", methods=["GET"])
    def api_cp_get_global_action(ga_id):
        ga = db.get_global_action(ga_id)
        if not ga:
            return _json_error("Not found", 404)
        ga["compliance_mappings"] = db.get_global_compliance_mappings(ga_id)
        # Get linked tenant actions count
        with db._conn() as conn:
            rows = conn.execute(
                """SELECT a.id, a.title, a.status, a.tenant_name, a.source_report_date
                   FROM actions a WHERE a.global_action_id=? ORDER BY a.tenant_name""",
                (ga_id,),
            ).fetchall()
        ga["linked_tenant_actions"] = [dict(r) for r in rows]
        return jsonify(ga)

    @app.route("/api/control-plane/global-actions/<ga_id>", methods=["PUT"])
    def api_cp_update_global_action(ga_id):
        data = request.get_json() or {}
        result = db.update_global_action(ga_id, **data)
        if not result:
            return _json_error("Not found", 404)
        db.audit("global_action.update", actor=session.get("username"), entity_type="global_action", entity_id=ga_id)
        return jsonify(result)

    @app.route("/api/control-plane/global-actions/<ga_id>", methods=["DELETE"])
    def api_cp_delete_global_action(ga_id):
        db.delete_global_action(ga_id)
        db.audit("global_action.delete", actor=session.get("username"), entity_type="global_action", entity_id=ga_id)
        return jsonify({"status": "deleted"})

    @app.route("/api/control-plane/global-actions/<ga_id>/compliance", methods=["GET"])
    def api_cp_get_ga_compliance(ga_id):
        return jsonify(db.get_global_compliance_mappings(ga_id))

    @app.route("/api/control-plane/global-actions/<ga_id>/compliance", methods=["POST"])
    def api_cp_add_ga_compliance(ga_id):
        data = request.get_json() or {}
        if not data.get("framework") or not data.get("control_id"):
            return _json_error("framework and control_id required")
        result = db.add_global_compliance_mapping(
            ga_id, data["framework"], data["control_id"],
            data.get("control_name", ""), data.get("control_family", ""), data.get("notes", ""),
        )
        return jsonify(result), 201

    @app.route("/api/control-plane/global-actions/<ga_id>/compliance/<int:mapping_id>", methods=["DELETE"])
    def api_cp_delete_ga_compliance(ga_id, mapping_id):
        db.remove_global_compliance_mapping(mapping_id)
        return jsonify({"status": "deleted"})

    @app.route("/api/control-plane/global-actions/<ga_id>/link-action", methods=["POST"])
    def api_cp_link_action(ga_id):
        data = request.get_json() or {}
        action_id = data.get("action_id")
        if not action_id:
            return _json_error("action_id required")
        db.link_action_to_global(action_id, ga_id)
        return jsonify({"status": "linked"})

    @app.route("/api/control-plane/migrate", methods=["POST"])
    def api_cp_migrate():
        result = db.migrate_actions_to_global()
        return jsonify(result)

    @app.route("/api/control-plane/compliance-summary", methods=["GET"])
    def api_cp_compliance_summary():
        return jsonify(db.get_global_compliance_summary())

    @app.route("/api/control-plane/cross-tenant", methods=["GET"])
    def api_cp_cross_tenant():
        """Show implementation status of global actions across all tenants.
        Supports pagination (limit/offset) and filtering by source_tool/workload."""
        limit = min(int(request.args.get("limit", 100)), 5000)
        offset = max(int(request.args.get("offset", 0)), 0)
        source_tool = request.args.get("source_tool")
        workload = request.args.get("workload")

        where = []
        params: list = []
        if source_tool:
            where.append("ga.source_tool=?")
            params.append(source_tool)
        if workload:
            where.append("ga.workload=?")
            params.append(workload)
        where_clause = ("WHERE " + " AND ".join(where)) if where else ""

        with db._conn() as conn:
            tenants = [r["name"] for r in conn.execute("SELECT name FROM tenants ORDER BY name").fetchall()]
            total = conn.execute(
                f"SELECT COUNT(*) as c FROM global_actions ga {where_clause}",
                params,
            ).fetchone()["c"]
            page_ga_ids = [
                r["id"] for r in conn.execute(
                    f"""SELECT ga.id FROM global_actions ga {where_clause}
                        ORDER BY ga.source_tool, ga.title LIMIT ? OFFSET ?""",
                    params + [limit, offset],
                ).fetchall()
            ]
            if not page_ga_ids:
                return jsonify({
                    "tenants": tenants, "global_actions": [],
                    "total": total, "limit": limit, "offset": offset,
                })
            placeholders = ",".join("?" * len(page_ga_ids))
            rows = conn.execute(
                f"""SELECT ga.id, ga.title, ga.source_tool, ga.workload, ga.review_status,
                          a.tenant_name, a.status, a.id as action_id
                   FROM global_actions ga
                   LEFT JOIN actions a ON a.global_action_id=ga.id
                   WHERE ga.id IN ({placeholders})
                   ORDER BY ga.source_tool, ga.title, a.tenant_name""",
                page_ga_ids,
            ).fetchall()

        by_ga: dict = {}
        for r in rows:
            d = dict(r)
            gid = d["id"]
            if gid not in by_ga:
                by_ga[gid] = {
                    "id": gid, "title": d["title"], "source_tool": d["source_tool"],
                    "workload": d["workload"], "review_status": d["review_status"],
                    "tenant_status": {},
                }
            if d["tenant_name"]:
                by_ga[gid]["tenant_status"][d["tenant_name"]] = {
                    "status": d["status"], "action_id": d["action_id"],
                }

        return jsonify({
            "tenants": tenants,
            "global_actions": list(by_ga.values()),
            "total": total, "limit": limit, "offset": offset,
        })

    # ── Control Plane: Users ──

    @app.route("/api/control-plane/users", methods=["GET"])
    @require_role("admin", "analyst")
    def api_cp_list_users():
        users = db.list_users()
        for u in users:
            u["tenant_access"] = db.get_user_tenant_access(u["id"])
        return jsonify(users)

    @app.route("/api/control-plane/users", methods=["POST"])
    @require_role("admin", "analyst")
    def api_cp_create_user():
        data = request.get_json() or {}
        username = data.get("username", "").strip()
        password = data.get("password", "")
        if not username or not password:
            return _json_error("username and password required")
        if not _USERNAME_RE.match(username):
            return _json_error("Username must be 1-63 chars, start alphanumeric, letters/digits/._- only")
        if len(password) < 12:
            return _json_error("Password must be at least 12 characters")
        existing = db.get_user_by_username(username)
        if existing:
            return _json_error(f"User '{username}' already exists")
        valid_roles = [r.value for r in UserRole]
        role = data.get("role", "viewer")
        if role not in valid_roles:
            return _json_error(f"Invalid role. Must be one of: {', '.join(valid_roles)}")
        user = db.create_user(
            username=username, password=password,
            display_name=data.get("display_name", ""),
            email=data.get("email", ""),
            role=role,
        )
        # Set tenant access if provided
        for ta in data.get("tenant_access", []):
            if ta.get("tenant_name"):
                db.set_user_tenant_access(user["id"], ta["tenant_name"], ta.get("workloads", []))
        db.audit("user.create", actor=session.get("username"), entity_type="user", entity_id=user["id"], detail=f"role={role}")
        return jsonify(user), 201

    @app.route("/api/control-plane/users/<user_id>", methods=["GET"])
    def api_cp_get_user(user_id):
        user = db.get_user(user_id)
        if not user:
            return _json_error("Not found", 404)
        user["tenant_access"] = db.get_user_tenant_access(user_id)
        return jsonify(user)

    @app.route("/api/control-plane/users/<user_id>", methods=["PUT"])
    @require_role("admin", "analyst")
    def api_cp_update_user(user_id):
        data = request.get_json() or {}
        allowed = {"display_name", "email", "role", "is_active", "password"}
        kwargs = {k: v for k, v in data.items() if k in allowed}
        if "role" in kwargs:
            valid_roles = [r.value for r in UserRole]
            if kwargs["role"] not in valid_roles:
                return _json_error(f"Invalid role. Must be one of: {', '.join(valid_roles)}")
        if str(user_id) == str(session.get("user_id")) and "role" in data:
            return jsonify({"error": "Cannot change your own role"}), 403
        if str(user_id) == str(session.get("user_id")) and data.get("is_active") is False:
            return jsonify({"error": "Cannot deactivate yourself"}), 403
        user = db.update_user(user_id, **kwargs)
        if not user:
            return _json_error("Not found", 404)
        # Update tenant access if provided
        if "tenant_access" in data:
            # Remove old access and re-set
            old_access = db.get_user_tenant_access(user_id)
            for ta in old_access:
                db.remove_user_tenant_access(user_id, ta["tenant_name"])
            for ta in data["tenant_access"]:
                if ta.get("tenant_name"):
                    db.set_user_tenant_access(user_id, ta["tenant_name"], ta.get("workloads", []))
        user["tenant_access"] = db.get_user_tenant_access(user_id)
        db.audit("user.update", actor=session.get("username"), entity_type="user", entity_id=user_id, detail=",".join(kwargs.keys()))
        return jsonify(user)

    @app.route("/api/control-plane/users/<user_id>", methods=["DELETE"])
    @require_role("admin", "analyst")
    def api_cp_delete_user(user_id):
        if user_id == session.get("user_id"):
            return _json_error("Cannot delete your own account")
        db.delete_user(user_id)
        db.audit("user.delete", actor=session.get("username"), entity_type="user", entity_id=user_id)
        return jsonify({"status": "deleted"})

    @app.route("/api/control-plane/users/<user_id>/tenant-access", methods=["POST"])
    def api_cp_set_user_tenant_access(user_id):
        data = request.get_json() or {}
        tenant_name = data.get("tenant_name")
        if not tenant_name:
            return _json_error("tenant_name required")
        db.set_user_tenant_access(user_id, tenant_name, data.get("workloads", []))
        return jsonify({"status": "ok"})

    @app.route("/api/control-plane/users/<user_id>/tenant-access/<tenant_name>", methods=["DELETE"])
    def api_cp_remove_user_tenant_access(user_id, tenant_name):
        db.remove_user_tenant_access(user_id, tenant_name)
        return jsonify({"status": "deleted"})

    # ── Control Plane: Tenant Frameworks ──

    @app.route("/api/control-plane/tenants/<tenant_name>/frameworks", methods=["GET"])
    def api_cp_get_tenant_frameworks(tenant_name):
        return jsonify(db.get_tenant_frameworks(tenant_name))

    @app.route("/api/control-plane/tenants/<tenant_name>/frameworks", methods=["PUT"])
    def api_cp_set_tenant_frameworks(tenant_name):
        data = request.get_json() or {}
        frameworks = data.get("frameworks", [])
        db.set_tenant_frameworks(tenant_name, frameworks)
        return jsonify(db.get_tenant_frameworks(tenant_name))

    @app.route("/api/control-plane/tenants/<tenant_name>/frameworks/<framework>", methods=["DELETE"])
    def api_cp_remove_tenant_framework(tenant_name, framework):
        db.remove_tenant_framework(tenant_name, framework)
        return jsonify({"status": "deleted"})

    @app.route("/api/control-plane/tenant-frameworks", methods=["GET"])
    def api_cp_all_tenant_frameworks():
        return jsonify(db.get_all_tenant_frameworks())

    # ── Enhanced import: auto-link to global actions ──

    @app.route("/api/control-plane/unlinked-actions", methods=["GET"])
    def api_cp_unlinked_actions():
        tenant_name = request.args.get("tenant")
        source_tool = request.args.get("source_tool")
        limit = min(int(request.args.get("limit", 200)), 1000)
        offset = max(int(request.args.get("offset", 0)), 0)
        where = ["global_action_id IS NULL"]
        params: list = []
        if tenant_name:
            where.append("tenant_name=?"); params.append(tenant_name)
        if source_tool:
            where.append("source_tool=?"); params.append(source_tool)
        where_clause = " AND ".join(where)
        with db._conn() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) as c FROM actions WHERE {where_clause}", params
            ).fetchone()["c"]
            rows = conn.execute(
                f"""SELECT id, title, source_tool, source_id, workload, status, tenant_name
                    FROM actions WHERE {where_clause}
                    ORDER BY source_tool, title LIMIT ? OFFSET ?""",
                params + [limit, offset],
            ).fetchall()
        # Preserve legacy list shape; total available via X-Total-Count header
        resp = jsonify([dict(r) for r in rows])
        resp.headers["X-Total-Count"] = str(total)
        return resp

    # ── Global Action Links ──

    @app.route("/api/control-plane/global-actions/<ga_id>/links", methods=["GET"])
    def api_cp_get_ga_links(ga_id):
        return jsonify(db.get_global_action_links(ga_id))

    @app.route("/api/control-plane/global-actions/<ga_id>/links", methods=["POST"])
    def api_cp_add_ga_link(ga_id):
        data = request.get_json() or {}
        target_id = data.get("target_id")
        if not target_id:
            return _json_error("target_id required")
        if target_id == ga_id:
            return _json_error("Cannot link an action to itself")
        result = db.add_global_action_link(ga_id, target_id, data.get("notes", ""))
        return jsonify(result), 201

    @app.route("/api/control-plane/global-actions/<ga_id>/links/<int:link_id>", methods=["DELETE"])
    def api_cp_delete_ga_link(ga_id, link_id):
        db.remove_global_action_link(link_id)
        return jsonify({"status": "deleted"})

    # ── Merge Global Actions ──

    @app.route("/api/control-plane/global-actions/merge", methods=["POST"])
    def api_cp_merge_global_actions():
        data = request.get_json() or {}
        keep_id = data.get("keep_id")
        merge_ids = data.get("merge_ids", [])
        if not keep_id or not merge_ids:
            return _json_error("keep_id and merge_ids required")
        if keep_id in merge_ids:
            return _json_error("keep_id cannot also be in merge_ids")
        result = db.merge_global_actions(keep_id, merge_ids)
        db.audit("global_action.merge", actor=session.get("username"), entity_type="global_action", entity_id=keep_id, detail=f"merged={','.join(merge_ids)}")
        return jsonify(result)

    # ── Create global action from a tenant action ──

    @app.route("/api/control-plane/create-from-action", methods=["POST"])
    def api_cp_create_from_action():
        data = request.get_json() or {}
        action_id = data.get("action_id")
        if not action_id:
            return _json_error("action_id required")
        result = db.create_global_action_from_tenant_action(action_id)
        if not result:
            return _json_error("Action not found", 404)
        return jsonify(result), 201

    return app


def run_server(port: int = 8080, db_path: str = None, open_browser: bool = True):
    """Start the web server and the automation scheduler."""
    from .database import DEFAULT_DB_PATH
    from .runner import start_scheduler
    app = create_app(db_path)
    start_scheduler(str(db_path or DEFAULT_DB_PATH))
    url = f"http://localhost:{port}"
    print(f"Starting M365 Security Posture Manager at {url}")
    if open_browser:
        webbrowser.open(url)
    app.run(host="0.0.0.0", port=port, debug=False)
