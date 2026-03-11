"""Flask web application - REST API + SPA frontend for M365 Security Posture.

Launch with: m365-posture web [--port 8080] [--no-browser]
"""

from __future__ import annotations

import io
import json
import os
import tempfile
import webbrowser
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, request, send_file, Response

from .database import Database
from .models import (
    Action, TenantConfig, ActionStatus, Priority, RiskLevel,
    UserImpact, ImplementationEffort, SourceTool, Workload,
    EssentialEightControl, EssentialEightMaturity, ComplianceFramework,
)
from .parsers import (
    SecureScoreParser, ScubaParser, ZeroTrustParser, SCTParser, M365AssessParser,
)
from .essential_eight import apply_e8_mapping, get_e8_summary
from .correlation import auto_correlate, get_correlation_summary
from .planner import simulate_plan, suggest_phases, get_prioritized_actions, calculate_action_roi
from .gitlab_export import export_to_gitlab_csv, export_to_gitlab_json, generate_gitlab_script
from .compliance import auto_map_compliance, map_action_to_frameworks
from .drift import detect_drift
from .web_frontend import get_spa_html

PARSER_MAP = {
    "secure-score": (SecureScoreParser, SourceTool.SECURE_SCORE.value),
    "scuba": (ScubaParser, SourceTool.SCUBA.value),
    "zero-trust": (ZeroTrustParser, SourceTool.ZERO_TRUST.value),
    "sct": (SCTParser, SourceTool.SCT.value),
    "m365-assess": (M365AssessParser, SourceTool.M365_ASSESS.value),
}


def create_app(db_path: str = None) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB
    db = Database(db_path)

    def _json_error(msg, code=400):
        return jsonify({"error": msg}), code

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
        return jsonify(db.list_tenants())

    @app.route("/api/tenants", methods=["POST"])
    def api_create_tenant():
        data = request.get_json()
        if not data or not data.get("name"):
            return _json_error("name is required")
        name = data["name"].strip().lower().replace(" ", "-")
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
        return jsonify(tenant)

    @app.route("/api/tenants/<name>", methods=["PUT"])
    def api_update_tenant(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        data = request.get_json() or {}
        tenant = db.update_tenant(name, **data)
        return jsonify(tenant)

    @app.route("/api/tenants/<name>", methods=["DELETE"])
    def api_delete_tenant(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        db.delete_tenant(name)
        return jsonify({"deleted": True})

    @app.route("/api/tenants/<name>/activate", methods=["POST"])
    def api_activate_tenant(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        db.set_active_tenant(name)
        return jsonify({"active": name})

    @app.route("/api/active-tenant", methods=["GET"])
    def api_active_tenant():
        tenant = db.get_active_tenant()
        return jsonify(tenant or {})

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
        actions = db.get_actions(name, filters)
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

    @app.route("/api/actions/<action_id>/history", methods=["GET"])
    def api_action_history(action_id):
        return jsonify(db.get_action_history(action_id))

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

        try:
            parser_cls, source_tool = PARSER_MAP[source]
            parser = parser_cls()
            actions = parser.parse_file(tmp_path)
            actions = apply_e8_mapping(actions)
            new_count, updated_count = db.merge_actions(name, actions, source_tool, file.filename)

            # Auto-correlate after import
            corr = auto_correlate(db, name)

            # Auto-map compliance frameworks
            compliance = auto_map_compliance(db, name)

            # Take score snapshot for trending
            snapshot = db.take_score_snapshot(name, trigger=f"import:{source}")

            # Expire any risk acceptances past their date
            expired = db.expire_risk_acceptances(name)

            # Detect drift vs previous snapshot
            drift = detect_drift(db, name, source_tool)

            return jsonify({
                "success": True,
                "source": source,
                "file": file.filename,
                "total_parsed": len(actions),
                "new_actions": new_count,
                "updated_actions": updated_count,
                "correlation": corr,
                "compliance": compliance,
                "drift": drift,
                "expired_risk_acceptances": len(expired),
                "snapshot": {"id": snapshot.get("id"), "percentage": snapshot.get("percentage")},
            })
        except Exception as e:
            return _json_error(f"Import failed: {str(e)}")
        finally:
            os.unlink(tmp_path)

    # ── Scores endpoint ──

    @app.route("/api/tenants/<name>/scores", methods=["GET"])
    def api_scores(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        return jsonify(db.get_scores(name))

    # ── Essential Eight endpoint ──

    @app.route("/api/tenants/<name>/e8", methods=["GET"])
    def api_e8(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        actions = db.get_actions(name)
        action_objects = [Action.from_dict(a) for a in actions]
        action_objects = apply_e8_mapping(action_objects)
        summary = get_e8_summary(action_objects)
        return jsonify(summary)

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

    @app.route("/api/correlation-groups", methods=["GET"])
    def api_correlation_groups():
        return jsonify(db.get_correlation_groups())

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

    @app.route("/api/tenants/<name>/dependency-graph", methods=["GET"])
    def api_dependency_graph(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        return jsonify(db.get_dependency_graph(name))

    @app.route("/api/tenants/<name>/blocked-actions", methods=["GET"])
    def api_blocked_actions(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        return jsonify(db.get_blocked_actions(name))

    @app.route("/api/tenants/<name>/implementation-order", methods=["POST"])
    def api_implementation_order(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        data = request.get_json() or {}
        action_ids = data.get("action_ids")
        return jsonify(db.get_implementation_order(name, action_ids))

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

    @app.route("/api/actions/<action_id>/compliance", methods=["GET"])
    def api_action_compliance(action_id):
        return jsonify(db.get_action_compliance(action_id))

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

    @app.route("/api/tenants/<name>/drift/detect", methods=["POST"])
    def api_detect_drift(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        data = request.get_json() or {}
        result = detect_drift(db, name, data.get("source_tool"))
        return jsonify(result)

    # ── Enums update ──

    @app.route("/api/enums/frameworks", methods=["GET"])
    def api_frameworks():
        return jsonify([f.value for f in ComplianceFramework])

    return app


def run_server(port: int = 8080, db_path: str = None, open_browser: bool = True):
    """Start the web server."""
    app = create_app(db_path)
    url = f"http://localhost:{port}"
    print(f"Starting M365 Security Posture Manager at {url}")
    if open_browser:
        webbrowser.open(url)
    app.run(host="0.0.0.0", port=port, debug=False)
