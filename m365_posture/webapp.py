"""Flask web application - REST API + SPA frontend for M365 Security Posture.

Launch with: m365-posture web [--port 8080] [--no-browser]
"""

from __future__ import annotations

import io
import json
import os
import shutil
import tempfile
import webbrowser
import zipfile
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
    SecureScoreParser, ScubaParser, ZeroTrustParser, ZeroTrustReportParser,
    SCTParser, M365AssessParser,
    enrich_actions_from_controls, load_seed_controls, parse_graph_control_profiles,
)
from .essential_eight import apply_e8_mapping, get_e8_summary, get_e8_controls_data
from .correlation import auto_correlate, get_correlation_summary
from .planner import simulate_plan, suggest_phases, get_prioritized_actions, calculate_action_roi
from .gitlab_export import export_to_gitlab_csv, export_to_gitlab_json, generate_gitlab_script
from .compliance import auto_map_compliance, map_action_to_frameworks
from .drift import detect_drift
from .graph_api import (
    start_device_code_flow, poll_for_token, fetch_secure_scores,
    fetch_control_profiles, client_credentials_token,
    start_interactive_auth, exchange_auth_code, _interactive_sessions,
)
from .web_frontend import get_spa_html

PARSER_MAP = {
    "secure-score": (SecureScoreParser, SourceTool.SECURE_SCORE.value),
    "scuba": (ScubaParser, SourceTool.SCUBA.value),
    "zero-trust": (ZeroTrustParser, SourceTool.ZERO_TRUST.value),
    "zero-trust-report": (ZeroTrustReportParser, SourceTool.ZERO_TRUST_REPORT.value),
    "sct": (SCTParser, SourceTool.SCT.value),
    "m365-assess": (M365AssessParser, SourceTool.M365_ASSESS.value),
}


def create_app(db_path: str = None) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024  # 200 MB (ZT reports with data can be large)
    app.json.sort_keys = False  # Preserve dict insertion order (E8 controls, etc.)
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

    @app.route("/api/actions/<action_id>/history", methods=["GET"])
    def api_action_history(action_id):
        return jsonify(db.get_action_history(action_id))

    # ── Import endpoint ──

    def _store_zt_report(db, tenant_name, filename, tmp_path, parser, actions):
        """Store ZT report HTML and data files, save metadata to DB."""
        reports_dir = Path(db.db_path).parent / "zt_reports" / tenant_name
        reports_dir.mkdir(parents=True, exist_ok=True)

        import uuid as _uuid
        report_id = str(_uuid.uuid4())[:8]
        report_dir = reports_dir / report_id
        report_dir.mkdir(exist_ok=True)

        html_path = ""
        data_dir = ""

        if Path(tmp_path).suffix.lower() == ".zip":
            # Extract ZIP contents to report directory
            extract_dir = getattr(parser, "_extract_dir", None)
            if extract_dir and Path(extract_dir).exists():
                # Move extracted files to permanent storage
                for item in Path(extract_dir).iterdir():
                    dest = report_dir / item.name
                    if item.is_dir():
                        shutil.copytree(str(item), str(dest), dirs_exist_ok=True)
                    else:
                        shutil.copy2(str(item), str(dest))
                shutil.rmtree(extract_dir, ignore_errors=True)

            # Find HTML file
            for html_file in report_dir.rglob("*.html"):
                html_path = str(html_file)
                break

            # Find zt-export data dir
            for candidate in report_dir.rglob("zt-export"):
                if candidate.is_dir():
                    data_dir = str(candidate)
                    break
        else:
            # Single JSON file - copy it
            shutil.copy2(tmp_path, str(report_dir / filename))

        # Count statuses
        from collections import Counter
        status_counts = Counter(a.status for a in actions)

        metadata = parser.report_metadata if hasattr(parser, "report_metadata") else {}
        report_data = {
            "id": report_id,
            "imported_at": datetime.utcnow().isoformat(),
            "executed_at": metadata.get("executed_at", ""),
            "report_tenant_id": metadata.get("tenant_id", ""),
            "report_tenant_name": metadata.get("tenant_name", ""),
            "report_domain": metadata.get("domain", ""),
            "report_account": metadata.get("account", ""),
            "tool_version": metadata.get("tool_version", ""),
            "test_result_summary": getattr(parser, "test_result_summary", {}),
            "tenant_info": getattr(parser, "tenant_info", {}),
            "html_path": html_path,
            "data_dir": data_dir,
            "total_tests": len(actions),
            "passed_tests": status_counts.get("Completed", 0),
            "failed_tests": status_counts.get("ToDo", 0),
            "source_file": filename,
        }
        return db.store_zt_report(tenant_name, report_data)

    def _store_scuba_report(db, tenant_name, filename, tmp_path, parser, actions):
        """Store SCuBA report HTML and data files, save metadata to DB."""
        reports_dir = Path(db.db_path).parent / "scuba_reports" / tenant_name
        reports_dir.mkdir(parents=True, exist_ok=True)

        import uuid as _uuid
        report_id = str(_uuid.uuid4())[:8]
        report_dir = reports_dir / report_id
        report_dir.mkdir(exist_ok=True)

        html_path = ""

        if Path(tmp_path).suffix.lower() == ".zip":
            # Extract ZIP contents to report directory
            extract_dir = getattr(parser, "_extract_dir", None)
            if extract_dir and Path(extract_dir).exists():
                for item in Path(extract_dir).iterdir():
                    dest = report_dir / item.name
                    if item.is_dir():
                        shutil.copytree(str(item), str(dest), dirs_exist_ok=True)
                    else:
                        shutil.copy2(str(item), str(dest))
                shutil.rmtree(extract_dir, ignore_errors=True)

            # Find BaselineReports.html (main ScubaGear report)
            for html_file in report_dir.rglob("BaselineReports.html"):
                html_path = str(html_file)
                break
            # Fall back to any HTML
            if not html_path:
                for html_file in report_dir.rglob("*.html"):
                    html_path = str(html_file)
                    break
        else:
            # Single JSON/CSV file - copy it
            shutil.copy2(tmp_path, str(report_dir / filename))

        # Count statuses
        from collections import Counter
        status_counts = Counter(a.status for a in actions)

        metadata = parser.report_metadata if hasattr(parser, "report_metadata") else {}
        product_summary = parser.product_summary if hasattr(parser, "product_summary") else {}

        report_data = {
            "id": report_id,
            "imported_at": datetime.utcnow().isoformat(),
            "executed_at": metadata.get("timestamp", ""),
            "report_tenant_id": metadata.get("tenant_id", ""),
            "report_tenant_name": metadata.get("tenant_name", ""),
            "report_domain": metadata.get("domain", ""),
            "tool_version": metadata.get("tool_version", ""),
            "report_uuid": metadata.get("report_uuid", ""),
            "products_assessed": metadata.get("products_assessed", []),
            "product_summary": product_summary,
            "total_controls": len(actions),
            "passed_controls": status_counts.get("Completed", 0),
            "failed_controls": status_counts.get("ToDo", 0),
            "warning_controls": status_counts.get("In Planning", 0),
            "manual_controls": status_counts.get("Not Applicable", 0),
            "source_file": filename,
            "html_path": html_path,
        }
        return db.store_scuba_report(tenant_name, report_data)

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

            # Enrich Secure Score actions from the reference control table
            if source == "secure-score":
                actions = enrich_actions_from_controls(db, actions)

            new_count, updated_count, updated_details = db.merge_actions(name, actions, source_tool, file.filename)

            # For Zero Trust Report: store HTML report and metadata
            zt_report_id = None
            if source == "zero-trust-report":
                zt_report_id = _store_zt_report(db, name, file.filename, tmp_path, parser, actions)

            # For SCuBA: store report metadata
            scuba_report_id = None
            if source == "scuba":
                scuba_report_id = _store_scuba_report(db, name, file.filename, tmp_path, parser, actions)

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

            # Count actions whose status was protected during import
            protected_actions = [d for d in updated_details if d.get("status_protected")]

            # Find stale actions: same source_tool but not in this import
            all_tenant_actions = db.get_actions(name)
            import_ts = datetime.utcnow().isoformat()
            stale_actions = []
            for a in all_tenant_actions:
                if a["source_tool"] == source_tool and a.get("last_seen_in_report"):
                    # If last_seen is significantly older than this import, it's stale
                    if a["last_seen_in_report"] < import_ts[:10]:
                        stale_actions.append({
                            "id": a["id"], "title": a["title"],
                            "status": a["status"],
                            "last_seen": a["last_seen_in_report"],
                        })

            result = {
                "success": True,
                "source": source,
                "file": file.filename,
                "total_parsed": len(actions),
                "new_actions": new_count,
                "updated_actions": updated_count,
                "updated_details": updated_details,
                "protected_actions": protected_actions,
                "stale_actions": stale_actions,
                "correlation": corr,
                "compliance": compliance,
                "drift": drift,
                "expired_risk_acceptances": len(expired),
                "snapshot": {"id": snapshot.get("id"), "percentage": snapshot.get("percentage")},
            }
            if zt_report_id:
                result["zt_report_id"] = zt_report_id
            if scuba_report_id:
                result["scuba_report_id"] = scuba_report_id
            return jsonify(result)
        except Exception as e:
            return _json_error(f"Import failed: {str(e)}")
        finally:
            os.unlink(tmp_path)

    # ── Zero Trust Report endpoints ──

    def _zt_reports_dir():
        return Path(db.db_path).parent / "zt_reports"

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

    @app.route("/api/zt-reports/<report_id>/html", methods=["GET"])
    def api_zt_report_html(report_id):
        report = db.get_zt_report(report_id)
        if not report:
            return _json_error("Report not found", 404)
        html_path = report.get("html_path", "")
        if not html_path or not Path(html_path).exists():
            return _json_error("HTML report file not found", 404)
        return send_file(html_path, mimetype="text/html")

    @app.route("/api/zt-reports/<report_id>/data/<path:filepath>", methods=["GET"])
    def api_zt_report_data(report_id, filepath):
        """Serve files from the report's zt-export data directory."""
        report = db.get_zt_report(report_id)
        if not report:
            return _json_error("Report not found", 404)
        data_dir = report.get("data_dir", "")
        if not data_dir:
            return _json_error("No data directory for this report", 404)
        full_path = Path(data_dir) / filepath
        # Security: ensure path stays within data_dir
        try:
            full_path.resolve().relative_to(Path(data_dir).resolve())
        except ValueError:
            return _json_error("Invalid path", 400)
        if not full_path.exists():
            return _json_error("File not found", 404)
        mime = "application/json" if full_path.suffix == ".json" else "application/octet-stream"
        return send_file(str(full_path), mimetype=mime)

    # ── Scores endpoint ──

    @app.route("/api/tenants/<name>/scores", methods=["GET"])
    def api_scores(name):
        if not db.get_tenant(name):
            return _json_error("Tenant not found", 404)
        exclude_na = request.args.get("exclude_na", "").lower() in ("1", "true", "yes")
        return jsonify(db.get_scores(name, exclude_na=exclude_na))

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

    @app.route("/api/e8/controls", methods=["GET"])
    def api_e8_controls():
        """Return the full E8 control definitions with maturity requirements."""
        return jsonify(get_e8_controls_data())

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
        existing = db.get_correlation_groups()
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

        # Get current scores
        current = db.get_scores(name)
        snap_label = "Snapshot (" + snapshot["timestamp"][:10] + ")"
        cur_label = "Current"

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
                },
                snap_label: {
                    "percentage": snapshot.get("percentage", 0),
                    "total_actions": snapshot.get("total_actions", 0),
                    "completed_actions": snapshot.get("completed_actions", 0),
                },
            },
            "by_tool": {},
            "by_workload": {},
        }

        # Merge tool data
        all_tools = set(list(current.get("by_tool", {}).keys()) +
                        list(snapshot.get("by_tool", {}).keys()))
        for tool in sorted(all_tools):
            result["by_tool"][tool] = {
                cur_label: current.get("by_tool", {}).get(tool, {}),
                snap_label: snapshot.get("by_tool", {}).get(tool, {}),
            }

        # Merge workload data
        all_wl = set(list(current.get("by_workload", {}).keys()) +
                      list(snapshot.get("by_workload", {}).keys()))
        for wl in sorted(all_wl):
            result["by_workload"][wl] = {
                cur_label: current.get("by_workload", {}).get(wl, {}),
                snap_label: snapshot.get("by_workload", {}).get(wl, {}),
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

    @app.route("/api/responsible-persons", methods=["GET"])
    def api_list_persons():
        return jsonify(db.get_responsible_persons())

    @app.route("/api/responsible-persons", methods=["POST"])
    def api_create_person():
        data = request.get_json() or {}
        if not data.get("name"):
            return _json_error("name is required")
        pid = db.create_responsible_person(
            data["name"], data.get("email", ""),
            data.get("role", ""), data.get("department", ""))
        return jsonify({"id": pid, "name": data["name"]})

    @app.route("/api/responsible-persons/<pid>", methods=["PUT"])
    def api_update_person(pid):
        data = request.get_json() or {}
        db.update_responsible_person(pid, data)
        return jsonify({"ok": True})

    @app.route("/api/responsible-persons/<pid>", methods=["DELETE"])
    def api_delete_person(pid):
        db.delete_responsible_person(pid)
        return jsonify({"ok": True})

    @app.route("/api/actions/<action_id>/persons", methods=["GET"])
    def api_action_persons(action_id):
        return jsonify(db.get_action_persons(action_id))

    @app.route("/api/actions/<action_id>/persons", methods=["POST"])
    def api_assign_person(action_id):
        data = request.get_json() or {}
        person_id = data.get("person_id")
        if not person_id:
            return _json_error("person_id required")
        db.assign_person_to_action(action_id, person_id)
        return jsonify({"ok": True})

    @app.route("/api/actions/<action_id>/persons/<pid>", methods=["DELETE"])
    def api_unassign_person(action_id, pid):
        db.unassign_person_from_action(action_id, pid)
        return jsonify({"ok": True})

    @app.route("/api/responsible-persons/<pid>/actions", methods=["GET"])
    def api_person_actions(pid):
        tenant = request.args.get("tenant")
        return jsonify(db.get_person_actions(pid, tenant))

    @app.route("/api/tenants/<name>/action-persons", methods=["GET"])
    def api_all_action_persons(name):
        """Return all action→person assignments for a tenant."""
        return jsonify(db.get_all_action_person_assignments(name))

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

    # ── Pin/unpin actions on dashboard ──

    @app.route("/api/actions/<action_id>/pin", methods=["POST"])
    def api_pin_action(action_id):
        action = db.get_action(action_id)
        if not action:
            return _json_error("Action not found", 404)
        db.update_action(action_id, {"pinned_priority": 1})
        return jsonify({"pinned": True})

    @app.route("/api/actions/<action_id>/unpin", methods=["POST"])
    def api_unpin_action(action_id):
        action = db.get_action(action_id)
        if not action:
            return _json_error("Action not found", 404)
        db.update_action(action_id, {"pinned_priority": 0})
        return jsonify({"pinned": False})

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

    # ── Secure Score Controls (reference table) endpoints ──

    @app.route("/api/secure-score-controls", methods=["GET"])
    def api_list_controls():
        return jsonify(db.list_controls())

    @app.route("/api/secure-score-controls/<control_id>", methods=["GET"])
    def api_get_control(control_id):
        ctrl = db.get_control(control_id)
        if not ctrl:
            return _json_error("Control not found", 404)
        return jsonify(ctrl)

    @app.route("/api/secure-score-controls/<control_id>", methods=["PUT"])
    def api_update_control(control_id):
        data = request.get_json() or {}
        from .models import SecureScoreControl as SSC
        existing = db.get_control(control_id)
        if not existing:
            return _json_error("Control not found", 404)
        existing.update(data)
        existing["id"] = control_id  # Prevent id change
        ctrl = SSC.from_dict(existing)
        result = db.upsert_control(ctrl)
        return jsonify(result)

    @app.route("/api/secure-score-controls/<control_id>", methods=["DELETE"])
    def api_delete_control(control_id):
        if not db.get_control(control_id):
            return _json_error("Control not found", 404)
        db.delete_control(control_id)
        return jsonify({"deleted": True})

    @app.route("/api/secure-score-controls/seed", methods=["POST"])
    def api_seed_controls():
        """Load built-in seed data into the controls reference table."""
        controls = load_seed_controls()
        if not controls:
            return _json_error("Seed data file not found")
        result = db.seed_controls(controls)
        return jsonify(result)

    # ── Graph API (Device Code Auth) ──

    # In-memory store for pending device code flows (per-tenant)
    _device_flows = {}

    @app.route("/api/tenants/<name>/graph/device-code", methods=["POST"])
    def api_graph_device_code(name):
        """Start device code authentication flow for Graph API access."""
        tenant = db.get_tenant(name)
        if not tenant:
            return _json_error("Tenant not found", 404)

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
            # Fetch scores and control profiles for full enrichment
            scores_data = fetch_secure_scores(flow["access_token"])
            try:
                profiles_data = fetch_control_profiles(flow["access_token"])
            except Exception:
                profiles_data = None

            # If we got profiles, update the reference table too
            if profiles_data:
                try:
                    controls = parse_graph_control_profiles(profiles_data)
                    db.seed_controls(controls)
                except Exception:
                    pass  # Non-critical

            parser = SecureScoreParser()
            actions, overall_scores = parser.parse_graph_response(scores_data, profiles_data)
            actions = apply_e8_mapping(actions)
            actions = enrich_actions_from_controls(db, actions)

            source_tool = SourceTool.SECURE_SCORE.value
            new_count, updated_count, _ = db.merge_actions(name, actions, source_tool, "graph_api")

            # Remove any duplicates from previous imports with different source_id formats
            dedup = db.deduplicate_actions(name, source_tool)

            # Store the authoritative overall scores from Graph API
            if overall_scores.get("maxScore", 0) > 0:
                db.store_graph_scores(name, overall_scores)

            # Post-import processing
            corr = auto_correlate(db, name)
            compliance = auto_map_compliance(db, name)
            snapshot = db.take_score_snapshot(name, trigger="import:graph-api")
            expired = db.expire_risk_acceptances(name)
            drift = detect_drift(db, name, source_tool)

            return jsonify({
                "success": True,
                "source": "Microsoft Graph API",
                "total_parsed": len(actions),
                "new_actions": new_count,
                "updated_actions": updated_count,
                "correlation": corr,
                "compliance": compliance,
                "drift": drift,
                "expired_risk_acceptances": len(expired),
                "snapshot": {"id": snapshot.get("id"), "percentage": snapshot.get("percentage")},
                "profiles_loaded": getattr(parser, '_profile_count', 0),
                "unmatched_controls": getattr(parser, '_unmatched_controls', []),
                "duplicates_removed": dedup.get("removed", 0),
            })
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

    # ── Enums update ──

    @app.route("/api/enums/frameworks", methods=["GET"])
    def api_frameworks():
        return jsonify([f.value for f in ComplianceFramework])

    # ── Database Migration ──

    @app.route("/api/admin/migrate-database", methods=["POST"])
    def api_migrate_database():
        """Migrate to per-tenant database layout."""
        from .tenant_db import migrate_to_per_tenant, is_migrated
        if is_migrated():
            return jsonify({"already_migrated": True,
                            "message": "Database already migrated to per-tenant layout."})
        result = migrate_to_per_tenant(db.db_path)
        return jsonify(result)

    @app.route("/api/admin/migration-status", methods=["GET"])
    def api_migration_status():
        from .tenant_db import is_migrated, MIGRATION_MARKER, TENANT_DB_DIR
        if not is_migrated():
            return jsonify({"migrated": False})
        import json as _json
        marker = _json.loads(MIGRATION_MARKER.read_text())
        tenant_dbs = list(TENANT_DB_DIR.glob("*.db"))
        return jsonify({
            "migrated": True,
            "migrated_at": marker.get("migrated_at"),
            "tenants": marker.get("tenants", []),
            "tenant_db_count": len(tenant_dbs),
        })

    return app


def run_server(port: int = 8080, db_path: str = None, open_browser: bool = True):
    """Start the web server."""
    app = create_app(db_path)
    url = f"http://localhost:{port}"
    print(f"Starting M365 Security Posture Manager at {url}")
    if open_browser:
        webbrowser.open(url)
    app.run(host="0.0.0.0", port=port, debug=False)
