"""Shared import pipeline.

Turns a report file (or a Graph API token) into merged tenant actions plus
all post-import processing: E8 mapping, reference-control enrichment,
global-action auto-linking, report storage, correlation, compliance mapping,
score snapshot, risk-acceptance expiry and drift detection.

Used by both the web API (manual uploads / interactive Graph imports) and
the automation runner (scheduled runs).
"""

from __future__ import annotations

import shutil
import uuid
from collections import Counter
from datetime import datetime
from pathlib import Path

from .models import SourceTool
from .parsers import (
    SecureScoreParser, ScubaParser, ZeroTrustParser, ZeroTrustReportParser,
    SCTParser, M365AssessParser, MaesterParser,
    enrich_actions_from_controls, parse_graph_control_profiles,
)
from .essential_eight import apply_e8_mapping
from .correlation import auto_correlate
from .compliance import auto_map_compliance
from .drift import detect_drift

PARSER_MAP = {
    "secure-score": (SecureScoreParser, SourceTool.SECURE_SCORE.value),
    "scuba": (ScubaParser, SourceTool.SCUBA.value),
    "zero-trust": (ZeroTrustParser, SourceTool.ZERO_TRUST.value),
    "zero-trust-report": (ZeroTrustReportParser, SourceTool.ZERO_TRUST_REPORT.value),
    "sct": (SCTParser, SourceTool.SCT.value),
    "m365-assess": (M365AssessParser, SourceTool.M365_ASSESS.value),
    "maester": (MaesterParser, SourceTool.MAESTER.value),
}


class TenantMismatchError(Exception):
    """Raised when a report was generated for a different tenant than the
    import target. Carries a structured payload for the UI to offer the
    right choices (import into the matching tenant / force / cancel)."""

    def __init__(self, payload: dict):
        super().__init__(payload.get("message", "Report tenant mismatch"))
        self.payload = payload


def _verify_report_tenant(db, tenant_name: str, parser):
    """Compare the tenant identity embedded in the report (SCuBA and Zero
    Trust reports carry the Entra tenant ID) against the import target.

    Raises TenantMismatchError when the report clearly belongs to a
    different tenant. Imports stay allowed when neither side has a tenant
    ID to compare.
    """
    meta = getattr(parser, "report_metadata", {}) or {}
    report_tid = (meta.get("tenant_id") or "").strip().lower()
    if not report_tid:
        return  # Report carries no tenant identity — nothing to verify

    target = db.get_tenant(tenant_name) or {}
    target_tid = (target.get("tenant_id") or "").strip().lower()
    if target_tid and report_tid == target_tid:
        return  # Verified match

    matching = [t for t in db.list_tenants()
                if (t.get("tenant_id") or "").strip().lower() == report_tid
                and t["name"] != tenant_name]

    if (target_tid and report_tid != target_tid) or (not target_tid and matching):
        report_label = meta.get("tenant_name") or meta.get("domain") or meta.get("tenant_id")
        if matching:
            hint = ("It matches your configured tenant "
                    + ", ".join(f"'{t.get('display_name') or t['name']}'" for t in matching) + ".")
        elif target_tid:
            hint = "It does not match any configured tenant."
        else:
            hint = ""
        raise TenantMismatchError({
            "tenant_mismatch": True,
            "message": (f"This report was generated for tenant '{report_label}' "
                        f"({meta.get('tenant_id', '')}), not for the selected tenant "
                        f"'{target.get('display_name') or tenant_name}'. {hint}").strip(),
            "target_tenant": tenant_name,
            "target_tenant_display": target.get("display_name") or tenant_name,
            "target_tenant_id": target.get("tenant_id") or "",
            "report_tenant_id": meta.get("tenant_id", ""),
            "report_tenant_name": meta.get("tenant_name", ""),
            "report_domain": meta.get("domain", ""),
            "matching_tenants": [
                {"name": t["name"], "display_name": t.get("display_name") or t["name"]}
                for t in matching
            ],
        })


def store_zt_report(db, tenant_name: str, filename: str, tmp_path: str,
                    parser, actions) -> str:
    """Store ZT report HTML and data files, save metadata to DB."""
    reports_dir = Path(db.db_path).parent / "zt_reports" / tenant_name
    reports_dir.mkdir(parents=True, exist_ok=True)

    report_id = str(uuid.uuid4())[:8]
    report_dir = reports_dir / report_id
    report_dir.mkdir(exist_ok=True)

    html_path = ""
    data_dir = ""

    if Path(tmp_path).suffix.lower() == ".zip":
        # Move extracted files to permanent storage
        extract_dir = getattr(parser, "_extract_dir", None)
        if extract_dir and Path(extract_dir).exists():
            for item in Path(extract_dir).iterdir():
                dest = report_dir / item.name
                if item.is_dir():
                    shutil.copytree(str(item), str(dest), dirs_exist_ok=True)
                else:
                    shutil.copy2(str(item), str(dest))
            shutil.rmtree(extract_dir, ignore_errors=True)

        for html_file in report_dir.rglob("*.html"):
            html_path = str(html_file)
            break
        for candidate in report_dir.rglob("zt-export"):
            if candidate.is_dir():
                data_dir = str(candidate)
                break
    else:
        shutil.copy2(tmp_path, str(report_dir / filename))

    status_counts = Counter(a.status for a in actions)
    metadata = getattr(parser, "report_metadata", {}) or {}
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


def store_scuba_report(db, tenant_name: str, filename: str, tmp_path: str,
                       parser, actions) -> str:
    """Store SCuBA report HTML and data files, save metadata to DB."""
    reports_dir = Path(db.db_path).parent / "scuba_reports" / tenant_name
    reports_dir.mkdir(parents=True, exist_ok=True)

    report_id = str(uuid.uuid4())[:8]
    report_dir = reports_dir / report_id
    report_dir.mkdir(exist_ok=True)

    html_path = ""

    if Path(tmp_path).suffix.lower() == ".zip":
        extract_dir = getattr(parser, "_extract_dir", None)
        if extract_dir and Path(extract_dir).exists():
            for item in Path(extract_dir).iterdir():
                dest = report_dir / item.name
                if item.is_dir():
                    shutil.copytree(str(item), str(dest), dirs_exist_ok=True)
                else:
                    shutil.copy2(str(item), str(dest))
            shutil.rmtree(extract_dir, ignore_errors=True)

        for html_file in report_dir.rglob("BaselineReports.html"):
            html_path = str(html_file)
            break
        if not html_path:
            for html_file in report_dir.rglob("*.html"):
                html_path = str(html_file)
                break
    else:
        shutil.copy2(tmp_path, str(report_dir / filename))

    status_counts = Counter(a.status for a in actions)
    metadata = getattr(parser, "report_metadata", {}) or {}
    product_summary = getattr(parser, "product_summary", {}) or {}

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


def store_maester_report(db, tenant_name: str, filename: str, tmp_path: str,
                         parser, actions) -> str:
    """Store Maester report HTML files and save metadata to DB."""
    reports_dir = Path(db.db_path).parent / "maester_reports" / tenant_name
    reports_dir.mkdir(parents=True, exist_ok=True)

    report_id = str(uuid.uuid4())[:8]
    report_dir = reports_dir / report_id
    report_dir.mkdir(exist_ok=True)

    html_path = ""

    if Path(tmp_path).suffix.lower() == ".zip":
        extract_dir = getattr(parser, "_extract_dir", None)
        if extract_dir and Path(extract_dir).exists():
            for item in Path(extract_dir).iterdir():
                dest = report_dir / item.name
                if item.is_dir():
                    shutil.copytree(str(item), str(dest), dirs_exist_ok=True)
                else:
                    shutil.copy2(str(item), str(dest))
            shutil.rmtree(extract_dir, ignore_errors=True)
        for html_file in report_dir.rglob("*.html"):
            html_path = str(html_file)
            break
    else:
        shutil.copy2(tmp_path, str(report_dir / filename))

    metadata = getattr(parser, "report_metadata", {}) or {}
    summary = getattr(parser, "test_summary", {}) or {}
    status_counts = Counter(a.status for a in actions)
    report_data = {
        "id": report_id,
        "imported_at": datetime.utcnow().isoformat(),
        "executed_at": metadata.get("executed_at", ""),
        "report_tenant_id": metadata.get("tenant_id", ""),
        "report_tenant_name": metadata.get("tenant_name", ""),
        "report_account": metadata.get("account", ""),
        "tool_version": metadata.get("tool_version", ""),
        "total_tests": summary.get("total", len(actions)),
        "passed_tests": summary.get("passed", status_counts.get("Completed", 0)),
        "failed_tests": summary.get("failed", status_counts.get("ToDo", 0)),
        "skipped_tests": summary.get("skipped", status_counts.get("Not Applicable", 0)),
        "source_file": filename,
        "html_path": html_path,
    }
    return db.store_maester_report(tenant_name, report_data)


def _notify_import(db, tenant_name: str, result: dict) -> None:
    """Best-effort notification hook — an unreachable mail server must never
    fail an import."""
    try:
        from .notifications import notify_import_events
        outcome = notify_import_events(db, tenant_name, result)
        if outcome.get("sent") or outcome.get("errors"):
            result["notifications"] = outcome
    except Exception:
        pass


def process_file_import(db, tenant_name: str, source: str,
                        file_path: str, filename: str,
                        force_tenant: bool = False) -> dict:
    """Parse and merge a report file for a tenant, then run all post-import
    processing. Returns the import result dict. Raises on parse errors and
    raises TenantMismatchError when the report belongs to a different tenant
    (unless force_tenant is set)."""
    parser_cls, source_tool = PARSER_MAP[source]
    parser = parser_cls()
    import_started = datetime.utcnow().isoformat()
    actions = parser.parse_file(file_path)

    # Guard against importing a report into the wrong tenant.
    if not force_tenant:
        try:
            _verify_report_tenant(db, tenant_name, parser)
        except TenantMismatchError:
            # The rejected upload must not leave its extracted ZIP behind.
            extract_dir = getattr(parser, "_extract_dir", None)
            if extract_dir:
                shutil.rmtree(extract_dir, ignore_errors=True)
            raise

    actions = apply_e8_mapping(actions)
    actions = enrich_actions_from_controls(db, actions)

    new_count, updated_count, updated_details, imported_ids = db.merge_actions(
        tenant_name, actions, source_tool, filename)

    link_result = db.bulk_auto_link_imported(imported_ids)

    zt_report_id = None
    if source == "zero-trust-report":
        zt_report_id = store_zt_report(db, tenant_name, filename, file_path, parser, actions)

    scuba_report_id = None
    if source == "scuba":
        scuba_report_id = store_scuba_report(db, tenant_name, filename, file_path, parser, actions)

    maester_report_id = None
    if source == "maester":
        maester_report_id = store_maester_report(db, tenant_name, filename, file_path, parser, actions)

    corr = auto_correlate(db, tenant_name)
    compliance = auto_map_compliance(db, tenant_name)
    snapshot = db.take_score_snapshot(tenant_name, trigger=f"import:{source}")
    expired = db.expire_risk_acceptances(tenant_name)
    drift = detect_drift(db, tenant_name, source_tool)

    protected_actions = [d for d in updated_details if d.get("status_protected")]

    # Stale actions: same source_tool but not touched by this import.
    # Everything present in the report was stamped with a fresh
    # last_seen_in_report during merge, so anything older than the import
    # start no longer appears in the tool's latest report.
    all_tenant_actions = db.get_actions(tenant_name)
    stale_actions = []
    for a in all_tenant_actions:
        if a["source_tool"] == source_tool and a.get("last_seen_in_report"):
            if a["last_seen_in_report"] < import_started:
                stale_actions.append({
                    "id": a["id"], "title": a["title"],
                    "status": a["status"],
                    "last_seen": a["last_seen_in_report"],
                })

    meta = getattr(parser, "report_metadata", {}) or {}
    result = {
        "success": True,
        "source": source,
        "file": filename,
        "report_identity": {
            "tenant_id": meta.get("tenant_id", ""),
            "tenant_name": meta.get("tenant_name", ""),
            "domain": meta.get("domain", ""),
        } if meta.get("tenant_id") or meta.get("domain") else None,
        "tenant_verified": bool(
            meta.get("tenant_id")
            and (db.get_tenant(tenant_name) or {}).get("tenant_id", "").strip().lower()
            == (meta.get("tenant_id") or "").strip().lower()),
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
        "unlinked_actions": link_result["unlinked"],
    }
    if zt_report_id:
        result["zt_report_id"] = zt_report_id
    if scuba_report_id:
        result["scuba_report_id"] = scuba_report_id
    if maester_report_id:
        result["maester_report_id"] = maester_report_id
    _notify_import(db, tenant_name, result)
    return result


def import_secure_scores_with_token(db, tenant_name: str, access_token: str,
                                    cloud: str = "global") -> dict:
    """Import Secure Score data from the Graph API with an existing token.

    Fetches scores and control profiles, merges actions, updates the
    reference control table and runs the full post-import processing.
    ``cloud`` selects the national-cloud Graph endpoint.
    """
    from .graph_api import fetch_secure_scores, fetch_control_profiles

    scores_data = fetch_secure_scores(access_token, cloud=cloud)
    try:
        profiles_data = fetch_control_profiles(access_token, cloud=cloud)
    except Exception:
        profiles_data = None

    if profiles_data:
        try:
            controls = parse_graph_control_profiles(profiles_data)
            db.seed_controls(controls)
        except Exception:
            pass  # Reference data update is best-effort

    parser = SecureScoreParser()
    actions, overall_scores = parser.parse_graph_response(scores_data, profiles_data)
    actions = apply_e8_mapping(actions)
    actions = enrich_actions_from_controls(db, actions)

    source_tool = SourceTool.SECURE_SCORE.value
    new_count, updated_count, updated_details, imported_ids = db.merge_actions(
        tenant_name, actions, source_tool, "graph_api")
    db.bulk_auto_link_imported(imported_ids)

    dedup = db.deduplicate_actions(tenant_name, source_tool)

    if overall_scores.get("maxScore", 0) > 0:
        db.store_graph_scores(tenant_name, overall_scores)

    corr = auto_correlate(db, tenant_name)
    compliance = auto_map_compliance(db, tenant_name)
    snapshot = db.take_score_snapshot(tenant_name, trigger="import:graph-api")
    expired = db.expire_risk_acceptances(tenant_name)
    drift = detect_drift(db, tenant_name, source_tool)

    protected_actions = [d for d in updated_details if d.get("status_protected")]

    result = {
        "success": True,
        "source": "Microsoft Graph API",
        "total_parsed": len(actions),
        "new_actions": new_count,
        "updated_actions": updated_count,
        "protected_actions": protected_actions,
        "correlation": corr,
        "compliance": compliance,
        "drift": drift,
        "expired_risk_acceptances": len(expired),
        "snapshot": {"id": snapshot.get("id"), "percentage": snapshot.get("percentage")},
        "profiles_loaded": getattr(parser, "_profile_count", 0),
        "unmatched_controls": getattr(parser, "_unmatched_controls", []),
        "duplicates_removed": dedup.get("removed", 0),
    }
    _notify_import(db, tenant_name, result)
    return result
