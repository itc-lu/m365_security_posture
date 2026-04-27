"""CLI interface for M365 Security Posture Management Tool."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from . import __version__
from .models import (
    Action, TenantConfig, ActionStatus, Priority, RiskLevel,
    UserImpact, ImplementationEffort, SourceTool, Workload,
)
from .storage import StorageManager, TenantStore
from .parsers import SecureScoreParser, ScubaParser, ZeroTrustParser, SCTParser, M365AssessParser
from .essential_eight import apply_e8_mapping, get_e8_summary
from .scoring import calculate_total_score, compare_tenants
from .report import generate_dashboard
from .gitlab_export import export_to_gitlab_csv, export_to_gitlab_json, generate_gitlab_script


PARSER_MAP = {
    "secure-score": SecureScoreParser,
    "scuba": ScubaParser,
    "zero-trust": ZeroTrustParser,
    "sct": SCTParser,
    "m365-assess": M365AssessParser,
}

SOURCE_TOOL_MAP = {
    "secure-score": SourceTool.SECURE_SCORE.value,
    "scuba": SourceTool.SCUBA.value,
    "zero-trust": SourceTool.ZERO_TRUST.value,
    "sct": SourceTool.SCT.value,
    "m365-assess": SourceTool.M365_ASSESS.value,
}


def get_storage(args) -> StorageManager:
    data_dir = getattr(args, "data_dir", None)
    return StorageManager(data_dir)


def require_active_tenant(storage: StorageManager) -> TenantStore:
    store = storage.get_active_store()
    if not store:
        print("Error: No active tenant. Use 'tenant add' or 'tenant switch' first.")
        sys.exit(1)
    return store


# ── Tenant commands ──

def cmd_tenant_add(args):
    storage = get_storage(args)
    config = TenantConfig(
        tenant_id=args.tenant_id or "",
        tenant_name=args.name,
        display_name=args.display_name or args.name,
        client_id=args.client_id or "",
        client_secret=args.client_secret or "",
        certificate_path=args.certificate or "",
        use_interactive=args.interactive,
    )
    storage.create_tenant(args.name, config)
    print(f"Tenant '{args.name}' added and set as active.")


def cmd_tenant_list(args):
    storage = get_storage(args)
    tenants = storage.list_tenants()
    active = storage.get_active_tenant()
    if not tenants:
        print("No tenants configured. Use 'tenant add' to add one.")
        return
    print("Tenants:")
    for t in tenants:
        marker = " (active)" if t == active else ""
        store = storage.get_tenant_store(t)
        config = store.load_config()
        display = config.display_name if config else t
        actions = store.load_actions()
        print(f"  {'>' if t == active else ' '} {t} - {display} [{len(actions)} actions]{marker}")


def cmd_tenant_switch(args):
    storage = get_storage(args)
    try:
        storage.set_active_tenant(args.name)
        print(f"Switched to tenant '{args.name}'.")
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)


def cmd_tenant_remove(args):
    storage = get_storage(args)
    if args.name not in storage.list_tenants():
        print(f"Tenant '{args.name}' not found.")
        sys.exit(1)
    if not args.yes:
        confirm = input(f"Delete tenant '{args.name}' and all data? (y/N): ")
        if confirm.lower() != "y":
            print("Cancelled.")
            return
    storage.delete_tenant(args.name)
    print(f"Tenant '{args.name}' removed.")


# ── Import commands ──

def cmd_import(args):
    storage = get_storage(args)
    store = require_active_tenant(storage)

    source = args.source
    file_path = args.file

    if source not in PARSER_MAP:
        print(f"Error: Unknown source '{source}'. Valid: {', '.join(PARSER_MAP.keys())}")
        sys.exit(1)

    if not os.path.exists(file_path):
        print(f"Error: File not found: {file_path}")
        sys.exit(1)

    parser = PARSER_MAP[source]()
    try:
        actions = parser.parse_file(file_path)
    except Exception as e:
        print(f"Error parsing {source} file: {e}")
        sys.exit(1)

    # Apply E8 mapping
    actions = apply_e8_mapping(actions)

    new_count, updated_count = store.merge_actions(
        actions, SOURCE_TOOL_MAP[source], file_path
    )

    # Update scores
    all_actions = store.load_actions()
    scores = {}
    for tool in set(a.source_tool for a in all_actions):
        tool_actions = [a for a in all_actions if a.source_tool == tool]
        total = sum(a.score or 0 for a in tool_actions)
        max_total = sum(a.max_score or 0 for a in tool_actions)
        scores[tool] = {
            "score": total,
            "max_score": max_total,
            "percentage": round((total / max_total * 100), 1) if max_total > 0 else 0,
            "date": datetime.utcnow().isoformat(),
        }
    store.save_scores(scores)

    print(f"Imported {len(actions)} actions from {source}:")
    print(f"  New: {new_count}")
    print(f"  Updated: {updated_count}")
    print(f"  Total actions for tenant: {len(all_actions)}")


def cmd_fetch_secure_score(args):
    storage = get_storage(args)
    store = require_active_tenant(storage)
    config = store.load_config()

    if not config:
        print("Error: Tenant not configured.")
        sys.exit(1)

    try:
        from .collectors.graph_client import GraphClient
    except ImportError as e:
        print(f"Error: {e}")
        sys.exit(1)

    client = GraphClient(config)
    print("Authenticating with Microsoft Graph...")
    try:
        client.authenticate()
    except Exception as e:
        print(f"Authentication failed: {e}")
        sys.exit(1)

    output_file = str(store.reports_dir / f"secure_score_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json")
    print("Fetching Secure Score data...")
    client.fetch_and_save(output_file)
    print(f"Saved to: {output_file}")

    # Auto-import
    parser = SecureScoreParser()
    actions = parser.parse_file(output_file)
    actions = apply_e8_mapping(actions)
    new_count, updated_count = store.merge_actions(
        actions, SourceTool.SECURE_SCORE.value, output_file
    )
    print(f"Auto-imported: {new_count} new, {updated_count} updated actions.")


# ── Action commands ──

def cmd_actions_list(args):
    storage = get_storage(args)
    store = require_active_tenant(storage)
    actions = store.load_actions()

    if args.status:
        actions = [a for a in actions if a.status == args.status]
    if args.workload:
        actions = [a for a in actions if a.workload == args.workload]
    if args.source:
        actions = [a for a in actions if a.source_tool == SOURCE_TOOL_MAP.get(args.source, args.source)]
    if args.priority:
        actions = [a for a in actions if a.priority == args.priority]

    if not actions:
        print("No actions found matching filters.")
        return

    print(f"{'ID':<10} {'Status':<15} {'Priority':<12} {'Workload':<18} {'Source':<22} {'Title'}")
    print("-" * 120)
    for a in actions:
        print(f"{a.id:<10} {a.status:<15} {a.priority:<12} {a.workload:<18} {a.source_tool:<22} {a.title[:50]}")
    print(f"\nTotal: {len(actions)} actions")


def cmd_action_show(args):
    storage = get_storage(args)
    store = require_active_tenant(storage)
    actions = store.load_actions()

    action = next((a for a in actions if a.id == args.id), None)
    if not action:
        print(f"Action '{args.id}' not found.")
        sys.exit(1)

    print(f"{'='*60}")
    print(f"ID:               {action.id}")
    print(f"Title:            {action.title}")
    print(f"Source:           {action.source_tool} ({action.source_id})")
    print(f"Status:           {action.status}")
    print(f"Priority:         {action.priority}")
    print(f"Risk Level:       {action.risk_level}")
    print(f"User Impact:      {action.user_impact}")
    print(f"Impl. Effort:     {action.implementation_effort}")
    print(f"Workload:         {action.workload}")
    print(f"Required Licence: {action.required_licence or 'N/A'}")
    print(f"Score:            {action.score}/{action.max_score} ({action.score_percentage}%)")
    print(f"E8 Control:       {action.essential_eight_control or 'N/A'}")
    print(f"E8 Maturity:      {action.essential_eight_maturity or 'N/A'}")
    print(f"Category:         {action.category}")
    print(f"Planned Date:     {action.planned_date or 'Not set'}")
    print(f"Responsible:      {action.responsible or 'Not assigned'}")
    print(f"Reference:        {action.reference_url or 'N/A'}")
    print(f"{'='*60}")
    if action.description:
        print(f"\nDescription:\n{action.description}")
    if action.current_value:
        print(f"\nCurrent Value:\n{action.current_value}")
    if action.recommended_value:
        print(f"\nRecommended Value:\n{action.recommended_value}")
    if action.remediation_steps:
        print(f"\nRemediation Steps:\n{action.remediation_steps}")
    if action.history:
        print(f"\nHistory ({len(action.history)} entries):")
        for entry in action.history:
            ts = entry.get("timestamp", "")[:19]
            parts = []
            if entry.get("old_status"):
                parts.append(f'{entry["old_status"]} -> {entry["new_status"]}')
            if entry.get("old_score") is not None:
                parts.append(f'Score: {entry["old_score"]} -> {entry["new_score"]}')
            if entry.get("source_report"):
                parts.append(f'From: {entry["source_report"]}')
            print(f"  [{ts}] {'; '.join(parts)}")


def cmd_action_update(args):
    storage = get_storage(args)
    store = require_active_tenant(storage)
    actions = store.load_actions()

    action = next((a for a in actions if a.id == args.id), None)
    if not action:
        print(f"Action '{args.id}' not found.")
        sys.exit(1)

    if args.status:
        action.update_status(args.status, changed_by=args.by or "", notes=args.notes or "")
    if args.priority:
        action.priority = args.priority
    if args.planned_date:
        action.planned_date = args.planned_date
    if args.responsible:
        action.responsible = args.responsible
    if args.notes:
        action.notes = args.notes
    if args.tags:
        action.tags = [t.strip() for t in args.tags.split(",")]

    action.updated_at = datetime.utcnow().isoformat()
    store.save_actions(actions)
    print(f"Action '{args.id}' updated.")


# ── Score commands ──

def cmd_score(args):
    storage = get_storage(args)
    store = require_active_tenant(storage)
    actions = store.load_actions()
    scores = calculate_total_score(actions)

    print(f"\n{'='*50}")
    print(f"  Overall Score: {scores['percentage']:.1f}%")
    print(f"  Actions: {scores['completed_actions']}/{scores['total_actions']} completed")
    print(f"{'='*50}")

    print("\nBy Source Tool:")
    for tool, data in scores.get("by_tool", {}).items():
        bar = "█" * int(data["percentage"] / 5) + "░" * (20 - int(data["percentage"] / 5))
        print(f"  {tool:<25} {bar} {data['percentage']:5.1f}% ({data['completed']}/{data['total']})")

    print("\nBy Workload:")
    for wl, data in scores.get("by_workload", {}).items():
        bar = "█" * int(data["percentage"] / 5) + "░" * (20 - int(data["percentage"] / 5))
        print(f"  {wl:<25} {bar} {data['percentage']:5.1f}% ({data['completed']}/{data['total']})")


def cmd_compare(args):
    storage = get_storage(args)
    tenant_names = args.tenants.split(",")

    if len(tenant_names) < 2:
        print("Error: Specify at least 2 tenants separated by commas.")
        sys.exit(1)

    tenant_scores = {}
    for name in tenant_names:
        name = name.strip()
        if name not in storage.list_tenants():
            print(f"Error: Tenant '{name}' not found.")
            sys.exit(1)
        store = storage.get_tenant_store(name)
        actions = store.load_actions()
        tenant_scores[name] = calculate_total_score(actions)

    comparison = compare_tenants(tenant_scores)

    print(f"\n{'='*60}")
    print("  Tenant Comparison")
    print(f"{'='*60}")

    print(f"\n{'Tenant':<20} {'Score':>8} {'Actions':>10} {'Completed':>10}")
    print("-" * 50)
    for tenant in tenant_names:
        tenant = tenant.strip()
        data = comparison["overall"].get(tenant, {})
        print(f"{tenant:<20} {data.get('percentage', 0):>7.1f}% {data.get('total_actions', 0):>10} {data.get('completed_actions', 0):>10}")

    if args.report:
        # Generate comparison report
        all_actions = {}
        for name in tenant_names:
            name = name.strip()
            store = storage.get_tenant_store(name)
            all_actions[name] = store.load_actions()

        # Use the first tenant as the base for the report
        first_tenant = tenant_names[0].strip()
        output = args.report
        generate_dashboard(
            all_actions[first_tenant],
            f"Comparison: {', '.join(t.strip() for t in tenant_names)}",
            output,
            comparison_data=comparison,
        )
        print(f"\nComparison report saved to: {output}")


# ── Report commands ──

def cmd_report(args):
    storage = get_storage(args)
    store = require_active_tenant(storage)
    actions = store.load_actions()
    config = store.load_config()

    tenant_name = config.display_name if config else store.tenant_name
    actions = apply_e8_mapping(actions)

    output = args.output or str(
        store.reports_dir / f"dashboard_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"
    )

    generate_dashboard(actions, tenant_name, output)
    print(f"Report generated: {output}")


def cmd_e8(args):
    storage = get_storage(args)
    store = require_active_tenant(storage)
    actions = store.load_actions()
    actions = apply_e8_mapping(actions)
    store.save_actions(actions)  # persist E8 mapping

    e8 = get_e8_summary(actions)
    controls = e8.get("controls", e8)
    overall = e8.get("overall", {})

    print(f"\n{'='*60}")
    print("  Essential Eight Compliance Summary")
    print(f"{'='*60}\n")

    if overall:
        print(f"  Overall: {overall.get('overall_percentage', 0):.1f}% | Achieved: {overall.get('overall_achieved_maturity', 'N/A')} | {overall.get('controls_mapped', 0)}/8 controls mapped\n")

    for control, data in controls.items():
        bar = "█" * int(data["percentage"] / 5) + "░" * (20 - int(data["percentage"] / 5))
        print(f"  {control:<45} {bar} {data['percentage']:5.1f}%")
        print(f"    Achieved: {data['achieved_maturity']} | {data['completed_actions']}/{data['total_actions']} actions")
        for ml, ml_data in data.get("maturity_levels", {}).items():
            print(f"      {ml}: {ml_data['completed']}/{ml_data['total']} ({ml_data['percentage']:.0f}%)")
        print()


# ── Export commands ──

def cmd_export_gitlab(args):
    storage = get_storage(args)
    store = require_active_tenant(storage)
    actions = store.load_actions()
    config = store.load_config()
    tenant_name = config.display_name if config else store.tenant_name

    filter_status = None
    if args.status:
        filter_status = [s.strip() for s in args.status.split(",")]

    fmt = args.format or "csv"
    output = args.output or str(
        store.reports_dir / f"gitlab_issues_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.{fmt}"
    )

    if fmt == "csv":
        export_to_gitlab_csv(actions, output, tenant_name, filter_status)
    elif fmt == "json":
        export_to_gitlab_json(actions, output, tenant_name,
                              project_id=args.project_id, filter_status=filter_status)
    elif fmt == "script":
        generate_gitlab_script(actions, output, tenant_name,
                               project_path=args.project_path or "GROUP/PROJECT",
                               filter_status=filter_status)
    else:
        print(f"Unknown format: {fmt}. Use csv, json, or script.")
        sys.exit(1)

    print(f"GitLab export saved to: {output}")


def cmd_history(args):
    storage = get_storage(args)
    store = require_active_tenant(storage)

    history = store.load_import_history()
    if not history:
        print("No import history.")
        return

    print(f"{'Date':<22} {'Source':<25} {'File':<35} {'New':>5} {'Updated':>8}")
    print("-" * 100)
    for entry in history:
        ts = entry.get("timestamp", "")[:19]
        src = entry.get("source_tool", "")
        fp = os.path.basename(entry.get("file_path", ""))[:34]
        print(f"{ts:<22} {src:<25} {fp:<35} {entry.get('new_actions', 0):>5} {entry.get('updated_actions', 0):>8}")


def cmd_web(args):
    try:
        from .webapp import run_server
    except ImportError as e:
        print(f"Error: Flask is required for the web UI. Install with: pip install flask")
        print(f"Details: {e}")
        sys.exit(1)

    db_path = args.db_path
    if not db_path:
        data_dir = getattr(args, "data_dir", None)
        if data_dir:
            db_path = os.path.join(data_dir, "m365_posture.db")

    run_server(port=args.port, db_path=db_path, open_browser=not args.no_browser)


# ── JSON → SQLite migration ──

def cmd_migrate_from_json(args):
    """Migrate legacy JSON-based tenant data into the SQLite database."""
    from .database import Database
    from .storage import DEFAULT_DATA_DIR

    data_dir = Path(getattr(args, "data_dir", None) or DEFAULT_DATA_DIR)
    db_path = getattr(args, "db_path", None)
    dry_run = getattr(args, "dry_run", False)
    only_tenant = getattr(args, "tenant", None)

    if not data_dir.exists():
        print(f"Error: Data directory '{data_dir}' does not exist.")
        sys.exit(1)

    storage = StorageManager(str(data_dir))
    tenants = storage.list_tenants()

    if only_tenant:
        if only_tenant not in tenants:
            print(f"Error: Tenant '{only_tenant}' not found in {data_dir}")
            sys.exit(1)
        tenants = [only_tenant]

    if not tenants:
        print("No tenants found in JSON storage.")
        return

    print(f"Found {len(tenants)} tenant(s): {', '.join(tenants)}")
    if dry_run:
        print("[DRY RUN] No changes will be written.\n")

    db = Database(db_path) if not dry_run else None
    grand = {"tenants": 0, "actions": 0, "skipped": 0, "history": 0, "deps": 0, "imports": 0, "snapshots": 0}

    for tenant_name in tenants:
        store = storage.get_tenant_store(tenant_name)
        config = store.load_config()
        if not config:
            print(f"\n[{tenant_name}] WARNING: no config.json found, skipping.")
            continue

        print(f"\n[{tenant_name}]")
        stats = {"actions": 0, "skipped": 0, "history": 0, "deps": 0, "imports": 0}

        # 1. Tenant record
        if not dry_run:
            if db.get_tenant(tenant_name):
                print("  Tenant already in DB, skipping config.")
            else:
                db.create_tenant(tenant_name, config)
                print(f"  + Created tenant '{tenant_name}' ({config.display_name})")
                grand["tenants"] += 1
        else:
            print(f"  Would create tenant '{tenant_name}' ({config.display_name})")
            grand["tenants"] += 1

        # 2. Actions + embedded history
        actions = store.load_actions()
        id_map = {}
        for action in actions:
            d = action.to_dict()
            aid = d.get("id") or ""
            if not dry_run:
                if db.get_action(aid):
                    id_map[aid] = aid
                    stats["skipped"] += 1
                    continue
                created = db.create_action(tenant_name, d)
                db_id = created["id"]
                id_map[aid] = db_id
                stats["actions"] += 1
                history_entries = d.get("history", [])
                if history_entries:
                    with db._conn() as conn:
                        conn.executemany(
                            """INSERT INTO action_history
                               (action_id, timestamp, old_status, new_status,
                                old_score, new_score, source_report, changed_by, notes)
                               VALUES (?,?,?,?,?,?,?,?,?)""",
                            [(db_id,
                              h.get("timestamp", datetime.utcnow().isoformat()),
                              h.get("old_status"), h.get("new_status"),
                              h.get("old_score"), h.get("new_score"),
                              h.get("source_report", ""),
                              h.get("changed_by", ""),
                              h.get("notes", ""))
                             for h in history_entries],
                        )
                    stats["history"] += len(history_entries)
            else:
                id_map[aid] = aid
                stats["actions"] += 1
                stats["history"] += len(d.get("history", []))

        print(f"  Actions: {stats['actions']} migrated, {stats['skipped']} already existed, "
              f"{stats['history']} history entries")

        # 3. Action dependencies (depends_on / blocks)
        for action in actions:
            d = action.to_dict()
            src_id = id_map.get(d.get("id", ""))
            if not src_id:
                continue
            for dep_id in d.get("depends_on", []):
                tgt = id_map.get(dep_id)
                if tgt:
                    if not dry_run:
                        try:
                            db.add_dependency(src_id, tgt, "depends_on")
                            stats["deps"] += 1
                        except Exception:
                            pass
                    else:
                        stats["deps"] += 1
            for blocked_id in d.get("blocks", []):
                tgt = id_map.get(blocked_id)
                if tgt:
                    if not dry_run:
                        try:
                            db.add_dependency(tgt, src_id, "depends_on")
                            stats["deps"] += 1
                        except Exception:
                            pass
                    else:
                        stats["deps"] += 1
        if stats["deps"]:
            print(f"  Dependencies: {stats['deps']} migrated")

        # 4. Import history
        import_history = store.load_import_history()
        if import_history:
            if not dry_run:
                existing_count = len(db.get_import_history(tenant_name))
                if existing_count == 0:
                    with db._conn() as conn:
                        conn.executemany(
                            """INSERT INTO import_history
                               (tenant_name, timestamp, source_tool, file_path,
                                action_count, new_actions, updated_actions)
                               VALUES (?,?,?,?,?,?,?)""",
                            [(tenant_name,
                              r.get("timestamp", datetime.utcnow().isoformat()),
                              r.get("source_tool", ""),
                              r.get("file_path", ""),
                              r.get("action_count", 0),
                              r.get("new_actions", 0),
                              r.get("updated_actions", 0))
                             for r in import_history],
                        )
                    stats["imports"] = len(import_history)
                    print(f"  Import history: {stats['imports']} records migrated")
                else:
                    print(f"  Import history: already present, skipping")
            else:
                stats["imports"] = len(import_history)
                print(f"  Import history: {stats['imports']} records would be migrated")

        # 5. Score snapshot
        scores = store.load_scores()
        if scores and not dry_run and stats["actions"] > 0:
            try:
                db.take_score_snapshot(tenant_name, trigger="json_migration")
                grand["snapshots"] += 1
                print("  + Score snapshot created")
            except Exception as e:
                print(f"  WARNING: Could not create score snapshot: {e}")
        elif scores:
            grand["snapshots"] += 1

        for k in ("actions", "skipped", "history", "deps", "imports"):
            grand[k] += stats[k]

    verb = "[DRY RUN] Would migrate" if dry_run else "Migrated"
    print(f"\n{verb}:")
    print(f"  Tenants:         {grand['tenants']}")
    print(f"  Actions:         {grand['actions']} (skipped existing: {grand['skipped']})")
    print(f"  History entries: {grand['history']}")
    print(f"  Dependencies:    {grand['deps']}")
    print(f"  Import records:  {grand['imports']}")
    print(f"  Score snapshots: {grand['snapshots']}")


# ── Main CLI ──

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="m365-posture",
        description="M365 Security Posture Management Tool",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--data-dir", dest="data_dir", help="Path to data directory")
    sub = parser.add_subparsers(dest="command")

    # Tenant commands
    tenant = sub.add_parser("tenant", help="Manage tenants")
    tenant_sub = tenant.add_subparsers(dest="tenant_command")

    add = tenant_sub.add_parser("add", help="Add a new tenant")
    add.add_argument("name", help="Tenant short name (used as directory name)")
    add.add_argument("--tenant-id", help="Azure AD tenant ID")
    add.add_argument("--display-name", help="Display name")
    add.add_argument("--client-id", help="App registration client ID")
    add.add_argument("--client-secret", help="App registration client secret")
    add.add_argument("--certificate", help="Path to certificate file")
    add.add_argument("--interactive", action="store_true", help="Use interactive auth")
    add.set_defaults(func=cmd_tenant_add)

    ls = tenant_sub.add_parser("list", help="List tenants")
    ls.set_defaults(func=cmd_tenant_list)

    sw = tenant_sub.add_parser("switch", help="Switch active tenant")
    sw.add_argument("name", help="Tenant name to switch to")
    sw.set_defaults(func=cmd_tenant_switch)

    rm = tenant_sub.add_parser("remove", help="Remove a tenant")
    rm.add_argument("name", help="Tenant name to remove")
    rm.add_argument("-y", "--yes", action="store_true", help="Skip confirmation")
    rm.set_defaults(func=cmd_tenant_remove)

    # Import command
    imp = sub.add_parser("import", help="Import assessment data")
    imp.add_argument("source", choices=list(PARSER_MAP.keys()),
                     help="Source tool type")
    imp.add_argument("file", help="Path to report file (JSON/CSV)")
    imp.set_defaults(func=cmd_import)

    # Fetch command
    fetch = sub.add_parser("fetch", help="Fetch data from MS Graph API")
    fetch.add_argument("source", choices=["secure-score"], help="Data to fetch")
    fetch.set_defaults(func=cmd_fetch_secure_score)

    # Actions commands
    actions = sub.add_parser("actions", help="View and manage actions")
    actions_sub = actions.add_subparsers(dest="actions_command")

    act_list = actions_sub.add_parser("list", help="List actions")
    act_list.add_argument("--status", help="Filter by status")
    act_list.add_argument("--workload", help="Filter by workload")
    act_list.add_argument("--source", help="Filter by source tool")
    act_list.add_argument("--priority", help="Filter by priority")
    act_list.set_defaults(func=cmd_actions_list)

    act_show = actions_sub.add_parser("show", help="Show action details")
    act_show.add_argument("id", help="Action ID")
    act_show.set_defaults(func=cmd_action_show)

    act_update = actions_sub.add_parser("update", help="Update action properties")
    act_update.add_argument("id", help="Action ID")
    act_update.add_argument("--status", choices=[s.value for s in ActionStatus])
    act_update.add_argument("--priority", choices=[p.value for p in Priority])
    act_update.add_argument("--planned-date", help="Planned date (YYYY-MM-DD)")
    act_update.add_argument("--responsible", help="Responsible person")
    act_update.add_argument("--notes", help="Notes")
    act_update.add_argument("--tags", help="Tags (comma-separated)")
    act_update.add_argument("--by", help="Changed by (username)")
    act_update.set_defaults(func=cmd_action_update)

    # Score command
    score = sub.add_parser("score", help="Show security posture scores")
    score.set_defaults(func=cmd_score)

    # Compare command
    cmp = sub.add_parser("compare", help="Compare tenant security postures")
    cmp.add_argument("tenants", help="Comma-separated tenant names")
    cmp.add_argument("--report", help="Generate HTML comparison report to file")
    cmp.set_defaults(func=cmd_compare)

    # Report command
    report = sub.add_parser("report", help="Generate HTML dashboard report")
    report.add_argument("-o", "--output", help="Output HTML file path")
    report.set_defaults(func=cmd_report)

    # Essential Eight command
    e8 = sub.add_parser("e8", help="Show Essential Eight compliance")
    e8.set_defaults(func=cmd_e8)

    # Export command
    export = sub.add_parser("export", help="Export to GitLab")
    export.add_argument("--format", choices=["csv", "json", "script"], default="csv")
    export.add_argument("-o", "--output", help="Output file path")
    export.add_argument("--status", help="Filter by status (comma-separated)")
    export.add_argument("--project-id", type=int, help="GitLab project ID (for JSON format)")
    export.add_argument("--project-path", help="GitLab project path (for script format)")
    export.set_defaults(func=cmd_export_gitlab)

    # History command
    hist = sub.add_parser("history", help="Show import history")
    hist.set_defaults(func=cmd_history)

    # Web UI command
    web = sub.add_parser("web", help="Launch web management interface")
    web.add_argument("-p", "--port", type=int, default=8080, help="Port (default: 8080)")
    web.add_argument("--no-browser", action="store_true", help="Don't open browser automatically")
    web.add_argument("--db", dest="db_path", help="Path to SQLite database file")
    web.set_defaults(func=cmd_web)

    # Migrate from JSON command
    migrate = sub.add_parser("migrate-from-json", help="Migrate legacy JSON tenant data to the SQLite database")
    migrate.add_argument("--data-dir", help="Source JSON data directory (default: ./data)")
    migrate.add_argument("--db", dest="db_path", help="Target SQLite database path")
    migrate.add_argument("--tenant", help="Migrate only this tenant (default: all)")
    migrate.add_argument("--dry-run", action="store_true", help="Show what would be migrated without writing")
    migrate.set_defaults(func=cmd_migrate_from_json)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "tenant" and not getattr(args, "tenant_command", None):
        cmd_tenant_list(args)
        return

    if args.command == "actions" and not getattr(args, "actions_command", None):
        cmd_actions_list(args)
        return

    func = getattr(args, "func", None)
    if func:
        func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
