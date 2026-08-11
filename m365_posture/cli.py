"""CLI entry point for the M365 Security Posture Management Tool.

The tool is managed entirely through its web interface (``m365-posture web``).
The CLI exists to launch the web app and to migrate legacy JSON tenant data
(from pre-SQLite versions of this tool) into the database.
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path

from . import __version__


def cmd_web(args):
    """Launch the web management interface."""
    try:
        from .webapp import run_server
    except ImportError as e:
        print("Error: Flask is required for the web UI. Install with: pip install flask")
        print(f"Details: {e}")
        sys.exit(1)

    db_path = args.db_path
    if not db_path:
        data_dir = getattr(args, "data_dir", None)
        if data_dir:
            db_path = os.path.join(data_dir, "m365_posture.db")

    run_server(port=args.port, db_path=db_path, open_browser=not args.no_browser,
               host=args.host)


def cmd_run(args):
    """Run one automation task headlessly and exit with a CI-friendly code.

    Exit codes: 0 = success, 1 = run failed, 2 = success but the score
    regressed (only with --fail-on-regression), 3 = configuration error.
    """
    import json as _json

    from .database import Database
    from .runner import execute_task, TASK_TYPES

    db = Database(args.db_path)
    tenant = db.get_tenant(args.tenant)
    if not tenant:
        print(f"Error: tenant '{args.tenant}' not found. "
              f"Known tenants: {', '.join(t['name'] for t in db.list_tenants()) or '(none)'}")
        sys.exit(3)
    if args.task not in TASK_TYPES:
        print(f"Error: unknown task '{args.task}'. Valid: {', '.join(TASK_TYPES)}")
        sys.exit(3)

    started = datetime.utcnow().isoformat()
    run_id = execute_task(db, args.tenant, args.task, trigger="cli")
    run = next((r for r in db.get_tool_runs(args.tenant, 50) if r["id"] == run_id), {})
    status = run.get("status", "error")

    # Drift reports written during this run reveal regressions
    drifts = [d for d in db.get_drift_reports(args.tenant, 5)
              if d.get("timestamp", "") >= started]
    regressions = [r for d in drifts for r in (d.get("regressions") or [])]
    score_delta = drifts[0].get("score_delta") if drifts else None
    regressed = bool(regressions) or (score_delta is not None and score_delta < 0)

    outcome = {
        "task": args.task,
        "tenant": args.tenant,
        "run_id": run_id,
        "status": status,
        "detail": run.get("detail", ""),
        "score_delta": score_delta,
        "regressions": regressions,
        "regressed": regressed,
    }

    if args.as_json:
        print(_json.dumps(outcome, indent=2))
    else:
        print(f"Task:     {args.task} (tenant: {args.tenant}, run #{run_id})")
        print(f"Status:   {status}")
        if run.get("detail"):
            print(f"Detail:   {run['detail'].splitlines()[0][:200]}")
        if score_delta is not None:
            print(f"Score:    {score_delta:+.2f}% since previous import")
        if regressions:
            print(f"Regressions ({len(regressions)}):")
            for r in regressions[:10]:
                print(f"  - {r.get('scope', '?')}: {r.get('old_value', '?')}% "
                      f"-> {r.get('new_value', '?')}% ({r.get('delta', 0):+.2f}%)")

    if status != "success":
        sys.exit(1)
    if args.fail_on_regression and regressed:
        sys.exit(2)
    sys.exit(0)


def cmd_migrate_from_json(args):
    """Migrate legacy JSON-based tenant data into the SQLite database."""
    from .database import Database
    from .storage import StorageManager, DEFAULT_DATA_DIR

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
                    print("  Import history: already present, skipping")
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="m365-posture",
        description="M365 Security Posture Management Tool. "
                    "Run 'm365-posture web' to start the management interface.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--data-dir", dest="data_dir", help="Path to data directory")
    sub = parser.add_subparsers(dest="command")

    web = sub.add_parser("web", help="Launch the web management interface")
    web.add_argument("-p", "--port", type=int, default=8080, help="Port (default: 8080)")
    web.add_argument("--host", default=None,
                     help="Bind address (default: 127.0.0.1; use 0.0.0.0 to expose on the network)")
    web.add_argument("--no-browser", action="store_true", help="Don't open browser automatically")
    web.add_argument("--db", dest="db_path", help="Path to SQLite database file")
    web.set_defaults(func=cmd_web)

    run = sub.add_parser(
        "run",
        help="Run one automation task headlessly (for CI/CD pipelines)",
        description="Executes a configured automation task and exits with a "
                    "CI-friendly code: 0 success, 1 run failed, 2 regression "
                    "detected (with --fail-on-regression), 3 config error.")
    run.add_argument("task",
                     choices=["secure_score", "scuba", "zero_trust", "maester"],
                     help="Task type to execute")
    run.add_argument("--tenant", required=True, help="Tenant name")
    run.add_argument("--db", dest="db_path", help="Path to SQLite database file")
    run.add_argument("--fail-on-regression", action="store_true",
                     help="Exit 2 when the imported score regressed")
    run.add_argument("--json", dest="as_json", action="store_true",
                     help="Print the outcome as JSON")
    run.set_defaults(func=cmd_run)

    migrate = sub.add_parser("migrate-from-json",
                             help="Migrate legacy JSON tenant data to the SQLite database")
    migrate.add_argument("--data-dir", help="Source JSON data directory (default: ./data)")
    migrate.add_argument("--db", dest="db_path", help="Target SQLite database path")
    migrate.add_argument("--tenant", help="Migrate only this tenant (default: all)")
    migrate.add_argument("--dry-run", action="store_true",
                         help="Show what would be migrated without writing")
    migrate.set_defaults(func=cmd_migrate_from_json)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    func = getattr(args, "func", None)
    if func:
        func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
