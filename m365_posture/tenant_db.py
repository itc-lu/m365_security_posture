"""Per-tenant database layer for M365 Security Posture Management.

Phase 1 of database architecture migration: splits the monolithic SQLite
database into per-tenant databases for better isolation, performance, and
future encryption support.

Architecture:
  - Central DB (m365_posture.db): tenants, responsible_persons,
    correlation_groups, secure_score_controls, gitlab_templates
  - Per-tenant DBs (data/tenants/{name}.db): actions, action_history,
    plans, plan_items, import_history, score_snapshots, drift_reports,
    zt_reports, scuba_reports, compliance_mappings, action_dependencies,
    action_responsible, action_links
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional

from .database import Database, DEFAULT_DB_PATH, _generate_id

TENANT_DB_DIR = Path(__file__).parent.parent / "data" / "tenants"
MIGRATION_MARKER = Path(__file__).parent.parent / "data" / ".migrated_v1"


def is_migrated() -> bool:
    """Check if the database has been migrated to per-tenant layout."""
    return MIGRATION_MARKER.exists()


class TenantDatabase(Database):
    """Extended Database that uses per-tenant SQLite files when migrated.

    If migration has not occurred, falls back to the monolithic database
    (full backwards compatibility).

    After migration:
    - Central DB has global/shared tables
    - Each tenant gets its own DB file at data/tenants/{name}.db
    - All tenant-scoped queries route to the tenant's DB
    """

    def __init__(self, db_path: str = None):
        self._central_path = str(db_path or DEFAULT_DB_PATH)
        self._migrated = is_migrated()
        # Initialize central DB (with all tables for backwards compat)
        super().__init__(db_path)
        if self._migrated:
            TENANT_DB_DIR.mkdir(parents=True, exist_ok=True)
            self._backfill_completed_scores_per_tenant()

    def _backfill_completed_scores_per_tenant(self):
        """One-shot fix for actions stuck at score < max_score after being
        marked Completed before the auto-bump-on-status-change fix landed."""
        for db_file in TENANT_DB_DIR.glob("*.db"):
            try:
                conn = sqlite3.connect(str(db_file))
                conn.row_factory = sqlite3.Row
                conn.execute("""CREATE TABLE IF NOT EXISTS schema_migrations (
                    name TEXT PRIMARY KEY,
                    applied_at TEXT NOT NULL
                )""")
                row = conn.execute(
                    "SELECT name FROM schema_migrations WHERE name='completed_score_backfill_v1'"
                ).fetchone()
                if row is None:
                    cur = conn.execute(
                        """UPDATE actions
                              SET score = COALESCE(max_score, 1.0),
                                  score_percentage = 100.0,
                                  max_score = COALESCE(max_score, 1.0),
                                  updated_at = ?
                            WHERE status = 'Completed'
                              AND (score IS NULL OR score < COALESCE(max_score, 1.0))""",
                        (datetime.utcnow().isoformat(),),
                    )
                    conn.execute(
                        "INSERT INTO schema_migrations(name, applied_at) VALUES('completed_score_backfill_v1', ?)",
                        (datetime.utcnow().isoformat(),),
                    )
                    conn.commit()
                    if cur.rowcount:
                        print(f"[INFO] Backfilled score for {cur.rowcount} Completed action(s) in {db_file.name}.", flush=True)
                conn.close()
            except Exception as e:
                print(f"[WARNING] Completed-score backfill skipped for {db_file.name}: {e}", flush=True)

    @contextmanager
    def _tenant_conn(self, tenant_name: str):
        """Get connection to a tenant's dedicated database."""
        if not self._migrated:
            # Fall back to central DB
            with self._conn() as conn:
                yield conn
            return

        tenant_path = TENANT_DB_DIR / f"{tenant_name}.db"
        if not tenant_path.exists():
            self._init_tenant_db(tenant_name)

        conn = sqlite3.connect(str(tenant_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_tenant_db(self, tenant_name: str):
        """Create and initialize a new tenant database with schema."""
        tenant_path = TENANT_DB_DIR / f"{tenant_name}.db"
        tenant_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(tenant_path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(_TENANT_SCHEMA)
        conn.commit()
        conn.close()

    # ── Override tenant-scoped methods to use tenant DB ──

    def get_actions(self, tenant_name: str, filters: dict = None) -> list:
        filters = filters or {}
        where = ["1=1"]  # no tenant_name filter needed in per-tenant DB
        params: list = []

        if self._migrated:
            pass  # Per-tenant DB has no tenant_name column
        else:
            where = ["tenant_name=?"]
            params = [tenant_name]

        for key in ("status", "workload", "source_tool", "priority",
                    "essential_eight_control", "correlation_group_id"):
            if key in filters and filters[key]:
                where.append(f"{key}=?")
                params.append(filters[key])

        if filters.get("search"):
            where.append("(title LIKE ? OR description LIKE ?)")
            term = f"%{filters['search']}%"
            params.extend([term, term])

        sql = f"SELECT * FROM actions WHERE {' AND '.join(where)} ORDER BY priority, title"
        with self._tenant_conn(tenant_name) as conn:
            rows = conn.execute(sql, params).fetchall()
            return [self._row_to_action_dict(r, conn) for r in rows]

    def get_action(self, action_id: str) -> Optional[dict]:
        if not self._migrated:
            return super().get_action(action_id)
        # Need to search across tenant DBs (or use a lookup)
        # For efficiency, check if caller context provides tenant
        # Fall back to scanning tenant DBs
        for db_file in TENANT_DB_DIR.glob("*.db"):
            conn = sqlite3.connect(str(db_file))
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
            if row:
                result = self._row_to_action_dict(row, conn)
                conn.close()
                return result
            conn.close()
        return None

    def create_action(self, tenant_name: str, data: dict) -> dict:
        if not self._migrated:
            return super().create_action(tenant_name, data)

        action_id = data.get("id") or _generate_id()
        now = datetime.utcnow().isoformat()
        with self._tenant_conn(tenant_name) as conn:
            conn.execute(
                """INSERT INTO actions (id, title, description, source_tool,
                   source_id, reference_id, workload, status, priority,
                   risk_level, user_impact, implementation_effort,
                   required_licence, score, max_score, score_percentage,
                   essential_eight_control, essential_eight_maturity,
                   remediation_steps, current_value, recommended_value,
                   category, subcategory, planned_date, responsible,
                   tags, notes, reference_url, source_report_file,
                   source_report_date, raw_data, correlation_group_id,
                   created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (action_id, data.get("title", ""), data.get("description", ""),
                 data.get("source_tool", "Manual"), data.get("source_id", ""),
                 data.get("reference_id", ""), data.get("workload", "General"),
                 data.get("status", "ToDo"), data.get("priority", "Medium"),
                 data.get("risk_level", "Medium"), data.get("user_impact", "Low"),
                 data.get("implementation_effort", "Medium"),
                 data.get("required_licence", ""),
                 data.get("score"), data.get("max_score"),
                 data.get("score_percentage", 0),
                 data.get("essential_eight_control"),
                 data.get("essential_eight_maturity"),
                 data.get("remediation_steps", ""),
                 data.get("current_value", ""),
                 data.get("recommended_value", ""),
                 data.get("category", ""), data.get("subcategory", ""),
                 data.get("planned_date"), data.get("responsible", ""),
                 json.dumps(data.get("tags", [])), data.get("notes", ""),
                 data.get("reference_url", ""),
                 data.get("source_report_file", ""),
                 data.get("source_report_date", ""),
                 json.dumps(data.get("raw_data", {})),
                 data.get("correlation_group_id"),
                 now, now),
            )
        return self.get_action(action_id)

    def update_action(self, action_id: str, data: dict, changed_by: str = "") -> Optional[dict]:
        if not self._migrated:
            return super().update_action(action_id, data, changed_by)

        # Find which tenant DB has this action
        tenant_name = self._find_action_tenant(action_id)
        if not tenant_name:
            return None

        with self._tenant_conn(tenant_name) as conn:
            existing = conn.execute("SELECT * FROM actions WHERE id=?",
                                     (action_id,)).fetchone()
            if not existing:
                return None

            # Status change history
            if data.get("status") and data["status"] != existing["status"]:
                conn.execute(
                    """INSERT INTO action_history (action_id, timestamp,
                       old_status, new_status, changed_by) VALUES (?, ?, ?, ?, ?)""",
                    (action_id, datetime.utcnow().isoformat(),
                     existing["status"], data["status"], changed_by),
                )

            # Explicit score change history
            if "score" in data and data["score"] != existing["score"]:
                conn.execute(
                    """INSERT INTO action_history (action_id, timestamp,
                       old_score, new_score, source_report, changed_by)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (action_id, datetime.utcnow().isoformat(),
                     existing["score"], data["score"],
                     data.get("source_report", ""), changed_by),
                )

            allowed = {
                "title", "description", "status", "priority", "risk_level",
                "user_impact", "implementation_effort", "workload",
                "required_licence", "score", "max_score", "score_percentage",
                "essential_eight_control", "essential_eight_maturity",
                "remediation_steps", "current_value", "recommended_value",
                "category", "subcategory", "planned_date", "responsible",
                "notes", "reference_url", "correlation_group_id",
                "risk_justification", "risk_owner", "risk_review_date",
                "risk_expiry_date", "risk_accepted_at",
                "pinned_priority", "import_suggested_status",
                "last_seen_in_report",
            }
            updates = {k: v for k, v in data.items() if k in allowed}
            if "tags" in data:
                updates["tags"] = json.dumps(data["tags"])
            if "raw_data" in data:
                updates["raw_data"] = json.dumps(data["raw_data"])

            # When an action transitions to Completed and the caller did not
            # actually change the score, auto-fill it to max_score. Treats an
            # echoed score that equals the existing score as "no change" — the
            # edit modal always sends the current score back on save.
            new_status = updates.get("status")
            old_score = existing["score"]
            transitioning_to_completed = (
                new_status == "Completed" and existing["status"] != "Completed"
            )
            explicit_score_change = (
                "score" in updates and updates["score"] != old_score
            )
            if transitioning_to_completed and not explicit_score_change:
                max_s = existing["max_score"] or 1.0
                if "max_score" in updates and updates["max_score"]:
                    max_s = updates["max_score"]
                updates["score"] = max_s
                updates["score_percentage"] = 100.0
                if not existing["max_score"] and "max_score" not in updates:
                    updates["max_score"] = max_s
                if old_score != max_s:
                    conn.execute(
                        """INSERT INTO action_history (action_id, timestamp,
                           old_score, new_score, source_report, changed_by)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        (action_id, datetime.utcnow().isoformat(),
                         old_score, max_s, "status_completed", changed_by),
                    )

            if updates:
                updates["updated_at"] = datetime.utcnow().isoformat()
                sets = ", ".join(f"{k}=?" for k in updates)
                vals = list(updates.values()) + [action_id]
                conn.execute(f"UPDATE actions SET {sets} WHERE id=?", vals)

        return self.get_action(action_id)

    def delete_action(self, action_id: str):
        if not self._migrated:
            return super().delete_action(action_id)

        tenant_name = self._find_action_tenant(action_id)
        if tenant_name:
            with self._tenant_conn(tenant_name) as conn:
                conn.execute("DELETE FROM actions WHERE id=?", (action_id,))

    def _find_action_tenant(self, action_id: str) -> Optional[str]:
        """Find which tenant database contains an action."""
        if not self._migrated:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT tenant_name FROM actions WHERE id=?",
                    (action_id,)).fetchone()
                return row["tenant_name"] if row else None

        for db_file in TENANT_DB_DIR.glob("*.db"):
            tenant_name = db_file.stem
            conn = sqlite3.connect(str(db_file))
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT id FROM actions WHERE id=?",
                               (action_id,)).fetchone()
            conn.close()
            if row:
                return tenant_name
        return None

    # ── Plan operations (tenant-scoped) ──

    def get_plans(self, tenant_name: str) -> list:
        if not self._migrated:
            return super().get_plans(tenant_name)
        with self._tenant_conn(tenant_name) as conn:
            rows = conn.execute(
                """SELECT p.*, COUNT(pi.id) as item_count
                   FROM plans p LEFT JOIN plan_items pi ON p.id = pi.plan_id
                   GROUP BY p.id ORDER BY p.created_at DESC"""
            ).fetchall()
            return [dict(r) for r in rows]

    def get_plan(self, plan_id: str) -> Optional[dict]:
        if not self._migrated:
            return super().get_plan(plan_id)
        # Search tenant DBs
        for db_file in TENANT_DB_DIR.glob("*.db"):
            conn = sqlite3.connect(str(db_file))
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM plans WHERE id=?",
                               (plan_id,)).fetchone()
            if row:
                plan = dict(row)
                items = conn.execute(
                    """SELECT pi.*, a.title, a.status, a.priority, a.risk_level,
                       a.workload, a.source_tool, a.score, a.max_score,
                       a.user_impact, a.implementation_effort, a.required_licence,
                       a.essential_eight_control, a.essential_eight_maturity
                       FROM plan_items pi JOIN actions a ON pi.action_id = a.id
                       WHERE pi.plan_id=? ORDER BY pi.phase, pi.sequence""",
                    (plan_id,)
                ).fetchall()
                plan["items"] = [dict(i) for i in items]
                # Add actions field for backwards compatibility
                plan["actions"] = plan["items"]
                conn.close()
                return plan
            conn.close()
        return None

    # ── Import history (tenant-scoped) ──

    def get_import_history(self, tenant_name: str) -> list:
        if not self._migrated:
            return super().get_import_history(tenant_name)
        with self._tenant_conn(tenant_name) as conn:
            rows = conn.execute(
                "SELECT * FROM import_history ORDER BY timestamp DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    # ── Score snapshots (tenant-scoped) ──

    def get_score_snapshots(self, tenant_name: str, limit: int = 50) -> list:
        if not self._migrated:
            return super().get_score_snapshots(tenant_name, limit)
        with self._tenant_conn(tenant_name) as conn:
            rows = conn.execute(
                "SELECT * FROM score_snapshots ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    # ── Responsible persons (tenant-scoped action assignments) ──

    def get_action_persons(self, action_id: str) -> list:
        if not self._migrated:
            return super().get_action_persons(action_id)
        # Persons are in central DB, assignments in tenant DB
        tenant_name = self._find_action_tenant(action_id)
        if not tenant_name:
            return []
        with self._tenant_conn(tenant_name) as conn:
            person_ids = [r["person_id"] for r in conn.execute(
                "SELECT person_id FROM action_responsible WHERE action_id=?",
                (action_id,)
            ).fetchall()]
        if not person_ids:
            return []
        with self._conn() as conn:
            placeholders = ",".join("?" * len(person_ids))
            rows = conn.execute(
                f"SELECT * FROM responsible_persons WHERE id IN ({placeholders}) ORDER BY name",
                person_ids
            ).fetchall()
            return [dict(r) for r in rows]

    def assign_person_to_action(self, action_id: str, person_id: str):
        if not self._migrated:
            return super().assign_person_to_action(action_id, person_id)
        tenant_name = self._find_action_tenant(action_id)
        if not tenant_name:
            return
        with self._tenant_conn(tenant_name) as conn:
            conn.execute(
                """INSERT OR IGNORE INTO action_responsible
                   (action_id, person_id, assigned_at) VALUES (?, ?, ?)""",
                (action_id, person_id, datetime.utcnow().isoformat()),
            )

    def unassign_person_from_action(self, action_id: str, person_id: str):
        if not self._migrated:
            return super().unassign_person_from_action(action_id, person_id)
        tenant_name = self._find_action_tenant(action_id)
        if not tenant_name:
            return
        with self._tenant_conn(tenant_name) as conn:
            conn.execute(
                "DELETE FROM action_responsible WHERE action_id=? AND person_id=?",
                (action_id, person_id),
            )


# ── Tenant DB Schema (no tenant_name columns needed) ──

_TENANT_SCHEMA = """
CREATE TABLE IF NOT EXISTS actions (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL DEFAULT '',
    description TEXT DEFAULT '',
    source_tool TEXT NOT NULL DEFAULT 'Manual',
    source_id TEXT DEFAULT '',
    reference_id TEXT DEFAULT '',
    workload TEXT DEFAULT 'General',
    status TEXT DEFAULT 'ToDo',
    priority TEXT DEFAULT 'Medium',
    risk_level TEXT DEFAULT 'Medium',
    user_impact TEXT DEFAULT 'Low',
    implementation_effort TEXT DEFAULT 'Medium',
    required_licence TEXT DEFAULT '',
    score REAL,
    max_score REAL,
    score_percentage REAL,
    essential_eight_control TEXT,
    essential_eight_maturity TEXT,
    remediation_steps TEXT DEFAULT '',
    current_value TEXT DEFAULT '',
    recommended_value TEXT DEFAULT '',
    category TEXT DEFAULT '',
    subcategory TEXT DEFAULT '',
    planned_date TEXT,
    responsible TEXT DEFAULT '',
    tags TEXT DEFAULT '[]',
    notes TEXT DEFAULT '',
    reference_url TEXT DEFAULT '',
    source_report_file TEXT DEFAULT '',
    source_report_date TEXT DEFAULT '',
    raw_data TEXT DEFAULT '{}',
    correlation_group_id TEXT,
    created_at TEXT,
    updated_at TEXT,
    risk_justification TEXT DEFAULT '',
    risk_owner TEXT DEFAULT '',
    risk_review_date TEXT,
    risk_expiry_date TEXT,
    risk_accepted_at TEXT,
    control_id TEXT,
    threats TEXT DEFAULT '[]',
    tier TEXT DEFAULT '',
    action_type TEXT DEFAULT '',
    remediation_impact TEXT DEFAULT '',
    deprecated INTEGER DEFAULT 0,
    pinned_priority INTEGER DEFAULT 0,
    import_suggested_status TEXT DEFAULT '',
    last_seen_in_report TEXT
);

CREATE INDEX IF NOT EXISTS idx_actions_source ON actions(source_tool);
CREATE INDEX IF NOT EXISTS idx_actions_status ON actions(status);
CREATE INDEX IF NOT EXISTS idx_actions_correlation ON actions(correlation_group_id);
CREATE INDEX IF NOT EXISTS idx_actions_source_id ON actions(source_tool, source_id);

CREATE TABLE IF NOT EXISTS action_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id TEXT NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    timestamp TEXT NOT NULL,
    old_status TEXT,
    new_status TEXT,
    old_score REAL,
    new_score REAL,
    source_report TEXT,
    changed_by TEXT DEFAULT '',
    notes TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_history_action ON action_history(action_id);

CREATE TABLE IF NOT EXISTS import_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_tool TEXT NOT NULL,
    file_path TEXT NOT NULL,
    action_count INTEGER DEFAULT 0,
    new_actions INTEGER DEFAULT 0,
    updated_actions INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS plans (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    status TEXT DEFAULT 'Draft',
    responsible_person TEXT DEFAULT '',
    start_date TEXT,
    end_date TEXT,
    priority TEXT DEFAULT 'Medium',
    implementation_effort TEXT DEFAULT 'Medium',
    created_at TEXT,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS plan_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plan_id TEXT NOT NULL REFERENCES plans(id) ON DELETE CASCADE,
    action_id TEXT NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    phase INTEGER DEFAULT 1,
    sequence INTEGER DEFAULT 0,
    estimated_days INTEGER,
    notes TEXT DEFAULT '',
    UNIQUE(plan_id, action_id)
);
CREATE INDEX IF NOT EXISTS idx_plan_items_plan ON plan_items(plan_id);

CREATE TABLE IF NOT EXISTS score_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    trigger TEXT DEFAULT 'import',
    total_score REAL DEFAULT 0,
    total_max REAL DEFAULT 0,
    percentage REAL DEFAULT 0,
    total_actions INTEGER DEFAULT 0,
    completed_actions INTEGER DEFAULT 0,
    by_tool TEXT DEFAULT '{}',
    by_workload TEXT DEFAULT '{}',
    by_status TEXT DEFAULT '{}',
    by_priority TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_snapshots_ts ON score_snapshots(timestamp);

CREATE TABLE IF NOT EXISTS action_dependencies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id TEXT NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    depends_on_id TEXT NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    dependency_type TEXT DEFAULT 'requires',
    notes TEXT DEFAULT '',
    created_at TEXT,
    UNIQUE(action_id, depends_on_id)
);

CREATE TABLE IF NOT EXISTS compliance_mappings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id TEXT NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    framework TEXT NOT NULL,
    control_id TEXT NOT NULL,
    control_name TEXT DEFAULT '',
    control_family TEXT DEFAULT '',
    notes TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_compliance_action ON compliance_mappings(action_id);

CREATE TABLE IF NOT EXISTS drift_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_tool TEXT NOT NULL,
    previous_snapshot_id INTEGER,
    current_snapshot_id INTEGER,
    score_before REAL,
    score_after REAL,
    score_delta REAL,
    regressions TEXT DEFAULT '[]',
    improvements TEXT DEFAULT '[]',
    new_findings TEXT DEFAULT '[]',
    resolved_findings TEXT DEFAULT '[]',
    summary TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS action_responsible (
    action_id TEXT NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    person_id TEXT NOT NULL,
    assigned_at TEXT,
    PRIMARY KEY (action_id, person_id)
);
CREATE INDEX IF NOT EXISTS idx_action_responsible_person ON action_responsible(person_id);

CREATE TABLE IF NOT EXISTS action_links (
    source_action_id TEXT NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    target_action_id TEXT NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    link_type TEXT DEFAULT 'related',
    created_at TEXT,
    PRIMARY KEY (source_action_id, target_action_id)
);
"""


# ── Migration ──

def migrate_to_per_tenant(db_path: str = None) -> dict:
    """Migrate monolithic database to per-tenant layout.

    Returns a summary dict with migration results.
    """
    db_path = str(db_path or DEFAULT_DB_PATH)
    if not Path(db_path).exists():
        return {"error": "Database not found"}

    if is_migrated():
        return {"already_migrated": True}

    TENANT_DB_DIR.mkdir(parents=True, exist_ok=True)

    # Backup the original database
    backup_path = db_path + ".backup"
    if not Path(backup_path).exists():
        shutil.copy2(db_path, backup_path)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    results = {"tenants": {}, "backup": backup_path}

    try:
        tenants = conn.execute("SELECT name FROM tenants").fetchall()

        for tenant_row in tenants:
            tname = tenant_row["name"]
            tenant_path = TENANT_DB_DIR / f"{tname}.db"

            # Create tenant DB
            tconn = sqlite3.connect(str(tenant_path))
            tconn.execute("PRAGMA journal_mode=WAL")
            tconn.executescript(_TENANT_SCHEMA)

            tenant_result = {}

            # Migrate actions (drop tenant_name column)
            actions = conn.execute(
                "SELECT * FROM actions WHERE tenant_name=?", (tname,)
            ).fetchall()
            for a in actions:
                d = dict(a)
                d.pop("tenant_name", None)
                cols = list(d.keys())
                placeholders = ",".join("?" * len(cols))
                col_names = ",".join(cols)
                try:
                    tconn.execute(
                        f"INSERT OR IGNORE INTO actions ({col_names}) VALUES ({placeholders})",
                        list(d.values())
                    )
                except sqlite3.OperationalError:
                    # Handle missing columns gracefully
                    pass
            tenant_result["actions"] = len(actions)

            # Migrate action_history
            action_ids = [a["id"] for a in actions]
            if action_ids:
                placeholders = ",".join("?" * len(action_ids))
                history = conn.execute(
                    f"SELECT * FROM action_history WHERE action_id IN ({placeholders})",
                    action_ids
                ).fetchall()
                for h in history:
                    d = dict(h)
                    cols = list(d.keys())
                    phs = ",".join("?" * len(cols))
                    try:
                        tconn.execute(
                            f"INSERT OR IGNORE INTO action_history ({','.join(cols)}) VALUES ({phs})",
                            list(d.values())
                        )
                    except sqlite3.OperationalError:
                        pass
                tenant_result["history"] = len(history)

            # Migrate plans and plan_items
            plans = conn.execute(
                "SELECT * FROM plans WHERE tenant_name=?", (tname,)
            ).fetchall()
            for p in plans:
                d = dict(p)
                d.pop("tenant_name", None)
                cols = list(d.keys())
                phs = ",".join("?" * len(cols))
                try:
                    tconn.execute(
                        f"INSERT OR IGNORE INTO plans ({','.join(cols)}) VALUES ({phs})",
                        list(d.values())
                    )
                except sqlite3.OperationalError:
                    pass
            tenant_result["plans"] = len(plans)

            plan_ids = [p["id"] for p in plans]
            if plan_ids:
                phs_p = ",".join("?" * len(plan_ids))
                items = conn.execute(
                    f"SELECT * FROM plan_items WHERE plan_id IN ({phs_p})",
                    plan_ids
                ).fetchall()
                for item in items:
                    d = dict(item)
                    cols = list(d.keys())
                    phs = ",".join("?" * len(cols))
                    try:
                        tconn.execute(
                            f"INSERT OR IGNORE INTO plan_items ({','.join(cols)}) VALUES ({phs})",
                            list(d.values())
                        )
                    except sqlite3.OperationalError:
                        pass

            # Migrate import_history
            imports = conn.execute(
                "SELECT * FROM import_history WHERE tenant_name=?", (tname,)
            ).fetchall()
            for imp in imports:
                d = dict(imp)
                d.pop("tenant_name", None)
                cols = list(d.keys())
                phs = ",".join("?" * len(cols))
                try:
                    tconn.execute(
                        f"INSERT OR IGNORE INTO import_history ({','.join(cols)}) VALUES ({phs})",
                        list(d.values())
                    )
                except sqlite3.OperationalError:
                    pass
            tenant_result["imports"] = len(imports)

            # Migrate score_snapshots
            snaps = conn.execute(
                "SELECT * FROM score_snapshots WHERE tenant_name=?", (tname,)
            ).fetchall()
            for s in snaps:
                d = dict(s)
                d.pop("tenant_name", None)
                cols = list(d.keys())
                phs = ",".join("?" * len(cols))
                try:
                    tconn.execute(
                        f"INSERT OR IGNORE INTO score_snapshots ({','.join(cols)}) VALUES ({phs})",
                        list(d.values())
                    )
                except sqlite3.OperationalError:
                    pass
            tenant_result["snapshots"] = len(snaps)

            # Migrate drift_reports
            drifts = conn.execute(
                "SELECT * FROM drift_reports WHERE tenant_name=?", (tname,)
            ).fetchall()
            for dr in drifts:
                d = dict(dr)
                d.pop("tenant_name", None)
                cols = list(d.keys())
                phs = ",".join("?" * len(cols))
                try:
                    tconn.execute(
                        f"INSERT OR IGNORE INTO drift_reports ({','.join(cols)}) VALUES ({phs})",
                        list(d.values())
                    )
                except sqlite3.OperationalError:
                    pass
            tenant_result["drift_reports"] = len(drifts)

            # Migrate compliance_mappings
            if action_ids:
                phs_a = ",".join("?" * len(action_ids))
                mappings = conn.execute(
                    f"SELECT * FROM compliance_mappings WHERE action_id IN ({phs_a})",
                    action_ids
                ).fetchall()
                for m in mappings:
                    d = dict(m)
                    cols = list(d.keys())
                    phs = ",".join("?" * len(cols))
                    try:
                        tconn.execute(
                            f"INSERT OR IGNORE INTO compliance_mappings ({','.join(cols)}) VALUES ({phs})",
                            list(d.values())
                        )
                    except sqlite3.OperationalError:
                        pass
                tenant_result["compliance_mappings"] = len(mappings)

            # Migrate action_responsible
            if action_ids:
                try:
                    assignments = conn.execute(
                        f"SELECT * FROM action_responsible WHERE action_id IN ({phs_a})",
                        action_ids
                    ).fetchall()
                    for ar in assignments:
                        d = dict(ar)
                        cols = list(d.keys())
                        phs = ",".join("?" * len(cols))
                        tconn.execute(
                            f"INSERT OR IGNORE INTO action_responsible ({','.join(cols)}) VALUES ({phs})",
                            list(d.values())
                        )
                    tenant_result["person_assignments"] = len(assignments)
                except sqlite3.OperationalError:
                    tenant_result["person_assignments"] = 0

            # Migrate action_links
            if action_ids:
                try:
                    links = conn.execute(
                        f"SELECT * FROM action_links WHERE source_action_id IN ({phs_a})"
                        f" OR target_action_id IN ({phs_a})",
                        action_ids + action_ids
                    ).fetchall()
                    for lnk in links:
                        d = dict(lnk)
                        cols = list(d.keys())
                        phs = ",".join("?" * len(cols))
                        tconn.execute(
                            f"INSERT OR IGNORE INTO action_links ({','.join(cols)}) VALUES ({phs})",
                            list(d.values())
                        )
                    tenant_result["action_links"] = len(links)
                except sqlite3.OperationalError:
                    tenant_result["action_links"] = 0

            # Migrate action_dependencies
            if action_ids:
                deps = conn.execute(
                    f"SELECT * FROM action_dependencies WHERE action_id IN ({phs_a})",
                    action_ids
                ).fetchall()
                for dep in deps:
                    d = dict(dep)
                    cols = list(d.keys())
                    phs = ",".join("?" * len(cols))
                    try:
                        tconn.execute(
                            f"INSERT OR IGNORE INTO action_dependencies ({','.join(cols)}) VALUES ({phs})",
                            list(d.values())
                        )
                    except sqlite3.OperationalError:
                        pass
                tenant_result["dependencies"] = len(deps)

            tconn.commit()
            tconn.close()
            results["tenants"][tname] = tenant_result

        # Write migration marker
        MIGRATION_MARKER.write_text(
            json.dumps({
                "migrated_at": datetime.utcnow().isoformat(),
                "source_db": db_path,
                "tenants": list(results["tenants"].keys()),
            }, indent=2)
        )
        results["success"] = True

    except Exception as e:
        results["error"] = str(e)
        results["success"] = False
    finally:
        conn.close()

    return results
