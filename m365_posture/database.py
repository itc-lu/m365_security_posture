"""SQLite database layer for M365 Security Posture Management.

Replaces JSON file storage with a proper relational database.
Supports action correlation across tools and remediation planning.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional

import hashlib
import secrets

from .models import (
    Action, TenantConfig, ActionStatus, SecureScoreControl,
    SourceTool, Workload, GlobalAction, User,
)

DEFAULT_DB_PATH = Path(__file__).parent.parent / "data" / "m365_posture.db"


def _generate_id() -> str:
    return str(uuid.uuid4())[:8]


def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
    return f"pbkdf2:sha256:{salt}:{dk.hex()}"


def _verify_password(password: str, stored_hash: str) -> bool:
    try:
        _, algo, salt, dk_hex = stored_hash.split(":", 3)
        dk = hashlib.pbkdf2_hmac(algo, password.encode(), salt.encode(), 260000)
        return secrets.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


class Database:
    """SQLite-backed storage for all tenant and action data."""

    def __init__(self, db_path: str = None):
        self.db_path = str(db_path or DEFAULT_DB_PATH)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path)
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

    def _init_schema(self):
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS tenants (
                    name TEXT PRIMARY KEY,
                    tenant_id TEXT DEFAULT '',
                    display_name TEXT DEFAULT '',
                    client_id TEXT DEFAULT '',
                    client_secret TEXT DEFAULT '',
                    certificate_path TEXT DEFAULT '',
                    use_interactive INTEGER DEFAULT 0,
                    notes TEXT DEFAULT '',
                    created_at TEXT,
                    is_active INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS actions (
                    id TEXT PRIMARY KEY,
                    tenant_name TEXT NOT NULL REFERENCES tenants(name) ON DELETE CASCADE,
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
                    updated_at TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_actions_tenant ON actions(tenant_name);
                CREATE INDEX IF NOT EXISTS idx_actions_source ON actions(source_tool);
                CREATE INDEX IF NOT EXISTS idx_actions_status ON actions(status);
                CREATE INDEX IF NOT EXISTS idx_actions_correlation ON actions(correlation_group_id);
                CREATE INDEX IF NOT EXISTS idx_actions_source_id ON actions(tenant_name, source_tool, source_id);
                CREATE INDEX IF NOT EXISTS idx_actions_tenant_tool_title ON actions(tenant_name, source_tool, title);
                CREATE INDEX IF NOT EXISTS idx_actions_updated_at ON actions(updated_at);

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

                CREATE TABLE IF NOT EXISTS correlation_groups (
                    id TEXT PRIMARY KEY,
                    canonical_name TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    keywords TEXT DEFAULT '[]',
                    created_at TEXT
                );

                CREATE TABLE IF NOT EXISTS import_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_name TEXT NOT NULL REFERENCES tenants(name) ON DELETE CASCADE,
                    timestamp TEXT NOT NULL,
                    source_tool TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    action_count INTEGER DEFAULT 0,
                    new_actions INTEGER DEFAULT 0,
                    updated_actions INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS plans (
                    id TEXT PRIMARY KEY,
                    tenant_name TEXT NOT NULL REFERENCES tenants(name) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    status TEXT DEFAULT 'Draft',
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

                -- Score snapshots for trending
                CREATE TABLE IF NOT EXISTS score_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_name TEXT NOT NULL REFERENCES tenants(name) ON DELETE CASCADE,
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
                CREATE INDEX IF NOT EXISTS idx_snapshots_tenant ON score_snapshots(tenant_name, timestamp);

                -- Action dependencies
                CREATE TABLE IF NOT EXISTS action_dependencies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action_id TEXT NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
                    depends_on_id TEXT NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
                    dependency_type TEXT DEFAULT 'requires',
                    notes TEXT DEFAULT '',
                    created_at TEXT,
                    UNIQUE(action_id, depends_on_id)
                );
                CREATE INDEX IF NOT EXISTS idx_deps_action ON action_dependencies(action_id);
                CREATE INDEX IF NOT EXISTS idx_deps_target ON action_dependencies(depends_on_id);

                -- Compliance framework mappings
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
                CREATE INDEX IF NOT EXISTS idx_compliance_framework ON compliance_mappings(framework, control_id);

                -- Drift detection results
                CREATE TABLE IF NOT EXISTS drift_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_name TEXT NOT NULL REFERENCES tenants(name) ON DELETE CASCADE,
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
                CREATE INDEX IF NOT EXISTS idx_drift_tenant ON drift_reports(tenant_name, timestamp);

                -- Reference table of Secure Score controls (shared across tenants)
                CREATE TABLE IF NOT EXISTS secure_score_controls (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL DEFAULT '',
                    description TEXT DEFAULT '',
                    remediation_steps TEXT DEFAULT '',
                    prerequisites TEXT DEFAULT '',
                    user_impact_description TEXT DEFAULT '',
                    implementation_cost TEXT DEFAULT '',
                    category TEXT DEFAULT '',
                    product TEXT DEFAULT '',
                    reference_url TEXT DEFAULT '',
                    max_score REAL DEFAULT 0,
                    title_variants TEXT DEFAULT '[]',
                    updated_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_ssc_title ON secure_score_controls(title);

                -- Zero Trust Report storage (HTML reports + metadata)
                CREATE TABLE IF NOT EXISTS zt_reports (
                    id TEXT PRIMARY KEY,
                    tenant_name TEXT NOT NULL REFERENCES tenants(name) ON DELETE CASCADE,
                    imported_at TEXT NOT NULL,
                    executed_at TEXT DEFAULT '',
                    report_tenant_id TEXT DEFAULT '',
                    report_tenant_name TEXT DEFAULT '',
                    report_domain TEXT DEFAULT '',
                    report_account TEXT DEFAULT '',
                    tool_version TEXT DEFAULT '',
                    test_result_summary TEXT DEFAULT '{}',
                    tenant_info TEXT DEFAULT '{}',
                    html_path TEXT DEFAULT '',
                    data_dir TEXT DEFAULT '',
                    total_tests INTEGER DEFAULT 0,
                    passed_tests INTEGER DEFAULT 0,
                    failed_tests INTEGER DEFAULT 0,
                    source_file TEXT DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_zt_reports_tenant ON zt_reports(tenant_name);

                -- SCuBA (ScubaGear) Report storage
                CREATE TABLE IF NOT EXISTS scuba_reports (
                    id TEXT PRIMARY KEY,
                    tenant_name TEXT NOT NULL REFERENCES tenants(name) ON DELETE CASCADE,
                    imported_at TEXT NOT NULL,
                    executed_at TEXT DEFAULT '',
                    report_tenant_id TEXT DEFAULT '',
                    report_tenant_name TEXT DEFAULT '',
                    report_domain TEXT DEFAULT '',
                    tool_version TEXT DEFAULT '',
                    report_uuid TEXT DEFAULT '',
                    products_assessed TEXT DEFAULT '[]',
                    product_summary TEXT DEFAULT '{}',
                    total_controls INTEGER DEFAULT 0,
                    passed_controls INTEGER DEFAULT 0,
                    failed_controls INTEGER DEFAULT 0,
                    warning_controls INTEGER DEFAULT 0,
                    manual_controls INTEGER DEFAULT 0,
                    source_file TEXT DEFAULT '',
                    html_path TEXT DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_scuba_reports_tenant ON scuba_reports(tenant_name);

                CREATE TABLE IF NOT EXISTS gitlab_templates (
                    id TEXT PRIMARY KEY,
                    tenant_name TEXT NOT NULL REFERENCES tenants(name) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    template_type TEXT NOT NULL DEFAULT 'assessment',
                    title_template TEXT DEFAULT '',
                    body_template TEXT DEFAULT '',
                    labels TEXT DEFAULT '[]',
                    created_at TEXT,
                    updated_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_gitlab_tpl_tenant ON gitlab_templates(tenant_name);

                -- ── Control Plane ──

                CREATE TABLE IF NOT EXISTS global_actions (
                    id TEXT PRIMARY KEY,
                    source_tool TEXT NOT NULL DEFAULT 'Manual',
                    source_id TEXT DEFAULT '',
                    title TEXT NOT NULL DEFAULT '',
                    description TEXT DEFAULT '',
                    workload TEXT DEFAULT 'General',
                    category TEXT DEFAULT '',
                    subcategory TEXT DEFAULT '',
                    priority TEXT DEFAULT 'Medium',
                    risk_level TEXT DEFAULT 'Medium',
                    user_impact TEXT DEFAULT 'Low',
                    implementation_effort TEXT DEFAULT 'Medium',
                    required_licence TEXT DEFAULT '',
                    score REAL,
                    max_score REAL,
                    essential_eight_control TEXT,
                    essential_eight_maturity TEXT,
                    implementation_steps TEXT DEFAULT '',
                    risk_explanation TEXT DEFAULT '',
                    additional_info TEXT DEFAULT '',
                    reference_url TEXT DEFAULT '',
                    tags TEXT DEFAULT '[]',
                    review_status TEXT DEFAULT 'To Review',
                    created_at TEXT,
                    updated_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_ga_source ON global_actions(source_tool, source_id);
                CREATE INDEX IF NOT EXISTS idx_ga_review ON global_actions(review_status);
                CREATE INDEX IF NOT EXISTS idx_ga_workload ON global_actions(workload);

                CREATE TABLE IF NOT EXISTS global_compliance_mappings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    global_action_id TEXT NOT NULL REFERENCES global_actions(id) ON DELETE CASCADE,
                    framework TEXT NOT NULL,
                    control_id TEXT NOT NULL,
                    control_name TEXT DEFAULT '',
                    control_family TEXT DEFAULT '',
                    notes TEXT DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_gcm_action ON global_compliance_mappings(global_action_id);
                CREATE INDEX IF NOT EXISTS idx_gcm_framework ON global_compliance_mappings(framework, control_id);

                -- Per-tenant override of a global action's implementation steps.
                CREATE TABLE IF NOT EXISTS action_implementation_overrides (
                    tenant_name TEXT NOT NULL REFERENCES tenants(name) ON DELETE CASCADE,
                    global_action_id TEXT NOT NULL REFERENCES global_actions(id) ON DELETE CASCADE,
                    implementation_steps TEXT DEFAULT '',
                    updated_by TEXT DEFAULT '',
                    updated_at TEXT,
                    PRIMARY KEY (tenant_name, global_action_id)
                );

                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    display_name TEXT DEFAULT '',
                    email TEXT DEFAULT '',
                    role TEXT DEFAULT 'viewer',
                    is_active INTEGER DEFAULT 1,
                    must_change_password INTEGER DEFAULT 0,
                    created_at TEXT,
                    updated_at TEXT,
                    last_login TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

                CREATE TABLE IF NOT EXISTS user_tenant_access (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    tenant_name TEXT NOT NULL REFERENCES tenants(name) ON DELETE CASCADE,
                    workloads TEXT DEFAULT '[]',
                    UNIQUE(user_id, tenant_name)
                );
                CREATE INDEX IF NOT EXISTS idx_uta_user ON user_tenant_access(user_id);
                CREATE INDEX IF NOT EXISTS idx_uta_tenant ON user_tenant_access(tenant_name);

                CREATE TABLE IF NOT EXISTS tenant_frameworks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_name TEXT NOT NULL REFERENCES tenants(name) ON DELETE CASCADE,
                    framework TEXT NOT NULL,
                    UNIQUE(tenant_name, framework)
                );
                CREATE INDEX IF NOT EXISTS idx_tf_tenant ON tenant_frameworks(tenant_name);

                -- Global action equivalence links (cross-tool)
                CREATE TABLE IF NOT EXISTS global_action_links (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action_a_id TEXT NOT NULL REFERENCES global_actions(id) ON DELETE CASCADE,
                    action_b_id TEXT NOT NULL REFERENCES global_actions(id) ON DELETE CASCADE,
                    notes TEXT DEFAULT '',
                    created_at TEXT,
                    UNIQUE(action_a_id, action_b_id)
                );
                CREATE INDEX IF NOT EXISTS idx_gal_a ON global_action_links(action_a_id);
                CREATE INDEX IF NOT EXISTS idx_gal_b ON global_action_links(action_b_id);

                -- Source aliases for merged global actions
                CREATE TABLE IF NOT EXISTS global_action_source_aliases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    global_action_id TEXT NOT NULL REFERENCES global_actions(id) ON DELETE CASCADE,
                    source_tool TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    UNIQUE(source_tool, source_id)
                );
                CREATE INDEX IF NOT EXISTS idx_gasa_ga ON global_action_source_aliases(global_action_id);

                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    actor TEXT,
                    action TEXT NOT NULL,
                    entity_type TEXT,
                    entity_id TEXT,
                    detail TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_log(entity_type, entity_id);
            """)

            # Add risk acceptance columns to actions (idempotent)
            for col, coltype, default in [
                ("risk_justification", "TEXT", "''"),
                ("risk_owner", "TEXT", "''"),
                ("risk_review_date", "TEXT", "NULL"),
                ("risk_expiry_date", "TEXT", "NULL"),
                ("risk_accepted_at", "TEXT", "NULL"),
                ("control_id", "TEXT", "NULL"),
                ("reference_id", "TEXT", "''"),
                ("threats", "TEXT", "'[]'"),
                ("tier", "TEXT", "''"),
                ("action_type", "TEXT", "''"),
                ("remediation_impact", "TEXT", "''"),
                ("deprecated", "INTEGER", "0"),
            ]:
                try:
                    conn.execute(f"ALTER TABLE actions ADD COLUMN {col} {coltype} DEFAULT {default}")
                except sqlite3.OperationalError:
                    pass  # Column already exists

            # Add pinned_priority column to actions for dashboard pinning
            for col, coltype, default in [
                ("pinned_priority", "INTEGER", "0"),
            ]:
                try:
                    conn.execute(f"ALTER TABLE actions ADD COLUMN {col} {coltype} DEFAULT {default}")
                except sqlite3.OperationalError:
                    pass

            # Add global_action_id link to actions (idempotent)
            for col, coltype, default in [
                ("global_action_id", "TEXT", "NULL"),
            ]:
                try:
                    conn.execute(f"ALTER TABLE actions ADD COLUMN {col} {coltype} DEFAULT {default}")
                except sqlite3.OperationalError:
                    pass

            # Create index on global_action_id (must run after ALTER TABLE above)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_actions_global_action ON actions(global_action_id)")

            # Ensure default admin user exists
            existing_admin = conn.execute(
                "SELECT id FROM users WHERE role='admin' LIMIT 1"
            ).fetchone()
            if not existing_admin:
                admin_id = str(uuid.uuid4())[:8]
                now = datetime.utcnow().isoformat()
                pw_hash = _hash_password("admin")
                conn.execute(
                    """INSERT OR IGNORE INTO users
                       (id, username, password_hash, display_name, email, role, is_active, must_change_password, created_at, updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (admin_id, "admin", pw_hash, "Administrator", "", "admin", 1, 1, now, now),
                )

            # Add plan metadata columns (responsible, dates, priority, effort)
            for col, coltype, default in [
                ("responsible_person", "TEXT", "''"),
                ("start_date", "TEXT", "NULL"),
                ("end_date", "TEXT", "NULL"),
                ("priority", "TEXT", "'Medium'"),
                ("implementation_effort", "TEXT", "'Medium'"),
            ]:
                try:
                    conn.execute(f"ALTER TABLE plans ADD COLUMN {col} {coltype} DEFAULT {default}")
                except sqlite3.OperationalError:
                    pass

            # Add must_change_password column to users (idempotent)
            try:
                conn.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER DEFAULT 0")
            except sqlite3.OperationalError:
                pass
            # Add import_suggested_status to track what import wanted to set
            # when status was protected (Risk Accepted, Completed, etc.)
            for col, coltype, default in [
                ("import_suggested_status", "TEXT", "''"),
                ("last_seen_in_report", "TEXT", "NULL"),
            ]:
                try:
                    conn.execute(f"ALTER TABLE actions ADD COLUMN {col} {coltype} DEFAULT {default}")
                except sqlite3.OperationalError:
                    pass

            # The responsible_persons / action_responsible tables were removed;
            # responsibility is now expressed as a User Management user reference
            # on the action itself.
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS action_links (
                    source_action_id TEXT NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
                    target_action_id TEXT NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
                    link_type TEXT DEFAULT 'related',
                    created_at TEXT,
                    PRIMARY KEY (source_action_id, target_action_id)
                );
            """)

            # Add Graph API overall scores and metadata to tenants (idempotent)
            for col, coltype, default in [
                ("graph_current_score", "REAL", "NULL"),
                ("graph_max_score", "REAL", "NULL"),
                ("graph_score_date", "TEXT", "NULL"),
                ("graph_active_user_count", "INTEGER", "0"),
                ("graph_licensed_user_count", "INTEGER", "0"),
                ("graph_enabled_services", "TEXT", "''"),
                ("graph_comparative_scores", "TEXT", "''"),
            ]:
                try:
                    conn.execute(f"ALTER TABLE tenants ADD COLUMN {col} {coltype} DEFAULT {default}")
                except sqlite3.OperationalError:
                    pass

            # Auto-run CP migration once, guarded by schema_migrations table
            try:
                conn.execute("""CREATE TABLE IF NOT EXISTS schema_migrations (
                    name TEXT PRIMARY KEY,
                    applied_at TEXT NOT NULL
                )""")
                row = conn.execute("SELECT name FROM schema_migrations WHERE name='cp_migration_v1'").fetchone()
                if row is None:
                    count = self.migrate_actions_to_global()
                    conn.execute("INSERT INTO schema_migrations(name, applied_at) VALUES('cp_migration_v1', ?)", (datetime.utcnow().isoformat(),))
                    if count:
                        print(f"[INFO] Auto-migrated {count} actions to Control Plane global actions.", flush=True)
            except Exception as e:
                print(f"[WARNING] Auto-migration skipped: {e}", flush=True)

            # Backfill global_actions.implementation_steps from tenant
            # actions.remediation_steps. Implementation is now a global field
            # with optional per-tenant override; before this change every
            # tenant carried its own copy of the imported steps.
            try:
                row = conn.execute(
                    "SELECT name FROM schema_migrations WHERE name='global_implementation_backfill_v1'"
                ).fetchone()
                if row is None:
                    cur = conn.execute(
                        """UPDATE global_actions
                              SET implementation_steps = (
                                    SELECT a.remediation_steps
                                      FROM actions a
                                     WHERE a.global_action_id = global_actions.id
                                       AND a.remediation_steps IS NOT NULL
                                       AND a.remediation_steps <> ''
                                     ORDER BY a.updated_at DESC
                                     LIMIT 1
                                  ),
                                  updated_at = ?
                            WHERE (implementation_steps IS NULL OR implementation_steps = '')
                              AND EXISTS (
                                    SELECT 1 FROM actions a
                                     WHERE a.global_action_id = global_actions.id
                                       AND a.remediation_steps IS NOT NULL
                                       AND a.remediation_steps <> ''
                              )""",
                        (datetime.utcnow().isoformat(),),
                    )
                    conn.execute(
                        "INSERT INTO schema_migrations(name, applied_at) VALUES('global_implementation_backfill_v1', ?)",
                        (datetime.utcnow().isoformat(),),
                    )
                    if cur.rowcount:
                        print(
                            f"[INFO] Backfilled implementation_steps on {cur.rowcount} global action(s) from tenant data.",
                            flush=True,
                        )
            except Exception as e:
                print(f"[WARNING] Implementation backfill skipped: {e}", flush=True)

            # Backfill score for actions that were marked Completed before the
            # auto-bump-on-status-change fix landed. They show up as Completed
            # but with score < max_score (e.g. SCuBA pass/fail at 0/1).
            try:
                row = conn.execute("SELECT name FROM schema_migrations WHERE name='completed_score_backfill_v1'").fetchone()
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
                    if cur.rowcount:
                        print(f"[INFO] Backfilled score for {cur.rowcount} Completed action(s).", flush=True)
            except Exception as e:
                print(f"[WARNING] Completed-score backfill skipped: {e}", flush=True)

    # ── Zero Trust Reports ──

    def store_zt_report(self, tenant_name: str, report_data: dict) -> str:
        """Store a Zero Trust Report record. Returns the report ID."""
        report_id = report_data.get("id") or str(uuid.uuid4())[:8]
        with self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO zt_reports
                   (id, tenant_name, imported_at, executed_at, report_tenant_id,
                    report_tenant_name, report_domain, report_account, tool_version,
                    test_result_summary, tenant_info, html_path, data_dir,
                    total_tests, passed_tests, failed_tests, source_file)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (report_id, tenant_name,
                 report_data.get("imported_at", datetime.utcnow().isoformat()),
                 report_data.get("executed_at", ""),
                 report_data.get("report_tenant_id", ""),
                 report_data.get("report_tenant_name", ""),
                 report_data.get("report_domain", ""),
                 report_data.get("report_account", ""),
                 report_data.get("tool_version", ""),
                 json.dumps(report_data.get("test_result_summary", {})),
                 json.dumps(report_data.get("tenant_info", {})),
                 report_data.get("html_path", ""),
                 report_data.get("data_dir", ""),
                 report_data.get("total_tests", 0),
                 report_data.get("passed_tests", 0),
                 report_data.get("failed_tests", 0),
                 report_data.get("source_file", "")),
            )
        return report_id

    def get_zt_reports(self, tenant_name: str) -> list[dict]:
        """Get all Zero Trust Reports for a tenant."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM zt_reports WHERE tenant_name=? ORDER BY imported_at DESC",
                (tenant_name,),
            ).fetchall()
            results = []
            for row in rows:
                d = dict(row)
                d["test_result_summary"] = json.loads(d.get("test_result_summary") or "{}")
                d["tenant_info"] = json.loads(d.get("tenant_info") or "{}")
                results.append(d)
            return results

    def get_zt_report(self, report_id: str) -> dict | None:
        """Get a single ZT report by ID."""
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM zt_reports WHERE id=?", (report_id,)).fetchone()
            if not row:
                return None
            d = dict(row)
            d["test_result_summary"] = json.loads(d.get("test_result_summary") or "{}")
            d["tenant_info"] = json.loads(d.get("tenant_info") or "{}")
            return d

    # ── SCuBA Reports ──

    def store_scuba_report(self, tenant_name: str, report_data: dict) -> str:
        """Store a SCuBA Report record. Returns the report ID."""
        report_id = report_data.get("id") or str(uuid.uuid4())[:8]
        with self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO scuba_reports
                   (id, tenant_name, imported_at, executed_at, report_tenant_id,
                    report_tenant_name, report_domain, tool_version, report_uuid,
                    products_assessed, product_summary, total_controls, passed_controls,
                    failed_controls, warning_controls, manual_controls, source_file, html_path)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (report_id, tenant_name,
                 report_data.get("imported_at", datetime.utcnow().isoformat()),
                 report_data.get("executed_at", ""),
                 report_data.get("report_tenant_id", ""),
                 report_data.get("report_tenant_name", ""),
                 report_data.get("report_domain", ""),
                 report_data.get("tool_version", ""),
                 report_data.get("report_uuid", ""),
                 json.dumps(report_data.get("products_assessed", [])),
                 json.dumps(report_data.get("product_summary", {})),
                 report_data.get("total_controls", 0),
                 report_data.get("passed_controls", 0),
                 report_data.get("failed_controls", 0),
                 report_data.get("warning_controls", 0),
                 report_data.get("manual_controls", 0),
                 report_data.get("source_file", ""),
                 report_data.get("html_path", "")),
            )
        return report_id

    def get_scuba_reports(self, tenant_name: str) -> list[dict]:
        """Get all SCuBA Reports for a tenant."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM scuba_reports WHERE tenant_name=? ORDER BY imported_at DESC",
                (tenant_name,),
            ).fetchall()
            results = []
            for row in rows:
                d = dict(row)
                d["products_assessed"] = json.loads(d.get("products_assessed") or "[]")
                d["product_summary"] = json.loads(d.get("product_summary") or "{}")
                results.append(d)
            return results

    def get_scuba_report(self, report_id: str) -> dict | None:
        """Get a single SCuBA report by ID."""
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM scuba_reports WHERE id=?", (report_id,)).fetchone()
            if not row:
                return None
            d = dict(row)
            d["products_assessed"] = json.loads(d.get("products_assessed") or "[]")
            d["product_summary"] = json.loads(d.get("product_summary") or "{}")
            return d

    # ── GitLab Templates ──

    def get_gitlab_templates(self, tenant_name: str) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM gitlab_templates WHERE tenant_name=? ORDER BY template_type, name",
                (tenant_name,),
            ).fetchall()
            result = []
            for r in rows:
                d = dict(r)
                d["labels"] = json.loads(d.get("labels") or "[]")
                result.append(d)
            return result

    def get_gitlab_template(self, template_id: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM gitlab_templates WHERE id=?", (template_id,)).fetchone()
            if not row:
                return None
            d = dict(row)
            d["labels"] = json.loads(d.get("labels") or "[]")
            return d

    def create_gitlab_template(self, tenant_name: str, name: str, template_type: str,
                                title_template: str, body_template: str,
                                labels: list[str] = None) -> dict:
        tid = _generate_id()
        now = datetime.utcnow().isoformat()
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO gitlab_templates (id, tenant_name, name, template_type,
                   title_template, body_template, labels, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (tid, tenant_name, name, template_type,
                 title_template, body_template, json.dumps(labels or []), now, now),
            )
        return self.get_gitlab_template(tid)

    def update_gitlab_template(self, template_id: str, **kwargs) -> dict | None:
        allowed = {"name", "template_type", "title_template", "body_template", "labels"}
        updates = {}
        for k, v in kwargs.items():
            if k in allowed:
                updates[k] = json.dumps(v) if k == "labels" else v
        if updates:
            updates["updated_at"] = datetime.utcnow().isoformat()
            sets = ", ".join(f"{k}=?" for k in updates)
            vals = list(updates.values()) + [template_id]
            with self._conn() as conn:
                conn.execute(f"UPDATE gitlab_templates SET {sets} WHERE id=?", vals)
        return self.get_gitlab_template(template_id)

    def delete_gitlab_template(self, template_id: str):
        with self._conn() as conn:
            conn.execute("DELETE FROM gitlab_templates WHERE id=?", (template_id,))

    # ── Graph API overall scores ──

    def store_graph_scores(self, tenant_name: str, overall_scores: dict):
        """Store the authoritative overall scores and metadata from Microsoft Graph API."""
        with self._conn() as conn:
            conn.execute(
                """UPDATE tenants SET graph_current_score=?, graph_max_score=?,
                   graph_score_date=?, graph_active_user_count=?,
                   graph_licensed_user_count=?, graph_enabled_services=?,
                   graph_comparative_scores=?
                   WHERE name=?""",
                (overall_scores.get("currentScore", 0),
                 overall_scores.get("maxScore", 0),
                 overall_scores.get("createdDateTime") or datetime.utcnow().isoformat(),
                 overall_scores.get("activeUserCount", 0),
                 overall_scores.get("licensedUserCount", 0),
                 json.dumps(overall_scores.get("enabledServices", [])),
                 json.dumps(overall_scores.get("averageComparativeScores", [])),
                 tenant_name),
            )

    # ── Secure Score Controls (reference table) ──

    def upsert_control(self, control: SecureScoreControl) -> dict:
        """Insert or update a secure score control reference entry."""
        now = datetime.utcnow().isoformat()
        with self._conn() as conn:
            existing = conn.execute(
                "SELECT id FROM secure_score_controls WHERE id=?", (control.id,)
            ).fetchone()
            variants_json = json.dumps(control.title_variants if control.title_variants else [])
            if existing:
                conn.execute(
                    """UPDATE secure_score_controls SET title=?, description=?,
                       remediation_steps=?, prerequisites=?, user_impact_description=?,
                       implementation_cost=?, category=?, product=?, reference_url=?,
                       max_score=?, title_variants=?, updated_at=?
                       WHERE id=?""",
                    (control.title, control.description, control.remediation_steps,
                     control.prerequisites, control.user_impact_description,
                     control.implementation_cost, control.category, control.product,
                     control.reference_url, control.max_score, variants_json, now,
                     control.id),
                )
            else:
                conn.execute(
                    """INSERT INTO secure_score_controls
                       (id, title, description, remediation_steps, prerequisites,
                        user_impact_description, implementation_cost, category, product,
                        reference_url, max_score, title_variants, updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (control.id, control.title, control.description,
                     control.remediation_steps, control.prerequisites,
                     control.user_impact_description, control.implementation_cost,
                     control.category, control.product, control.reference_url,
                     control.max_score, variants_json, now),
                )
        return self.get_control(control.id)

    def get_control(self, control_id: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM secure_score_controls WHERE id=?", (control_id,)
            ).fetchone()
            if not row:
                return None
            d = dict(row)
            d["title_variants"] = json.loads(d.get("title_variants", "[]"))
            return d

    def list_controls(self) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM secure_score_controls ORDER BY title"
            ).fetchall()
            result = []
            for r in rows:
                d = dict(r)
                d["title_variants"] = json.loads(d.get("title_variants", "[]"))
                result.append(d)
            return result

    def delete_control(self, control_id: str):
        with self._conn() as conn:
            conn.execute("DELETE FROM secure_score_controls WHERE id=?", (control_id,))

    def find_control_by_title(self, title: str) -> dict | None:
        """Find a control by exact title or any title variant (case-insensitive)."""
        title_lower = title.strip().lower()
        with self._conn() as conn:
            # Try exact title match first
            row = conn.execute(
                "SELECT * FROM secure_score_controls WHERE LOWER(title)=?",
                (title_lower,),
            ).fetchone()
            if row:
                d = dict(row)
                d["title_variants"] = json.loads(d.get("title_variants", "[]"))
                return d

            # Search title_variants (JSON array)
            rows = conn.execute("SELECT * FROM secure_score_controls").fetchall()
            for r in rows:
                variants = json.loads(r["title_variants"] or "[]")
                for v in variants:
                    if v.strip().lower() == title_lower:
                        d = dict(r)
                        d["title_variants"] = variants
                        return d
        return None

    def seed_controls(self, controls: list[SecureScoreControl]) -> dict:
        """Bulk upsert controls from seed data. Returns counts."""
        new_count = 0
        updated_count = 0
        for ctrl in controls:
            with self._conn() as conn:
                existing = conn.execute(
                    "SELECT id FROM secure_score_controls WHERE id=?", (ctrl.id,)
                ).fetchone()
            self.upsert_control(ctrl)
            if existing:
                updated_count += 1
            else:
                new_count += 1
        return {"new": new_count, "updated": updated_count, "total": len(controls)}

    # ── Tenant operations ──

    def create_tenant(self, name: str, config: TenantConfig) -> dict:
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO tenants (name, tenant_id, display_name, client_id,
                   client_secret, certificate_path, use_interactive, notes, created_at, is_active)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)""",
                (name, config.tenant_id, config.display_name or name,
                 config.client_id, config.client_secret, config.certificate_path,
                 1 if config.use_interactive else 0, config.notes,
                 datetime.utcnow().isoformat()),
            )
            # If no active tenant, set this one
            row = conn.execute("SELECT COUNT(*) as c FROM tenants WHERE is_active=1").fetchone()
            if row["c"] == 0:
                conn.execute("UPDATE tenants SET is_active=1 WHERE name=?", (name,))
        return self.get_tenant(name)

    def get_tenant(self, name: str) -> Optional[dict]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM tenants WHERE name=?", (name,)).fetchone()
            return dict(row) if row else None

    def list_tenants(self) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT t.*, COUNT(a.id) as action_count
                   FROM tenants t LEFT JOIN actions a ON t.name = a.tenant_name
                   GROUP BY t.name ORDER BY t.name"""
            ).fetchall()
            return [dict(r) for r in rows]

    def update_tenant(self, name: str, **kwargs) -> Optional[dict]:
        allowed = {"tenant_id", "display_name", "client_id", "client_secret",
                    "certificate_path", "use_interactive", "notes"}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return self.get_tenant(name)
        sets = ", ".join(f"{k}=?" for k in updates)
        vals = list(updates.values()) + [name]
        with self._conn() as conn:
            conn.execute(f"UPDATE tenants SET {sets} WHERE name=?", vals)
        return self.get_tenant(name)

    def delete_tenant(self, name: str):
        with self._conn() as conn:
            was_active = conn.execute(
                "SELECT is_active FROM tenants WHERE name=?", (name,)
            ).fetchone()
            conn.execute("DELETE FROM tenants WHERE name=?", (name,))
            if was_active and was_active["is_active"]:
                first = conn.execute("SELECT name FROM tenants LIMIT 1").fetchone()
                if first:
                    conn.execute("UPDATE tenants SET is_active=1 WHERE name=?", (first["name"],))

    def set_active_tenant(self, name: str):
        with self._conn() as conn:
            conn.execute("UPDATE tenants SET is_active=0 WHERE is_active=1")
            conn.execute("UPDATE tenants SET is_active=1 WHERE name=?", (name,))

    def get_active_tenant(self) -> Optional[dict]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM tenants WHERE is_active=1").fetchone()
            return dict(row) if row else None

    # ── Action operations ──

    def _row_to_action_dict(self, row: sqlite3.Row, conn=None) -> dict:
        d = dict(row)
        d["tags"] = json.loads(d.get("tags") or "[]")
        d["raw_data"] = json.loads(d.get("raw_data") or "{}")
        d["threats"] = json.loads(d.get("threats") or "[]")
        d["deprecated"] = bool(d.get("deprecated", 0))
        # Ensure risk fields exist even on older DBs
        for field in ("risk_justification", "risk_owner", "risk_review_date",
                       "risk_expiry_date", "risk_accepted_at",
                       "tier", "action_type", "remediation_impact", "reference_id"):
            if field not in d:
                d[field] = None
        if conn:
            history = conn.execute(
                "SELECT * FROM action_history WHERE action_id=? ORDER BY timestamp",
                (d["id"],)
            ).fetchall()
            d["history"] = [dict(h) for h in history]
            # Merge implementation steps from global action and tenant override.
            ga_id = d.get("global_action_id")
            global_steps = ""
            override_steps = None
            if ga_id:
                ga = conn.execute(
                    "SELECT implementation_steps FROM global_actions WHERE id=?",
                    (ga_id,)
                ).fetchone()
                global_steps = (ga["implementation_steps"] if ga else "") or ""
                ov = conn.execute(
                    """SELECT implementation_steps, updated_by, updated_at
                         FROM action_implementation_overrides
                        WHERE tenant_name=? AND global_action_id=?""",
                    (d.get("tenant_name", ""), ga_id),
                ).fetchone()
                if ov:
                    override_steps = ov["implementation_steps"] or ""
                    d["implementation_override_updated_by"] = ov["updated_by"]
                    d["implementation_override_updated_at"] = ov["updated_at"]
            d["global_implementation_steps"] = global_steps
            if ga_id:
                d["implementation_steps"] = (
                    override_steps if override_steps is not None else global_steps
                )
            else:
                # Action not yet linked to a global action — fall back to the
                # per-tenant column (legacy / freshly imported / manual).
                d["implementation_steps"] = d.get("remediation_steps") or ""
            d["is_implementation_overridden"] = override_steps is not None
        else:
            d["history"] = []
            d["global_implementation_steps"] = ""
            d["implementation_steps"] = d.get("remediation_steps") or ""
            d["is_implementation_overridden"] = False
        return d

    def get_actions(self, tenant_name: str, filters: dict = None,
                    allowed_workloads: list = None) -> list[dict]:
        filters = filters or {}
        where = ["tenant_name=?"]
        params = [tenant_name]

        for key in ("status", "workload", "source_tool", "priority",
                    "essential_eight_control", "correlation_group_id"):
            if key in filters and filters[key]:
                where.append(f"{key}=?")
                params.append(filters[key])


        if allowed_workloads:
            placeholders = ",".join("?" * len(allowed_workloads))
            where.append(f"workload IN ({placeholders})")
            params.extend(allowed_workloads)
        if filters.get("search"):
            where.append("(title LIKE ? OR description LIKE ?)")
            term = f"%{filters['search']}%"
            params.extend([term, term])

        sql = f"SELECT * FROM actions WHERE {' AND '.join(where)} ORDER BY priority, title"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
            return [self._row_to_action_dict(r, conn) for r in rows]

    def get_action(self, action_id: str) -> Optional[dict]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
            if not row:
                return None
            return self._row_to_action_dict(row, conn)

    def create_action(self, tenant_name: str, data: dict) -> dict:
        action_id = data.get("id") or _generate_id()
        now = datetime.utcnow().isoformat()
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO actions (id, tenant_name, title, description, source_tool,
                   source_id, reference_id, workload, status, priority, risk_level, user_impact,
                   implementation_effort, required_licence, score, max_score, score_percentage,
                   essential_eight_control, essential_eight_maturity, remediation_steps,
                   current_value, recommended_value, category, subcategory, planned_date,
                   responsible, tags, notes, reference_url, source_report_file,
                   source_report_date, raw_data, correlation_group_id,
                   threats, tier, action_type, remediation_impact, deprecated,
                   created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (action_id, tenant_name,
                 data.get("title", ""), data.get("description", ""),
                 data.get("source_tool", "Manual"), data.get("source_id", ""),
                 data.get("reference_id", ""),
                 data.get("workload", "General"), data.get("status", "ToDo"),
                 data.get("priority", "Medium"), data.get("risk_level", "Medium"),
                 data.get("user_impact", "Low"), data.get("implementation_effort", "Medium"),
                 data.get("required_licence", ""),
                 data.get("score"), data.get("max_score"), data.get("score_percentage"),
                 data.get("essential_eight_control"), data.get("essential_eight_maturity"),
                 data.get("remediation_steps", ""), data.get("current_value", ""),
                 data.get("recommended_value", ""), data.get("category", ""),
                 data.get("subcategory", ""), data.get("planned_date"),
                 data.get("responsible", ""),
                 json.dumps(data.get("tags", [])), data.get("notes", ""),
                 data.get("reference_url", ""), data.get("source_report_file", ""),
                 data.get("source_report_date", ""),
                 json.dumps(data.get("raw_data", {})),
                 data.get("correlation_group_id"),
                 json.dumps(data.get("threats", [])),
                 data.get("tier", ""),
                 data.get("action_type", ""),
                 data.get("remediation_impact", ""),
                 1 if data.get("deprecated") else 0,
                 data.get("created_at", now), now),
            )
        return self.get_action(action_id)

    def update_action(self, action_id: str, data: dict, changed_by: str = "") -> Optional[dict]:
        existing = self.get_action(action_id)
        if not existing:
            return None

        with self._conn() as conn:
            # Track status changes
            if "status" in data and data["status"] != existing["status"]:
                conn.execute(
                    """INSERT INTO action_history (action_id, timestamp, old_status,
                       new_status, changed_by, notes)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (action_id, datetime.utcnow().isoformat(),
                     existing["status"], data["status"],
                     changed_by, data.get("change_notes", "")),
                )

            # Track explicit score changes from caller
            if "score" in data and data["score"] != existing["score"]:
                conn.execute(
                    """INSERT INTO action_history (action_id, timestamp, old_score,
                       new_score, source_report, changed_by)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (action_id, datetime.utcnow().isoformat(),
                     existing["score"], data["score"],
                     data.get("source_report", ""), changed_by),
                )

            allowed = {
                "title", "description", "status", "priority", "risk_level",
                "user_impact", "implementation_effort", "workload", "required_licence",
                "score", "max_score", "score_percentage",
                "essential_eight_control", "essential_eight_maturity",
                "remediation_steps", "current_value", "recommended_value",
                "category", "subcategory", "planned_date", "responsible",
                "notes", "reference_url", "correlation_group_id",
                "risk_justification", "risk_owner", "risk_review_date",
                "risk_expiry_date", "risk_accepted_at",
                "pinned_priority", "import_suggested_status", "last_seen_in_report",
            }
            updates = {}
            for k, v in data.items():
                if k in allowed:
                    updates[k] = v
            if "tags" in data:
                updates["tags"] = json.dumps(data["tags"])
            if "raw_data" in data:
                updates["raw_data"] = json.dumps(data["raw_data"])

            # When an action transitions to Completed and the caller did not
            # actually change the score, auto-fill it to max_score (default 1.0
            # for pass/fail sources like SCuBA). Treats an echoed score that
            # equals the existing score as "no change" — the edit modal always
            # sends the current score back on save.
            new_status = updates.get("status")
            old_score = existing.get("score")
            transitioning_to_completed = (
                new_status == ActionStatus.COMPLETED.value
                and existing.get("status") != ActionStatus.COMPLETED.value
            )
            explicit_score_change = (
                "score" in updates and updates["score"] != old_score
            )
            if transitioning_to_completed and not explicit_score_change:
                max_s = existing.get("max_score") or 1.0
                if "max_score" in updates and updates["max_score"]:
                    max_s = updates["max_score"]
                updates["score"] = max_s
                updates["score_percentage"] = 100.0
                if not existing.get("max_score") and "max_score" not in updates:
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
        with self._conn() as conn:
            conn.execute("DELETE FROM actions WHERE id=?", (action_id,))

    def merge_actions(self, tenant_name: str, new_actions: list[Action],
                      source_tool: str, source_file: str) -> tuple[int, int, list[dict], list[str]]:
        """Smart merge: update existing actions, add new ones.

        Returns (new_count, updated_count, updated_details, touched_ids).
        updated_details is a list of {id, title, source_id, matched_by} for transparency.
        touched_ids is the list of action IDs that were inserted or updated.
        """
        new_count = 0
        updated_count = 0
        updated_details = []
        touched_ids = []
        # Secure Score legacy fallbacks only apply to Secure Score imports
        is_secure_score = (source_tool == SourceTool.SECURE_SCORE.value)

        with self._conn() as conn:
            for action in new_actions:
                # Look for existing by source_tool + source_id (primary match)
                existing = None
                matched_by = ""
                if action.source_id:
                    row = conn.execute(
                        "SELECT * FROM actions WHERE tenant_name=? AND source_tool=? AND source_id=?",
                        (tenant_name, action.source_tool, action.source_id),
                    ).fetchone()
                    if row:
                        existing = dict(row)
                        matched_by = "source_id"

                    # Fallback: old-style source_id (ss_<name>) — Secure Score only
                    if not existing and is_secure_score:
                        old_style_id = f"ss_{action.source_id.replace(' ', '_').lower()[:40]}"
                        row = conn.execute(
                            "SELECT * FROM actions WHERE tenant_name=? AND source_tool=? AND source_id=?",
                            (tenant_name, action.source_tool, old_style_id),
                        ).fetchone()
                        if row:
                            existing = dict(row)
                            matched_by = "old_style_source_id"

                    # Fallback: controlName as old title — Secure Score only
                    if not existing and is_secure_score and action.source_id:
                        row = conn.execute(
                            "SELECT * FROM actions WHERE tenant_name=? AND source_tool=? AND title=?",
                            (tenant_name, action.source_tool, action.source_id),
                        ).fetchone()
                        if row:
                            existing = dict(row)
                            matched_by = "source_id_as_title"

                    # Fallback: title match — Secure Score only
                    if not existing and is_secure_score and action.title:
                        row = conn.execute(
                            "SELECT * FROM actions WHERE tenant_name=? AND source_tool=? AND title=?",
                            (tenant_name, action.source_tool, action.title),
                        ).fetchone()
                        if row:
                            existing = dict(row)
                            matched_by = "title"

                if existing:
                    # Update existing action with all current data
                    changes = {}

                    # Determine whether status (and therefore score) is protected
                    _protected_statuses = {
                        "Risk Accepted", "Completed", "In Progress", "Exception",
                    }
                    _existing_status = existing["status"]
                    _import_status = action.status
                    _status_protected = _existing_status in _protected_statuses

                    # When user manually completed an action, protect its score from
                    # being reset by a subsequent import that still reports failure.
                    _score_protected = (
                        _status_protected
                        and _existing_status == ActionStatus.COMPLETED.value
                        and _import_status != ActionStatus.COMPLETED.value
                    )

                    # Always sync max_score (factual metadata from source tool)
                    changes["max_score"] = action.max_score

                    if _score_protected:
                        # Keep score at max_score to reflect the completed state
                        max_s = action.max_score or existing.get("max_score") or 0
                        changes["score"] = max_s
                        changes["score_percentage"] = 100.0 if max_s > 0 else 0
                    else:
                        # Sync score from import
                        if action.score is not None and action.score != existing.get("score"):
                            conn.execute(
                                """INSERT INTO action_history (action_id, timestamp, old_score,
                                   new_score, source_report) VALUES (?, ?, ?, ?, ?)""",
                                (existing["id"], datetime.utcnow().isoformat(),
                                 existing.get("score"), action.score, source_file),
                            )
                        changes["score"] = action.score
                        if action.max_score and action.max_score > 0:
                            changes["score_percentage"] = round(
                                (action.score / action.max_score) * 100, 2)
                        else:
                            changes["score_percentage"] = 0

                    if _import_status != _existing_status:
                        # Protect manually-set statuses from being overwritten by imports.
                        # Risk Accepted, Completed, In Progress, and Exception are user decisions
                        # that should not be reset by a new report import.
                        if not _status_protected:
                            conn.execute(
                                """INSERT INTO action_history (action_id, timestamp,
                                   old_status, new_status, source_report)
                                   VALUES (?, ?, ?, ?, ?)""",
                                (existing["id"], datetime.utcnow().isoformat(),
                                 existing["status"], action.status, source_file),
                            )
                            changes["status"] = action.status
                        else:
                            # Record that the import wanted to change status, but we preserved
                            # the user's decision. Store the import's suggested status for reference.
                            changes["import_suggested_status"] = action.status

                    # Always update source_id and title to latest format
                    changes["source_id"] = action.source_id
                    if action.title:
                        changes["title"] = action.title

                    # Always sync enriched fields from profile
                    if action.description:
                        changes["description"] = action.description
                    if action.remediation_steps:
                        changes["remediation_steps"] = action.remediation_steps
                    changes["current_value"] = action.current_value or existing.get("current_value", "")
                    if action.recommended_value:
                        changes["recommended_value"] = action.recommended_value
                    if action.essential_eight_control:
                        changes["essential_eight_control"] = action.essential_eight_control
                        changes["essential_eight_maturity"] = action.essential_eight_maturity

                    # Link to reference control if available
                    control_id = getattr(action, "control_id", None)
                    if control_id:
                        changes["control_id"] = control_id

                    # Always update reference_id, workload, category, subcategory, priority
                    if action.reference_id:
                        changes["reference_id"] = action.reference_id
                    if action.workload and action.workload != Workload.GENERAL.value:
                        changes["workload"] = action.workload
                    elif action.workload and not existing.get("workload"):
                        changes["workload"] = action.workload
                    if action.category:
                        changes["category"] = action.category
                    if action.subcategory:
                        changes["subcategory"] = action.subcategory
                    if action.priority:
                        changes["priority"] = action.priority
                    if action.risk_level:
                        changes["risk_level"] = action.risk_level

                    # Always sync user_impact and implementation_effort from profile
                    if action.user_impact:
                        changes["user_impact"] = action.user_impact
                    if action.implementation_effort:
                        changes["implementation_effort"] = action.implementation_effort
                    if action.reference_url:
                        changes["reference_url"] = action.reference_url
                    if action.required_licence:
                        changes["required_licence"] = action.required_licence

                    # Always sync Secure Score enrichment fields
                    if action.threats:
                        changes["threats"] = json.dumps(action.threats)
                    if action.tier:
                        changes["tier"] = action.tier
                    if action.action_type:
                        changes["action_type"] = action.action_type
                    if action.remediation_impact:
                        changes["remediation_impact"] = action.remediation_impact
                    changes["deprecated"] = 1 if action.deprecated else 0

                    changes["source_report_file"] = source_file
                    changes["source_report_date"] = datetime.utcnow().isoformat()
                    changes["last_seen_in_report"] = datetime.utcnow().isoformat()
                    changes["updated_at"] = datetime.utcnow().isoformat()
                    changes["raw_data"] = json.dumps(action.raw_data if hasattr(action, "raw_data") else {})

                    sets = ", ".join(f"{k}=?" for k in changes)
                    vals = list(changes.values()) + [existing["id"]]
                    conn.execute(f"UPDATE actions SET {sets} WHERE id=?", vals)
                    updated_count += 1
                    touched_ids.append(existing["id"])
                    detail = {
                        "id": existing["id"],
                        "title": action.title,
                        "source_id": action.source_id,
                        "existing_source_id": existing.get("source_id", ""),
                        "matched_by": matched_by,
                    }
                    if "import_suggested_status" in changes and changes["import_suggested_status"]:
                        detail["status_protected"] = True
                        detail["current_status"] = existing["status"]
                        detail["import_wanted_status"] = changes["import_suggested_status"]
                    updated_details.append(detail)
                else:
                    # Insert new action
                    now = datetime.utcnow().isoformat()
                    action_id = action.id or _generate_id()
                    control_id = getattr(action, "control_id", None) or None
                    conn.execute(
                        """INSERT INTO actions (id, tenant_name, title, description,
                           source_tool, source_id, reference_id, workload, status, priority,
                           risk_level, user_impact, implementation_effort, required_licence,
                           score, max_score, score_percentage,
                           essential_eight_control, essential_eight_maturity,
                           remediation_steps, current_value, recommended_value,
                           category, subcategory, planned_date, responsible,
                           tags, notes, reference_url, source_report_file,
                           source_report_date, raw_data, created_at, updated_at, control_id,
                           threats, tier, action_type, remediation_impact, deprecated,
                           last_seen_in_report)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (action_id, tenant_name, action.title, action.description,
                         action.source_tool, action.source_id, action.reference_id,
                         action.workload,
                         action.status, action.priority, action.risk_level,
                         action.user_impact, action.implementation_effort,
                         action.required_licence,
                         action.score, action.max_score, action.score_percentage,
                         action.essential_eight_control, action.essential_eight_maturity,
                         action.remediation_steps, action.current_value,
                         action.recommended_value, action.category, action.subcategory,
                         action.planned_date, action.responsible,
                         json.dumps(action.tags), action.notes, action.reference_url,
                         source_file, now,
                         json.dumps(action.raw_data if hasattr(action, "raw_data") else {}),
                         action.created_at or now, now, control_id,
                         json.dumps(action.threats), action.tier, action.action_type,
                         action.remediation_impact, 1 if action.deprecated else 0,
                         now),
                    )
                    new_count += 1
                    touched_ids.append(action_id)

            # Record import
            conn.execute(
                """INSERT INTO import_history (tenant_name, timestamp, source_tool,
                   file_path, action_count, new_actions, updated_actions)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (tenant_name, datetime.utcnow().isoformat(), source_tool,
                 source_file, len(new_actions), new_count, updated_count),
            )

        return new_count, updated_count, updated_details, touched_ids

    def deduplicate_actions(self, tenant_name: str, source_tool: str = None) -> dict:
        """Remove duplicate actions, keeping the most recently updated one.

        Duplicates are detected by matching source_id (new-style controlName)
        against old-style source_id (ss_<controlname>) and by matching titles
        that are controlName slugs vs profile titles for the same control.
        """
        actions = self.get_actions(tenant_name)
        if source_tool:
            actions = [a for a in actions if a["source_tool"] == source_tool]

        # Group by normalized controlName
        groups = {}
        for a in actions:
            sid = a.get("source_id", "")
            # Normalize: strip ss_ prefix, lowercase
            key = sid.lower()
            if key.startswith("ss_"):
                key = key[3:]
            if key not in groups:
                groups[key] = []
            groups[key].append(a)

        removed = 0
        with self._conn() as conn:
            for key, group in groups.items():
                if len(group) <= 1:
                    continue
                # Keep the one with the most recent updated_at
                group.sort(key=lambda a: a.get("updated_at", ""), reverse=True)
                keep = group[0]
                for dup in group[1:]:
                    conn.execute("DELETE FROM actions WHERE id=?", (dup["id"],))
                    removed += 1

        return {"removed": removed, "checked": len(actions)}

    # ── Action history ──

    def get_action_history(self, action_id: str) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM action_history WHERE action_id=? ORDER BY timestamp",
                (action_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_tenant_change_log(self, tenant_name: str, limit: int = 100) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT ah.*, a.title as action_title, a.source_tool
                   FROM action_history ah
                   JOIN actions a ON ah.action_id = a.id
                   WHERE a.tenant_name=?
                   ORDER BY ah.timestamp DESC LIMIT ?""",
                (tenant_name, limit),
            ).fetchall()
            return [dict(r) for r in rows]

    # ── Import history ──

    def get_import_history(self, tenant_name: str) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM import_history WHERE tenant_name=? ORDER BY timestamp DESC",
                (tenant_name,),
            ).fetchall()
            return [dict(r) for r in rows]

    # ── Correlation groups ──

    def get_correlated_actions(self, group_id: str) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM actions WHERE correlation_group_id=? ORDER BY source_tool",
                (group_id,),
            ).fetchall()
            return [self._row_to_action_dict(r, conn) for r in rows]

    def link_action_to_group(self, action_id: str, group_id: str):
        with self._conn() as conn:
            conn.execute(
                "UPDATE actions SET correlation_group_id=? WHERE id=?",
                (group_id, action_id),
            )

    def unlink_action(self, action_id: str):
        with self._conn() as conn:
            conn.execute(
                "UPDATE actions SET correlation_group_id=NULL WHERE id=?",
                (action_id,),
            )

    # ── Plans ──

    def create_plan(self, tenant_name: str, name: str, description: str = "") -> dict:
        pid = _generate_id()
        now = datetime.utcnow().isoformat()
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO plans (id, tenant_name, name, description, status,
                   created_at, updated_at) VALUES (?, ?, ?, ?, 'Draft', ?, ?)""",
                (pid, tenant_name, name, description, now, now),
            )
        return self.get_plan(pid)

    def get_plans(self, tenant_name: str) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT p.*, COUNT(pi.id) as item_count
                   FROM plans p LEFT JOIN plan_items pi ON p.id = pi.plan_id
                   WHERE p.tenant_name=? GROUP BY p.id ORDER BY p.created_at DESC""",
                (tenant_name,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_plan(self, plan_id: str) -> Optional[dict]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone()
            if not row:
                return None
            plan = dict(row)
            items = conn.execute(
                """SELECT pi.*, a.title, a.status, a.priority, a.risk_level,
                   a.workload, a.source_tool, a.score, a.max_score,
                   a.user_impact, a.implementation_effort, a.required_licence,
                   a.essential_eight_control, a.essential_eight_maturity
                   FROM plan_items pi JOIN actions a ON pi.action_id = a.id
                   WHERE pi.plan_id=? ORDER BY pi.phase, pi.sequence""",
                (plan_id,),
            ).fetchall()
            plan["items"] = [dict(i) for i in items]
            return plan

    def update_plan(self, plan_id: str, **kwargs) -> Optional[dict]:
        allowed = {"name", "description", "status", "responsible_person",
                   "start_date", "end_date", "priority", "implementation_effort"}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if updates:
            updates["updated_at"] = datetime.utcnow().isoformat()
            sets = ", ".join(f"{k}=?" for k in updates)
            vals = list(updates.values()) + [plan_id]
            with self._conn() as conn:
                conn.execute(f"UPDATE plans SET {sets} WHERE id=?", vals)
        return self.get_plan(plan_id)

    def delete_plan(self, plan_id: str):
        with self._conn() as conn:
            conn.execute("DELETE FROM plans WHERE id=?", (plan_id,))

    def add_plan_item(self, plan_id: str, action_id: str, phase: int = 1,
                       sequence: int = 0, estimated_days: int = None,
                       notes: str = "") -> dict:
        with self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO plan_items (plan_id, action_id, phase,
                   sequence, estimated_days, notes) VALUES (?, ?, ?, ?, ?, ?)""",
                (plan_id, action_id, phase, sequence, estimated_days, notes),
            )
            conn.execute(
                "UPDATE plans SET updated_at=? WHERE id=?",
                (datetime.utcnow().isoformat(), plan_id),
            )
        return self.get_plan(plan_id)

    def remove_plan_item(self, plan_id: str, action_id: str):
        with self._conn() as conn:
            conn.execute(
                "DELETE FROM plan_items WHERE plan_id=? AND action_id=?",
                (plan_id, action_id),
            )

    def update_plan_item(self, plan_id: str, action_id: str, **kwargs):
        allowed = {"phase", "sequence", "estimated_days", "notes"}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if updates:
            sets = ", ".join(f"{k}=?" for k in updates)
            vals = list(updates.values()) + [plan_id, action_id]
            with self._conn() as conn:
                conn.execute(
                    f"UPDATE plan_items SET {sets} WHERE plan_id=? AND action_id=?", vals
                )

    # ── Score Snapshots ──

    def take_score_snapshot(self, tenant_name: str, trigger: str = "import") -> dict:
        """Capture current scores as a point-in-time snapshot."""
        scores = self.get_scores(tenant_name)
        now = datetime.utcnow().isoformat()
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO score_snapshots (tenant_name, timestamp, trigger,
                   total_score, total_max, percentage, total_actions, completed_actions,
                   by_tool, by_workload, by_status, by_priority)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (tenant_name, now, trigger,
                 scores.get("total_score", 0), scores.get("total_max", 0),
                 scores.get("percentage", 0), scores.get("total_actions", 0),
                 scores.get("completed_actions", 0),
                 json.dumps(scores.get("by_tool", {})),
                 json.dumps(scores.get("by_workload", {})),
                 json.dumps(scores.get("by_status", {})),
                 json.dumps(scores.get("by_priority", {}))),
            )
            snapshot_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        return {"id": snapshot_id, "timestamp": now, **scores}

    def get_score_snapshots(self, tenant_name: str, limit: int = 100) -> list[dict]:
        """Get historical score snapshots for trending."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM score_snapshots WHERE tenant_name=?
                   ORDER BY timestamp DESC LIMIT ?""",
                (tenant_name, limit),
            ).fetchall()
            result = []
            for r in rows:
                d = dict(r)
                d["by_tool"] = json.loads(d.get("by_tool") or "{}")
                d["by_workload"] = json.loads(d.get("by_workload") or "{}")
                d["by_status"] = json.loads(d.get("by_status") or "{}")
                d["by_priority"] = json.loads(d.get("by_priority") or "{}")
                result.append(d)
            return result

    def get_latest_snapshot(self, tenant_name: str) -> Optional[dict]:
        """Get the most recent score snapshot."""
        snapshots = self.get_score_snapshots(tenant_name, limit=1)
        return snapshots[0] if snapshots else None

    # ── Action Dependencies ──

    def add_dependency(self, action_id: str, depends_on_id: str,
                       dependency_type: str = "requires", notes: str = "") -> dict:
        """Add a dependency: action_id depends on depends_on_id."""
        if action_id == depends_on_id:
            raise ValueError("An action cannot depend on itself")
        # Check for circular dependency
        if self._would_create_cycle(action_id, depends_on_id):
            raise ValueError("This dependency would create a circular reference")
        with self._conn() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO action_dependencies
                   (action_id, depends_on_id, dependency_type, notes, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (action_id, depends_on_id, dependency_type, notes,
                 datetime.utcnow().isoformat()),
            )
        return {"action_id": action_id, "depends_on_id": depends_on_id,
                "dependency_type": dependency_type}

    def remove_dependency(self, action_id: str, depends_on_id: str):
        with self._conn() as conn:
            conn.execute(
                "DELETE FROM action_dependencies WHERE action_id=? AND depends_on_id=?",
                (action_id, depends_on_id),
            )

    def get_dependencies(self, action_id: str) -> dict:
        """Get what an action depends on and what depends on it."""
        with self._conn() as conn:
            depends_on = conn.execute(
                """SELECT ad.*, a.title, a.status, a.priority
                   FROM action_dependencies ad
                   JOIN actions a ON ad.depends_on_id = a.id
                   WHERE ad.action_id=?""",
                (action_id,),
            ).fetchall()
            blocked_by_me = conn.execute(
                """SELECT ad.*, a.title, a.status, a.priority
                   FROM action_dependencies ad
                   JOIN actions a ON ad.action_id = a.id
                   WHERE ad.depends_on_id=?""",
                (action_id,),
            ).fetchall()
        return {
            "depends_on": [dict(r) for r in depends_on],
            "blocks": [dict(r) for r in blocked_by_me],
        }

    def get_dependency_graph(self, tenant_name: str) -> list[dict]:
        """Get all dependencies for a tenant as edges."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT ad.*, a1.title as action_title, a1.status as action_status,
                   a2.title as depends_on_title, a2.status as depends_on_status
                   FROM action_dependencies ad
                   JOIN actions a1 ON ad.action_id = a1.id
                   JOIN actions a2 ON ad.depends_on_id = a2.id
                   WHERE a1.tenant_name=?""",
                (tenant_name,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_blocked_actions(self, tenant_name: str) -> list[dict]:
        """Get actions that are blocked by incomplete dependencies."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT DISTINCT a.*, dep_a.id as blocking_id, dep_a.title as blocking_title
                   FROM actions a
                   JOIN action_dependencies ad ON a.id = ad.action_id
                   JOIN actions dep_a ON ad.depends_on_id = dep_a.id
                   WHERE a.tenant_name=?
                   AND a.status NOT IN ('Completed', 'Not Applicable')
                   AND dep_a.status NOT IN ('Completed', 'Risk Accepted')""",
                (tenant_name,),
            ).fetchall()
            return [self._row_to_action_dict(r) for r in rows]

    def _would_create_cycle(self, action_id: str, depends_on_id: str) -> bool:
        """Check if adding action_id -> depends_on_id creates a cycle."""
        visited = set()
        stack = [action_id]
        with self._conn() as conn:
            while stack:
                current = stack.pop()
                if current in visited:
                    continue
                visited.add(current)
                # Get everything that depends on 'current' (current blocks these)
                rows = conn.execute(
                    "SELECT action_id FROM action_dependencies WHERE depends_on_id=?",
                    (current,),
                ).fetchall()
                for r in rows:
                    if r["action_id"] == depends_on_id:
                        return True
                    stack.append(r["action_id"])
        return False

    def get_implementation_order(self, tenant_name: str, action_ids: list[str] = None) -> list[dict]:
        """Topological sort of actions respecting dependencies."""
        with self._conn() as conn:
            if action_ids:
                placeholders = ",".join("?" * len(action_ids))
                actions = conn.execute(
                    f"SELECT * FROM actions WHERE id IN ({placeholders})", action_ids
                ).fetchall()
                deps = conn.execute(
                    f"""SELECT * FROM action_dependencies
                        WHERE action_id IN ({placeholders})
                        AND depends_on_id IN ({placeholders})""",
                    action_ids + action_ids,
                ).fetchall()
            else:
                actions = conn.execute(
                    "SELECT * FROM actions WHERE tenant_name=? AND status NOT IN ('Completed','Not Applicable')",
                    (tenant_name,),
                ).fetchall()
                deps = conn.execute(
                    """SELECT ad.* FROM action_dependencies ad
                       JOIN actions a ON ad.action_id = a.id
                       WHERE a.tenant_name=?""",
                    (tenant_name,),
                ).fetchall()

        action_map = {dict(a)["id"]: self._row_to_action_dict(a) for a in actions}
        # Build adjacency: action_id -> [depends_on_id, ...]
        in_degree = {aid: 0 for aid in action_map}
        graph = {aid: [] for aid in action_map}
        for d in deps:
            d = dict(d)
            if d["action_id"] in action_map and d["depends_on_id"] in action_map:
                graph[d["depends_on_id"]].append(d["action_id"])
                in_degree[d["action_id"]] = in_degree.get(d["action_id"], 0) + 1

        # Kahn's algorithm
        queue = [aid for aid, deg in in_degree.items() if deg == 0]
        ordered = []
        while queue:
            queue.sort(key=lambda x: action_map[x].get("priority", "Medium"))
            node = queue.pop(0)
            action_map[node]["_order"] = len(ordered) + 1
            ordered.append(action_map[node])
            for neighbor in graph.get(node, []):
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        # Any remaining are in cycles
        for aid in action_map:
            if aid not in {a["id"] for a in ordered}:
                action_map[aid]["_order"] = len(ordered) + 1
                action_map[aid]["_cycle"] = True
                ordered.append(action_map[aid])

        return ordered

    # ── Compliance Mappings ──

    def add_compliance_mapping(self, action_id: str, framework: str,
                                control_id: str, control_name: str = "",
                                control_family: str = "", notes: str = "") -> dict:
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO compliance_mappings
                   (action_id, framework, control_id, control_name, control_family, notes)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (action_id, framework, control_id, control_name, control_family, notes),
            )
        return {"action_id": action_id, "framework": framework, "control_id": control_id,
                "control_name": control_name, "control_family": control_family}

    def get_action_compliance(self, action_id: str) -> list[dict]:
        """Return compliance mappings for an action, sourced from the global
        action's mappings (and falling back to legacy per-tenant rows for
        actions not yet linked to a global action)."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT global_action_id FROM actions WHERE id=?", (action_id,)
            ).fetchone()
            ga_id = row["global_action_id"] if row else None
            if ga_id:
                rows = conn.execute(
                    """SELECT framework, control_id, control_name, control_family, notes
                         FROM global_compliance_mappings
                        WHERE global_action_id=?
                        ORDER BY framework, control_id""",
                    (ga_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM compliance_mappings WHERE action_id=? ORDER BY framework, control_id",
                    (action_id,),
                ).fetchall()
            return [dict(r) for r in rows]

    def get_compliance_summary(self, tenant_name: str, framework: str = None) -> dict:
        """Compliance posture for a tenant. Mappings live on the global action;
        we join tenant actions back via global_action_id and restrict the
        framework set to whichever frameworks the tenant has subscribed to (if
        any are configured). Legacy per-tenant compliance_mappings rows are
        included for any action not yet linked to a global action."""
        with self._conn() as conn:
            subscribed = [r["framework"] for r in conn.execute(
                "SELECT framework FROM tenant_frameworks WHERE tenant_name=?",
                (tenant_name,),
            ).fetchall()]
            allowed_frameworks = set(subscribed)
            params_global = [tenant_name]
            params_legacy = [tenant_name]
            framework_clause_global = ""
            framework_clause_legacy = ""
            if framework:
                framework_clause_global = " AND gcm.framework=?"
                framework_clause_legacy = " AND cm.framework=?"
                params_global.append(framework)
                params_legacy.append(framework)
            global_rows = conn.execute(
                f"""SELECT gcm.framework, gcm.control_id, gcm.control_name, gcm.control_family,
                           a.id as action_id, a.title, a.status, a.priority
                      FROM global_compliance_mappings gcm
                      JOIN actions a ON a.global_action_id = gcm.global_action_id
                     WHERE a.tenant_name=?{framework_clause_global}
                     ORDER BY gcm.framework, gcm.control_family, gcm.control_id""",
                params_global,
            ).fetchall()
            legacy_rows = conn.execute(
                f"""SELECT cm.framework, cm.control_id, cm.control_name, cm.control_family,
                           a.id as action_id, a.title, a.status, a.priority
                      FROM compliance_mappings cm
                      JOIN actions a ON cm.action_id = a.id
                     WHERE a.tenant_name=? AND a.global_action_id IS NULL{framework_clause_legacy}
                     ORDER BY cm.framework, cm.control_family, cm.control_id""",
                params_legacy,
            ).fetchall()
            rows = list(global_rows) + list(legacy_rows)
            # If the tenant has explicitly subscribed to a set of frameworks,
            # only show those. If no subscription is configured, show all.
            if allowed_frameworks and not framework:
                rows = [r for r in rows if dict(r)["framework"] in allowed_frameworks]

        # Group by framework -> control_family -> control
        result = {}
        for r in rows:
            r = dict(r)
            fw = r["framework"]
            if fw not in result:
                result[fw] = {"total_controls": 0, "completed_controls": 0,
                              "percentage": 0, "families": {}}
            fam = r.get("control_family") or "Other"
            if fam not in result[fw]["families"]:
                result[fw]["families"][fam] = {"controls": {}}
            ctrl_id = r["control_id"]
            if ctrl_id not in result[fw]["families"][fam]["controls"]:
                result[fw]["families"][fam]["controls"][ctrl_id] = {
                    "control_name": r["control_name"],
                    "actions": [], "status": "ToDo",
                }
            result[fw]["families"][fam]["controls"][ctrl_id]["actions"].append({
                "action_id": r["action_id"], "title": r["title"],
                "status": r["status"], "priority": r["priority"],
            })

        # Compute rollup stats
        for fw, fw_data in result.items():
            total = 0
            completed = 0
            for fam, fam_data in fw_data["families"].items():
                fam_total = 0
                fam_completed = 0
                for ctrl_id, ctrl_data in fam_data["controls"].items():
                    total += 1
                    fam_total += 1
                    statuses = [a["status"] for a in ctrl_data["actions"]]
                    if all(s in ("Completed", "Risk Accepted") for s in statuses):
                        ctrl_data["status"] = "Completed"
                        completed += 1
                        fam_completed += 1
                    elif any(s in ("Completed", "In Progress", "Risk Accepted") for s in statuses):
                        ctrl_data["status"] = "In Progress"
                    else:
                        ctrl_data["status"] = "ToDo"
                fam_data["total"] = fam_total
                fam_data["completed"] = fam_completed
                fam_data["percentage"] = round((fam_completed / fam_total) * 100, 2) if fam_total > 0 else 0
            fw_data["total_controls"] = total
            fw_data["completed_controls"] = completed
            fw_data["percentage"] = round((completed / total) * 100, 2) if total > 0 else 0

        return result

    def bulk_add_compliance_mappings(self, mappings: list[dict]):
        """Add many compliance mappings at once."""
        if not mappings:
            return
        with self._conn() as conn:
            conn.executemany(
                """INSERT OR IGNORE INTO compliance_mappings
                   (action_id, framework, control_id, control_name, control_family, notes)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                [(m["action_id"], m["framework"], m["control_id"],
                  m.get("control_name", ""), m.get("control_family", ""),
                  m.get("notes", "")) for m in mappings],
            )

    def clear_compliance_mappings(self, tenant_name: str, framework: str = None):
        """Clear compliance mappings for a tenant (optionally for a specific framework)."""
        with self._conn() as conn:
            if framework:
                conn.execute(
                    """DELETE FROM compliance_mappings WHERE action_id IN
                       (SELECT id FROM actions WHERE tenant_name=?)
                       AND framework=?""",
                    (tenant_name, framework),
                )
            else:
                conn.execute(
                    """DELETE FROM compliance_mappings WHERE action_id IN
                       (SELECT id FROM actions WHERE tenant_name=?)""",
                    (tenant_name,),
                )

    # ── Risk Acceptance ──

    def accept_risk(self, action_id: str, justification: str, risk_owner: str,
                    review_date: str = None, expiry_date: str = None,
                    changed_by: str = "") -> Optional[dict]:
        """Record a risk acceptance decision on an action."""
        existing = self.get_action(action_id)
        if not existing:
            return None
        now = datetime.utcnow().isoformat()
        with self._conn() as conn:
            conn.execute(
                """UPDATE actions SET status='Risk Accepted',
                   risk_justification=?, risk_owner=?, risk_review_date=?,
                   risk_expiry_date=?, risk_accepted_at=?, updated_at=?
                   WHERE id=?""",
                (justification, risk_owner, review_date, expiry_date, now, now, action_id),
            )
            conn.execute(
                """INSERT INTO action_history (action_id, timestamp, old_status,
                   new_status, changed_by, notes)
                   VALUES (?, ?, ?, 'Risk Accepted', ?, ?)""",
                (action_id, now, existing["status"], changed_by,
                 f"Risk accepted. Owner: {risk_owner}. Expiry: {expiry_date or 'None'}"),
            )
        return self.get_action(action_id)

    def get_expired_risk_acceptances(self, tenant_name: str) -> list[dict]:
        """Find actions where risk acceptance has expired."""
        now = datetime.utcnow().isoformat()
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM actions WHERE tenant_name=?
                   AND status='Risk Accepted'
                   AND risk_expiry_date IS NOT NULL
                   AND risk_expiry_date != ''
                   AND risk_expiry_date <= ?""",
                (tenant_name, now),
            ).fetchall()
            return [self._row_to_action_dict(r, conn) for r in rows]

    def get_upcoming_risk_reviews(self, tenant_name: str, days: int = 30) -> list[dict]:
        """Find risk-accepted actions with upcoming review dates."""
        from datetime import timedelta
        cutoff = (datetime.utcnow() + timedelta(days=days)).isoformat()
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM actions WHERE tenant_name=?
                   AND status='Risk Accepted'
                   AND risk_review_date IS NOT NULL
                   AND risk_review_date != ''
                   AND risk_review_date <= ?""",
                (tenant_name, cutoff),
            ).fetchall()
            return [self._row_to_action_dict(r, conn) for r in rows]

    def expire_risk_acceptances(self, tenant_name: str) -> list[dict]:
        """Expire risk acceptances past their expiry date. Returns affected actions."""
        expired = self.get_expired_risk_acceptances(tenant_name)
        now = datetime.utcnow().isoformat()
        with self._conn() as conn:
            for action in expired:
                conn.execute(
                    "UPDATE actions SET status='ToDo', updated_at=? WHERE id=?",
                    (now, action["id"]),
                )
                conn.execute(
                    """INSERT INTO action_history (action_id, timestamp, old_status,
                       new_status, changed_by, notes) VALUES (?, ?, 'Risk Accepted', 'ToDo', 'system',
                       'Risk acceptance expired')""",
                    (action["id"], now),
                )
        return expired

    # ── Drift Detection ──

    def save_drift_report(self, tenant_name: str, source_tool: str,
                          previous_snapshot_id: int, current_snapshot_id: int,
                          score_before: float, score_after: float,
                          regressions: list, improvements: list,
                          new_findings: list, resolved_findings: list,
                          summary: str) -> dict:
        now = datetime.utcnow().isoformat()
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO drift_reports (tenant_name, timestamp, source_tool,
                   previous_snapshot_id, current_snapshot_id,
                   score_before, score_after, score_delta,
                   regressions, improvements, new_findings, resolved_findings, summary)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (tenant_name, now, source_tool,
                 previous_snapshot_id, current_snapshot_id,
                 score_before, score_after, round(score_after - score_before, 2),
                 json.dumps(regressions), json.dumps(improvements),
                 json.dumps(new_findings), json.dumps(resolved_findings), summary),
            )
        return {"timestamp": now, "score_delta": round(score_after - score_before, 2),
                "regressions": len(regressions), "improvements": len(improvements),
                "new_findings": len(new_findings), "resolved_findings": len(resolved_findings)}

    def get_drift_reports(self, tenant_name: str, limit: int = 20) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM drift_reports WHERE tenant_name=? ORDER BY timestamp DESC LIMIT ?",
                (tenant_name, limit),
            ).fetchall()
            result = []
            for r in rows:
                d = dict(r)
                d["regressions"] = json.loads(d.get("regressions") or "[]")
                d["improvements"] = json.loads(d.get("improvements") or "[]")
                d["new_findings"] = json.loads(d.get("new_findings") or "[]")
                d["resolved_findings"] = json.loads(d.get("resolved_findings") or "[]")
                result.append(d)
            return result

    # ── Action Links (cross-tool) ──

    def link_actions(self, source_id: str, target_id: str,
                     link_type: str = "related") -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO action_links
                   (source_action_id, target_action_id, link_type, created_at)
                   VALUES (?, ?, ?, ?)""",
                (source_id, target_id, link_type, datetime.utcnow().isoformat()),
            )

    def unlink_actions(self, source_id: str, target_id: str) -> None:
        with self._conn() as conn:
            conn.execute(
                """DELETE FROM action_links
                   WHERE (source_action_id=? AND target_action_id=?)
                      OR (source_action_id=? AND target_action_id=?)""",
                (source_id, target_id, target_id, source_id),
            )

    def get_linked_actions(self, action_id: str) -> list:
        """Get all actions linked to the given action (bidirectional)."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT a.*, al.link_type,
                     CASE WHEN al.source_action_id=? THEN 'outgoing' ELSE 'incoming' END as direction
                   FROM action_links al
                   JOIN actions a ON a.id = CASE WHEN al.source_action_id=?
                     THEN al.target_action_id ELSE al.source_action_id END
                   WHERE al.source_action_id=? OR al.target_action_id=?""",
                (action_id, action_id, action_id, action_id),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_action_peers(self, action_id: str) -> list[dict]:
        """Return tenant-scoped peer actions: other actions in the same tenant
        that are correlated with this one via either correlation_group_id or
        an explicit action_links row. Used to flag cross-tool peers whose
        status may need review when this action changes."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT tenant_name, status, correlation_group_id FROM actions WHERE id=?",
                (action_id,),
            ).fetchone()
            if not row:
                return []
            tenant_name = row["tenant_name"]
            cg_id = row["correlation_group_id"]
            self_status = row["status"]
            peers = {}
            if cg_id:
                for r in conn.execute(
                    """SELECT id, title, source_tool, status, workload
                         FROM actions
                        WHERE tenant_name=? AND correlation_group_id=? AND id<>?""",
                    (tenant_name, cg_id, action_id),
                ).fetchall():
                    peers[r["id"]] = dict(r) | {"link_via": "correlation_group"}
            for r in conn.execute(
                """SELECT a.id, a.title, a.source_tool, a.status, a.workload
                     FROM action_links al
                     JOIN actions a ON a.id = CASE WHEN al.source_action_id=?
                          THEN al.target_action_id ELSE al.source_action_id END
                    WHERE (al.source_action_id=? OR al.target_action_id=?)
                      AND a.tenant_name=? AND a.id<>?""",
                (action_id, action_id, action_id, tenant_name, action_id),
            ).fetchall():
                if r["id"] not in peers:
                    peers[r["id"]] = dict(r) | {"link_via": "action_link"}
            for p in peers.values():
                p["status_differs"] = p.get("status") != self_status
            return list(peers.values())

    def get_peer_disagreements_for_tenant(self, tenant_name: str) -> dict:
        """Return {action_id: peer_count_with_different_status} so the actions
        list can render a "*" badge without one query per row."""
        with self._conn() as conn:
            cg_rows = conn.execute(
                """SELECT a1.id as a_id, a1.status as a_status,
                          a2.id as p_id, a2.status as p_status
                     FROM actions a1
                     JOIN actions a2
                       ON a2.tenant_name=a1.tenant_name
                      AND a2.correlation_group_id=a1.correlation_group_id
                      AND a2.id<>a1.id
                    WHERE a1.tenant_name=? AND a1.correlation_group_id IS NOT NULL""",
                (tenant_name,),
            ).fetchall()
            link_rows = conn.execute(
                """SELECT a1.id as a_id, a1.status as a_status,
                          a2.id as p_id, a2.status as p_status
                     FROM action_links al
                     JOIN actions a1 ON a1.id = al.source_action_id
                     JOIN actions a2 ON a2.id = al.target_action_id
                    WHERE a1.tenant_name=? AND a2.tenant_name=?
                    UNION
                   SELECT a2.id as a_id, a2.status as a_status,
                          a1.id as p_id, a1.status as p_status
                     FROM action_links al
                     JOIN actions a1 ON a1.id = al.source_action_id
                     JOIN actions a2 ON a2.id = al.target_action_id
                    WHERE a1.tenant_name=? AND a2.tenant_name=?""",
                (tenant_name, tenant_name, tenant_name, tenant_name),
            ).fetchall()
        seen = set()
        result: dict = {}
        for row in list(cg_rows) + list(link_rows):
            key = (row["a_id"], row["p_id"])
            if key in seen:
                continue
            seen.add(key)
            if row["a_status"] != row["p_status"]:
                result[row["a_id"]] = result.get(row["a_id"], 0) + 1
        return result

    # ── Scoring helpers ──

    def get_scores(self, tenant_name: str, exclude_na: bool = False) -> dict:
        """Calculate live scores from action data.

        Uses authoritative Graph API overall scores when available (stored
        by store_graph_scores). Falls back to summing per-action scores.
        Per-workload/tool breakdowns always use per-action data.

        If exclude_na is True, actions with status 'Not Applicable' or
        'Risk Accepted' are excluded from scoring (they don't count toward
        totals or percentages).
        """
        actions = self.get_actions(tenant_name)
        if not actions:
            return {"percentage": 0, "total_actions": 0, "completed_actions": 0,
                    "by_tool": {}, "by_workload": {}, "by_status": {}, "by_priority": {},
                    "excluded_count": 0}

        excluded_statuses = set()
        if exclude_na:
            excluded_statuses = {ActionStatus.NOT_APPLICABLE.value, ActionStatus.RISK_ACCEPTED.value}

        scored_actions = [a for a in actions if a["status"] not in excluded_statuses] if excluded_statuses else actions
        excluded_count = len(actions) - len(scored_actions)

        # Sum per-action scores
        action_total_score = sum(a.get("score") or 0 for a in scored_actions)
        action_total_max = sum(a.get("max_score") or 0 for a in scored_actions)
        completed = sum(1 for a in scored_actions if a["status"] == ActionStatus.COMPLETED.value)

        # Check for authoritative Graph API scores (used for Secure Score tool breakdown only)
        with self._conn() as conn:
            row = conn.execute(
                "SELECT graph_current_score, graph_max_score, graph_score_date FROM tenants WHERE name=?",
                (tenant_name,)
            ).fetchone()

        graph_score = None
        graph_max = None
        if row:
            graph_score = row["graph_current_score"] if "graph_current_score" in row.keys() else None
            graph_max = row["graph_max_score"] if "graph_max_score" in row.keys() else None

        # Overall score always combines ALL sources.
        # Graph API scores adjust the Secure Score tool's contribution but don't replace the total.
        total_score = action_total_score
        total_max = action_total_max

        by_tool = {}
        by_workload = {}
        by_status = {}
        by_priority = {}

        for a in scored_actions:
            tool = a["source_tool"]
            wl = a["workload"]
            st = a["status"]
            pr = a["priority"]

            for group, key in [(by_tool, tool), (by_workload, wl)]:
                if key not in group:
                    group[key] = {"score": 0, "max_score": 0, "total": 0, "completed": 0}
                group[key]["score"] += a.get("score") or 0
                group[key]["max_score"] += a.get("max_score") or 0
                group[key]["total"] += 1
                if a["status"] == ActionStatus.COMPLETED.value:
                    group[key]["completed"] += 1

            by_status[st] = by_status.get(st, 0) + 1
            by_priority[pr] = by_priority.get(pr, 0) + 1

        # Use Graph API authoritative scores for Secure Score tool breakdown only
        if graph_max and graph_max > 0:
            ss_key = "Microsoft Secure Score"
            if ss_key in by_tool:
                # Replace action-summed scores with Graph API authoritative scores
                ss_old_score = by_tool[ss_key]["score"]
                ss_old_max = by_tool[ss_key]["max_score"]
                by_tool[ss_key]["score"] = graph_score or 0
                by_tool[ss_key]["max_score"] = graph_max
                # Adjust overall totals to reflect Graph API correction for Secure Score
                total_score = total_score - ss_old_score + (graph_score or 0)
                total_max = total_max - ss_old_max + graph_max

        for group in [by_tool, by_workload]:
            for data in group.values():
                m = data["max_score"]
                data["percentage"] = round((data["score"] / m) * 100, 2) if m > 0 else 0

        return {
            "total_score": round(total_score, 2),
            "total_max": round(total_max, 2),
            "percentage": round((total_score / total_max) * 100, 2) if total_max > 0 else 0,
            "total_actions": len(scored_actions),
            "completed_actions": completed,
            "by_tool": by_tool,
            "by_workload": by_workload,
            "by_status": by_status,
            "by_priority": by_priority,
            "excluded_count": excluded_count,
            "exclude_na": exclude_na,
        }

    # ── Global Actions (Control Plane) ──

    def _row_to_global_action(self, row) -> dict:
        d = dict(row)
        d["tags"] = json.loads(d.get("tags") or "[]")
        return d

    def list_global_actions(self, source_tool: str = None, workload: str = None,
                             review_status: str = None, search: str = None) -> list[dict]:
        sql = "SELECT * FROM global_actions WHERE 1=1"
        params = []
        if source_tool:
            sql += " AND source_tool=?"
            params.append(source_tool)
        if workload:
            sql += " AND workload=?"
            params.append(workload)
        if review_status:
            sql += " AND review_status=?"
            params.append(review_status)
        if search:
            sql += " AND (title LIKE ? OR description LIKE ? OR source_id LIKE ?)"
            params += [f"%{search}%", f"%{search}%", f"%{search}%"]
        sql += " ORDER BY source_tool, workload, title"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row_to_global_action(r) for r in rows]

    def get_global_action(self, ga_id: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM global_actions WHERE id=?", (ga_id,)).fetchone()
        return self._row_to_global_action(row) if row else None

    def get_global_action_by_source(self, source_tool: str, source_id: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM global_actions WHERE source_tool=? AND source_id=?",
                (source_tool, source_id),
            ).fetchone()
        return self._row_to_global_action(row) if row else None

    def create_global_action(self, ga: GlobalAction) -> dict:
        now = datetime.utcnow().isoformat()
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO global_actions
                   (id, source_tool, source_id, title, description, workload, category, subcategory,
                    priority, risk_level, user_impact, implementation_effort, required_licence,
                    score, max_score, essential_eight_control, essential_eight_maturity,
                    implementation_steps, risk_explanation, additional_info, reference_url,
                    tags, review_status, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (ga.id, ga.source_tool, ga.source_id, ga.title, ga.description,
                 ga.workload, ga.category, ga.subcategory, ga.priority, ga.risk_level,
                 ga.user_impact, ga.implementation_effort, ga.required_licence,
                 ga.score, ga.max_score, ga.essential_eight_control, ga.essential_eight_maturity,
                 ga.implementation_steps, ga.risk_explanation, ga.additional_info,
                 ga.reference_url, json.dumps(ga.tags), ga.review_status, now, now),
            )
        return self.get_global_action(ga.id)

    def update_global_action(self, ga_id: str, **kwargs) -> dict | None:
        allowed = {
            "title", "description", "workload", "category", "subcategory", "priority",
            "risk_level", "user_impact", "implementation_effort", "required_licence",
            "score", "max_score", "essential_eight_control", "essential_eight_maturity",
            "implementation_steps", "risk_explanation", "additional_info", "reference_url",
            "tags", "review_status",
        }
        updates = {}
        for k, v in kwargs.items():
            if k in allowed:
                updates[k] = json.dumps(v) if k == "tags" else v
        if updates:
            updates["updated_at"] = datetime.utcnow().isoformat()
            sets = ", ".join(f"{k}=?" for k in updates)
            vals = list(updates.values()) + [ga_id]
            with self._conn() as conn:
                conn.execute(f"UPDATE global_actions SET {sets} WHERE id=?", vals)
                # Propagate enrichment fields to linked tenant actions (only overwrite if tenant field is empty)
                enrichment_fields = [
                    ("remediation_steps", kwargs.get("implementation_steps") or kwargs.get("remediation_steps")),
                    ("risk_level", kwargs.get("risk_level")),
                ]
                for col, val in enrichment_fields:
                    if val:
                        conn.execute(
                            f"UPDATE actions SET {col}=? WHERE global_action_id=? AND ({col} IS NULL OR {col}='')",
                            (val, ga_id)
                        )
        return self.get_global_action(ga_id)

    def delete_global_action(self, ga_id: str):
        with self._conn() as conn:
            conn.execute("DELETE FROM global_actions WHERE id=?", (ga_id,))

    # ── Per-tenant implementation overrides ──

    def get_implementation_override(self, tenant_name: str, global_action_id: str) -> Optional[dict]:
        with self._conn() as conn:
            row = conn.execute(
                """SELECT * FROM action_implementation_overrides
                    WHERE tenant_name=? AND global_action_id=?""",
                (tenant_name, global_action_id),
            ).fetchone()
            return dict(row) if row else None

    def set_implementation_override(self, tenant_name: str, global_action_id: str,
                                    implementation_steps: str, updated_by: str = "") -> dict:
        now = datetime.utcnow().isoformat()
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO action_implementation_overrides
                    (tenant_name, global_action_id, implementation_steps, updated_by, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(tenant_name, global_action_id) DO UPDATE SET
                        implementation_steps=excluded.implementation_steps,
                        updated_by=excluded.updated_by,
                        updated_at=excluded.updated_at""",
                (tenant_name, global_action_id, implementation_steps or "",
                 updated_by or "", now),
            )
        return {
            "tenant_name": tenant_name,
            "global_action_id": global_action_id,
            "implementation_steps": implementation_steps or "",
            "updated_by": updated_by or "",
            "updated_at": now,
        }

    def clear_implementation_override(self, tenant_name: str, global_action_id: str) -> bool:
        with self._conn() as conn:
            cur = conn.execute(
                """DELETE FROM action_implementation_overrides
                    WHERE tenant_name=? AND global_action_id=?""",
                (tenant_name, global_action_id),
            )
            return cur.rowcount > 0

    def link_action_to_global(self, action_id: str, global_action_id: str):
        with self._conn() as conn:
            conn.execute(
                "UPDATE actions SET global_action_id=? WHERE id=?",
                (global_action_id, action_id),
            )

    def migrate_actions_to_global(self) -> dict:
        """Populate global_actions from all distinct source_tool+source_id combos across tenants."""
        created = 0
        linked = 0
        with self._conn() as conn:
            # Get all distinct (source_tool, source_id) combinations — pick latest row
            rows = conn.execute("""
                SELECT a.source_tool, a.source_id, a.title, a.description, a.workload,
                       a.category, a.subcategory, a.priority, a.risk_level, a.user_impact,
                       a.implementation_effort, a.required_licence, a.score, a.max_score,
                       a.essential_eight_control, a.essential_eight_maturity,
                       a.remediation_steps, a.reference_url, a.tags
                FROM actions a
                INNER JOIN (
                    SELECT source_tool, source_id, MAX(updated_at) as max_updated
                    FROM actions
                    WHERE source_id != '' AND source_id IS NOT NULL
                      AND NOT EXISTS (
                        SELECT 1 FROM global_action_source_aliases gas
                        WHERE gas.source_tool = actions.source_tool AND gas.source_id = actions.source_id
                      )
                      AND NOT EXISTS (
                        SELECT 1 FROM global_actions ga
                        WHERE ga.source_tool = actions.source_tool AND ga.source_id = actions.source_id
                      )
                    GROUP BY source_tool, source_id
                ) latest ON a.source_tool = latest.source_tool
                       AND a.source_id = latest.source_id
                       AND a.updated_at = latest.max_updated
            """).fetchall()

            now = datetime.utcnow().isoformat()
            for row in rows:
                d = dict(row)
                # Check if global action already exists for this source
                existing = conn.execute(
                    "SELECT id FROM global_actions WHERE source_tool=? AND source_id=?",
                    (d["source_tool"], d["source_id"]),
                ).fetchone()

                if existing:
                    ga_id = existing["id"]
                else:
                    ga_id = _generate_id()
                    conn.execute(
                        """INSERT OR IGNORE INTO global_actions
                           (id, source_tool, source_id, title, description, workload, category,
                            subcategory, priority, risk_level, user_impact, implementation_effort,
                            required_licence, score, max_score, essential_eight_control,
                            essential_eight_maturity, implementation_steps, risk_explanation,
                            additional_info, reference_url, tags, review_status, created_at, updated_at)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (ga_id, d["source_tool"], d["source_id"], d["title"], d["description"],
                         d["workload"], d.get("category", ""), d.get("subcategory", ""),
                         d.get("priority", "Medium"), d.get("risk_level", "Medium"),
                         d.get("user_impact", "Low"), d.get("implementation_effort", "Medium"),
                         d.get("required_licence", ""), d.get("score"), d.get("max_score"),
                         d.get("essential_eight_control"), d.get("essential_eight_maturity"),
                         d.get("remediation_steps", ""), "", "", d.get("reference_url", ""),
                         d.get("tags", "[]"), "To Review", now, now),
                    )
                    created += 1

                # Link all matching tenant actions to this global action
                result = conn.execute(
                    """UPDATE actions SET global_action_id=?
                       WHERE source_tool=? AND source_id=? AND global_action_id IS NULL""",
                    (ga_id, d["source_tool"], d["source_id"]),
                )
                linked += result.rowcount

        return {"global_actions_created": created, "tenant_actions_linked": linked}

    # ── Global Compliance Mappings ──

    def get_global_compliance_mappings(self, global_action_id: str) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM global_compliance_mappings WHERE global_action_id=? ORDER BY framework, control_id",
                (global_action_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def add_global_compliance_mapping(self, global_action_id: str, framework: str,
                                       control_id: str, control_name: str = "",
                                       control_family: str = "", notes: str = "") -> dict:
        with self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO global_compliance_mappings
                   (global_action_id, framework, control_id, control_name, control_family, notes)
                   VALUES (?,?,?,?,?,?)""",
                (global_action_id, framework, control_id, control_name, control_family, notes),
            )
            row = conn.execute(
                "SELECT * FROM global_compliance_mappings WHERE global_action_id=? AND framework=? AND control_id=?",
                (global_action_id, framework, control_id),
            ).fetchone()
        return dict(row)

    def remove_global_compliance_mapping(self, mapping_id: int):
        with self._conn() as conn:
            conn.execute("DELETE FROM global_compliance_mappings WHERE id=?", (mapping_id,))

    def get_global_compliance_summary(self) -> dict:
        """Return count of global actions mapped per framework."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT framework, COUNT(DISTINCT global_action_id) as mapped_count
                   FROM global_compliance_mappings GROUP BY framework"""
            ).fetchall()
            total = conn.execute("SELECT COUNT(*) as c FROM global_actions").fetchone()["c"]
        result = {r["framework"]: r["mapped_count"] for r in rows}
        result["_total_actions"] = total
        return result

    # ── Users ──

    def _row_to_user(self, row, include_hash: bool = False) -> dict:
        d = dict(row)
        if not include_hash:
            d.pop("password_hash", None)
        d["is_active"] = bool(d.get("is_active", 1))
        d["must_change_password"] = bool(d.get("must_change_password", 0))
        return d

    def list_users(self) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM users ORDER BY username").fetchall()
        return [self._row_to_user(r) for r in rows]

    def get_user(self, user_id: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        return self._row_to_user(row) if row else None

    def get_user_by_username(self, username: str, include_hash: bool = False) -> dict | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return self._row_to_user(row, include_hash=include_hash) if row else None

    def authenticate_user(self, username: str, password: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username=? AND is_active=1", (username,)
            ).fetchone()
        if not row:
            return None
        user = dict(row)
        if not _verify_password(password, user.get("password_hash", "")):
            return None
        # Update last_login
        now = datetime.utcnow().isoformat()
        with self._conn() as conn:
            conn.execute("UPDATE users SET last_login=? WHERE id=?", (now, user["id"]))
        return self._row_to_user(row)

    def create_user(self, username: str, password: str, display_name: str = "",
                    email: str = "", role: str = "viewer") -> dict:
        uid = _generate_id()
        now = datetime.utcnow().isoformat()
        pw_hash = _hash_password(password)
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO users (id, username, password_hash, display_name, email, role,
                   is_active, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (uid, username, pw_hash, display_name, email, role, 1, now, now),
            )
        return self.get_user(uid)

    def update_user(self, user_id: str, **kwargs) -> dict | None:
        allowed = {"display_name", "email", "role", "is_active", "must_change_password"}
        updates = {}
        for k, v in kwargs.items():
            if k in allowed:
                updates[k] = v
        if "password" in kwargs:
            updates["password_hash"] = _hash_password(kwargs["password"])
            # Clear must-change flag when password is successfully changed
            updates["must_change_password"] = 0
        if updates:
            updates["updated_at"] = datetime.utcnow().isoformat()
            sets = ", ".join(f"{k}=?" for k in updates)
            vals = list(updates.values()) + [user_id]
            with self._conn() as conn:
                conn.execute(f"UPDATE users SET {sets} WHERE id=?", vals)
        return self.get_user(user_id)

    def delete_user(self, user_id: str):
        with self._conn() as conn:
            conn.execute("DELETE FROM users WHERE id=?", (user_id,))

    # ── User Tenant Access ──

    def get_user_tenant_access(self, user_id: str) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM user_tenant_access WHERE user_id=?", (user_id,)
            ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["workloads"] = json.loads(d.get("workloads") or "[]")
            result.append(d)
        return result

    def set_user_tenant_access(self, user_id: str, tenant_name: str, workloads: list[str] = None):
        with self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO user_tenant_access (user_id, tenant_name, workloads)
                   VALUES (?,?,?)""",
                (user_id, tenant_name, json.dumps(workloads or [])),
            )

    def remove_user_tenant_access(self, user_id: str, tenant_name: str):
        with self._conn() as conn:
            conn.execute(
                "DELETE FROM user_tenant_access WHERE user_id=? AND tenant_name=?",
                (user_id, tenant_name),
            )

    # ── Tenant Frameworks ──

    def get_tenant_frameworks(self, tenant_name: str) -> list[str]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT framework FROM tenant_frameworks WHERE tenant_name=? ORDER BY framework",
                (tenant_name,),
            ).fetchall()
        return [r["framework"] for r in rows]

    def set_tenant_framework(self, tenant_name: str, framework: str):
        with self._conn() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO tenant_frameworks (tenant_name, framework) VALUES (?,?)",
                (tenant_name, framework),
            )

    def remove_tenant_framework(self, tenant_name: str, framework: str):
        with self._conn() as conn:
            conn.execute(
                "DELETE FROM tenant_frameworks WHERE tenant_name=? AND framework=?",
                (tenant_name, framework),
            )

    def set_tenant_frameworks(self, tenant_name: str, frameworks: list[str]):
        with self._conn() as conn:
            conn.execute("DELETE FROM tenant_frameworks WHERE tenant_name=?", (tenant_name,))
            for fw in frameworks:
                conn.execute(
                    "INSERT OR IGNORE INTO tenant_frameworks (tenant_name, framework) VALUES (?,?)",
                    (tenant_name, fw),
                )

    def get_all_tenant_frameworks(self) -> dict:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT tenant_name, framework FROM tenant_frameworks ORDER BY tenant_name, framework"
            ).fetchall()
        result: dict = {}
        for r in rows:
            result.setdefault(r["tenant_name"], []).append(r["framework"])
        return result

    # ── Global Action Links (equivalences) ──

    def get_global_action_links(self, ga_id: str) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT gal.id as link_id, ga.id, ga.title, ga.source_tool, ga.workload,
                          ga.review_status, gal.notes
                   FROM global_action_links gal
                   JOIN global_actions ga ON (
                     CASE WHEN gal.action_a_id=? THEN gal.action_b_id ELSE gal.action_a_id END = ga.id
                   )
                   WHERE gal.action_a_id=? OR gal.action_b_id=?""",
                (ga_id, ga_id, ga_id),
            ).fetchall()
        return [dict(r) for r in rows]

    def add_global_action_link(self, action_a_id: str, action_b_id: str, notes: str = "") -> dict:
        now = datetime.utcnow().isoformat()
        # Insert both directions for easy querying
        with self._conn() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO global_action_links (action_a_id, action_b_id, notes, created_at) VALUES (?,?,?,?)",
                (action_a_id, action_b_id, notes, now),
            )
            row = conn.execute(
                "SELECT * FROM global_action_links WHERE action_a_id=? AND action_b_id=?",
                (action_a_id, action_b_id),
            ).fetchone()
        return dict(row) if row else {}

    def remove_global_action_link(self, link_id: int):
        with self._conn() as conn:
            conn.execute("DELETE FROM global_action_links WHERE id=?", (link_id,))

    # ── Global Action Source Aliases ──

    def get_source_aliases(self, ga_id: str) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM global_action_source_aliases WHERE global_action_id=?", (ga_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    def add_source_alias(self, ga_id: str, source_tool: str, source_id: str):
        with self._conn() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO global_action_source_aliases (global_action_id, source_tool, source_id) VALUES (?,?,?)",
                (ga_id, source_tool, source_id),
            )

    # ── Merge Global Actions ──

    def merge_global_actions(self, keep_id: str, merge_ids: list[str]) -> dict:
        """Merge merge_ids into keep_id. Returns stats."""
        relinked = 0
        mappings_merged = 0
        now = datetime.utcnow().isoformat()
        with self._conn() as conn:
            for mid in merge_ids:
                src = conn.execute("SELECT * FROM global_actions WHERE id=?", (mid,)).fetchone()
                if not src:
                    continue
                src = dict(src)
                # Re-link all tenant actions
                r = conn.execute(
                    "UPDATE actions SET global_action_id=? WHERE global_action_id=?",
                    (keep_id, mid),
                )
                relinked += r.rowcount
                # Merge compliance mappings (ignore duplicates)
                cmaps = conn.execute(
                    "SELECT * FROM global_compliance_mappings WHERE global_action_id=?", (mid,)
                ).fetchall()
                for cm in cmaps:
                    conn.execute(
                        """INSERT OR IGNORE INTO global_compliance_mappings
                           (global_action_id, framework, control_id, control_name, control_family, notes)
                           VALUES (?,?,?,?,?,?)""",
                        (keep_id, cm["framework"], cm["control_id"],
                         cm["control_name"], cm["control_family"], cm["notes"]),
                    )
                    mappings_merged += 1
                # Migrate equivalence links — delete any that would become duplicates first
                conn.execute(
                    "DELETE FROM global_action_links WHERE (action_a_id=? AND action_b_id=?) OR (action_a_id=? AND action_b_id=?)",
                    (keep_id, mid, mid, keep_id),
                )
                conn.execute(
                    "UPDATE OR IGNORE global_action_links SET action_a_id=? WHERE action_a_id=?",
                    (keep_id, mid),
                )
                conn.execute(
                    "UPDATE OR IGNORE global_action_links SET action_b_id=? WHERE action_b_id=?",
                    (keep_id, mid),
                )
                # Remove self-links created by the above
                conn.execute(
                    "DELETE FROM global_action_links WHERE action_a_id=action_b_id"
                )
                # Add source alias so future imports of this source_id still match
                if src.get("source_id"):
                    conn.execute(
                        "INSERT OR IGNORE INTO global_action_source_aliases (global_action_id, source_tool, source_id) VALUES (?,?,?)",
                        (keep_id, src["source_tool"], src["source_id"]),
                    )
                # Re-link existing aliases
                conn.execute(
                    "UPDATE global_action_source_aliases SET global_action_id=? WHERE global_action_id=?",
                    (keep_id, mid),
                )
                # Delete merged action
                conn.execute("DELETE FROM global_actions WHERE id=?", (mid,))
            conn.execute("UPDATE global_actions SET updated_at=? WHERE id=?", (now, keep_id))
        return {"kept_id": keep_id, "tenant_actions_relinked": relinked, "mappings_merged": mappings_merged}

    # ── Updated find_global_action_for_import (checks aliases) ──

    def find_global_action_for_import(self, source_tool: str, source_id: str,
                                       title: str = "") -> dict | None:
        with self._conn() as conn:
            if source_id:
                # Check primary source_id
                row = conn.execute(
                    "SELECT * FROM global_actions WHERE source_tool=? AND source_id=?",
                    (source_tool, source_id),
                ).fetchone()
                if row:
                    return self._row_to_global_action(row)
                # Check aliases (created by merges)
                alias = conn.execute(
                    """SELECT ga.* FROM global_action_source_aliases sa
                       JOIN global_actions ga ON ga.id=sa.global_action_id
                       WHERE sa.source_tool=? AND sa.source_id=?""",
                    (source_tool, source_id),
                ).fetchone()
                if alias:
                    return self._row_to_global_action(alias)
            if title:
                row = conn.execute(
                    "SELECT * FROM global_actions WHERE source_tool=? AND title=?",
                    (source_tool, title),
                ).fetchone()
                if row:
                    return self._row_to_global_action(row)
                # Broader case-insensitive match across any source_tool (covers merged GAs
                # that kept a canonical title from another tool).
                row = conn.execute(
                    "SELECT * FROM global_actions WHERE LOWER(title)=LOWER(?)",
                    (title,),
                ).fetchone()
                if row:
                    return self._row_to_global_action(row)
        return None

    # ── Correlation groups (control plane CRUD) ──

    def list_correlation_groups(self) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT cg.*, COUNT(a.id) as action_count FROM correlation_groups cg"
                " LEFT JOIN actions a ON a.correlation_group_id=cg.id"
                " GROUP BY cg.id ORDER BY cg.canonical_name"
            ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["keywords"] = json.loads(d.get("keywords") or "[]")
            result.append(d)
        return result

    def create_correlation_group(self, canonical_name: str, description: str = "",
                                  keywords: list[str] = None) -> dict:
        gid = _generate_id()
        now = datetime.utcnow().isoformat()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO correlation_groups (id, canonical_name, description, keywords, created_at) VALUES (?,?,?,?,?)",
                (gid, canonical_name, description, json.dumps(keywords or []), now),
            )
        return self.get_correlation_group(gid)

    def get_correlation_group(self, group_id: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM correlation_groups WHERE id=?", (group_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["keywords"] = json.loads(d.get("keywords") or "[]")
        return d

    def update_correlation_group(self, group_id: str, **kwargs) -> dict | None:
        allowed = {"canonical_name", "description", "keywords"}
        updates = {}
        for k, v in kwargs.items():
            if k in allowed:
                updates[k] = json.dumps(v) if k == "keywords" else v
        if updates:
            sets = ", ".join(f"{k}=?" for k in updates)
            vals = list(updates.values()) + [group_id]
            with self._conn() as conn:
                conn.execute(f"UPDATE correlation_groups SET {sets} WHERE id=?", vals)
        return self.get_correlation_group(group_id)

    def delete_correlation_group(self, group_id: str):
        with self._conn() as conn:
            conn.execute("UPDATE actions SET correlation_group_id=NULL WHERE correlation_group_id=?", (group_id,))
            conn.execute("DELETE FROM correlation_groups WHERE id=?", (group_id,))

    # ── Create global action from a single tenant action ──

    def create_global_action_from_tenant_action(self, action_id: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
        if not row:
            return None
        a = dict(row)
        # Check if a global action already exists for this source
        existing = self.find_global_action_for_import(a["source_tool"], a["source_id"], a["title"])
        if existing:
            self.link_action_to_global(action_id, existing["id"])
            return existing
        ga = GlobalAction(
            source_tool=a["source_tool"],
            source_id=a.get("source_id", ""),
            title=a["title"],
            description=a.get("description", ""),
            workload=a.get("workload", "General"),
            category=a.get("category", ""),
            subcategory=a.get("subcategory", ""),
            priority=a.get("priority", "Medium"),
            risk_level=a.get("risk_level", "Medium"),
            user_impact=a.get("user_impact", "Low"),
            implementation_effort=a.get("implementation_effort", "Medium"),
            required_licence=a.get("required_licence", ""),
            score=a.get("score"),
            max_score=a.get("max_score"),
            essential_eight_control=a.get("essential_eight_control"),
            essential_eight_maturity=a.get("essential_eight_maturity"),
            implementation_steps=a.get("remediation_steps", ""),
            reference_url=a.get("reference_url", ""),
            tags=json.loads(a.get("tags") or "[]"),
            review_status="To Review",
        )
        result = self.create_global_action(ga)
        self.link_action_to_global(action_id, result["id"])
        return result

    def audit(self, action: str, actor: str = None, entity_type: str = None,
              entity_id: str = None, detail: str = None):
        """Append an immutable audit record."""
        from datetime import datetime
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO audit_log(timestamp, actor, action, entity_type, entity_id, detail) VALUES(?,?,?,?,?,?)",
                (datetime.utcnow().isoformat(), actor, action, entity_type, entity_id, detail),
            )

    def get_audit_log(self, entity_type: str = None, entity_id: str = None,
                      limit: int = 100, offset: int = 0) -> list[dict]:
        """Fetch audit records, optionally filtered by entity."""
        with self._conn() as conn:
            if entity_type and entity_id:
                rows = conn.execute(
                    "SELECT * FROM audit_log WHERE entity_type=? AND entity_id=? ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                    (entity_type, entity_id, limit, offset),
                ).fetchall()
            elif entity_type:
                rows = conn.execute(
                    "SELECT * FROM audit_log WHERE entity_type=? ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                    (entity_type, limit, offset),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
            return [dict(r) for r in rows]

    def bulk_auto_link_imported(self, action_ids: list[str]) -> dict:
        """Auto-link a batch of freshly imported tenant actions to global actions
        in a single transaction. Avoids N+1 connection churn.

        Returns: {"linked": N, "already_linked": N, "unlinked": [action_dicts]}
        """
        if not action_ids:
            return {"linked": 0, "already_linked": 0, "unlinked": []}

        linked = 0
        already_linked = 0
        unlinked = []

        placeholders = ",".join("?" * len(action_ids))
        with self._conn() as conn:
            rows = conn.execute(
                f"SELECT * FROM actions WHERE id IN ({placeholders})",
                action_ids,
            ).fetchall()
            for r in rows:
                a = dict(r)
                aid = a["id"]

                if a.get("global_action_id"):
                    ga_row = conn.execute(
                        "SELECT * FROM global_actions WHERE id=?", (a["global_action_id"],)
                    ).fetchone()
                    if ga_row and ga_row["implementation_steps"] and not a.get("remediation_steps"):
                        conn.execute(
                            "UPDATE actions SET remediation_steps=? WHERE id=?",
                            (ga_row["implementation_steps"], aid),
                        )
                    already_linked += 1
                    continue

                ga = None
                src_tool = a.get("source_tool", "")
                src_id = a.get("source_id", "") or ""
                title = a.get("title", "") or ""

                if src_id:
                    ga = conn.execute(
                        "SELECT * FROM global_actions WHERE source_tool=? AND source_id=?",
                        (src_tool, src_id),
                    ).fetchone()
                    if not ga:
                        ga = conn.execute(
                            """SELECT ga.* FROM global_action_source_aliases sa
                               JOIN global_actions ga ON ga.id=sa.global_action_id
                               WHERE sa.source_tool=? AND sa.source_id=?""",
                            (src_tool, src_id),
                        ).fetchone()
                if not ga and title:
                    ga = conn.execute(
                        "SELECT * FROM global_actions WHERE source_tool=? AND title=?",
                        (src_tool, title),
                    ).fetchone()
                    if not ga:
                        ga = conn.execute(
                            "SELECT * FROM global_actions WHERE LOWER(title)=LOWER(?)",
                            (title,),
                        ).fetchone()

                if ga:
                    conn.execute(
                        "UPDATE actions SET global_action_id=? WHERE id=?",
                        (ga["id"], aid),
                    )
                    if ga["implementation_steps"] and not a.get("remediation_steps"):
                        conn.execute(
                            "UPDATE actions SET remediation_steps=? WHERE id=?",
                            (ga["implementation_steps"], aid),
                        )
                    linked += 1
                else:
                    unlinked.append({
                        "id": aid, "title": a.get("title", ""),
                        "source_tool": src_tool, "source_id": src_id,
                        "status": a.get("status", ""),
                    })

        return {"linked": linked, "already_linked": already_linked, "unlinked": unlinked}
