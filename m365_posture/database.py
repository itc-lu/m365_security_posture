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

from .models import Action, TenantConfig, ActionStatus, ComplianceFramework, SecureScoreControl, SourceTool, Workload

DEFAULT_DB_PATH = Path(__file__).parent.parent / "data" / "m365_posture.db"


def _generate_id() -> str:
    return str(uuid.uuid4())[:8]


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
        else:
            d["history"] = []
        return d

    def get_actions(self, tenant_name: str, filters: dict = None) -> list[dict]:
        filters = filters or {}
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

            # Track score changes
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
            }
            updates = {}
            for k, v in data.items():
                if k in allowed:
                    updates[k] = v
            if "tags" in data:
                updates["tags"] = json.dumps(data["tags"])
            if "raw_data" in data:
                updates["raw_data"] = json.dumps(data["raw_data"])

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
                      source_tool: str, source_file: str) -> tuple[int, int, list[dict]]:
        """Smart merge: update existing actions, add new ones.

        Returns (new_count, updated_count, updated_details).
        updated_details is a list of {id, title, source_id, matched_by} for transparency.
        """
        new_count = 0
        updated_count = 0
        updated_details = []
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

                    # Always sync score and max_score from latest import
                    if action.score is not None and action.score != existing.get("score"):
                        conn.execute(
                            """INSERT INTO action_history (action_id, timestamp, old_score,
                               new_score, source_report) VALUES (?, ?, ?, ?, ?)""",
                            (existing["id"], datetime.utcnow().isoformat(),
                             existing.get("score"), action.score, source_file),
                        )
                    changes["score"] = action.score
                    changes["max_score"] = action.max_score
                    if action.max_score and action.max_score > 0:
                        changes["score_percentage"] = round(
                            (action.score / action.max_score) * 100, 2)
                    else:
                        changes["score_percentage"] = 0

                    if action.status != existing["status"]:
                        conn.execute(
                            """INSERT INTO action_history (action_id, timestamp,
                               old_status, new_status, source_report)
                               VALUES (?, ?, ?, ?, ?)""",
                            (existing["id"], datetime.utcnow().isoformat(),
                             existing["status"], action.status, source_file),
                        )
                        changes["status"] = action.status

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
                    changes["updated_at"] = datetime.utcnow().isoformat()
                    changes["raw_data"] = json.dumps(action.raw_data if hasattr(action, "raw_data") else {})

                    sets = ", ".join(f"{k}=?" for k in changes)
                    vals = list(changes.values()) + [existing["id"]]
                    conn.execute(f"UPDATE actions SET {sets} WHERE id=?", vals)
                    updated_count += 1
                    updated_details.append({
                        "id": existing["id"],
                        "title": action.title,
                        "source_id": action.source_id,
                        "existing_source_id": existing.get("source_id", ""),
                        "matched_by": matched_by,
                    })
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
                           threats, tier, action_type, remediation_impact, deprecated)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
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
                         action.remediation_impact, 1 if action.deprecated else 0),
                    )
                    new_count += 1

            # Record import
            conn.execute(
                """INSERT INTO import_history (tenant_name, timestamp, source_tool,
                   file_path, action_count, new_actions, updated_actions)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (tenant_name, datetime.utcnow().isoformat(), source_tool,
                 source_file, len(new_actions), new_count, updated_count),
            )

        return new_count, updated_count, updated_details

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

    def create_correlation_group(self, canonical_name: str, description: str = "",
                                  keywords: list[str] = None) -> dict:
        gid = _generate_id()
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO correlation_groups (id, canonical_name, description,
                   keywords, created_at) VALUES (?, ?, ?, ?, ?)""",
                (gid, canonical_name, description,
                 json.dumps(keywords or []), datetime.utcnow().isoformat()),
            )
        return {"id": gid, "canonical_name": canonical_name,
                "description": description, "keywords": keywords or []}

    def get_correlation_groups(self) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM correlation_groups ORDER BY canonical_name").fetchall()
            result = []
            for r in rows:
                d = dict(r)
                d["keywords"] = json.loads(d.get("keywords") or "[]")
                result.append(d)
            return result

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

    def update_correlation_group(self, group_id: str, canonical_name: str,
                                  description: str = "", keywords: list[str] = None) -> dict:
        with self._conn() as conn:
            conn.execute(
                """UPDATE correlation_groups SET canonical_name=?, description=?, keywords=?
                   WHERE id=?""",
                (canonical_name, description, json.dumps(keywords or []), group_id),
            )
        return {"id": group_id, "canonical_name": canonical_name,
                "description": description, "keywords": keywords or []}

    def delete_correlation_group(self, group_id: str):
        with self._conn() as conn:
            # Unlink all actions first
            conn.execute("UPDATE actions SET correlation_group_id=NULL WHERE correlation_group_id=?",
                         (group_id,))
            conn.execute("DELETE FROM correlation_groups WHERE id=?", (group_id,))

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
        allowed = {"name", "description", "status"}
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
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM compliance_mappings WHERE action_id=? ORDER BY framework, control_id",
                (action_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_compliance_summary(self, tenant_name: str, framework: str = None) -> dict:
        """Get compliance posture across frameworks."""
        with self._conn() as conn:
            if framework:
                rows = conn.execute(
                    """SELECT cm.framework, cm.control_id, cm.control_name, cm.control_family,
                       a.id as action_id, a.title, a.status, a.priority
                       FROM compliance_mappings cm
                       JOIN actions a ON cm.action_id = a.id
                       WHERE a.tenant_name=? AND cm.framework=?
                       ORDER BY cm.control_family, cm.control_id""",
                    (tenant_name, framework),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT cm.framework, cm.control_id, cm.control_name, cm.control_family,
                       a.id as action_id, a.title, a.status, a.priority
                       FROM compliance_mappings cm
                       JOIN actions a ON cm.action_id = a.id
                       WHERE a.tenant_name=?
                       ORDER BY cm.framework, cm.control_family, cm.control_id""",
                    (tenant_name,),
                ).fetchall()

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
        with self._conn() as conn:
            for m in mappings:
                conn.execute(
                    """INSERT OR IGNORE INTO compliance_mappings
                       (action_id, framework, control_id, control_name, control_family, notes)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (m["action_id"], m["framework"], m["control_id"],
                     m.get("control_name", ""), m.get("control_family", ""),
                     m.get("notes", "")),
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

    # ── Scoring helpers ──

    def get_scores(self, tenant_name: str) -> dict:
        """Calculate live scores from action data.

        Uses authoritative Graph API overall scores when available (stored
        by store_graph_scores). Falls back to summing per-action scores.
        Per-workload/tool breakdowns always use per-action data.
        """
        actions = self.get_actions(tenant_name)
        if not actions:
            return {"percentage": 0, "total_actions": 0, "completed_actions": 0,
                    "by_tool": {}, "by_workload": {}, "by_status": {}, "by_priority": {}}

        # Sum per-action scores
        action_total_score = sum(a.get("score") or 0 for a in actions)
        action_total_max = sum(a.get("max_score") or 0 for a in actions)
        completed = sum(1 for a in actions if a["status"] == ActionStatus.COMPLETED.value)

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

        for a in actions:
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
            "total_actions": len(actions),
            "completed_actions": completed,
            "by_tool": by_tool,
            "by_workload": by_workload,
            "by_status": by_status,
            "by_priority": by_priority,
        }

