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

from .models import Action, TenantConfig, ActionStatus

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
            """)

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
                   source_id, workload, status, priority, risk_level, user_impact,
                   implementation_effort, required_licence, score, max_score, score_percentage,
                   essential_eight_control, essential_eight_maturity, remediation_steps,
                   current_value, recommended_value, category, subcategory, planned_date,
                   responsible, tags, notes, reference_url, source_report_file,
                   source_report_date, raw_data, correlation_group_id, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (action_id, tenant_name,
                 data.get("title", ""), data.get("description", ""),
                 data.get("source_tool", "Manual"), data.get("source_id", ""),
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
                      source_tool: str, source_file: str) -> tuple[int, int]:
        """Smart merge: update existing actions, add new ones. Returns (new, updated)."""
        new_count = 0
        updated_count = 0

        with self._conn() as conn:
            for action in new_actions:
                # Look for existing by source_tool + source_id
                existing = None
                if action.source_id:
                    row = conn.execute(
                        "SELECT * FROM actions WHERE tenant_name=? AND source_tool=? AND source_id=?",
                        (tenant_name, action.source_tool, action.source_id),
                    ).fetchone()
                    if row:
                        existing = dict(row)

                if existing:
                    # Update existing action
                    changes = {}
                    if action.score is not None and action.score != existing["score"]:
                        conn.execute(
                            """INSERT INTO action_history (action_id, timestamp, old_score,
                               new_score, source_report) VALUES (?, ?, ?, ?, ?)""",
                            (existing["id"], datetime.utcnow().isoformat(),
                             existing["score"], action.score, source_file),
                        )
                        changes["score"] = action.score
                        changes["max_score"] = action.max_score
                        if action.max_score and action.max_score > 0:
                            changes["score_percentage"] = round(
                                (action.score / action.max_score) * 100, 1)

                    if action.status != existing["status"]:
                        if existing["status"] in ("ToDo", "Completed") and existing["source_tool"] == source_tool:
                            conn.execute(
                                """INSERT INTO action_history (action_id, timestamp,
                                   old_status, new_status, source_report)
                                   VALUES (?, ?, ?, ?, ?)""",
                                (existing["id"], datetime.utcnow().isoformat(),
                                 existing["status"], action.status, source_file),
                            )
                            changes["status"] = action.status

                    if action.description:
                        changes["description"] = action.description
                    if action.remediation_steps:
                        changes["remediation_steps"] = action.remediation_steps
                    if action.current_value:
                        changes["current_value"] = action.current_value
                    if action.recommended_value:
                        changes["recommended_value"] = action.recommended_value
                    if action.essential_eight_control:
                        changes["essential_eight_control"] = action.essential_eight_control
                        changes["essential_eight_maturity"] = action.essential_eight_maturity

                    changes["source_report_file"] = source_file
                    changes["source_report_date"] = datetime.utcnow().isoformat()
                    changes["updated_at"] = datetime.utcnow().isoformat()
                    changes["raw_data"] = json.dumps(action.raw_data if hasattr(action, "raw_data") else {})

                    sets = ", ".join(f"{k}=?" for k in changes)
                    vals = list(changes.values()) + [existing["id"]]
                    conn.execute(f"UPDATE actions SET {sets} WHERE id=?", vals)
                    updated_count += 1
                else:
                    # Insert new action
                    now = datetime.utcnow().isoformat()
                    action_id = action.id or _generate_id()
                    conn.execute(
                        """INSERT INTO actions (id, tenant_name, title, description,
                           source_tool, source_id, workload, status, priority, risk_level,
                           user_impact, implementation_effort, required_licence,
                           score, max_score, score_percentage,
                           essential_eight_control, essential_eight_maturity,
                           remediation_steps, current_value, recommended_value,
                           category, subcategory, planned_date, responsible,
                           tags, notes, reference_url, source_report_file,
                           source_report_date, raw_data, created_at, updated_at)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (action_id, tenant_name, action.title, action.description,
                         action.source_tool, action.source_id, action.workload,
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
                         action.created_at or now, now),
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

        return new_count, updated_count

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

    # ── Scoring helpers ──

    def get_scores(self, tenant_name: str) -> dict:
        """Calculate live scores from action data."""
        actions = self.get_actions(tenant_name)
        if not actions:
            return {"percentage": 0, "total_actions": 0, "completed_actions": 0,
                    "by_tool": {}, "by_workload": {}, "by_status": {}, "by_priority": {}}

        total_score = sum(a.get("score") or 0 for a in actions)
        total_max = sum(a.get("max_score") or 0 for a in actions)
        completed = sum(1 for a in actions if a["status"] == ActionStatus.COMPLETED.value)

        by_tool = {}
        by_workload = {}
        by_status = {}
        by_priority = {}

        for a in actions:
            tool = a["source_tool"]
            wl = a["workload"]
            st = a["status"]
            pr = a["priority"]

            for group, key, in [(by_tool, tool), (by_workload, wl)]:
                if key not in group:
                    group[key] = {"score": 0, "max_score": 0, "total": 0, "completed": 0}
                group[key]["score"] += a.get("score") or 0
                group[key]["max_score"] += a.get("max_score") or 0
                group[key]["total"] += 1
                if a["status"] == ActionStatus.COMPLETED.value:
                    group[key]["completed"] += 1

            by_status[st] = by_status.get(st, 0) + 1
            by_priority[pr] = by_priority.get(pr, 0) + 1

        for group in [by_tool, by_workload]:
            for data in group.values():
                m = data["max_score"]
                data["percentage"] = round((data["score"] / m) * 100, 1) if m > 0 else 0

        return {
            "total_score": round(total_score, 1),
            "total_max": round(total_max, 1),
            "percentage": round((total_score / total_max) * 100, 1) if total_max > 0 else 0,
            "total_actions": len(actions),
            "completed_actions": completed,
            "by_tool": by_tool,
            "by_workload": by_workload,
            "by_status": by_status,
            "by_priority": by_priority,
        }

