"""JSON-based storage for tenant data with history tracking."""

from __future__ import annotations

import json
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional

from .models import Action, TenantConfig, TenantData


DEFAULT_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")


class TenantStore:
    """Manages JSON file storage for a single tenant."""

    def __init__(self, data_dir: str, tenant_name: str):
        self.data_dir = Path(data_dir)
        self.tenant_name = tenant_name
        self.tenant_dir = self.data_dir / tenant_name
        self.tenant_dir.mkdir(parents=True, exist_ok=True)
        self.config_file = self.tenant_dir / "config.json"
        self.actions_file = self.tenant_dir / "actions.json"
        self.history_file = self.tenant_dir / "import_history.json"
        self.scores_file = self.tenant_dir / "scores.json"
        self.reports_dir = self.tenant_dir / "reports"
        self.reports_dir.mkdir(exist_ok=True)

    def save_config(self, config: TenantConfig):
        self._write_json(self.config_file, config.to_dict())

    def load_config(self) -> Optional[TenantConfig]:
        data = self._read_json(self.config_file)
        return TenantConfig.from_dict(data) if data else None

    def save_actions(self, actions: list[Action]):
        data = [a.to_dict() if isinstance(a, Action) else a for a in actions]
        self._write_json(self.actions_file, data)

    def load_actions(self) -> list[Action]:
        data = self._read_json(self.actions_file)
        if not data:
            return []
        return [Action.from_dict(d) for d in data]

    def save_scores(self, scores: dict):
        self._write_json(self.scores_file, scores)

    def load_scores(self) -> dict:
        return self._read_json(self.scores_file) or {}

    def add_import_record(self, source_tool: str, file_path: str, action_count: int,
                          new_count: int, updated_count: int):
        history = self._read_json(self.history_file) or []
        history.append({
            "timestamp": datetime.utcnow().isoformat(),
            "source_tool": source_tool,
            "file_path": file_path,
            "action_count": action_count,
            "new_actions": new_count,
            "updated_actions": updated_count,
        })
        self._write_json(self.history_file, history)

    def load_import_history(self) -> list[dict]:
        return self._read_json(self.history_file) or []

    def get_tenant_data(self) -> TenantData:
        return TenantData(
            tenant=self.load_config().to_dict() if self.load_config() else {},
            actions=[a.to_dict() for a in self.load_actions()],
            import_history=self.load_import_history(),
            scores=self.load_scores(),
        )

    def merge_actions(self, new_actions: list[Action], source_tool: str,
                      source_file: str) -> tuple[int, int]:
        """Merge new actions with existing ones. Returns (new_count, updated_count)."""
        existing = self.load_actions()
        existing_by_source_id = {}
        for a in existing:
            key = f"{a.source_tool}::{a.source_id}"
            if a.source_id:
                existing_by_source_id[key] = a

        new_count = 0
        updated_count = 0

        for new_action in new_actions:
            key = f"{new_action.source_tool}::{new_action.source_id}"
            if key in existing_by_source_id and new_action.source_id:
                old = existing_by_source_id[key]
                # Update score if changed
                if new_action.score is not None and new_action.score != old.score:
                    old.update_score(new_action.score, new_action.max_score, source_file)
                # Update status based on score changes
                if new_action.status != old.status:
                    # Only auto-update if the old status was from the same tool
                    if old.status in ("ToDo", "Completed") and old.source_tool == source_tool:
                        old.update_status(new_action.status, source_file)
                # Update descriptive fields
                if new_action.description:
                    old.description = new_action.description
                if new_action.remediation_steps:
                    old.remediation_steps = new_action.remediation_steps
                if new_action.current_value:
                    old.current_value = new_action.current_value
                if new_action.recommended_value:
                    old.recommended_value = new_action.recommended_value
                old.source_report_file = source_file
                old.source_report_date = datetime.utcnow().isoformat()
                old.updated_at = datetime.utcnow().isoformat()
                # Preserve raw data
                old.raw_data = new_action.raw_data
                updated_count += 1
            else:
                new_action.source_report_file = source_file
                new_action.source_report_date = datetime.utcnow().isoformat()
                existing.append(new_action)
                if new_action.source_id:
                    existing_by_source_id[key] = new_action
                new_count += 1

        self.save_actions(existing)
        self.add_import_record(source_tool, source_file, len(new_actions),
                               new_count, updated_count)
        return new_count, updated_count

    def _write_json(self, path: Path, data):
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)

    def _read_json(self, path: Path):
        if not path.exists():
            return None
        with open(path) as f:
            return json.load(f)


class StorageManager:
    """Manages multiple tenant stores."""

    def __init__(self, data_dir: str = None):
        self.data_dir = Path(data_dir or DEFAULT_DATA_DIR)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._active_tenant_file = self.data_dir / ".active_tenant"

    def list_tenants(self) -> list[str]:
        tenants = []
        if not self.data_dir.exists():
            return tenants
        for d in sorted(self.data_dir.iterdir()):
            if d.is_dir() and not d.name.startswith("."):
                tenants.append(d.name)
        return tenants

    def get_tenant_store(self, tenant_name: str) -> TenantStore:
        return TenantStore(str(self.data_dir), tenant_name)

    def create_tenant(self, tenant_name: str, config: TenantConfig) -> TenantStore:
        store = self.get_tenant_store(tenant_name)
        store.save_config(config)
        if not self.get_active_tenant():
            self.set_active_tenant(tenant_name)
        return store

    def delete_tenant(self, tenant_name: str):
        tenant_dir = self.data_dir / tenant_name
        if tenant_dir.exists():
            shutil.rmtree(tenant_dir)
        if self.get_active_tenant() == tenant_name:
            tenants = self.list_tenants()
            if tenants:
                self.set_active_tenant(tenants[0])
            else:
                self._active_tenant_file.unlink(missing_ok=True)

    def set_active_tenant(self, tenant_name: str):
        if tenant_name not in self.list_tenants():
            raise ValueError(f"Tenant '{tenant_name}' does not exist")
        self._active_tenant_file.write_text(tenant_name)

    def get_active_tenant(self) -> Optional[str]:
        if self._active_tenant_file.exists():
            name = self._active_tenant_file.read_text().strip()
            if name in self.list_tenants():
                return name
        return None

    def get_active_store(self) -> Optional[TenantStore]:
        tenant = self.get_active_tenant()
        if tenant:
            return self.get_tenant_store(tenant)
        return None
