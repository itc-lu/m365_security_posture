"""Read-only access to the legacy JSON file storage.

Pre-SQLite versions of this tool stored each tenant as a directory of JSON
files (``data/<tenant>/config.json``, ``actions.json``, …). This module reads
that layout so ``m365-posture migrate-from-json`` can move the data into the
SQLite database. It never writes.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from .models import Action, TenantConfig


DEFAULT_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")


def _read_json(path: Path):
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


class TenantStore:
    """Reads the JSON files of a single legacy tenant directory."""

    def __init__(self, data_dir: str, tenant_name: str):
        self.tenant_name = tenant_name
        self.tenant_dir = Path(data_dir) / tenant_name

    def load_config(self) -> Optional[TenantConfig]:
        data = _read_json(self.tenant_dir / "config.json")
        return TenantConfig.from_dict(data) if data else None

    def load_actions(self) -> list[Action]:
        data = _read_json(self.tenant_dir / "actions.json")
        return [Action.from_dict(d) for d in data] if data else []

    def load_import_history(self) -> list[dict]:
        return _read_json(self.tenant_dir / "import_history.json") or []

    def load_scores(self) -> dict:
        return _read_json(self.tenant_dir / "scores.json") or {}


class StorageManager:
    """Enumerates legacy tenant directories in a JSON data directory."""

    def __init__(self, data_dir: str = None):
        self.data_dir = Path(data_dir or DEFAULT_DATA_DIR)

    def list_tenants(self) -> list[str]:
        if not self.data_dir.exists():
            return []
        return [d.name for d in sorted(self.data_dir.iterdir())
                if d.is_dir() and not d.name.startswith(".")
                and (d / "config.json").exists()]

    def get_tenant_store(self, tenant_name: str) -> TenantStore:
        return TenantStore(str(self.data_dir), tenant_name)
