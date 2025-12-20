from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from .storage_utils import atomic_write_json, backup_file, ensure_parent_dir

DEFAULT_SCHEMA_VERSION = 1


def _default_permissions() -> Dict[str, Any]:
    return {"schema_version": DEFAULT_SCHEMA_VERSION, "permissions": {}}


def load_permissions(path: str) -> Dict[str, Any]:
    ensure_parent_dir(path)

    if not os.path.exists(path):
        atomic_write_json(path, _default_permissions())
        return _default_permissions()

    try:
        if os.path.getsize(path) == 0:
            backup_file(path, suffix="empty")
            atomic_write_json(path, _default_permissions())
            return _default_permissions()
    except OSError:
        pass

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except json.JSONDecodeError:
        backup_file(path)
        atomic_write_json(path, _default_permissions())
        return _default_permissions()
    except Exception:
        return _default_permissions()

    if not isinstance(raw, dict):
        backup_file(path, suffix="badroot")
        atomic_write_json(path, _default_permissions())
        return _default_permissions()

    raw.setdefault("schema_version", DEFAULT_SCHEMA_VERSION)
    raw.setdefault("permissions", {})
    if not isinstance(raw["permissions"], dict):
        raw["permissions"] = {}
    return raw


def save_permissions(path: str, data: Dict[str, Any]) -> None:
    if not isinstance(data, dict):
        raise ValueError("permissions data must be a dict.")
    data.setdefault("schema_version", DEFAULT_SCHEMA_VERSION)
    data.setdefault("permissions", {})
    atomic_write_json(path, data)


def get_allowed_role_ids(data: Dict[str, Any], key: str) -> Optional[List[int]]:
    rec = data.get("permissions", {}).get(key)
    if rec is None:
        return None
    allowed = rec.get("allowed_role_ids")
    if allowed is None:
        return []
    return [int(x) for x in allowed]
