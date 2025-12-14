from __future__ import annotations

import json
import os
import tempfile
from typing import Any, Dict, List, Optional

DEFAULT_SCHEMA_VERSION = 1

def _ensure_file(path: str, default_json: Any) -> None:
    folder = os.path.dirname(os.path.abspath(path))
    if folder and not os.path.exists(folder):
        os.makedirs(folder, exist_ok=True)
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(default_json, f, indent=2)

def _atomic_write_json(path: str, data: Any) -> None:
    folder = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(folder, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".roleperm_", suffix=".tmp", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass

def load_permissions(path: str) -> Dict[str, Any]:
    _ensure_file(path, {"schema_version": DEFAULT_SCHEMA_VERSION, "permissions": {}})
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f) or {}
    if not isinstance(raw, dict):
        raise ValueError("permissions.json must contain a JSON object.")
    raw.setdefault("schema_version", DEFAULT_SCHEMA_VERSION)
    raw.setdefault("permissions", {})
    if not isinstance(raw["permissions"], dict):
        raise ValueError("'permissions' must be an object.")
    return raw

def save_permissions(path: str, data: Dict[str, Any]) -> None:
    if not isinstance(data, dict):
        raise ValueError("permissions data must be a dict.")
    data.setdefault("schema_version", DEFAULT_SCHEMA_VERSION)
    data.setdefault("permissions", {})
    _atomic_write_json(path, data)

def get_allowed_role_ids(data: Dict[str, Any], key: str) -> Optional[List[int]]:
    rec = data.get("permissions", {}).get(key)
    if rec is None:
        return None
    allowed = rec.get("allowed_role_ids")
    if allowed is None:
        return []
    return [int(x) for x in allowed]
