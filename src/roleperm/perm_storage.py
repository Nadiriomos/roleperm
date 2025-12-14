from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime
from typing import Any, Dict, List, Optional

DEFAULT_SCHEMA_VERSION = 1

def _ensure_folder_for_file(path: str) -> None:
    folder = os.path.dirname(os.path.abspath(path))
    if folder and not os.path.exists(folder):
        os.makedirs(folder, exist_ok=True)

def _atomic_write_json(path: str, data: Any) -> None:
    _ensure_folder_for_file(path)
    folder = os.path.dirname(os.path.abspath(path)) or "."
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

def _backup_corrupt_file(path: str, *, suffix: str = "corrupt") -> None:
    try:
        if not os.path.exists(path):
            return
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = f"{path}.{suffix}.{ts}.bak"
        os.replace(path, backup)
    except OSError:
        pass

def _default_permissions() -> Dict[str, Any]:
    return {"schema_version": DEFAULT_SCHEMA_VERSION, "permissions": {}}

def load_permissions(path: str) -> Dict[str, Any]:
    _ensure_folder_for_file(path)

    if not os.path.exists(path):
        _atomic_write_json(path, _default_permissions())
        return _default_permissions()

    try:
        if os.path.getsize(path) == 0:
            _backup_corrupt_file(path, suffix="empty")
            _atomic_write_json(path, _default_permissions())
            return _default_permissions()
    except OSError:
        pass

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except json.JSONDecodeError:
        _backup_corrupt_file(path)
        _atomic_write_json(path, _default_permissions())
        return _default_permissions()
    except Exception:
        return _default_permissions()

    if not isinstance(raw, dict):
        _backup_corrupt_file(path, suffix="badroot")
        _atomic_write_json(path, _default_permissions())
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
    _atomic_write_json(path, data)

def get_allowed_role_ids(data: Dict[str, Any], key: str) -> Optional[List[int]]:
    rec = data.get("permissions", {}).get(key)
    if rec is None:
        return None
    allowed = rec.get("allowed_role_ids")
    if allowed is None:
        return []
    return [int(x) for x in allowed]
