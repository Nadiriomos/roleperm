from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime
from typing import Any, List, Optional

@dataclass(frozen=True)
class RoleRecord:
    name: str
    id: int
    kdf: str
    iterations: int
    salt: str
    password_hash: str

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

def _load_roles_raw(path: str) -> List[dict]:
    """Load raw roles list. If missing/empty/invalid JSON, recover safely."""
    _ensure_folder_for_file(path)

    if not os.path.exists(path):
        _atomic_write_json(path, [])
        return []

    try:
        if os.path.getsize(path) == 0:
            _backup_corrupt_file(path, suffix="empty")
            _atomic_write_json(path, [])
            return []
    except OSError:
        pass

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except json.JSONDecodeError:
        _backup_corrupt_file(path)
        _atomic_write_json(path, [])
        return []
    except Exception:
        return []

    if raw is None:
        raw = []

    if not isinstance(raw, list):
        _backup_corrupt_file(path, suffix="badroot")
        _atomic_write_json(path, [])
        return []

    return [x for x in raw if isinstance(x, dict)]

def roles_exist(path: str) -> bool:
    try:
        return len(_load_roles_raw(path)) > 0
    except Exception:
        return False

def load_role_records(path: str) -> List[RoleRecord]:
    raw = _load_roles_raw(path)
    out: List[RoleRecord] = []
    for item in raw:
        out.append(RoleRecord(
            name=item["name"],
            id=int(item["id"]),
            kdf=item.get("kdf", "pbkdf2_sha256"),
            iterations=int(item.get("iterations", 200_000)),
            salt=item.get("salt", ""),
            password_hash=item.get("password_hash", ""),
        ))
    return out

def save_role_records(path: str, records: List[RoleRecord]) -> None:
    _atomic_write_json(path, [r.__dict__ for r in records])

def find_role_by_name(path: str, name: str) -> Optional[RoleRecord]:
    needle = name.strip().lower()
    for r in load_role_records(path):
        if r.name.strip().lower() == needle:
            return r
    return None
