from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, List, Optional

from .storage_utils import atomic_write_json, backup_file, ensure_parent_dir


@dataclass(frozen=True)
class RoleRecord:
    name: str
    id: int
    kdf: str
    iterations: int
    salt: str
    password_hash: str


def _load_roles_raw(path: str) -> List[dict]:
    """Load raw roles list.

    If missing/empty/invalid JSON, recover safely by writing an empty list.
    """
    ensure_parent_dir(path)

    if not os.path.exists(path):
        atomic_write_json(path, [])
        return []

    try:
        if os.path.getsize(path) == 0:
            backup_file(path, suffix="empty")
            atomic_write_json(path, [])
            return []
    except OSError:
        # If we can't stat the file, fall back to trying to read it.
        pass

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except json.JSONDecodeError:
        backup_file(path)
        atomic_write_json(path, [])
        return []
    except Exception:
        # Be conservative: don't crash app for IO errors.
        return []

    if raw is None:
        raw = []

    if not isinstance(raw, list):
        backup_file(path, suffix="badroot")
        atomic_write_json(path, [])
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
        out.append(
            RoleRecord(
                name=item["name"],
                id=int(item["id"]),
                kdf=item.get("kdf", "pbkdf2_sha256"),
                iterations=int(item.get("iterations", 200_000)),
                salt=item.get("salt", ""),
                password_hash=item.get("password_hash", ""),
            )
        )
    return out


def save_role_records(path: str, records: List[RoleRecord]) -> None:
    atomic_write_json(path, [r.__dict__ for r in records])


def find_role_by_name(path: str, name: str) -> Optional[RoleRecord]:
    needle = name.strip().lower()
    for r in load_role_records(path):
        if r.name.strip().lower() == needle:
            return r
    return None
