from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from typing import Any, List, Optional

@dataclass(frozen=True)
class RoleRecord:
    name: str
    id: int
    kdf: str
    iterations: int
    salt: str
    password_hash: str

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

def load_role_records(path: str) -> List[RoleRecord]:
    _ensure_file(path, [])
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f) or []
    if not isinstance(raw, list):
        raise ValueError("roles.json must contain a JSON list.")
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
    _ensure_file(path, [])
    data = [r.__dict__ for r in records]
    _atomic_write_json(path, data)

def find_role_by_name(path: str, name: str) -> Optional[RoleRecord]:
    needle = name.strip().lower()
    for r in load_role_records(path):
        if r.name.strip().lower() == needle:
            return r
    return None
