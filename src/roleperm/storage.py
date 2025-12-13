from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from typing import Iterable, List, Optional


@dataclass(frozen=True)
class RoleRecord:
    """
    Stored role record (contains password hash material).
    This is what goes in roles.json.
    """
    name: str
    id: int
    kdf: str
    iterations: int
    salt: str
    password_hash: str


def _normalize_name(name: str) -> str:
    return name.strip().lower()


def ensure_roles_file(path: str) -> None:
    """Create an empty roles file if missing."""
    folder = os.path.dirname(os.path.abspath(path))
    if folder and not os.path.exists(folder):
        os.makedirs(folder, exist_ok=True)
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump([], f, indent=2)


def load_roles(path: str) -> List[RoleRecord]:
    ensure_roles_file(path)
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if data is None:
        data = []
    if not isinstance(data, list):
        raise ValueError("roles.json must contain a JSON array.")

    roles: List[RoleRecord] = []
    for idx, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(f"roles.json item #{idx} must be an object.")
        try:
            roles.append(
                RoleRecord(
                    name=item["name"],
                    id=int(item["id"]),
                    kdf=item.get("kdf", "pbkdf2_sha256"),
                    iterations=int(item.get("iterations", 200_000)),
                    salt=item["salt"],
                    password_hash=item["password_hash"],
                )
            )
        except KeyError as e:
            missing = str(e).strip("'")
            raise ValueError(f"roles.json item #{idx} missing required field '{missing}'.") from None
    return roles


def save_roles(path: str, roles: Iterable[RoleRecord]) -> None:
    """
    Atomic write to reduce file corruption risk:
    write to temp file in same directory, then os.replace.
    """
    ensure_roles_file(path)
    folder = os.path.dirname(os.path.abspath(path))
    payload = [
        {
            "name": r.name,
            "id": int(r.id),
            "kdf": r.kdf,
            "iterations": int(r.iterations),
            "salt": r.salt,
            "password_hash": r.password_hash,
        }
        for r in roles
    ]

    fd, tmp_path = tempfile.mkstemp(prefix=".roles.", suffix=".tmp", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    finally:
        # If os.replace fails, try to clean up the temp file.
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass


def get_role_by_name(path: str, name: str) -> Optional[RoleRecord]:
    target = _normalize_name(name)
    for r in load_roles(path):
        if _normalize_name(r.name) == target:
            return r
    return None


def get_role_by_id(path: str, role_id: int) -> Optional[RoleRecord]:
    for r in load_roles(path):
        if r.id == int(role_id):
            return r
    return None
