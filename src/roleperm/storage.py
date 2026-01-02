from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from .storage_utils import atomic_write_json, load_json_with_recovery


@dataclass(frozen=True)
class RoleRecord:
    name: str
    id: int
    kdf: str
    iterations: int
    salt: str
    password_hash: str


def _load_roles_raw(path: str) -> List[dict]:
    """
    Load raw roles list. If missing/empty/invalid JSON/bad root, recover safely.

    Returns: list of dicts (filters out non-dicts).
    """
    raw = load_json_with_recovery(
        path,
        default_factory=lambda: [],
        expected_type=list,
        empty_suffix="empty",
    )
    # Filter to dict items only (defensive)
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
        # Keep the same defaults you already relied on elsewhere
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
