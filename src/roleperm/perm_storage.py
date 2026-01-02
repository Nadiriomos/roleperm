from __future__ import annotations

from typing import Any, Dict, List, Optional

from .storage_utils import atomic_write_json, load_json_with_recovery

DEFAULT_SCHEMA_VERSION = 1


def _default_permissions() -> Dict[str, Any]:
    return {"schema_version": DEFAULT_SCHEMA_VERSION, "permissions": {}}


def load_permissions(path: str) -> Dict[str, Any]:
    """
    Load permissions dict. If missing/empty/invalid JSON/bad root, recover safely.

    Ensures:
      - schema_version exists
      - permissions exists and is a dict
    """
    raw = load_json_with_recovery(
        path,
        default_factory=_default_permissions,
        expected_type=dict,
        empty_suffix="empty",
    )

    raw.setdefault("schema_version", DEFAULT_SCHEMA_VERSION)
    raw.setdefault("permissions", {})

    if not isinstance(raw.get("permissions"), dict):
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
