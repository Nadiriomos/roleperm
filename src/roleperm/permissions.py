from __future__ import annotations

from dataclasses import dataclass
from functools import wraps
from typing import Callable, Dict, Optional

from .auth import current_role, current_role_id
from .config import resolve_permissions_file
from .constants import OWNER_ID
from .perm_storage import get_allowed_role_ids, load_permissions
from .validators import validate_permissions_data


@dataclass(frozen=True)
class PermissionMeta:
    key: str
    label: str
    qualname: str
    module: str


_PERMISSION_REGISTRY: Dict[str, PermissionMeta] = {}


def list_registered_permissions() -> Dict[str, PermissionMeta]:
    """Return a snapshot of registered permissions (key -> meta)."""
    return dict(_PERMISSION_REGISTRY)


def permission_key(key: str, *, label: Optional[str] = None):
    """Decorator to register a permission key + optional label.

    Use it to make permission keys discoverable by the admin UI.
    """
    if not isinstance(key, str) or not key.strip():
        raise ValueError("permission key must be a non-empty string.")
    key = key.strip()

    def deco(func: Callable) -> Callable:
        lab = label.strip() if isinstance(label, str) and label.strip() else key

        # Ignore duplicate registrations so the first registration stays authoritative
        # (usually the one provided by the library).
        if key not in _PERMISSION_REGISTRY:
            _PERMISSION_REGISTRY[key] = PermissionMeta(
                key=key,
                label=lab,
                qualname=getattr(func, "__qualname__", func.__name__),
                module=getattr(func, "__module__", ""),
            )
        setattr(func, "__roleperm_permission_key__", key)
        setattr(func, "__roleperm_permission_label__", lab)
        return func

    return deco


def role_required(role_id: int):
    """Hard role check. Owner (id=0) bypasses it."""
    if not isinstance(role_id, int):
        raise ValueError("role_id must be an int.")

    def deco(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            rid = current_role_id()
            if rid is None:
                raise PermissionError("Not logged in.")
            if rid == OWNER_ID:
                return func(*args, **kwargs)
            if rid != role_id:
                r = current_role()
                name = r.name if r else "unknown"
                raise PermissionError(
                    f"Unauthorized: role '{name}' (id={rid}) cannot access '{func.__name__}'. Required id={role_id}."
                )
            return func(*args, **kwargs)

        return wrapper

    return deco


def check_permission_for_role_id(
    role_id: int,
    key: str,
    *,
    permissions_file: Optional[str] = None,
    default_allow_missing: bool = False,
) -> bool:
    """Pure check function used by decorators and UIs."""
    if role_id == OWNER_ID:
        return True
    if not isinstance(role_id, int):
        return False

    path = resolve_permissions_file(permissions_file)
    data = load_permissions(path)
    validate_permissions_data(data)

    allowed = get_allowed_role_ids(data, key)
    if allowed is None:
        return bool(default_allow_missing)
    return role_id in set(int(x) for x in allowed)


def permission_required(key: str, *, permissions_file: Optional[str] = None, default_allow: bool = False):
    if not isinstance(key, str) or not key.strip():
        raise ValueError("permission key must be a non-empty string.")
    key = key.strip()

    def deco(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            rid = current_role_id()
            if rid is None:
                raise PermissionError("Not logged in.")
            if rid == OWNER_ID:
                return func(*args, **kwargs)
            if not check_permission_for_role_id(
                rid,
                key,
                permissions_file=permissions_file,
                default_allow_missing=default_allow,
            ):
                r = current_role()
                name = r.name if r else "unknown"
                raise PermissionError(
                    f"Unauthorized: role '{name}' (id={rid}) cannot access permission '{key}'."
                )
            return func(*args, **kwargs)

        return wrapper

    return deco
