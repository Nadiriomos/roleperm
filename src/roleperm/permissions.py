from __future__ import annotations

from dataclasses import dataclass
from functools import wraps
from typing import Callable, Dict, Optional

from .auth import current_role, current_role_id
from .perm_storage import load_permissions, get_allowed_role_ids
from .validators import validate_permissions_data

DEFAULT_PERMISSIONS_FILE = "permissions.json"

@dataclass(frozen=True)
class PermissionMeta:
    key: str
    label: str
    qualname: str
    module: str

_PERMISSION_REGISTRY: Dict[str, PermissionMeta] = {}

def list_registered_permissions() -> Dict[str, PermissionMeta]:
    return dict(_PERMISSION_REGISTRY)

def permission_key(key: str, *, label: Optional[str] = None) -> Callable[[Callable], Callable]:
    if not isinstance(key, str) or not key.strip():
        raise ValueError("permission key must be a non-empty string.")
    key = key.strip()
    def deco(func: Callable) -> Callable:
        lab = label.strip() if isinstance(label, str) and label.strip() else key
        meta = PermissionMeta(
            key=key,
            label=lab,
            qualname=getattr(func, "__qualname__", func.__name__),
            module=getattr(func, "__module__", ""),
        )
        _PERMISSION_REGISTRY[key] = meta
        setattr(func, "__roleperm_permission_key__", key)
        setattr(func, "__roleperm_permission_label__", lab)
        return func
    return deco

def role_required(role_id: int) -> Callable[[Callable], Callable]:
    if not isinstance(role_id, int):
        raise ValueError("role_id must be an int.")
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            rid = current_role_id()
            if rid is None:
                raise PermissionError("Not logged in.")
            if rid != role_id:
                r = current_role()
                name = r.name if r else "unknown"
                raise PermissionError(f"Unauthorized: role '{name}' (id={rid}) cannot access '{func.__name__}'. Required id={role_id}.")
            return func(*args, **kwargs)
        return wrapper
    return decorator

def permission_required(key: str, *, permissions_file: str = DEFAULT_PERMISSIONS_FILE, default_allow: bool = False) -> Callable[[Callable], Callable]:
    if not isinstance(key, str) or not key.strip():
        raise ValueError("permission key must be a non-empty string.")
    key = key.strip()
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            rid = current_role_id()
            if rid is None:
                raise PermissionError("Not logged in.")
            data = load_permissions(permissions_file)
            validate_permissions_data(data)
            allowed = get_allowed_role_ids(data, key)
            if allowed is None:
                if not default_allow:
                    raise PermissionError(f"Permission '{key}' is not configured; access denied by default.")
                return func(*args, **kwargs)
            if rid not in set(allowed):
                r = current_role()
                name = r.name if r else "unknown"
                raise PermissionError(f"Unauthorized: role '{name}' (id={rid}) cannot access permission '{key}'.")
            return func(*args, **kwargs)
        return wrapper
    return decorator
