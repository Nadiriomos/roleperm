from __future__ import annotations

from dataclasses import dataclass
from functools import wraps
from typing import Callable, Dict, Optional, TypeVar

from .auth import OWNER_ID, current_role, current_role_id
from .config import resolve_permissions_file
from .perm_storage import get_allowed_role_ids, load_permissions
from .validators import validate_permissions_data

F = TypeVar("F", bound=Callable[..., object])


# ---------- Exceptions (still subclasses of PermissionError, so your tests keep passing) ----------

class NotAuthenticated(PermissionError):
    """Raised when a permission/role check is performed without a logged-in role."""


class PermissionDenied(PermissionError):
    """Raised when a logged-in role is not allowed to perform an action."""


# ---------- Registry (so admin UI can list known permission keys) ----------

@dataclass(frozen=True)
class PermissionMeta:
    key: str
    label: str
    qualname: str
    module: str


_PERMISSION_REGISTRY: Dict[str, PermissionMeta] = {}


def list_registered_permissions() -> Dict[str, PermissionMeta]:
    """Return a copy of the current permission registry."""
    return dict(_PERMISSION_REGISTRY)


def _norm_key(key: str) -> str:
    if not isinstance(key, str) or not key.strip():
        raise ValueError("permission key must be a non-empty string.")
    return key.strip()


def permission_key(key: str, *, label: Optional[str] = None):
    """
    Decorator that registers a permission key for discovery in admin UI.
    Registration is in-memory (it does NOT write permissions.json).

    Duplicate keys are ignored (first registration wins).
    """
    key = _norm_key(key)

    def deco(func: Callable) -> Callable:
        lab = label.strip() if isinstance(label, str) and label.strip() else key

        if key not in _PERMISSION_REGISTRY:
            _PERMISSION_REGISTRY[key] = PermissionMeta(
                key=key,
                label=lab,
                qualname=getattr(func, "__qualname__", getattr(func, "__name__", "<callable>")),
                module=getattr(func, "__module__", ""),
            )

        # Tag the function for introspection (optional convenience)
        setattr(func, "__roleperm_permission_key__", key)
        setattr(func, "__roleperm_permission_label__", lab)
        return func

    return deco


# ---------- Core check helpers (framework integrations will call these) ----------

def require_login() -> int:
    """Return current role id or raise NotAuthenticated."""
    rid = current_role_id()
    if rid is None:
        raise NotAuthenticated("Not logged in.")
    return rid


def check_permission_for_role_id(
    role_id: int,
    key: str,
    *,
    permissions_file: Optional[str] = None,
    default_allow_missing: bool = False,
) -> bool:
    """
    Check if `role_id` is allowed for permission `key`.

    Rules:
      - Owner (id=0) is always allowed.
      - If key is missing in permissions.json: allow only if default_allow_missing=True
    """
    key = _norm_key(key)

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

    allowed_set = {int(x) for x in allowed}
    return role_id in allowed_set


def check_permission(
    key: str,
    *,
    permissions_file: Optional[str] = None,
    default_allow_missing: bool = False,
) -> bool:
    """
    Check permission for the *current session role*.
    Returns False if not logged in.
    """
    rid = current_role_id()
    if rid is None:
        return False
    return check_permission_for_role_id(
        rid,
        key,
        permissions_file=permissions_file,
        default_allow_missing=default_allow_missing,
    )


def require_permission(
    key: str,
    *,
    permissions_file: Optional[str] = None,
    default_allow_missing: bool = False,
) -> None:
    """
    Enforce a permission for the current session role.
    Raises NotAuthenticated / PermissionDenied.
    """
    rid = require_login()
    if rid == OWNER_ID:
        return

    if not check_permission_for_role_id(
        rid,
        key,
        permissions_file=permissions_file,
        default_allow_missing=default_allow_missing,
    ):
        r = current_role()
        name = r.name if r else "unknown"
        raise PermissionDenied(f"Unauthorized: role '{name}' (id={rid}) cannot access permission '{_norm_key(key)}'.")


# ---------- Decorators (kept for backward compatibility) ----------

def role_required(role_id: int):
    """Hard role check (Owner bypasses)."""
    if not isinstance(role_id, int):
        raise ValueError("role_id must be an int.")

    def deco(func: F) -> F:
        @wraps(func)
        def wrapper(*args, **kwargs):
            rid = require_login()
            if rid == OWNER_ID:
                return func(*args, **kwargs)
            if rid != role_id:
                r = current_role()
                name = r.name if r else "unknown"
                raise PermissionDenied(
                    f"Unauthorized: role '{name}' (id={rid}) cannot access '{func.__name__}'. Required id={role_id}."
                )
            return func(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return deco


def permission_required(
    key: str,
    *,
    permissions_file: Optional[str] = None,
    default_allow: bool = False,
):
    """
    Decorator enforcing permission `key` for the current session role.

    - If permission key missing in permissions.json: allowed only if default_allow=True
    - Owner bypasses.
    """
    key = _norm_key(key)

    def deco(func: F) -> F:
        @wraps(func)
        def wrapper(*args, **kwargs):
            require_permission(
                key,
                permissions_file=permissions_file,
                default_allow_missing=default_allow,
            )
            return func(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return deco
