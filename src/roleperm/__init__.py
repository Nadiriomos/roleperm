"""
roleperm public API.

This module re-exports the most commonly used functions/classes so users can:
    import roleperm as rp

Web integrations typically use:
- rp.set_current_role(...)  (per-request)
- rp.require_permission(...) / rp.check_permission(...)
"""

from __future__ import annotations

import json

from .config import configure, get_paths

from .auth import (
    OWNER_ID,
    OWNER_NAME,
    Role,
    authenticate,
    login_and_set_session,
    set_current_role,
    session_as,
    add_role,
    edit_role,
    delete_role,
    get_roles,
    current_role,
    current_role_id,
    current_username,
    logout,
)

# Tk-based login popup (desktop only; safe to import because tkinter is imported lazily inside ui.py)
from .ui import login

from .permissions import (
    # registry + decorators
    permission_key,
    permission_required,
    role_required,
    list_registered_permissions,
    # checks/guards (web-friendly)
    check_permission_for_role_id,
    check_permission,
    require_login,
    require_permission,
    # exceptions
    NotAuthenticated,
    PermissionDenied,
)

from .admin_ui import (
    MANAGE_PERMISSION_KEY,
    MANAGE_PERMISSION_LABEL,
    open_admin_panel,
)

from .validators import (
    RolesValidationError,
    PermissionsValidationError,
    validate_roles_data,
    validate_permissions_data,
)

__version__ = "0.2.4"

__all__ = [
    # config
    "configure",
    "get_paths",
    # auth/session
    "OWNER_ID",
    "OWNER_NAME",
    "Role",
    "authenticate",
    "login_and_set_session",
    "set_current_role",
    "session_as",
    "login",
    "logout",
    "current_role",
    "current_role_id",
    "current_username",
    "add_role",
    "edit_role",
    "delete_role",
    "get_roles",
    # permissions
    "permission_key",
    "permission_required",
    "role_required",
    "list_registered_permissions",
    "check_permission_for_role_id",
    "check_permission",
    "require_login",
    "require_permission",
    "NotAuthenticated",
    "PermissionDenied",
    # admin
    "open_admin_panel",
    "MANAGE_PERMISSION_KEY",
    "MANAGE_PERMISSION_LABEL",
    # validators
    "RolesValidationError",
    "PermissionsValidationError",
    "validate_roles_file",
    "validate_permissions_file",
]


def validate_roles_file(path: str, *, strict: bool = True) -> None:
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    validate_roles_data(raw, strict=strict)


def validate_permissions_file(path: str) -> None:
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    validate_permissions_data(raw)
