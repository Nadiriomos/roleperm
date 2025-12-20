from __future__ import annotations

import json

from .admin_ui import MANAGE_PERMISSION_KEY, MANAGE_PERMISSION_LABEL, open_admin_panel
from .auth import (
    Role,
    add_role,
    authenticate,
    current_role,
    current_role_id,
    current_username,
    delete_role,
    edit_role,
    get_roles,
    logout,
)
from .config import configure, get_paths
from .constants import OWNER_ID, OWNER_NAME
from .permissions import (
    check_permission_for_role_id,
    list_registered_permissions,
    permission_key,
    permission_required,
    role_required,
)
from .ui import login
from .validators import (
    PermissionsValidationError,
    RolesValidationError,
    validate_permissions_data,
    validate_roles_data,
)

__version__ = "0.2.4"

__all__ = [
    "configure",
    "get_paths",
    "Role",
    "authenticate",
    "login",
    "logout",
    "current_role",
    "current_role_id",
    "current_username",
    "add_role",
    "edit_role",
    "delete_role",
    "get_roles",
    "role_required",
    "permission_key",
    "permission_required",
    "check_permission_for_role_id",
    "list_registered_permissions",
    "open_admin_panel",
    "MANAGE_PERMISSION_KEY",
    "MANAGE_PERMISSION_LABEL",
    "OWNER_ID",
    "OWNER_NAME",
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
