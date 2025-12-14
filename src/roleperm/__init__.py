from .auth import (
    DEFAULT_ROLES_FILE,
    Role,
    authenticate,
    add_role,
    edit_role,
    delete_role,
    get_roles,
    current_role,
    current_role_id,
    logout,
)
from .ui import login
from .permissions import (
    DEFAULT_PERMISSIONS_FILE,
    role_required,
    permission_key,
    permission_required,
    list_registered_permissions,
)
from .admin_ui import open_admin_panel
from .validators import (
    RolesValidationError,
    PermissionsValidationError,
    validate_roles_data,
    validate_permissions_data,
)
import json

__all__ = [
    "DEFAULT_ROLES_FILE",
    "DEFAULT_PERMISSIONS_FILE",
    "Role",
    "authenticate",
    "login",
    "logout",
    "current_role",
    "current_role_id",
    "add_role",
    "edit_role",
    "delete_role",
    "get_roles",
    "role_required",
    "permission_key",
    "permission_required",
    "list_registered_permissions",
    "open_admin_panel",
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
