"""
roleperm — stdlib-only role permissions for desktop apps.

Public API is intentionally small and stable.
"""

from .auth import (
    DEFAULT_ROLES_FILE,
    add_role,
    edit_role,
    delete_role,
    get_roles,
    authenticate,
    login,
    logout,
    current_role,
    current_role_id,
)
from .permissions import role_required
from .validator import validate_roles_file, RolesValidationError

__all__ = [
    "DEFAULT_ROLES_FILE",
    "add_role",
    "edit_role",
    "delete_role",
    "get_roles",
    "authenticate",
    "login",
    "logout",
    "current_role",
    "current_role_id",
    "role_required",
    "validate_roles_file",
    "RolesValidationError",
]
