from .config import configure, get_paths
from .auth import Role, authenticate, add_role, edit_role, delete_role, get_roles, current_role, current_role_id, current_username, logout
from .ui import login
from .permissions import role_required, permission_key, permission_required, list_registered_permissions, check_permission_for_role_id
from .admin_ui import open_admin_panel, MANAGE_PERMISSION_KEY, MANAGE_PERMISSION_LABEL
from .validators import RolesValidationError, PermissionsValidationError, validate_roles_data, validate_permissions_data
import json

__version__ = "0.2.3"

__all__=[
    "configure","get_paths","Role","authenticate","login","logout","current_role","current_role_id","current_username",
    "add_role","edit_role","delete_role","get_roles",
    "role_required","permission_key","permission_required","check_permission_for_role_id","list_registered_permissions",
    "open_admin_panel","MANAGE_PERMISSION_KEY","MANAGE_PERMISSION_LABEL",
    "RolesValidationError","PermissionsValidationError","validate_roles_file","validate_permissions_file",
]

def validate_roles_file(path: str, *, strict: bool=True)->None:
    with open(path,"r",encoding="utf-8") as f:
        raw=json.load(f)
    validate_roles_data(raw, strict=strict)

def validate_permissions_file(path: str)->None:
    with open(path,"r",encoding="utf-8") as f:
        raw=json.load(f)
    validate_permissions_data(raw)
