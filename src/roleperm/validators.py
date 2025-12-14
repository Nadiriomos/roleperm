from __future__ import annotations
from typing import Any, List
from .utils import is_hex, MIN_ITERATIONS

class RolesValidationError(ValueError):
    def __init__(self, errors: List[str]):
        super().__init__("Invalid roles file:\n- " + "\n- ".join(errors))
        self.errors=errors

class PermissionsValidationError(ValueError):
    def __init__(self, errors: List[str]):
        super().__init__("Invalid permissions file:\n- " + "\n- ".join(errors))
        self.errors=errors

def validate_roles_data(raw: Any, *, strict: bool=True)->None:
    errors: List[str]=[]
    if not isinstance(raw,list):
        raise RolesValidationError(["Root must be a JSON list."])
    seen_ids=set(); seen_names=set()
    for i,item in enumerate(raw):
        if not isinstance(item,dict):
            errors.append(f"[{i}] Each role must be an object."); continue
        name=item.get("name"); rid=item.get("id")
        salt=item.get("salt"); pw_hash=item.get("password_hash")
        kdf=item.get("kdf","pbkdf2_sha256"); iterations=item.get("iterations",200_000)
        if not isinstance(name,str) or not name.strip():
            errors.append(f"[{i}] 'name' must be a non-empty string.")
        else:
            key=name.strip().lower()
            if key in seen_names: errors.append(f"[{i}] Duplicate role name (case-insensitive): {name!r}.")
            seen_names.add(key)
        if not isinstance(rid,int):
            errors.append(f"[{i}] 'id' must be an integer.")
        else:
            if rid in seen_ids: errors.append(f"[{i}] Duplicate role id: {rid}.")
            seen_ids.add(rid)
        if strict and kdf!="pbkdf2_sha256":
            errors.append(f"[{i}] Unsupported kdf {kdf!r}. Expected 'pbkdf2_sha256'.")
        if not isinstance(iterations,int) or iterations<MIN_ITERATIONS:
            errors.append(f"[{i}] 'iterations' must be int >= {MIN_ITERATIONS}.")
        if not isinstance(salt,str) or not salt or not is_hex(salt) or (len(salt)%2!=0):
            errors.append(f"[{i}] 'salt' must be non-empty even-length hex string.")
        if not isinstance(pw_hash,str) or not pw_hash or not is_hex(pw_hash):
            errors.append(f"[{i}] 'password_hash' must be non-empty hex string.")
    if errors: raise RolesValidationError(errors)

def validate_permissions_data(raw: Any)->None:
    errors: List[str]=[]
    if not isinstance(raw,dict):
        raise PermissionsValidationError(["Root must be a JSON object."])
    schema=raw.get("schema_version"); perms=raw.get("permissions")
    if schema is None or not isinstance(schema,int):
        errors.append("'schema_version' must be an integer.")
    if perms is None:
        errors.append("'permissions' field is required.")
    elif not isinstance(perms,dict):
        errors.append("'permissions' must be an object mapping keys to records.")
    else:
        for key,rec in perms.items():
            if not isinstance(key,str) or not key.strip():
                errors.append("Permission keys must be non-empty strings."); continue
            if not isinstance(rec,dict):
                errors.append(f"Permission {key!r} must be an object."); continue
            label=rec.get("label")
            if label is not None and not isinstance(label,str):
                errors.append(f"Permission {key!r}: 'label' must be a string if present.")
            allowed=rec.get("allowed_role_ids",[])
            if not isinstance(allowed,list):
                errors.append(f"Permission {key!r}: 'allowed_role_ids' must be a list.")
            else:
                for j,rid in enumerate(allowed):
                    if not isinstance(rid,int):
                        errors.append(f"Permission {key!r}: allowed_role_ids[{j}] must be int.")
    if errors: raise PermissionsValidationError(errors)
