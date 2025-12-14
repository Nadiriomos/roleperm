from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional
from .config import resolve_roles_file
from .storage import RoleRecord, load_role_records, save_role_records, find_role_by_name
from .utils import DEFAULT_ITERATIONS, generate_salt_hex, pbkdf2_sha256, verify_pbkdf2_sha256
from .validators import validate_roles_data

@dataclass(frozen=True)
class Role:
    name: str
    id: int

@dataclass(frozen=True)
class Session:
    role: Role

_current_session: Optional[Session]=None

def _set_session(role: Role)->None:
    global _current_session
    _current_session=Session(role=role)

def current_role()->Optional[Role]:
    return None if _current_session is None else _current_session.role

def current_role_id()->Optional[int]:
    r=current_role()
    return None if r is None else r.id

def current_username()->Optional[str]:
    r=current_role()
    return None if r is None else r.name

def logout()->None:
    global _current_session
    _current_session=None

def authenticate(username: str, password: str, *, roles_file: Optional[str]=None)->Role:
    path=resolve_roles_file(roles_file)
    rec=find_role_by_name(path, username)
    if rec is None: raise ValueError("Unknown username.")
    if rec.kdf!="pbkdf2_sha256": raise ValueError("Unsupported password hashing method in roles file.")
    if not verify_pbkdf2_sha256(password, rec.salt, rec.password_hash, rec.iterations):
        raise ValueError("Incorrect password.")
    return Role(name=rec.name, id=rec.id)

def add_role(name: str, role_id: int, password: str, *, roles_file: Optional[str]=None)->Role:
    path=resolve_roles_file(roles_file)
    name=name.strip()
    if not name: raise ValueError("Role name cannot be empty.")
    if not isinstance(role_id,int): raise ValueError("role_id must be an int.")
    roles=load_role_records(path)
    if any(r.id==role_id for r in roles): raise ValueError(f"Role id {role_id} already exists.")
    if any(r.name.strip().lower()==name.lower() for r in roles): raise ValueError(f"Role name '{name}' already exists.")
    salt=generate_salt_hex()
    pw_hash=pbkdf2_sha256(password, salt, DEFAULT_ITERATIONS)
    rec=RoleRecord(name=name,id=role_id,kdf="pbkdf2_sha256",iterations=DEFAULT_ITERATIONS,salt=salt,password_hash=pw_hash)
    roles.append(rec)
    validate_roles_data([r.__dict__ for r in roles], strict=True)
    save_role_records(path, roles)
    return Role(name=name,id=role_id)

def edit_role(role_id: int, *, new_name: Optional[str]=None, new_password: Optional[str]=None, roles_file: Optional[str]=None)->Role:
    path=resolve_roles_file(roles_file)
    roles=load_role_records(path)
    rec=next((r for r in roles if r.id==role_id), None)
    if rec is None: raise ValueError(f"Role id {role_id} not found.")
    name=rec.name; salt=rec.salt; pw_hash=rec.password_hash; iterations=rec.iterations; kdf=rec.kdf
    if new_name is not None:
        nn=new_name.strip()
        if not nn: raise ValueError("new_name cannot be empty.")
        if any(r.id!=role_id and r.name.strip().lower()==nn.lower() for r in roles):
            raise ValueError(f"Role name '{nn}' already exists.")
        name=nn
    if new_password is not None:
        salt=generate_salt_hex(); iterations=DEFAULT_ITERATIONS; kdf="pbkdf2_sha256"; pw_hash=pbkdf2_sha256(new_password, salt, iterations)
    updated=RoleRecord(name=name,id=rec.id,kdf=kdf,iterations=iterations,salt=salt,password_hash=pw_hash)
    roles=[updated if r.id==role_id else r for r in roles]
    validate_roles_data([r.__dict__ for r in roles], strict=True)
    save_role_records(path, roles)
    return Role(name=updated.name,id=updated.id)

def delete_role(role_id: int, *, roles_file: Optional[str]=None)->None:
    path=resolve_roles_file(roles_file)
    roles=load_role_records(path)
    new_roles=[r for r in roles if r.id!=role_id]
    if len(new_roles)==len(roles): raise ValueError(f"Role id {role_id} not found.")
    validate_roles_data([r.__dict__ for r in new_roles], strict=True)
    save_role_records(path, new_roles)

def get_roles(*, roles_file: Optional[str]=None)->List[Role]:
    path=resolve_roles_file(roles_file)
    return [Role(name=r.name,id=r.id) for r in load_role_records(path)]
