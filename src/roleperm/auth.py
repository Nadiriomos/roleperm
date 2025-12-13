from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from .storage import RoleRecord, get_role_by_name, load_roles, save_roles
from .utils import PasswordHash, hash_password, verify_password


DEFAULT_ROLES_FILE = "roles.json"


@dataclass(frozen=True)
class Role:
    """Runtime role (safe to expose; no password material)."""
    name: str
    id: int


@dataclass(frozen=True)
class Session:
    role: Role


_current_session: Optional[Session] = None


def logout() -> None:
    """Clear the current in-memory session."""
    global _current_session
    _current_session = None


def _set_session(role: Role) -> None:
    global _current_session
    _current_session = Session(role=role)


def current_role() -> Optional[Role]:
    """Return the current role (or None if not logged in)."""
    return None if _current_session is None else _current_session.role


def current_role_id() -> Optional[int]:
    r = current_role()
    return None if r is None else r.id


def authenticate(username: str, password: str, *, roles_file: str = DEFAULT_ROLES_FILE) -> Role:
    """
    Headless authentication (no UI).
    Username is the role name in roles.json.
    """
    record = get_role_by_name(roles_file, username)
    if record is None:
        raise ValueError("Unknown username.")

    ph = PasswordHash(
        kdf=record.kdf,
        iterations=record.iterations,
        salt_hex=record.salt,
        hash_hex=record.password_hash,
    )
    if not verify_password(password, ph):
        raise ValueError("Incorrect password.")

    return Role(name=record.name, id=record.id)


def login(*, title: str = "Login", roles_file: str = DEFAULT_ROLES_FILE, logo_text: Optional[str] = None) -> Role:
    """
    Tkinter login popup.
    On success: sets current session and returns Role.
    """
    from .ui import login_popup  # import lazily so headless environments can still use the lib

    role = login_popup(title=title, roles_file=roles_file, logo_text=logo_text)
    _set_session(role)
    return role


def get_roles(*, roles_file: str = DEFAULT_ROLES_FILE) -> List[Role]:
    """Return roles (without password material)."""
    return [Role(name=r.name, id=r.id) for r in load_roles(roles_file)]


def add_role(name: str, role_id: int, password: str, *, roles_file: str = DEFAULT_ROLES_FILE) -> Role:
    """
    Add a new role record. Role name and id must be unique.
    """
    name = name.strip()
    if not name:
        raise ValueError("Role name cannot be empty.")

    roles = load_roles(roles_file)
    if any(r.id == int(role_id) for r in roles):
        raise ValueError(f"Role id {role_id} already exists.")
    if any(r.name.strip().lower() == name.lower() for r in roles):
        raise ValueError(f"Role name '{name}' already exists.")

    ph = hash_password(password)
    record = RoleRecord(
        name=name,
        id=int(role_id),
        kdf=ph.kdf,
        iterations=ph.iterations,
        salt=ph.salt_hex,
        password_hash=ph.hash_hex,
    )
    roles.append(record)
    save_roles(roles_file, roles)
    return Role(name=name, id=int(role_id))


def edit_role(
    role_id: int,
    *,
    new_name: Optional[str] = None,
    new_password: Optional[str] = None,
    roles_file: str = DEFAULT_ROLES_FILE,
) -> Role:
    """
    Edit role name and/or password.
    """
    roles = load_roles(roles_file)
    idx = next((i for i, r in enumerate(roles) if r.id == int(role_id)), None)
    if idx is None:
        raise ValueError(f"Role id {role_id} not found.")

    current = roles[idx]
    name = current.name
    if new_name is not None:
        nn = new_name.strip()
        if not nn:
            raise ValueError("new_name cannot be empty.")
        if any(r.id != int(role_id) and r.name.strip().lower() == nn.lower() for r in roles):
            raise ValueError(f"Role name '{nn}' already exists.")
        name = nn

    if new_password is not None:
        ph = hash_password(new_password)
        updated = RoleRecord(
            name=name,
            id=current.id,
            kdf=ph.kdf,
            iterations=ph.iterations,
            salt=ph.salt_hex,
            password_hash=ph.hash_hex,
        )
    else:
        updated = RoleRecord(
            name=name,
            id=current.id,
            kdf=current.kdf,
            iterations=current.iterations,
            salt=current.salt,
            password_hash=current.password_hash,
        )

    roles[idx] = updated
    save_roles(roles_file, roles)
    return Role(name=updated.name, id=updated.id)


def delete_role(role_id: int, *, roles_file: str = DEFAULT_ROLES_FILE) -> None:
    roles = load_roles(roles_file)
    new_roles = [r for r in roles if r.id != int(role_id)]
    if len(new_roles) == len(roles):
        raise ValueError(f"Role id {role_id} not found.")
    save_roles(roles_file, new_roles)
