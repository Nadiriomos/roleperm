from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Iterator, List, Optional

from .config import resolve_roles_file
from .storage import RoleRecord, find_role_by_name, load_role_records, save_role_records
from .storage_utils import FileLock
from .utils import DEFAULT_ITERATIONS, generate_salt_hex, pbkdf2_sha256, verify_pbkdf2_sha256
from .validators import RolesValidationError, validate_roles_data

OWNER_ID = 0
OWNER_NAME = "owner"


@dataclass(frozen=True)
class Role:
    name: str
    id: int


@dataclass(frozen=True)
class Session:
    role: Role


# Web-safe session store: each thread/request/task gets its own current role
_current_session: ContextVar[Optional[Session]] = ContextVar("roleperm_current_session", default=None)


def _set_session(role: Role) -> None:
    """Internal setter used by UI/admin modules."""
    _current_session.set(Session(role=role))


def set_current_role(role: Optional[Role]) -> None:
    """
    Public setter: web middleware/integrations should call this per request.
    Pass None to clear.
    """
    _current_session.set(None if role is None else Session(role=role))


def current_role() -> Optional[Role]:
    s = _current_session.get()
    return None if s is None else s.role


def current_role_id() -> Optional[int]:
    r = current_role()
    return None if r is None else r.id


def current_username() -> Optional[str]:
    r = current_role()
    return None if r is None else r.name


def logout() -> None:
    set_current_role(None)


@contextmanager
def session_as(role: Optional[Role]) -> Iterator[None]:
    """
    Temporarily set session within a context (useful for tests or internal flows).
    """
    token = _current_session.set(None if role is None else Session(role=role))
    try:
        yield
    finally:
        _current_session.reset(token)


def _roles_lock_path(roles_path: str) -> str:
    return roles_path + ".lock"


def _validate_loaded_roles(records: List[RoleRecord]) -> None:
    """
    Validate loaded roles structure. We keep strict=True so the file stays clean.
    If you ever need to support legacy formats, we can relax this later.
    """
    validate_roles_data([r.__dict__ for r in records], strict=True)


def authenticate(username: str, password: str, *, roles_file: Optional[str] = None) -> Role:
    """
    Validate credentials against roles.json and return Role on success.
    Raises ValueError on failure.
    """
    path = resolve_roles_file(roles_file)
    username = (username or "").strip()
    if not username:
        raise ValueError("Username cannot be empty.")

    rec = find_role_by_name(path, username)
    if rec is None:
        raise ValueError("Unknown username.")

    if rec.kdf != "pbkdf2_sha256":
        raise ValueError("Unsupported password hashing method in roles file.")

    if not rec.salt or not rec.password_hash:
        raise ValueError("Corrupt role record (missing salt/hash).")

    if not verify_pbkdf2_sha256(password, rec.salt, rec.password_hash, rec.iterations):
        raise ValueError("Incorrect password.")

    return Role(name=rec.name, id=rec.id)


def login_and_set_session(username: str, password: str, *, roles_file: Optional[str] = None) -> Role:
    """Authenticate and set the current session (desktop / simple apps)."""
    role = authenticate(username, password, roles_file=roles_file)
    _set_session(role)
    return role


def add_role(name: str, role_id: int, password: str, *, roles_file: Optional[str] = None) -> Role:
    path = resolve_roles_file(roles_file)
    name = (name or "").strip()

    if not name:
        raise ValueError("Role name cannot be empty.")
    if not isinstance(role_id, int):
        raise ValueError("role_id must be an int.")
    if role_id < 0:
        raise ValueError("role_id must be >= 0.")

    # Owner invariants
    if role_id == OWNER_ID and name.lower() != OWNER_NAME:
        raise ValueError(f"Owner role_id={OWNER_ID} must be named '{OWNER_NAME}'.")

    lock_path = _roles_lock_path(path)
    with FileLock(lock_path, timeout=10.0):
        roles = load_role_records(path)

        # Validate current file before modifying (keeps things clean)
        try:
            _validate_loaded_roles(roles)
        except RolesValidationError as e:
            raise ValueError(f"roles.json is invalid: {e}") from e

        if any(r.id == role_id for r in roles):
            raise ValueError(f"Role id {role_id} already exists.")
        if any(r.name.strip().lower() == name.lower() for r in roles):
            raise ValueError(f"Role name '{name}' already exists.")

        salt = generate_salt_hex()
        pw_hash = pbkdf2_sha256(password, salt, DEFAULT_ITERATIONS)

        rec = RoleRecord(
            name=name,
            id=role_id,
            kdf="pbkdf2_sha256",
            iterations=DEFAULT_ITERATIONS,
            salt=salt,
            password_hash=pw_hash,
        )
        roles.append(rec)

        _validate_loaded_roles(roles)
        save_role_records(path, roles)

    return Role(name=name, id=role_id)


def edit_role(
    role_id: int,
    *,
    new_name: Optional[str] = None,
    new_password: Optional[str] = None,
    roles_file: Optional[str] = None,
) -> Role:
    path = resolve_roles_file(roles_file)

    if not isinstance(role_id, int):
        raise ValueError("role_id must be an int.")

    lock_path = _roles_lock_path(path)
    with FileLock(lock_path, timeout=10.0):
        roles = load_role_records(path)
        try:
            _validate_loaded_roles(roles)
        except RolesValidationError as e:
            raise ValueError(f"roles.json is invalid: {e}") from e

        rec = next((r for r in roles if r.id == role_id), None)
        if rec is None:
            raise ValueError(f"Role id {role_id} not found.")

        name = rec.name
        salt = rec.salt
        pw_hash = rec.password_hash
        iterations = rec.iterations
        kdf = rec.kdf

        if new_name is not None:
            nn = new_name.strip()
            if not nn:
                raise ValueError("new_name cannot be empty.")

            # Owner cannot be renamed away from 'owner'
            if role_id == OWNER_ID and nn.lower() != OWNER_NAME:
                raise ValueError(f"Owner role_id={OWNER_ID} cannot be renamed (must stay '{OWNER_NAME}').")

            if any(r.id != role_id and r.name.strip().lower() == nn.lower() for r in roles):
                raise ValueError(f"Role name '{nn}' already exists.")
            name = nn

        if new_password is not None:
            salt = generate_salt_hex()
            iterations = DEFAULT_ITERATIONS
            kdf = "pbkdf2_sha256"
            pw_hash = pbkdf2_sha256(new_password, salt, iterations)

        updated = RoleRecord(
            name=name,
            id=rec.id,
            kdf=kdf,
            iterations=iterations,
            salt=salt,
            password_hash=pw_hash,
        )

        roles = [updated if r.id == role_id else r for r in roles]

        _validate_loaded_roles(roles)
        save_role_records(path, roles)

    return Role(name=updated.name, id=updated.id)


def delete_role(role_id: int, *, roles_file: Optional[str] = None) -> None:
    path = resolve_roles_file(roles_file)

    if not isinstance(role_id, int):
        raise ValueError("role_id must be an int.")

    if role_id == OWNER_ID:
        raise ValueError("Cannot delete the Owner role.")

    lock_path = _roles_lock_path(path)
    with FileLock(lock_path, timeout=10.0):
        roles = load_role_records(path)
        try:
            _validate_loaded_roles(roles)
        except RolesValidationError as e:
            raise ValueError(f"roles.json is invalid: {e}") from e

        new_roles = [r for r in roles if r.id != role_id]
        if len(new_roles) == len(roles):
            raise ValueError(f"Role id {role_id} not found.")

        _validate_loaded_roles(new_roles)
        save_role_records(path, new_roles)


def get_roles(*, roles_file: Optional[str] = None) -> List[Role]:
    path = resolve_roles_file(roles_file)
    # Read-only: no lock required (atomic writes already prevent partial reads).
    return [Role(name=r.name, id=r.id) for r in load_role_records(path)]