from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Tuple

from .storage import ensure_roles_file, load_roles


_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


class RolesValidationError(ValueError):
    """Raised when a roles file fails validation."""

    def __init__(self, errors: List[str]):
        self.errors = errors
        super().__init__("Invalid roles file:\n" + "\n".join(f"- {e}" for e in errors))


def validate_roles_file(path: str, *, strict: bool = True) -> None:
    """
    Validate a roles JSON file.

    - Ensures JSON is a list of objects.
    - Ensures required fields exist and are well-typed.
    - Ensures role names (case-insensitive) and ids are unique.
    - Ensures PBKDF2 parameters are sane.

    If strict=True (default), unknown fields are allowed, but KDF must be pbkdf2_sha256.
    Raises RolesValidationError on failure.
    """
    ensure_roles_file(path)

    errors: List[str] = []

    # Read raw JSON to validate shape and types before load_roles() normalizes/raises.
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except json.JSONDecodeError as e:
        raise RolesValidationError([f"JSON decode error: {e.msg} (line {e.lineno}, column {e.colno})"]) from None
    except OSError as e:
        raise RolesValidationError([f"Cannot open roles file: {e}"]) from None

    if not isinstance(raw, list):
        raise RolesValidationError(["Root JSON must be a list."])

    seen_ids: Dict[int, int] = {}
    seen_names: Dict[str, int] = {}

    for idx, item in enumerate(raw):
        prefix = f"item #{idx}"

        if not isinstance(item, dict):
            errors.append(f"{prefix}: must be an object/dict.")
            continue

        # Required fields
        for field in ("name", "id", "salt", "password_hash"):
            if field not in item:
                errors.append(f"{prefix}: missing required field '{field}'.")

        name = item.get("name")
        if isinstance(name, str):
            norm_name = name.strip().lower()
            if not norm_name:
                errors.append(f"{prefix}: 'name' cannot be empty.")
            else:
                if norm_name in seen_names:
                    errors.append(f"{prefix}: duplicate role name '{name}' (case-insensitive duplicate of item #{seen_names[norm_name]}).")
                else:
                    seen_names[norm_name] = idx
        elif name is not None:
            errors.append(f"{prefix}: 'name' must be a string.")

        rid = item.get("id")
        rid_int: int | None = None
        if rid is None:
            pass
        else:
            try:
                rid_int = int(rid)
                if rid_int < 0:
                    errors.append(f"{prefix}: 'id' must be >= 0.")
                else:
                    if rid_int in seen_ids:
                        errors.append(f"{prefix}: duplicate role id {rid_int} (duplicate of item #{seen_ids[rid_int]}).")
                    else:
                        seen_ids[rid_int] = idx
            except (TypeError, ValueError):
                errors.append(f"{prefix}: 'id' must be an integer.")

        # Optional PBKDF2 metadata (we validate if present)
        kdf = item.get("kdf", "pbkdf2_sha256")
        if strict and kdf != "pbkdf2_sha256":
            errors.append(f"{prefix}: unsupported kdf '{kdf}'. Expected 'pbkdf2_sha256'.")

        iters = item.get("iterations", 200_000)
        try:
            iters_int = int(iters)
            if iters_int < 50_000:
                errors.append(f"{prefix}: iterations too low ({iters_int}). Minimum is 50000.")
        except (TypeError, ValueError):
            errors.append(f"{prefix}: 'iterations' must be an integer.")

        salt = item.get("salt")
        if isinstance(salt, str):
            s = salt.strip()
            if not s:
                errors.append(f"{prefix}: 'salt' cannot be empty.")
            elif len(s) % 2 != 0 or not _HEX_RE.match(s):
                errors.append(f"{prefix}: 'salt' must be a hex string with even length.")
        elif salt is not None:
            errors.append(f"{prefix}: 'salt' must be a string.")

        ph = item.get("password_hash")
        if isinstance(ph, str):
            h = ph.strip()
            if not h:
                errors.append(f"{prefix}: 'password_hash' cannot be empty.")
            elif not _HEX_RE.match(h):
                errors.append(f"{prefix}: 'password_hash' must be a hex string.")
        elif ph is not None:
            errors.append(f"{prefix}: 'password_hash' must be a string.")

    # Also ensure load_roles doesn't choke on required fields / coercions
    # (this catches cases like a missing key that we already record, but is okay to double-check)
    if not errors:
        try:
            load_roles(path)
        except ValueError as e:
            errors.append(str(e))

    if errors:
        raise RolesValidationError(errors)
