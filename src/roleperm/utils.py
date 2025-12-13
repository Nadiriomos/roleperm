from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Final


# ---- Password hashing (stdlib-only) ----
# We use PBKDF2-HMAC-SHA256, which is available in Python's stdlib via hashlib.
DEFAULT_KDF: Final[str] = "pbkdf2_sha256"
DEFAULT_ITERATIONS: Final[int] = 200_000
SALT_BYTES: Final[int] = 16
HASH_BYTES: Final[int] = 32  # 32 bytes -> 64 hex chars


@dataclass(frozen=True)
class PasswordHash:
    kdf: str
    iterations: int
    salt_hex: str
    hash_hex: str


def generate_salt_hex(nbytes: int = SALT_BYTES) -> str:
    """Generate a cryptographically secure salt (hex string)."""
    return secrets.token_hex(nbytes)


def pbkdf2_sha256(password: str, salt_hex: str, iterations: int = DEFAULT_ITERATIONS) -> str:
    """
    Return a hex-encoded PBKDF2-HMAC-SHA256 digest.

    We hex-decode the salt and derive HASH_BYTES bytes.
    """
    if not isinstance(password, str) or password == "":
        raise ValueError("Password must be a non-empty string.")
    if not isinstance(salt_hex, str) or salt_hex == "":
        raise ValueError("salt_hex must be a non-empty string.")
    if not isinstance(iterations, int) or iterations < 50_000:
        # Keep a floor to avoid accidental weak configs.
        raise ValueError("iterations must be an int >= 50000.")

    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=HASH_BYTES)
    return dk.hex()


def hash_password(password: str, *, iterations: int = DEFAULT_ITERATIONS) -> PasswordHash:
    """Create a new salt and return a PasswordHash record."""
    salt_hex = generate_salt_hex()
    hash_hex = pbkdf2_sha256(password, salt_hex, iterations)
    return PasswordHash(kdf=DEFAULT_KDF, iterations=iterations, salt_hex=salt_hex, hash_hex=hash_hex)


def verify_password(password: str, ph: PasswordHash) -> bool:
    """
    Constant-time password verification.

    Uses hmac.compare_digest to mitigate timing attacks.
    """
    if ph.kdf != DEFAULT_KDF:
        raise ValueError(f"Unsupported kdf '{ph.kdf}'.")
    computed = pbkdf2_sha256(password, ph.salt_hex, ph.iterations)
    return hmac.compare_digest(computed, ph.hash_hex)
