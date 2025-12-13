from __future__ import annotations

from functools import wraps
from typing import Callable, TypeVar, cast

from .auth import current_role

F = TypeVar("F", bound=Callable[..., object])


def role_required(role_id: int) -> Callable[[F], F]:
    """
    Decorator enforcing that the current session role has the required role_id.

    - Not logged in -> PermissionError
    - Wrong role -> PermissionError
    """
    required = int(role_id)

    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args, **kwargs):
            r = current_role()
            if r is None:
                raise PermissionError("Not logged in.")
            if r.id != required:
                raise PermissionError(
                    f"Unauthorized: role '{r.name}' (id={r.id}) cannot access '{func.__name__}'. Required id={required}."
                )
            return func(*args, **kwargs)

        return cast(F, wrapper)

    return decorator
