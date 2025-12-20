"""Project-wide constants.

Keeping these in one place prevents subtle bugs where modules drift apart
(e.g., multiple OWNER_ID definitions).
"""

from __future__ import annotations

OWNER_ID: int = 0
OWNER_NAME: str = "owner"

MANAGE_PERMISSION_KEY: str = "roleperm.manage"
MANAGE_PERMISSION_LABEL: str = "Manage Roles & Permissions"
