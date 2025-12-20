from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime
from typing import Any


def ensure_parent_dir(path: str) -> None:
    folder = os.path.dirname(os.path.abspath(path))
    if folder and not os.path.exists(folder):
        os.makedirs(folder, exist_ok=True)


def atomic_write_json(path: str, data: Any) -> None:
    """Write JSON atomically (write temp + fsync + replace)."""
    ensure_parent_dir(path)
    folder = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".roleperm_", suffix=".tmp", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass


def backup_file(path: str, *, suffix: str = "corrupt") -> None:
    """Move a bad file aside so we can recreate a fresh one."""
    try:
        if not os.path.exists(path):
            return
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = f"{path}.{suffix}.{ts}.bak"
        os.replace(path, backup)
    except OSError:
        pass
