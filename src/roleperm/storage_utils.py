from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Optional, Type


def ensure_parent_dir(file_path: str) -> None:
    folder = os.path.dirname(os.path.abspath(file_path))
    if folder and not os.path.exists(folder):
        os.makedirs(folder, exist_ok=True)


def _fsync_dir_best_effort(folder: str) -> None:
    """
    Best-effort directory fsync for durability after atomic replace (POSIX).
    On some platforms this may fail; we intentionally ignore errors.
    """
    try:
        fd = os.open(folder, os.O_DIRECTORY)  # type: ignore[attr-defined]
    except Exception:
        return
    try:
        os.fsync(fd)
    except Exception:
        pass
    finally:
        try:
            os.close(fd)
        except Exception:
            pass


def atomic_write_json(path: str, data: Any) -> None:
    """
    Write JSON to `path` safely:
      - write temp file in same directory
      - fsync file
      - os.replace() into place
      - best-effort fsync directory
    """
    ensure_parent_dir(path)
    folder = os.path.dirname(os.path.abspath(path)) or "."

    fd, tmp_path = tempfile.mkstemp(prefix=".roleperm_", suffix=".tmp", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
        _fsync_dir_best_effort(folder)
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass


def backup_file(path: str, *, suffix: str = "corrupt") -> None:
    """
    Rename file to a timestamped backup:
      <path>.<suffix>.<YYYYmmdd-HHMMSS>.bak
    """
    try:
        if not os.path.exists(path):
            return
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = f"{path}.{suffix}.{ts}.bak"
        os.replace(path, backup)
    except OSError:
        pass


class FileLock:

    def __init__(self, lock_path: str, *, timeout: float = 5.0, poll: float = 0.05) -> None:
        self.lock_path = lock_path
        self.timeout = timeout
        self.poll = poll
        self._fd: Optional[int] = None

    def __enter__(self) -> "FileLock":
        start = time.monotonic()
        while True:
            try:
                self._fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
                try:
                    os.write(self._fd, str(os.getpid()).encode("utf-8"))
                except Exception:
                    pass
                return self
            except FileExistsError:
                if (time.monotonic() - start) >= self.timeout:
                    raise TimeoutError(f"Could not acquire lock: {self.lock_path}")
                time.sleep(self.poll)

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            if self._fd is not None:
                try:
                    os.close(self._fd)
                except Exception:
                    pass
        finally:
            self._fd = None
            try:
                if os.path.exists(self.lock_path):
                    os.remove(self.lock_path)
            except Exception:
                pass


def load_json_with_recovery(
    path: str,
    *,
    default_factory: Callable[[], Any],
    expected_type: Type[Any],
    empty_suffix: str = "empty",
) -> Any:
    """
    Load JSON from `path` and recover safely on:
      - missing file: write default
      - empty file: backup + write default
      - invalid JSON: backup + write default
      - wrong root type: backup + write default

    Returns the loaded object (or default).
    """
    ensure_parent_dir(path)

    if not os.path.exists(path):
        default = default_factory()
        atomic_write_json(path, default)
        return default

    try:
        if os.path.getsize(path) == 0:
            backup_file(path, suffix=empty_suffix)
            default = default_factory()
            atomic_write_json(path, default)
            return default
    except OSError:
        # If size can't be read, fall through and try json.load
        pass

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except json.JSONDecodeError:
        backup_file(path, suffix="corrupt")
        default = default_factory()
        atomic_write_json(path, default)
        return default
    except Exception:
        # For unexpected I/O errors, return default without destructive changes
        return default_factory()

    if not isinstance(raw, expected_type):
        backup_file(path, suffix="badroot")
        default = default_factory()
        atomic_write_json(path, default)
        return default

    return raw
