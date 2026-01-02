from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

DEFAULT_DATA_DIR_NAME = "roleperm"

# Environment variables (nice for Docker / systemd / hosting panels)
ENV_DATA_DIR = "ROLEPERM_DATA_DIR"     # full directory path (highest priority)
ENV_BASE_DIR = "ROLEPERM_BASE_DIR"     # base directory that will contain data_dir_name[/app_name]
ENV_APP_NAME = "ROLEPERM_APP_NAME"     # optional namespace folder name


@dataclass(frozen=True)
class RolePermPaths:
    """
    Resolved filesystem locations used by roleperm.

    - base_dir: folder that contains data_dir
    - data_dir: folder containing roles.json and permissions.json
    """
    base_dir: str
    data_dir: str
    roles_file: str
    permissions_file: str


_paths: Optional[RolePermPaths] = None


def _abspath(p: str) -> str:
    return os.path.abspath(os.path.expanduser(p))


def _sanitize_component(name: str) -> str:
    """
    Sanitize a folder name component to avoid path traversal / weird separators.
    Keeps: letters, numbers, dot, dash, underscore.
    """
    name = name.strip()
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
    return name.strip("._-") or "app"


def _platform_user_data_home() -> str:
    """
    A reasonable per-user data root (stdlib-only).
    Linux:  $XDG_DATA_HOME or ~/.local/share
    macOS:  ~/Library/Application Support
    Windows: %APPDATA% or ~/AppData/Roaming
    """
    if os.name == "nt":
        return os.environ.get("APPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Roaming")
    if sys.platform == "darwin":
        return os.path.join(os.path.expanduser("~"), "Library", "Application Support")
    return os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")


def _guess_base_dir() -> str:
    """
    Legacy fallback: try script directory, else __main__.__file__, else CWD.
    Good for desktop scripts, not ideal for servers (so it's the LAST fallback).
    """
    argv0 = sys.argv[0] if sys.argv else ""
    if argv0 and os.path.exists(argv0):
        try:
            return os.path.dirname(os.path.abspath(argv0)) or os.getcwd()
        except OSError:
            return os.getcwd()

    main_mod = sys.modules.get("__main__")
    main_file = getattr(main_mod, "__file__", None)
    if isinstance(main_file, str) and os.path.exists(main_file):
        lf = main_file.lower()
        if "site-packages" in lf or "dist-packages" in lf:
            return os.getcwd()
        return os.path.dirname(os.path.abspath(main_file)) or os.getcwd()

    return os.getcwd()


def _build_paths(
    *,
    app_name: Optional[str],
    base_dir: Optional[str],
    data_dir: Optional[str],
    data_dir_name: str,
    use_user_data_dir: bool,
) -> RolePermPaths:
    # Priority 1: explicit data_dir argument
    if data_dir:
        dd = Path(_abspath(data_dir))
        bd = dd.parent
        roles_file = dd / "roles.json"
        permissions_file = dd / "permissions.json"
        return RolePermPaths(
            base_dir=str(bd),
            data_dir=str(dd),
            roles_file=str(roles_file),
            permissions_file=str(permissions_file),
        )

    # Priority 2: env var ROLEPERM_DATA_DIR
    env_data_dir = os.environ.get(ENV_DATA_DIR)
    if env_data_dir:
        dd = Path(_abspath(env_data_dir))
        bd = dd.parent
        return RolePermPaths(
            base_dir=str(bd),
            data_dir=str(dd),
            roles_file=str(dd / "roles.json"),
            permissions_file=str(dd / "permissions.json"),
        )

    # app_name can come from argument or env
    eff_app_name = app_name or os.environ.get(ENV_APP_NAME)
    app_component = _sanitize_component(eff_app_name) if eff_app_name else None

    # Priority 3: explicit base_dir argument
    eff_base_dir = base_dir or os.environ.get(ENV_BASE_DIR)

    # Priority 4: user data dir (opt-in)
    if eff_base_dir is None and use_user_data_dir:
        eff_base_dir = _platform_user_data_home()

    # Priority 5: legacy fallback (script dir/cwd)
    if eff_base_dir is None:
        eff_base_dir = _guess_base_dir()

    bd = Path(_abspath(eff_base_dir))

    # If app_name provided, namespace under base_dir
    if app_component:
        bd = bd / app_component

    dd = bd / data_dir_name
    return RolePermPaths(
        base_dir=str(bd),
        data_dir=str(dd),
        roles_file=str(dd / "roles.json"),
        permissions_file=str(dd / "permissions.json"),
    )


def configure(
    *,
    app_name: Optional[str] = None,
    base_dir: Optional[str] = None,
    data_dir: Optional[str] = None,
    data_dir_name: str = DEFAULT_DATA_DIR_NAME,
    use_user_data_dir: bool = False,
) -> RolePermPaths:
    """
    Configure where roleperm stores its JSON files.

    Best practice for web apps:
      - pass data_dir explicitly (e.g. /var/lib/myapp/roleperm)
      - OR set ROLEPERM_DATA_DIR in the environment

    Resolution priority:
      1) data_dir argument
      2) ROLEPERM_DATA_DIR
      3) base_dir argument / ROLEPERM_BASE_DIR
      4) if use_user_data_dir=True: platform user data directory
      5) legacy fallback: script dir / __main__.__file__ / cwd

    If app_name is set, roleperm namespaces under base_dir:
      base_dir/<app_name>/<data_dir_name>/
    """
    global _paths
    if not isinstance(data_dir_name, str) or not data_dir_name.strip():
        raise ValueError("data_dir_name must be a non-empty string.")
    _paths = _build_paths(
        app_name=app_name,
        base_dir=base_dir,
        data_dir=data_dir,
        data_dir_name=data_dir_name.strip(),
        use_user_data_dir=use_user_data_dir,
    )
    return _paths


def get_paths() -> RolePermPaths:
    global _paths
    if _paths is None:
        _paths = configure()
    return _paths


def resolve_roles_file(path: Optional[str]) -> str:
    return path if isinstance(path, str) and path else get_paths().roles_file


def resolve_permissions_file(path: Optional[str]) -> str:
    return path if isinstance(path, str) and path else get_paths().permissions_file