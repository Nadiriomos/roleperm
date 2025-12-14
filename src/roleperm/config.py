from __future__ import annotations
import os, sys
from dataclasses import dataclass
from typing import Optional

_DEFAULT_DATA_DIR_NAME="roleperm"

@dataclass(frozen=True)
class RolePermPaths:
    base_dir: str
    data_dir: str
    roles_file: str
    permissions_file: str

_paths: Optional[RolePermPaths]=None

def _guess_base_dir() -> str:
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

def configure(*, app_name: Optional[str]=None, base_dir: Optional[str]=None, data_dir_name: str=_DEFAULT_DATA_DIR_NAME) -> RolePermPaths:
    global _paths
    if base_dir is None:
        base_dir=_guess_base_dir()
    base_dir=os.path.abspath(base_dir)
    data_dir=os.path.join(base_dir, data_dir_name)
    roles_file=os.path.join(data_dir,"roles.json")
    permissions_file=os.path.join(data_dir,"permissions.json")
    _paths=RolePermPaths(base_dir=base_dir,data_dir=data_dir,roles_file=roles_file,permissions_file=permissions_file)
    return _paths

def get_paths() -> RolePermPaths:
    global _paths
    if _paths is None:
        _paths=configure()
    return _paths

def resolve_roles_file(path: Optional[str]) -> str:
    return path if isinstance(path,str) and path else get_paths().roles_file

def resolve_permissions_file(path: Optional[str]) -> str:
    return path if isinstance(path,str) and path else get_paths().permissions_file
