# roleperm Use Guide (v0.2.4)

Stdlib-only, JSON-backed **roles + permissions** for Python apps.

This guide is intentionally practical: it explains *how to wire roleperm into your app* from first run → login → password storage → permission checks → admin UI.

---

## Table of contents

- [Core concepts](#core-concepts)
- [Desktop Apps](#desktop-apps)
  - [Install](#install)
  - [Pick where JSON files live](#pick-where-json-files-live)
  - [First run and the Owner account](#first-run-and-the-owner-account)
  - [Create roles (users)](#create-roles-users)
  - [Login](#login)
  - [Check access in your code](#check-access-in-your-code)
  - [Register permissions for the Admin Panel](#register-permissions-for-the-admin-panel)
  - [Open the Admin Panel](#open-the-admin-panel)
  - [Understanding the data files](#understanding-the-data-files)
  - [Validation and auto-recovery](#validation-and-auto-recovery)
  - [Password hashing (what is stored)](#password-hashing-what-is-stored)
  - [Troubleshooting](#troubleshooting)
- [Web Apps](#web-apps)
  - [Important warning about sessions](#important-warning-about-sessions)
  - [Recommended pattern for web](#recommended-pattern-for-web)
  - [Flask example](#flask-example)
  - [FastAPI example](#fastapi-example)
  - [Django example](#django-example)
  - [Concurrency & deployment notes](#concurrency--deployment-notes)
- [Public API reference](#public-api-reference)

---

## Core concepts

### Roles
A **role** is the thing your user logs in as. It has:

- `name`: a unique role name (used as the login username)
- `id`: an integer role id

A role is returned as a simple dataclass:

```python
@dataclass(frozen=True)
class Role:
    name: str
    id: int
```

### The Owner (id=0)
roleperm reserves a special role:

- **Owner role name:** `owner`
- **Owner role id:** `0`

Owner is a super-user:

- Owner bypasses `role_required(...)`
- Owner bypasses `permission_required(...)`
- Owner can always open the Admin Panel (even if `roleperm.manage` is not granted)

**Important:** In the shipped v0.2.4 code, when the *only* role is the Owner, `login()` currently sets the session as owner immediately (no password prompt). If you want a password prompt in that scenario, see the security note under [Troubleshooting](#troubleshooting).

### Permissions
A **permission** is a string key like:

- `view_stock`
- `edit_students`
- `roleperm.manage` (built-in: controls access to the Admin Panel)

Permissions are stored in `permissions.json` as:
- key → `{ label, allowed_role_ids }`

Example:

```json
{
  "schema_version": 1,
  "permissions": {
    "view_stock": {
      "label": "View Stock",
      "allowed_role_ids": [2, 5]
    }
  }
}
```

### Session (desktop apps)
roleperm keeps the “current logged-in role” in **memory only** (no `state.json` file).

- `login()` sets the in-memory session
- `current_role_id()` / `current_username()` read it
- `logout()` clears it

This is great for desktop apps, but is **not safe for multi-user web servers** (see [Web Apps](#web-apps)).

---

# Desktop Apps

## Install

### From PyPI

```bash
pip install roleperm
```

### Optional UI dependencies

The core library is stdlib-only, but the Admin Panel can be rendered using:

- **tkinter (default)**: usually ships with Python on Windows/macOS/Linux
- **CustomTkinter**: install separately
  ```bash
  pip install customtkinter
  ```
- **PySide6 (Qt)**: install separately
  ```bash
  pip install PySide6
  ```

---

## Pick where JSON files live

roleperm stores two files:

- `roles.json` (users + hashed passwords)
- `permissions.json` (permission matrix)

You can control the folder with `configure()`:

```python
import roleperm as rp

rp.configure(base_dir=".", data_dir_name="roleperm")
# => ./roleperm/roles.json and ./roleperm/permissions.json
```

### Recommended: choose a writable app-data folder
In packaged apps (PyInstaller, etc.), the script directory may be read-only. Prefer a writable location, for example:

- Windows: `%APPDATA%/YourApp/`
- Linux: `~/.local/share/YourApp/`
- macOS: `~/Library/Application Support/YourApp/`

You can pass that path as `base_dir=...` and optionally keep `data_dir_name="roleperm"`.

### `app_name`
`login(app_name=...)` calls `configure(app_name=...)`.

In v0.2.4, `app_name` is accepted but not used to change paths (paths are controlled by `base_dir` + `data_dir_name`). It is kept for forward compatibility.

---

## First run and the Owner account

On first run, if `roles.json` is missing/empty/corrupt, roleperm will create it and (by default) offer an **Owner setup** dialog:

- “Create master password”
- “Confirm master password”

This creates the Owner role (`owner`, id `0`) and logs you in as Owner.

You can disable Owner setup by calling:

```python
rp.login(owner_setup=False)
```

…but in most apps you want Owner setup enabled.

---

## Create roles (users)

A “user” in roleperm is simply a role record. You create it via `add_role()`:

```python
import roleperm as rp

rp.configure(base_dir=".")
rp.add_role("admin", 2, "admin123")
rp.add_role("teacher", 3, "teach123")
```

Rules:

- role names are case-insensitive unique
- role ids are unique integers
- role id `0` is reserved for Owner

### Edit or delete roles

```python
rp.edit_role(3, new_name="Teacher", new_password="newpass")
rp.delete_role(3)
```

### List roles

```python
roles = rp.get_roles()
for r in roles:
    print(r.id, r.name)
```

---

## Login

### Typical login (shows a popup)
In desktop apps, you typically do:

```python
role = rp.login(title="My App Login", logo_text="My App")
if role is None:
    # user cancelled, or no roles exist
    raise SystemExit(0)

print("Logged in as", role.name, role.id)
```

Login behavior:

- If **no roles exist**, `login()` returns `None` and shows no popup.
- If user closes the popup, `login()` returns `None`.
- On success, `login()` returns a `Role` and sets the in-memory session.

### Login without the popup (advanced)
If you already collected username/password elsewhere:

```python
from roleperm.auth import _set_session

role = rp.authenticate("admin", "admin123")
_set_session(role)
```

This is used by the test suite and can be useful if you build your own UI.

---

## Check access in your code

roleperm gives you 2 main decorators.

### `@role_required(role_id)`
Use when a single role id is allowed.

```python
@rp.role_required(2)  # only role id 2 (and Owner)
def admin_only_action():
    ...
```

### `@permission_required("perm.key")`
Use when access is controlled via `permissions.json`.

```python
@rp.permission_required("view_stock", default_allow=False)
def view_stock():
    ...
```

- If no one is logged in: raises `PermissionError("Not logged in.")`
- If logged in role is Owner: always allowed
- Otherwise: checks `permissions.json`

---

## Register permissions for the Admin Panel

The Admin Panel only shows permissions that were *explicitly registered*.

Register a permission key with `permission_key()`:

```python
@rp.permission_key("view_stock", label="View Stock")
@rp.permission_required("view_stock", default_allow=False)
def view_stock():
    ...
```

Notes:
- `label` is what the Admin Panel displays.
- Duplicate keys are ignored (first registration wins).
- Registration happens when that Python code is imported/run. If a permission doesn’t show up in the Admin Panel, make sure the module defining it is imported.

### List registered permissions (debugging)

```python
reg = rp.list_registered_permissions()
print(reg.keys())
```

---

## Open the Admin Panel

The Admin Panel is a UI for:

- Adding/editing/deleting roles (Owner hidden)
- Assigning permission keys to roles
- Resetting Owner password (Owner-only button)

### Minimal example

```python
rp.open_admin_panel()
```

### The `roleperm.manage` permission
Opening the admin panel is protected by the built-in permission key:

- key: `roleperm.manage`
- label: `Manage Roles & Permissions`

The first time you call `open_admin_panel()`, roleperm ensures this permission exists in `permissions.json`.

If the current role is not Owner, it must have `roleperm.manage` allowed in `permissions.json`, otherwise `open_admin_panel()` returns `False`.

### Force re-authentication

```python
rp.open_admin_panel(require_reauth=True)
```

This always prompts for username/password before opening the panel (unless only the Owner exists).

### Choose UI backend: `ui="tk" | "ctk" | "qt"`

```python
rp.open_admin_panel(ui="tk")   # default
rp.open_admin_panel(ui="ctk")  # requires: pip install customtkinter
rp.open_admin_panel(ui="qt")   # requires: pip install PySide6
```

### Embed vs popup

```python
rp.open_admin_panel(mode="popup")      # default
rp.open_admin_panel(mode="embed", parent=some_parent_widget)
```

- In tkinter mode, `parent` is expected to be a tkinter widget.
- In Qt mode, `parent` must be a QWidget.
- In CustomTkinter mode, `parent` should be a tkinter/CTk widget.

If embedding fails for `ctk` or `qt`, the dispatcher silently falls back to a popup.

---

## Understanding the data files

### roles.json

`roles.json` is a JSON **list**. Each item is a record:

```json
[
  {
    "name": "admin",
    "id": 2,
    "kdf": "pbkdf2_sha256",
    "iterations": 200000,
    "salt": "ab12cd...",
    "password_hash": "9f83aa..."
  }
]
```

The `kdf/iterations/salt/password_hash` fields are used by `authenticate()`.

### permissions.json

`permissions.json` is a JSON **object**:

```json
{
  "schema_version": 1,
  "permissions": {
    "view_stock": { "label": "View Stock", "allowed_role_ids": [2] },
    "roleperm.manage": { "label": "Manage Roles & Permissions", "allowed_role_ids": [2] }
  }
}
```

- `allowed_role_ids` is a list of ints.
- Owner is not normally listed/edited in the Admin Panel.

---

## Validation and auto-recovery

roleperm validates the JSON schema (types, required fields) on load/save.

### Auto-recovery
If `roles.json` or `permissions.json` is:

- missing → created
- empty → backed up and recreated
- invalid JSON → backed up and recreated
- wrong root type → backed up and recreated

Backups are created next to the file with suffixes like:

- `.corrupt.<timestamp>`
- `.empty.<timestamp>`
- `.badroot.<timestamp>`

### Manual validation

```python
rp.validate_roles_file("path/to/roles.json", strict=True)
rp.validate_permissions_file("path/to/permissions.json")
```

---

## Password hashing (what is stored)

roleperm uses:

- Algorithm: **PBKDF2-HMAC-SHA256**
- Salt: random, stored as hex
- Default iterations: **200,000**
- Minimum iterations: **50,000**

Only the derived hash and salt are stored in `roles.json`. The raw password is never stored.

---

## Troubleshooting

### “I added a permission but it doesn't show in the Admin Panel”
Permissions only appear if registered via `@permission_key(...)`.

Make sure the module containing the decorated function is imported before opening the Admin Panel.

### “Owner-only install logs in without asking password”
In v0.2.4, `login()` sets the session to Owner immediately when it detects only the owner exists, even though the project changelog mentions a password-only prompt.

If you need the password prompt right now, the simplest safe workaround is:

- Don't rely on the “owner-only shortcut”
- Add at least one non-owner role, or
- Use `open_admin_panel(require_reauth=True)` for sensitive actions, or
- Implement a password-only dialog in your app and use `rp.authenticate("owner", password)` + `roleperm.auth._set_session(role)`.

### “PermissionError: Not logged in.”
Call `rp.login()` (or set the session manually) before using permission decorators.

### “CustomTkinter is not installed” / “PySide6 is not installed”
Install the optional UI dependency:

```bash
pip install customtkinter
pip install PySide6
```

---

# Web Apps

## Important warning about sessions

roleperm’s built-in session is a **single global variable** in process memory.

That means:
- it is not per-request,
- not per-user,
- not thread-safe,
- and not safe for a multi-user web server.

So for web apps you should:
- use `authenticate()` for login,
- store `role_id` in your framework’s session/JWT/etc,
- and use `check_permission_for_role_id(role_id, key)` for authorization.

---

## Recommended pattern for web

### Login flow (common to all frameworks)

1. User submits username/password
2. You call:

```python
role = rp.authenticate(username, password)
```

3. Store `role.id` somewhere per-user (session cookie, server session, JWT claim, etc.)
4. On each request, load role_id and enforce:

```python
ok = rp.check_permission_for_role_id(role_id, "some.permission", default_allow_missing=False)
```

---

## Flask example

```python
from flask import Flask, request, session, abort
import roleperm as rp

app = Flask(__name__)
app.secret_key = "change-me"

rp.configure(base_dir="/var/lib/myapp")  # wherever you want roles/permissions stored

def require_perm(key: str):
    def deco(fn):
        def wrapper(*args, **kwargs):
            rid = session.get("role_id")
            if rid is None:
                abort(401)
            if not rp.check_permission_for_role_id(int(rid), key, default_allow_missing=False):
                abort(403)
            return fn(*args, **kwargs)
        wrapper.__name__ = fn.__name__
        return wrapper
    return deco

@app.post("/login")
def login_route():
    u = request.form["username"]
    p = request.form["password"]
    role = rp.authenticate(u, p)
    session["role_id"] = role.id
    return "ok"

@app.get("/stock")
@require_perm("view_stock")
def stock():
    return "stock"
```

---

## FastAPI example

```python
from fastapi import FastAPI, Depends, HTTPException, Request
import roleperm as rp

app = FastAPI()
rp.configure(base_dir="/var/lib/myapp")

def require_perm(key: str):
    def dep(request: Request):
        rid = request.cookies.get("role_id")
        if rid is None:
            raise HTTPException(status_code=401, detail="Not logged in")
        ok = rp.check_permission_for_role_id(int(rid), key, default_allow_missing=False)
        if not ok:
            raise HTTPException(status_code=403, detail="Forbidden")
        return True
    return dep

@app.get("/stock")
def stock(_ok: bool = Depends(require_perm("view_stock"))):
    return {"ok": True}
```

In real apps, replace the cookie with:
- your session middleware,
- a signed cookie,
- or a JWT with a `role_id` claim.

---

## Django example

```python
from django.http import HttpResponseForbidden
from functools import wraps
import roleperm as rp

rp.configure(base_dir="/var/lib/myapp")

def require_perm(key: str):
    def deco(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            rid = request.session.get("role_id")
            if rid is None:
                return HttpResponseForbidden("Not logged in")
            if not rp.check_permission_for_role_id(int(rid), key, default_allow_missing=False):
                return HttpResponseForbidden("Forbidden")
            return view_func(request, *args, **kwargs)
        return wrapper
    return deco

@require_perm("view_stock")
def stock_view(request):
    return HttpResponse("stock")
```

---

## Concurrency & deployment notes

- roleperm writes JSON atomically (write temp file then replace), which prevents partial writes.
- But it does **not** implement file locking. Two processes saving at the same time can still cause “last write wins”.

For web deployments:
- Prefer a single process for role/permission admin changes, OR
- Add file locking around writes in your integration layer, OR
- Move role/permission storage to a real database (future roadmap).

---

# Public API reference

Everything below is importable from `import roleperm as rp`.

## Configuration

### `configure(app_name=None, base_dir=None, data_dir_name="roleperm") -> RolePermPaths`
Sets the default file locations.

- If `base_dir` is omitted, roleperm guesses a base directory from your script path / CWD.
- Returns a `RolePermPaths` dataclass with `.roles_file` and `.permissions_file`.

### `get_paths() -> RolePermPaths`
Returns the current paths (calls `configure()` with defaults if needed).

---

## Authentication + session

### `login(...) -> Role | None`
Shows a tkinter login popup, sets in-memory session on success.

Parameters:
- `title`: window title
- `app_name`: passed into `configure(app_name=...)` (v0.2.4 keeps this for compatibility)
- `roles_file`: override roles.json path
- `logo_text`: optional big label at top of login window
- `owner_setup`: whether Owner bootstrap is enabled

Returns:
- `Role` on success, otherwise `None`

### `authenticate(username, password, roles_file=None) -> Role`
Verifies credentials from `roles.json`.
Raises:
- `ValueError("Unknown username.")`
- `ValueError("Incorrect password.")`

### `current_role() -> Role | None`
Returns the logged-in role from the in-memory session.

### `current_role_id() -> int | None`
Returns the logged-in role id from the in-memory session.

### `current_username() -> str | None`
Returns the logged-in role name from the in-memory session.

### `logout() -> None`
Clears the in-memory session.

---

## Role management

### `add_role(name, role_id, password, roles_file=None) -> Role`
Creates a new role in roles.json (and returns the created role).

### `edit_role(role_id, new_name=None, new_password=None, roles_file=None) -> Role`
Edits an existing role by id.

### `delete_role(role_id, roles_file=None) -> None`
Deletes a role by id.

### `get_roles(roles_file=None) -> list[Role]`
Reads roles from roles.json.

---

## Authorization

### `permission_key(key, label=None)`
Decorator to register a permission for the Admin Panel.

### `list_registered_permissions() -> dict[str, PermissionMeta]`
Returns registered permissions metadata.

### `check_permission_for_role_id(role_id, key, permissions_file=None, default_allow_missing=False) -> bool`
Checks if a role id is allowed for a permission.

Owner (role id 0) always returns `True`.

### `permission_required(key, permissions_file=None, default_allow=False)`
Decorator that uses the *current in-memory session role id* and `permissions.json`.

### `role_required(role_id)`
Decorator enforcing a specific role id (Owner bypasses).

---

## Admin UI

### `open_admin_panel(...) -> bool`
Opens the Admin Panel for managing roles & permissions.

Key parameters:
- `ui`: `"tk"` (default), `"ctk"`, `"qt"`
- `mode`: `"popup"` (default) or `"embed"` (requires `parent=...`)
- `require_reauth`: force username/password prompt before opening
- `default_allow_manage`: what to do if the built-in manage key is missing (default True)

Returns:
- `True` if panel opened successfully
- `False` if blocked/cancelled

Constants:
- `MANAGE_PERMISSION_KEY = "roleperm.manage"`
- `MANAGE_PERMISSION_LABEL = "Manage Roles & Permissions"`

---

## Validation

### `RolesValidationError`, `PermissionsValidationError`
Raised by validators if JSON format is invalid.

### `validate_roles_file(path, strict=True) -> None`
Validate roles.json.

### `validate_permissions_file(path) -> None`
Validate permissions.json.
