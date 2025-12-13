# roleperm

A **stdlib-only**, lightweight role-permission library for Python desktop apps.

- JSON-backed role storage (portable; no DB required)
- Optional Tkinter login popup (library never auto-launches UI)
- Function-level permission enforcement via decorators
- Passwords stored as **PBKDF2-HMAC** hashes with per-role salts

## Quick start

```python
import roleperm as rp

# One-time setup (creates ./roles.json if missing)
rp.add_role("cashier", 1, "cash123")
rp.add_role("admin", 2, "admin123")

# Optional login popup
rp.login(title="My App Login")

@rp.role_required(2)
def delete_product():
    print("deleted")
```

## Design rules (stable contract)

- **Login uses role name** (the username field is the role name).
- Role name is used to locate the record; **permissions are enforced by role ID**.
- Unauthorized calls **raise `PermissionError`** (never silent).
- Stdlib only (no external dependencies).

## roles.json format

Example:

```json
[
  {
    "name": "admin",
    "id": 2,
    "kdf": "pbkdf2_sha256",
    "iterations": 200000,
    "salt": "hexsalt...",
    "password_hash": "hexhash..."
  }
]
```

## Validate roles.json

If you want to sanity-check a roles file (duplicates, missing fields, bad types, weak PBKDF2 params), call:

```python
import roleperm as rp

rp.validate_roles_file("roles.json")
```

On failure it raises `rp.RolesValidationError` with a readable list of issues.

## Running the demo

```bash
python -m roleperm.example_app
```

## License

MIT
