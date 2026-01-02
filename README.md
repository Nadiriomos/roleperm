# roleperm (v0.2.4)

Stdlib-only, JSON-backed role & permission enforcement for Python apps.

- ✅ Desktop-first (tkinter login + admin panel)
- ✅ Password hashing (PBKDF2-HMAC-SHA256)
- ✅ Permissions stored in a simple `permissions.json`
- ✅ Optional Admin UI backends: tkinter (default), CustomTkinter, PySide6 (Qt)

**Full documentation:** see `USE_GUIDE.md` (Desktop Apps + Web Apps).

---

## Install

```bash
pip install roleperm
```

Optional UI dependencies:

```bash
pip install customtkinter
pip install PySide6
```

---

## Quickstart (Desktop)

```python
import roleperm as rp

# Pick where roleperm stores roles.json + permissions.json
rp.configure(base_dir=".")

# Create a role (ignore error if it already exists)
try:
    rp.add_role("admin", 2, "admin123")
except ValueError:
    pass

@rp.permission_key("view_stock", label="View Stock")
@rp.permission_required("view_stock", default_allow=False)
def view_stock():
    print("Viewing stock")

def main():
    role = rp.login(title="Example Login", logo_text="Example App")
    if role is None:
        print("Login cancelled or no roles exist.")
        return

    try:
        view_stock()
    except PermissionError as e:
        print("Blocked:", e)

    # Admin panel is protected by roleperm.manage (Owner bypasses)
    rp.open_admin_panel(require_reauth=True)

if __name__ == "__main__":
    main()
```

---

## Files

By default roleperm stores:

- `./roleperm/roles.json`
- `./roleperm/permissions.json`

Use `rp.configure(base_dir=..., data_dir_name=...)` to change location.

---

## License

MIT (see `LICENSE`).