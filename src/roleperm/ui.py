from __future__ import annotations

from typing import Optional

from .auth import authenticate, _set_session, Role, add_role
from .config import configure, resolve_roles_file
from .storage import roles_exist, load_role_records

OWNER_NAME = "owner"
OWNER_ID = 0

def _owner_exists(roles_path: str) -> bool:
    try:
        for r in load_role_records(roles_path):
            if int(r.id) == OWNER_ID and r.name.strip().lower() == OWNER_NAME:
                return True
    except Exception:
        return False
    return False

def _owner_first_run_setup(roles_path: str, *, title: str) -> Optional[Role]:
    """Ensure owner role exists by prompting for password (password + confirm).

    Returns owner Role on success, None on cancel.
    """
    try:
        import tkinter as tk
        from tkinter import messagebox, simpledialog
    except Exception:
        return None

    try:
        root = tk.Tk()
    except Exception:
        return None

    root.withdraw()
    try:
        pw1 = simpledialog.askstring(title, "Set OWNER password:", parent=root, show="*")
        if pw1 is None or pw1 == "":
            return None
        pw2 = simpledialog.askstring(title, "Confirm OWNER password:", parent=root, show="*")
        if pw2 is None:
            return None
        if pw1 != pw2:
            messagebox.showerror("Mismatch", "Passwords do not match.")
            return None

        if not _owner_exists(roles_path):
            add_role(OWNER_NAME, OWNER_ID, pw1, roles_file=roles_path)

        role = authenticate(OWNER_NAME, pw1, roles_file=roles_path)
        _set_session(role)
        return role
    except Exception as e:
        try:
            messagebox.showerror("Error", f"Owner setup failed: {e}")
        except Exception:
            pass
        return None
    finally:
        try:
            root.destroy()
        except Exception:
            pass

def login(
    *,
    title: str = "Login",
    app_name: Optional[str] = None,
    roles_file: Optional[str] = None,
    logo_text: Optional[str] = None,
    owner_setup: bool = True,
) -> Optional[Role]:
    """Show login popup and store session in memory (foolproof)."""
    if app_name is not None:
        configure(app_name=app_name)

    path = resolve_roles_file(roles_file)

    has_roles = roles_exist(path)

    if owner_setup and (not has_roles or not _owner_exists(path)):
        owner = _owner_first_run_setup(path, title=title)
        if owner is None:
            return None
        try:
            records = load_role_records(path)
            others = [r for r in records if int(r.id) != OWNER_ID]
        except Exception:
            others = []
        if not others:
            return owner

    if not roles_exist(path):
        return None

    try:
        import tkinter as tk
        from tkinter import messagebox
    except Exception:
        return None

    try:
        root = tk.Tk()
    except Exception:
        return None

    result = {"role": None}
    root.title(title)
    root.resizable(False, False)

    frame = tk.Frame(root, padx=14, pady=14)
    frame.pack()

    if logo_text:
        tk.Label(frame, text=logo_text, font=("Arial", 14, "bold")).grid(row=0, column=0, columnspan=2, pady=(0, 10))

    tk.Label(frame, text="Username").grid(row=1, column=0, sticky="e", padx=(0, 8), pady=4)
    username = tk.Entry(frame, width=28)
    username.grid(row=1, column=1, pady=4)

    tk.Label(frame, text="Password").grid(row=2, column=0, sticky="e", padx=(0, 8), pady=4)
    password = tk.Entry(frame, width=28, show="*")
    password.grid(row=2, column=1, pady=4)

    def submit():
        u = username.get().strip()
        p = password.get()
        try:
            role = authenticate(u, p, roles_file=path)
            _set_session(role)
            result["role"] = role
            root.destroy()
        except ValueError as e:
            messagebox.showerror("Login failed", str(e))

    def on_close():
        result["role"] = None
        root.destroy()

    tk.Button(frame, text="Login", command=submit, width=12).grid(row=3, column=0, columnspan=2, pady=(10, 0))
    username.focus_set()
    root.bind("<Return>", lambda _e: submit())
    root.protocol("WM_DELETE_WINDOW", on_close)

    root.mainloop()
    return result["role"]
