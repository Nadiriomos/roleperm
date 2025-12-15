from __future__ import annotations

from typing import Dict, Optional

from .auth import authenticate, get_roles, add_role, edit_role, delete_role, current_role_id, _set_session
from .config import resolve_roles_file, resolve_permissions_file
from .permissions import list_registered_permissions, check_permission_for_role_id, permission_key, OWNER_ID
from .perm_storage import load_permissions, save_permissions
from .validators import validate_permissions_data, PermissionsValidationError
from .storage import roles_exist
from .ui import _owner_first_run_setup, login as login_popup, _only_owner_exists

MANAGE_PERMISSION_KEY = "roleperm.manage"
MANAGE_PERMISSION_LABEL = "Manage Roles & Permissions"

permission_key(MANAGE_PERMISSION_KEY, label=MANAGE_PERMISSION_LABEL)(lambda: None)

def open_admin_panel(
    *,
    roles_file: Optional[str] = None,
    permissions_file: Optional[str] = None,
    require_reauth: bool = False,
    title: str = "RolePerm Admin",
    default_allow_manage: bool = True,
) -> bool:
    """Admin panel (owner never blocked + owner hidden)."""
    import tkinter as tk
    from tkinter import ttk, messagebox, simpledialog

    rpath = resolve_roles_file(roles_file)
    ppath = resolve_permissions_file(permissions_file)

    if not roles_exist(rpath):
        owner = _owner_first_run_setup(rpath, title=title)
        if owner is None:
            return False
        role_id = OWNER_ID
    else:
        if require_reauth and not _only_owner_exists(rpath):
            auth_root = tk.Tk()
            auth_root.withdraw()
            try:
                u = simpledialog.askstring("Admin Panel", "Username (role name):", parent=auth_root)
                if u is None:
                    return False
                p = simpledialog.askstring("Admin Panel", "Password:", parent=auth_root, show="*")
                if p is None:
                    return False
                role = authenticate(u.strip(), p, roles_file=rpath)
                _set_session(role)
                role_id = role.id
            except ValueError as e:
                messagebox.showerror("Authentication failed", str(e))
                return False
            finally:
                auth_root.destroy()
        else:
            role_id = current_role_id()
            if role_id is None:
                role = login_popup(title=title, roles_file=rpath, owner_setup=True)
                if role is None:
                    return False
                role_id = role.id

    # Owner never blocked
    if role_id != OWNER_ID:
        ok = check_permission_for_role_id(
            role_id,
            MANAGE_PERMISSION_KEY,
            permissions_file=ppath,
            default_allow_missing=default_allow_manage,
        )
        if not ok:
            return False

    root = tk.Tk()
    root.title(title)
    root.geometry("760x480")

    nb = ttk.Notebook(root)
    nb.pack(fill="both", expand=True, padx=8, pady=8)

    # Roles tab (owner hidden)
    roles_frame = ttk.Frame(nb)
    nb.add(roles_frame, text="Roles")

    roles_list = tk.Listbox(roles_frame, height=14)
    roles_list.pack(side="left", fill="both", expand=True, padx=(8, 4), pady=8)

    roles_btns = ttk.Frame(roles_frame)
    roles_btns.pack(side="right", fill="y", padx=(4, 8), pady=8)

    def refresh_roles():
        roles_list.delete(0, tk.END)
        for r in get_roles(roles_file=rpath):
            if r.id == OWNER_ID:
                continue
            roles_list.insert(tk.END, f"{r.id}  |  {r.name}")

    def selected_role_id() -> Optional[int]:
        sel = roles_list.curselection()
        if not sel:
            return None
        txt = roles_list.get(sel[0])
        try:
            return int(txt.split("|")[0].strip())
        except Exception:
            return None

    def reset_owner_password():
        pw1 = simpledialog.askstring("owner password", "New owner password:", parent=root, show="*")
        if pw1 is None or pw1 == "":
            return
        pw2 = simpledialog.askstring("owner password", "Confirm owner password:", parent=root, show="*")
        if pw2 is None:
            return
        if pw1 != pw2:
            messagebox.showerror("Mismatch", "Passwords do not match.")
            return
        try:
            edit_role(OWNER_ID, new_password=pw1, roles_file=rpath)
            messagebox.showinfo("Success", "owner password updated.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def add_role_ui():
        try:
            rid = simpledialog.askinteger("Add Role", "Role ID (integer):", parent=root, minvalue=1)
            if rid is None:
                return
            name = simpledialog.askstring("Add Role", "Role name:", parent=root)
            if name is None:
                return
            pw1 = simpledialog.askstring("Add Role", "Password:", parent=root, show="*")
            if pw1 is None or pw1 == "":
                return
            pw2 = simpledialog.askstring("Add Role", "Confirm password:", parent=root, show="*")
            if pw2 is None:
                return
            if pw1 != pw2:
                messagebox.showerror("Mismatch", "Passwords do not match.")
                return
            add_role(name, rid, pw1, roles_file=rpath)
            refresh_roles()
            messagebox.showinfo("Success", "Role added.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def edit_role_ui():
        rid = selected_role_id()
        if rid is None:
            messagebox.showinfo("Select role", "Please select a role.")
            return
        try:
            new_name = simpledialog.askstring("Edit Role", "New role name (leave blank to keep):", parent=root)
            if new_name is not None and new_name.strip() == "":
                new_name = None
            reset = messagebox.askyesno("Reset password", "Reset password for this role?")
            new_pw = None
            if reset:
                pw1 = simpledialog.askstring("Reset password", "New password:", parent=root, show="*")
                if pw1 is None or pw1 == "":
                    return
                pw2 = simpledialog.askstring("Reset password", "Confirm password:", parent=root, show="*")
                if pw2 is None:
                    return
                if pw1 != pw2:
                    messagebox.showerror("Mismatch", "Passwords do not match.")
                    return
                new_pw = pw1
            edit_role(rid, new_name=new_name, new_password=new_pw, roles_file=rpath)
            refresh_roles()
            messagebox.showinfo("Success", "Role updated.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def delete_role_ui():
        rid = selected_role_id()
        if rid is None:
            messagebox.showinfo("Select role", "Please select a role.")
            return
        if not messagebox.askyesno("Confirm delete", f"Delete role id {rid}?"):
            return
        try:
            delete_role(rid, roles_file=rpath)
            refresh_roles()
            messagebox.showinfo("Success", "Role deleted.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    ttk.Button(roles_btns, text="Refresh", command=refresh_roles).pack(fill="x", pady=3)
    ttk.Button(roles_btns, text="Reset owner password", command=reset_owner_password).pack(fill="x", pady=3)
    ttk.Separator(roles_btns, orient="horizontal").pack(fill="x", pady=8)
    ttk.Button(roles_btns, text="Add", command=add_role_ui).pack(fill="x", pady=3)
    ttk.Button(roles_btns, text="Edit", command=edit_role_ui).pack(fill="x", pady=3)
    ttk.Button(roles_btns, text="Delete", command=delete_role_ui).pack(fill="x", pady=3)

    # Permissions tab (owner hidden; owner always implicitly allowed)
    perms_frame = ttk.Frame(nb)
    nb.add(perms_frame, text="Permissions")

    left = ttk.Frame(perms_frame)
    left.pack(side="left", fill="y", padx=(8, 4), pady=8)

    right = ttk.Frame(perms_frame)
    right.pack(side="right", fill="both", expand=True, padx=(4, 8), pady=8)

    perms_list = tk.Listbox(left, width=40, height=16)
    perms_list.pack(fill="y", expand=True)

    roles_checks_frame = ttk.LabelFrame(right, text="Allowed roles")
    roles_checks_frame.pack(fill="both", expand=True, padx=6, pady=6)

    status = ttk.Label(right, text="Select a permission to edit.")
    status.pack(fill="x", padx=6, pady=(0, 6))

    vars_by_role: Dict[int, tk.IntVar] = {}
    current_key: Optional[str] = None

    def refresh_permissions_list():
        perms_list.delete(0, tk.END)
        reg = list_registered_permissions()
        for key, meta in sorted(reg.items(), key=lambda kv: kv[0]):
            perms_list.insert(tk.END, f"{key}  |  {meta.label}")

    def load_roles_checkboxes(selected_key: str):
        nonlocal current_key
        current_key = selected_key

        for child in roles_checks_frame.winfo_children():
            child.destroy()
        vars_by_role.clear()

        roles = [r for r in get_roles(roles_file=rpath) if r.id != OWNER_ID]
        data = load_permissions(ppath)
        try:
            validate_permissions_data(data)
        except PermissionsValidationError as e:
            messagebox.showerror("Invalid permissions file", str(e))
            return

        allowed = set()
        rec = data.get("permissions", {}).get(selected_key)
        if rec and isinstance(rec, dict):
            allowed = set(int(x) for x in rec.get("allowed_role_ids", []) if isinstance(x, int))

        for r in roles:
            v = tk.IntVar(value=1 if r.id in allowed else 0)
            vars_by_role[r.id] = v
            ttk.Checkbutton(roles_checks_frame, text=f"{r.id} | {r.name}", variable=v).pack(anchor="w", padx=8, pady=2)

        status.config(text=f"Editing: {selected_key}")

    def on_select_permission(_event=None):
        sel = perms_list.curselection()
        if not sel:
            return
        text = perms_list.get(sel[0])
        key = text.split("|")[0].strip()
        load_roles_checkboxes(key)

    def save_current_permission():
        if not current_key:
            messagebox.showinfo("Select permission", "Select a permission first.")
            return

        data = load_permissions(ppath)
        data.setdefault("permissions", {})
        reg = list_registered_permissions()
        label = reg.get(current_key).label if current_key in reg else current_key

        allowed_ids = sorted([rid for rid, v in vars_by_role.items() if v.get() == 1])
        data["permissions"][current_key] = {"label": label, "allowed_role_ids": allowed_ids}

        try:
            validate_permissions_data(data)
        except PermissionsValidationError as e:
            messagebox.showerror("Validation error", str(e))
            return

        save_permissions(ppath, data)
        messagebox.showinfo("Saved", f"Saved permissions for '{current_key}'.")

    ttk.Button(right, text="Save changes", command=save_current_permission).pack(anchor="e", padx=6, pady=(0, 6))
    perms_list.bind("<<ListboxSelect>>", on_select_permission)

    refresh_roles()
    refresh_permissions_list()
    root.mainloop()
    return True
