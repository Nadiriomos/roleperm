from __future__ import annotations

from typing import Dict, List, Optional

from .auth import DEFAULT_ROLES_FILE, authenticate, get_roles, add_role, edit_role, delete_role
from .permissions import DEFAULT_PERMISSIONS_FILE, list_registered_permissions
from .perm_storage import load_permissions, save_permissions
from .validators import validate_permissions_data, PermissionsValidationError

def open_admin_panel(*, roles_file: str = DEFAULT_ROLES_FILE, permissions_file: str = DEFAULT_PERMISSIONS_FILE,
                     manager_role_ids: Optional[List[int]] = None, require_reauth: bool = True,
                     title: str = "RolePerm Admin") -> None:
    import tkinter as tk
    from tkinter import ttk, messagebox, simpledialog

    if require_reauth:
        auth_root = tk.Tk()
        auth_root.withdraw()
        try:
            u = simpledialog.askstring("Re-authenticate", "Username (role name):", parent=auth_root)
            if u is None:
                return
            p = simpledialog.askstring("Re-authenticate", "Password:", parent=auth_root, show="*")
            if p is None:
                return
            role = authenticate(u.strip(), p, roles_file=roles_file)
            if manager_role_ids is not None and role.id not in set(manager_role_ids):
                messagebox.showerror("Access denied", "You are not allowed to open the admin panel.")
                return
        except ValueError as e:
            messagebox.showerror("Authentication failed", str(e))
            return
        finally:
            auth_root.destroy()

    root = tk.Tk()
    root.title(title)
    root.geometry("760x460")

    nb = ttk.Notebook(root)
    nb.pack(fill="both", expand=True, padx=8, pady=8)

    # Roles tab
    roles_frame = ttk.Frame(nb)
    nb.add(roles_frame, text="Roles")

    roles_list = tk.Listbox(roles_frame, height=14)
    roles_list.pack(side="left", fill="both", expand=True, padx=(8, 4), pady=8)

    roles_btns = ttk.Frame(roles_frame)
    roles_btns.pack(side="right", fill="y", padx=(4, 8), pady=8)

    def refresh_roles():
        roles_list.delete(0, tk.END)
        for r in get_roles(roles_file=roles_file):
            roles_list.insert(tk.END, f"{r.id}  |  {r.name}")

    def get_selected_role_id() -> Optional[int]:
        sel = roles_list.curselection()
        if not sel:
            return None
        text = roles_list.get(sel[0])
        try:
            return int(text.split("|")[0].strip())
        except Exception:
            return None

    def add_role_ui():
        try:
            rid = simpledialog.askinteger("Add Role", "Role ID (integer):", parent=root, minvalue=0)
            if rid is None:
                return
            name = simpledialog.askstring("Add Role", "Role name:", parent=root)
            if name is None:
                return
            pw = simpledialog.askstring("Add Role", "Password:", parent=root, show="*")
            if pw is None:
                return
            add_role(name, rid, pw, roles_file=roles_file)
            refresh_roles()
            messagebox.showinfo("Success", "Role added.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def edit_role_ui():
        rid = get_selected_role_id()
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
                new_pw = simpledialog.askstring("Reset password", "New password:", parent=root, show="*")
                if new_pw is None:
                    return
            edit_role(rid, new_name=new_name, new_password=new_pw, roles_file=roles_file)
            refresh_roles()
            messagebox.showinfo("Success", "Role updated.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def delete_role_ui():
        rid = get_selected_role_id()
        if rid is None:
            messagebox.showinfo("Select role", "Please select a role.")
            return
        if not messagebox.askyesno("Confirm delete", f"Delete role id {rid}?"):
            return
        try:
            delete_role(rid, roles_file=roles_file)
            refresh_roles()
            messagebox.showinfo("Success", "Role deleted.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    ttk.Button(roles_btns, text="Refresh", command=refresh_roles).pack(fill="x", pady=3)
    ttk.Button(roles_btns, text="Add", command=add_role_ui).pack(fill="x", pady=3)
    ttk.Button(roles_btns, text="Edit", command=edit_role_ui).pack(fill="x", pady=3)
    ttk.Button(roles_btns, text="Delete", command=delete_role_ui).pack(fill="x", pady=3)

    # Permissions tab
    perms_frame = ttk.Frame(nb)
    nb.add(perms_frame, text="Permissions")

    left = ttk.Frame(perms_frame)
    left.pack(side="left", fill="y", padx=(8, 4), pady=8)

    right = ttk.Frame(perms_frame)
    right.pack(side="right", fill="both", expand=True, padx=(4, 8), pady=8)

    perms_list = tk.Listbox(left, width=36, height=16)
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

        roles = get_roles(roles_file=roles_file)
        data = load_permissions(permissions_file)
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

        data = load_permissions(permissions_file)
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

        save_permissions(permissions_file, data)
        messagebox.showinfo("Saved", f"Saved permissions for '{current_key}'.")

    ttk.Button(right, text="Save changes", command=save_current_permission).pack(anchor="e", padx=6, pady=(0, 6))
    perms_list.bind("<<ListboxSelect>>", on_select_permission)

    refresh_roles()
    refresh_permissions_list()
    root.mainloop()
