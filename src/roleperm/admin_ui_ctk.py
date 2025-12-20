# src/roleperm/admin_ui_ctk.py
from __future__ import annotations

from typing import Dict, Optional, Tuple

from .auth import get_roles, add_role, edit_role, delete_role, current_role_id
from .permissions import list_registered_permissions, OWNER_ID
from .perm_storage import load_permissions, save_permissions
from .validators import validate_permissions_data, PermissionsValidationError



def show_admin_panel_ctk(
    *,
    rpath: str,
    ppath: str,
    title: str = "RolePerm Admin",
    embedded: bool = False,
    parent=None,
) -> bool:
    try:
        import customtkinter as ctk
    except Exception as e:
        raise ImportError("CustomTkinter is not installed. Install with: pip install customtkinter") from e

    # dialogs: prefer CTkInputDialog if available, else fallback to tkinter.simpledialog/messagebox
    try:
        CTkInputDialog = ctk.CTkInputDialog  # type: ignore[attr-defined]
    except Exception:
        CTkInputDialog = None

    import tkinter as tk
    from tkinter import messagebox, simpledialog

    def ask_text(prompt: str, *, password: bool = False) -> Optional[str]:
        if CTkInputDialog is not None:
            d = CTkInputDialog(text=prompt, title=title)
            val = d.get_input()
            if val is None:
                return None
            val = str(val)
            if password:
                # CTkInputDialog doesn’t mask; fallback to simpledialog for masked input
                return simpledialog.askstring(title, prompt, parent=_tk_parent_for_dialogs(), show="*")
            return val
        return simpledialog.askstring(title, prompt, parent=_tk_parent_for_dialogs(), show="*" if password else None)

    def ask_int(prompt: str, *, minvalue: int = 1) -> Optional[int]:
        return simpledialog.askinteger(title, prompt, parent=_tk_parent_for_dialogs(), minvalue=minvalue)

    def _tk_parent_for_dialogs():
        # Use tk default root if present; otherwise create a hidden one.
        r = tk._default_root
        if r is None:
            r = tk.Tk()
            r.withdraw()
        return r

    # --- root/container ---
    # embedded: create a CTkFrame into the given parent; popup: create a CTkToplevel or CTk root
    _is_popup = True
    if embedded and parent is not None:
        root = ctk.CTkFrame(parent)
        root.pack(fill="both", expand=True)
        _is_popup = False
    else:
        # If app already has a tk root, make a Toplevel. Otherwise create CTk() as root.
        if tk._default_root is not None:
            root = ctk.CTkToplevel(tk._default_root)
        else:
            root = ctk.CTk()
        root.title(title)
        root.geometry("760x480")
        _is_popup = True

    # --- Tabview ---
    tabs = ctk.CTkTabview(root)
    tabs.pack(fill="both", expand=True, padx=8, pady=8)

    tab_roles = tabs.add("Roles")
    tab_perms = tabs.add("Permissions")

    # -------------------------
    # Roles tab (owner hidden)
    # -------------------------
    roles_left = ctk.CTkScrollableFrame(tab_roles)
    roles_left.pack(side="left", fill="both", expand=True, padx=(8, 4), pady=8)

    roles_right = ctk.CTkFrame(tab_roles)
    roles_right.pack(side="right", fill="y", padx=(4, 8), pady=8)

    roles_buttons: list[Tuple[int, ctk.CTkButton]] = []
    selected_role_id: Optional[int] = None

    def refresh_roles():
        nonlocal roles_buttons, selected_role_id
        selected_role_id = None
        for w in roles_left.winfo_children():
            w.destroy()
        roles_buttons.clear()

        for r in get_roles(roles_file=rpath):
            if r.id == OWNER_ID:
                continue
            btn = ctk.CTkButton(
                roles_left,
                text=f"{r.id} | {r.name}",
                anchor="w",
                command=lambda rid=r.id: select_role(rid),
            )
            btn.pack(fill="x", padx=6, pady=4)
            default_fg = btn.cget("fg_color")
            roles_buttons.append((r.id, btn, default_fg))
    
    def reset_owner_password():
        if current_role_id() != OWNER_ID:
            messagebox.showerror("Access denied", "Only the Owner can reset the Owner password.")
            return
        pw1 = ask_text("New owner password:", password=True)
        if pw1 is None or pw1 == "":
            return
        pw2 = ask_text("Confirm owner password:", password=True)
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

    def select_role(rid: int):
        nonlocal selected_role_id
        selected_role_id = rid
        # simple highlight by text prefix
        for rrid, btn, default_fg in roles_buttons:
            btn.configure(fg_color=default_fg)
        for rrid, btn, _default_fg in roles_buttons:
            if rrid == rid:
                btn.configure(fg_color=("gray75", "gray25"))

    def add_role_ui():
        rid = ask_int("Role ID (integer):", minvalue=1)
        if rid is None:
            return
        if rid == OWNER_ID:
            messagebox.showerror("Not allowed", "Role ID 0 is reserved.")
            return
        name = ask_text("Role name:")
        if name is None:
            return
        pw1 = ask_text("Password:", password=True)
        if pw1 is None or pw1 == "":
            return
        pw2 = ask_text("Confirm password:", password=True)
        if pw2 is None:
            return
        if pw1 != pw2:
            messagebox.showerror("Mismatch", "Passwords do not match.")
            return
        try:
            add_role(name, rid, pw1, roles_file=rpath)
            refresh_roles()
            messagebox.showinfo("Success", "Role added.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def edit_role_ui():
        nonlocal selected_role_id
        rid = selected_role_id
        if rid is None:
            messagebox.showinfo("Select role", "Please select a role.")
            return
        new_name = ask_text("New role name (leave blank to keep):")
        if new_name is not None and new_name.strip() == "":
            new_name = None

        reset = messagebox.askyesno("Reset password", "Reset password for this role?")
        new_pw = None
        if reset:
            pw1 = ask_text("New password:", password=True)
            if pw1 is None or pw1 == "":
                return
            pw2 = ask_text("Confirm password:", password=True)
            if pw2 is None:
                return
            if pw1 != pw2:
                messagebox.showerror("Mismatch", "Passwords do not match.")
                return
            new_pw = pw1

        try:
            edit_role(rid, new_name=new_name, new_password=new_pw, roles_file=rpath)
            refresh_roles()
            messagebox.showinfo("Success", "Role updated.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def delete_role_ui():
        nonlocal selected_role_id
        rid = selected_role_id
        if rid is None:
            messagebox.showinfo("Select role", "Please select a role.")
            return
        if not messagebox.askyesno("Confirm delete", f"Delete role id {rid}?"):
            return
        try:
            delete_role(rid, roles_file=rpath)
            selected_role_id = None
            refresh_roles()
            messagebox.showinfo("Success", "Role deleted.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    ctk.CTkButton(roles_right, text="Refresh", command=refresh_roles).pack(fill="x", pady=6, padx=8)
    ctk.CTkButton(roles_right, text="Reset owner password", command=reset_owner_password).pack(fill="x", pady=6, padx=8)
    sep = ctk.CTkFrame(roles_right, height=2)
    sep.pack(fill="x", padx=8, pady=10)
    ctk.CTkButton(roles_right, text="Add", command=add_role_ui).pack(fill="x", pady=6, padx=8)
    ctk.CTkButton(roles_right, text="Edit", command=edit_role_ui).pack(fill="x", pady=6, padx=8)
    ctk.CTkButton(roles_right, text="Delete", command=delete_role_ui).pack(fill="x", pady=6, padx=8)

    # -------------------------
    # Permissions tab (LABELS ONLY, owner hidden)
    # -------------------------
    perms_left = ctk.CTkScrollableFrame(tab_perms)
    perms_left.pack(side="left", fill="both", expand=True, padx=(8, 4), pady=8)

    perms_right = ctk.CTkFrame(tab_perms)
    perms_right.pack(side="right", fill="both", expand=True, padx=(4, 8), pady=8)

    status = ctk.CTkLabel(perms_right, text="Select a permission to edit.")
    status.pack(fill="x", padx=8, pady=(8, 4))

    allowed_frame = ctk.CTkScrollableFrame(perms_right)
    allowed_frame.pack(fill="both", expand=True, padx=8, pady=8)

    save_btn = ctk.CTkButton(perms_right, text="Save changes")
    save_btn.pack(anchor="e", padx=8, pady=(0, 8))

    current_key: Optional[str] = None
    perm_keys: list[str] = []               # index -> key
    perm_buttons: list[ctk.CTkButton] = []  # highlight
    vars_by_role: Dict[int, tk.IntVar] = {} # ok to use tk variables

    def refresh_permissions_list():
        nonlocal perm_keys, perm_buttons, current_key
        current_key = None
        perm_keys.clear()
        for w in perms_left.winfo_children():
            w.destroy()
        perm_buttons.clear()

        reg = list_registered_permissions()
        for key, meta in sorted(reg.items(), key=lambda kv: kv[0]):
            perm_keys.append(key)
            btn = ctk.CTkButton(
                perms_left,
                text=meta.label,  # LABEL ONLY
                anchor="w",
                command=lambda k=key: select_permission(k),
            )
            btn.pack(fill="x", padx=6, pady=4)
            perm_buttons.append(btn)

    def select_permission(key: str):
        nonlocal current_key
        current_key = key

        # clear role checks
        for w in allowed_frame.winfo_children():
            w.destroy()
        vars_by_role.clear()

        # load permission record
        data = load_permissions(ppath)
        try:
            validate_permissions_data(data)
        except PermissionsValidationError as e:
            messagebox.showerror("Invalid permissions file", str(e))
            return

        allowed = set()
        rec = data.get("permissions", {}).get(key)
        if rec and isinstance(rec, dict):
            raw_allowed = rec.get("allowed_role_ids", [])
            allowed = set(int(x) for x in raw_allowed if isinstance(x, (int, str)) and str(x).strip().isdigit())

        # render checkboxes for roles (owner hidden)
        roles = [r for r in get_roles(roles_file=rpath) if r.id != OWNER_ID]
        for r in roles:
            v = tk.IntVar(master=_tk_parent_for_dialogs(), value=1 if r.id in allowed else 0)
            vars_by_role[r.id] = v
            cb = ctk.CTkCheckBox(allowed_frame, text=f"{r.id} | {r.name}", variable=v, onvalue=1, offvalue=0)
            cb.pack(anchor="w", padx=8, pady=4)

        label = list_registered_permissions().get(key).label if key in list_registered_permissions() else key
        status.configure(text=f"Editing: {label}")

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
        messagebox.showinfo("Saved", f"Saved permissions for '{label}'.")

    save_btn.configure(command=save_current_permission)

    # init
    refresh_roles()
    refresh_permissions_list()

    # popup loop only if we created a new standalone window
    if _is_popup and isinstance(root, (ctk.CTk, ctk.CTkToplevel)):
        try:
            root.lift()
            root.focus_force()
        except Exception:
            pass
        if isinstance(root, ctk.CTk):
            root.mainloop()

    return True
