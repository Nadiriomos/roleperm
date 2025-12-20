# src/roleperm/admin_ui_qt.py
from __future__ import annotations

from typing import Dict, Optional

from .auth import get_roles, add_role, edit_role, delete_role
from .constants import OWNER_ID
from .permissions import list_registered_permissions
from .perm_storage import load_permissions, save_permissions
from .validators import validate_permissions_data, PermissionsValidationError


def show_admin_panel_pyside6(
    *,
    rpath: str,
    ppath: str,
    title: str = "RolePerm Admin",
    embedded: bool = False,
    parent=None,
) -> bool:
    try:
        from PySide6 import QtWidgets, QtCore
    except Exception as e:
        raise ImportError("PySide6 is not installed. Install with: pip install PySide6") from e

    app = QtWidgets.QApplication.instance()
    _owns_app = False
    if app is None:
        app = QtWidgets.QApplication([])
        _owns_app = True

    # If embedded requested but parent isn't a QWidget, let caller/dispatcher fallback silently.
    if embedded and parent is not None and not isinstance(parent, QtWidgets.QWidget):
        raise TypeError("Qt embed requires a QWidget parent")

    # Root widget
    if embedded and parent is not None:
        root = QtWidgets.QWidget(parent)
        _is_popup = False
    else:
        root = QtWidgets.QDialog()
        root.setWindowTitle(title)
        root.resize(760, 480)
        _is_popup = True

    main_layout = QtWidgets.QVBoxLayout(root)

    tabs = QtWidgets.QTabWidget()
    main_layout.addWidget(tabs)

    # -----------------------------
    # Roles tab (owner hidden)
    # -----------------------------
    roles_tab = QtWidgets.QWidget()
    tabs.addTab(roles_tab, "Roles")
    roles_layout = QtWidgets.QHBoxLayout(roles_tab)

    roles_list = QtWidgets.QListWidget()
    roles_layout.addWidget(roles_list, 1)

    roles_buttons = QtWidgets.QVBoxLayout()
    roles_layout.addLayout(roles_buttons)

    def refresh_roles():
        roles_list.clear()
        for r in get_roles(roles_file=rpath):
            if r.id == OWNER_ID:
                continue
            roles_list.addItem(f"{r.id}  |  {r.name}")

    def selected_role_id() -> Optional[int]:
        item = roles_list.currentItem()
        if not item:
            return None
        txt = item.text()
        try:
            return int(txt.split("|")[0].strip())
        except Exception:
            return None

    def ask_password_twice(title_txt: str):
        pw1, ok1 = QtWidgets.QInputDialog.getText(root, title_txt, "Password:", QtWidgets.QLineEdit.Password)
        if not ok1 or not pw1:
            return None
        pw2, ok2 = QtWidgets.QInputDialog.getText(root, title_txt, "Confirm password:", QtWidgets.QLineEdit.Password)
        if not ok2:
            return None
        if pw1 != pw2:
            QtWidgets.QMessageBox.critical(root, "Mismatch", "Passwords do not match.")
            return None
        return pw1

    def add_role_ui():
        rid, ok = QtWidgets.QInputDialog.getInt(root, "Add Role", "Role ID (integer):", 1, 1)
        if not ok:
            return
        if rid == OWNER_ID:
            QtWidgets.QMessageBox.critical(root, "Not allowed", "Role ID 0 is reserved.")
            return
        name, ok = QtWidgets.QInputDialog.getText(root, "Add Role", "Role name:")
        if not ok:
            return
        pw = ask_password_twice("Add Role")
        if pw is None:
            return
        try:
            add_role(name, rid, pw, roles_file=rpath)
            refresh_roles()
            QtWidgets.QMessageBox.information(root, "Success", "Role added.")
        except Exception as e:
            QtWidgets.QMessageBox.critical(root, "Error", str(e))

    def edit_role_ui():
        rid = selected_role_id()
        if rid is None:
            QtWidgets.QMessageBox.information(root, "Select role", "Please select a role.")
            return
        new_name, ok = QtWidgets.QInputDialog.getText(root, "Edit Role", "New role name (leave blank to keep):")
        if not ok:
            return
        new_name = new_name.strip() or None

        reset = QtWidgets.QMessageBox.question(root, "Reset password", "Reset password for this role?")
        new_pw = None
        if reset == QtWidgets.QMessageBox.Yes:
            new_pw = ask_password_twice("Reset password")
            if new_pw is None:
                return
        try:
            edit_role(rid, new_name=new_name, new_password=new_pw, roles_file=rpath)
            refresh_roles()
            QtWidgets.QMessageBox.information(root, "Success", "Role updated.")
        except Exception as e:
            QtWidgets.QMessageBox.critical(root, "Error", str(e))

    def delete_role_ui():
        rid = selected_role_id()
        if rid is None:
            QtWidgets.QMessageBox.information(root, "Select role", "Please select a role.")
            return
        confirm = QtWidgets.QMessageBox.question(root, "Confirm delete", f"Delete role id {rid}?")
        if confirm != QtWidgets.QMessageBox.Yes:
            return
        try:
            delete_role(rid, roles_file=rpath)
            refresh_roles()
            QtWidgets.QMessageBox.information(root, "Success", "Role deleted.")
        except Exception as e:
            QtWidgets.QMessageBox.critical(root, "Error", str(e))

    btn_refresh = QtWidgets.QPushButton("Refresh")
    btn_add = QtWidgets.QPushButton("Add")
    btn_edit = QtWidgets.QPushButton("Edit")
    btn_delete = QtWidgets.QPushButton("Delete")

    btn_refresh.clicked.connect(refresh_roles)
    btn_add.clicked.connect(add_role_ui)
    btn_edit.clicked.connect(edit_role_ui)
    btn_delete.clicked.connect(delete_role_ui)

    roles_buttons.addWidget(btn_refresh)
    roles_buttons.addSpacing(10)
    roles_buttons.addWidget(btn_add)
    roles_buttons.addWidget(btn_edit)
    roles_buttons.addWidget(btn_delete)
    roles_buttons.addStretch(1)

    # -----------------------------
    # Permissions tab (owner hidden, LABELS ONLY)
    # -----------------------------
    perms_tab = QtWidgets.QWidget()
    tabs.addTab(perms_tab, "Permissions")
    perms_layout = QtWidgets.QHBoxLayout(perms_tab)

    perms_list = QtWidgets.QListWidget()
    perms_layout.addWidget(perms_list, 1)

    right = QtWidgets.QVBoxLayout()
    perms_layout.addLayout(right, 2)

    status = QtWidgets.QLabel("Select a permission to edit.")
    right.addWidget(status)

    # scroll area for role checkboxes
    scroll = QtWidgets.QScrollArea()
    scroll.setWidgetResizable(True)
    right.addWidget(scroll, 1)

    roles_box = QtWidgets.QWidget()
    roles_box_layout = QtWidgets.QVBoxLayout(roles_box)
    roles_box_layout.setAlignment(QtCore.Qt.AlignTop)
    scroll.setWidget(roles_box)

    btn_save = QtWidgets.QPushButton("Save changes")
    right.addWidget(btn_save)

    current_key: Optional[str] = None
    perm_keys: list[str] = []
    check_by_role: Dict[int, QtWidgets.QCheckBox] = {}

    def refresh_permissions_list():
        perms_list.clear()
        perm_keys.clear()
        reg = list_registered_permissions()
        for key, meta in sorted(reg.items(), key=lambda kv: kv[0]):
            perm_keys.append(key)
            perms_list.addItem(meta.label)  # label only

    def clear_role_checks():
        nonlocal check_by_role
        check_by_role = {}
        while roles_box_layout.count():
            item = roles_box_layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()

    def load_roles_for_permission(key: str):
        nonlocal current_key
        current_key = key
        clear_role_checks()

        # load saved allowed ids
        data = load_permissions(ppath)
        try:
            validate_permissions_data(data)
        except PermissionsValidationError as e:
            QtWidgets.QMessageBox.critical(root, "Invalid permissions file", str(e))
            return

        allowed = set()
        rec = data.get("permissions", {}).get(key)
        if rec and isinstance(rec, dict):
            raw_allowed = rec.get("allowed_role_ids", [])
            allowed = set(
                int(x) for x in raw_allowed
                if isinstance(x, (int, str)) and str(x).strip().isdigit()
            )

        # build checkboxes (owner hidden)
        roles = [r for r in get_roles(roles_file=rpath) if r.id != OWNER_ID]
        for r in roles:
            cb = QtWidgets.QCheckBox(f"{r.id} | {r.name}")
            cb.setChecked(r.id in allowed)
            roles_box_layout.addWidget(cb)
            check_by_role[r.id] = cb

        reg = list_registered_permissions()
        label = reg.get(key).label if key in reg else key
        status.setText(f"Editing: {label}")

    def on_perm_selected():
        row = perms_list.currentRow()
        if row < 0 or row >= len(perm_keys):
            return
        load_roles_for_permission(perm_keys[row])

    def save_current_permission():
        if not current_key:
            QtWidgets.QMessageBox.information(root, "Select permission", "Select a permission first.")
            return

        data = load_permissions(ppath)
        data.setdefault("permissions", {})
        reg = list_registered_permissions()
        label = reg.get(current_key).label if current_key in reg else current_key

        allowed_ids = sorted([rid for rid, cb in check_by_role.items() if cb.isChecked()])
        data["permissions"][current_key] = {"label": label, "allowed_role_ids": allowed_ids}

        try:
            validate_permissions_data(data)
        except PermissionsValidationError as e:
            QtWidgets.QMessageBox.critical(root, "Validation error", str(e))
            return

        save_permissions(ppath, data)
        QtWidgets.QMessageBox.information(root, "Saved", f"Saved permissions for '{label}'.")

    perms_list.currentRowChanged.connect(lambda _i: on_perm_selected())
    btn_save.clicked.connect(save_current_permission)

    # init
    refresh_roles()
    refresh_permissions_list()

    # show
    if _is_popup:
        root.exec()
        if _owns_app:
            app.quit()
    else:
        root.show()

    return True