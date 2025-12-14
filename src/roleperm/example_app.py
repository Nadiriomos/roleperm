from __future__ import annotations

import roleperm as rp

def ensure_role(name, rid, pw):
    try:
        rp.add_role(name, rid, pw)
    except ValueError:
        pass

ensure_role("cashier", 1, "cash123")
ensure_role("admin", 2, "admin123")
ensure_role("owner", 3, "owner123")

@rp.permission_key("view_stock", label="View Stock")
@rp.permission_required("view_stock", default_allow=False)
def view_stock():
    print("✅ Viewing stock")

@rp.permission_key("delete_product", label="Delete Product")
@rp.permission_required("delete_product", default_allow=False)
def delete_product():
    print("✅ Product deleted")

def main():
    try:
        rp.login(title="Grocery Shop Login", logo_text="Grocery Shop")
    except PermissionError:
        print("Login cancelled.")
        return

    for fn in (view_stock, delete_product):
        try:
            fn()
        except PermissionError as e:
            print("❌", e)

    rp.open_admin_panel(require_reauth=True)

    for fn in (view_stock, delete_product):
        try:
            fn()
        except PermissionError as e:
            print("❌", e)

if __name__ == "__main__":
    main()
