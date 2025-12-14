from __future__ import annotations
import roleperm as rp
rp.configure(app_name="example")

def ensure_role(name,rid,pw):
    try: rp.add_role(name,rid,pw)
    except ValueError: pass

ensure_role("admin",2,"admin123")

@rp.permission_key("view_stock", label="View Stock")
@rp.permission_required("view_stock", default_allow=False)
def view_stock():
    print("✅ Viewing stock")

def main():
    role=rp.login(title="Example Login", app_name="example", logo_text="Example App")
    if role is None:
        print("No roles or login cancelled.")
        return
    try:
        view_stock()
    except PermissionError as e:
        print("❌", e)
    rp.open_admin_panel(require_reauth=True)

if __name__=="__main__":
    main()
