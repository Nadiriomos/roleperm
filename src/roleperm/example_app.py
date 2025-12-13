from __future__ import annotations

import roleperm as rp


def ensure_role(name: str, rid: int, pw: str) -> None:
    try:
        rp.add_role(name, rid, pw)
    except ValueError:
        # role already exists; ok for demo
        pass


ensure_role("cashier", 1, "cash123")
ensure_role("admin", 2, "admin123")
ensure_role("owner", 3, "owner123")


@rp.role_required(1)
def add_sale():
    print("✅ Sale added")


@rp.role_required(2)
def delete_product():
    print("✅ Product deleted")


@rp.role_required(3)
def view_revenue():
    print("✅ Full revenue report")


def main() -> None:
    try:
        role = rp.login(title="Grocery Shop Login", logo_text="Grocery Shop")
    except PermissionError as e:
        print(str(e))
        return

    print(f"Logged in as: {role.name} (id={role.id})\n")

    for fn in (add_sale, delete_product, view_revenue):
        try:
            fn()
        except PermissionError as e:
            print("❌", e)


if __name__ == "__main__":
    main()
