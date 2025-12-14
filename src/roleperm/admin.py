from __future__ import annotations
import roleperm as rp
def main()->int:
    return 0 if rp.open_admin_panel() else 1
if __name__=="__main__":
    raise SystemExit(main())
