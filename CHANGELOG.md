## 0.2.1
- Seamless config defaults
- login() returns None if no roles
- admin panel guarded by roleperm.manage

# 0.2.2
- Owner bypasses role_required
- Admin panel allows resetting owner password

# 0.2.3
- Foolproof bootstrap: Owner setup triggers on missing/empty/corrupt roles.json
- Admin panel opens safely on first run and prompts login if needed
- Auto-backup and recreate corrupt/empty roles.json and permissions.json

