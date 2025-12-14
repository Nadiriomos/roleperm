# Changelog

## 0.2.0
- Added configurable per-function permissions using `permissions.json`
- Added decorators: `permission_key()` (registration) and `permission_required()` (enforcement)
- Added Tkinter admin panel `open_admin_panel()` with Roles/Permissions tabs
- Added `validate_permissions_file()` and `PermissionsValidationError`

## 0.1.1
- Added roles file validator

## 0.1.0
- Initial MVP (roles.json, PBKDF2 hashing, Tkinter login, role_required decorator)
