# Changelog

## 0.1.0
- Initial stdlib-only release.
- JSON-backed role storage with atomic writes.
- PBKDF2-HMAC-SHA256 password hashing with per-role salt.
- Optional Tkinter login popup.
- `@role_required(role_id)` decorator raising `PermissionError` on unauthorized calls.

## 0.1.1
- Added roles file validator: `validate_roles_file()` and `RolesValidationError`.

