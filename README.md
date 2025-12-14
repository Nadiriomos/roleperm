# roleperm (v0.2.3)

Stdlib-only, JSON-backed role & permission enforcement for Python desktop apps.

## Seamless defaults
Calling `login(app_name="MyApp")` stores files in:

- `./roleperm/roles.json`
- `./roleperm/permissions.json`

No `state.json`. Session stays in memory.

## Login behavior
- If **no roles exist**, `login()` returns `None` and shows **no popup** (no crash).
- If user closes the popup, `login()` returns `None`.
- On success, `login()` returns a `Role` and sets session in memory.

## Admin panel access is a permission
Admin panel is guarded by `roleperm.manage` (editable in permissions.json).


## Corrupt/empty JSON recovery
If roles.json or permissions.json are empty or invalid JSON, roleperm will back them up and recreate fresh defaults.
