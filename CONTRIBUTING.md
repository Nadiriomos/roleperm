# Contributing

Thanks for contributing!

## Development setup

- Python 3.9+
- No runtime dependencies (stdlib-only)

Run tests:

```bash
python -m unittest discover -s tests -v
```

## Guidelines

- Keep the public API small and stable (prefer adding optional arguments over breaking changes).
- Avoid adding external dependencies unless absolutely necessary.
- Maintain backward-compatible JSON storage when possible (add fields, don't rename/remove).
- Keep security changes explicit in the changelog.

## Code style

- Type hints encouraged.
- Use clear error messages (especially for auth and permission failures).
