# Contributing

## Scope

SniffHound keeps the capture pipeline intentionally small:

- `socket` for raw capture
- `threading` for concurrency
- `sqlite3` for persistence
- `wsbuilder` for the HTTP/WebSocket runtime

## Workflow

1. Install dependencies and run the app locally.
2. Make a focused change.
3. Validate with the available build and compile checks.
4. Open a pull request with a concise summary of the behavioral change.

## Expectations

- Keep the native-only capture constraints intact.
- Prefer backwards-compatible settings and environment variables when practical.
- Add or update docs when the UI or API surface changes.

