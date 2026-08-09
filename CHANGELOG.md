# Changelog

## Unreleased

- Added explicit authorship, provenance, and repository protection documentation.
- Added CI enforcement for commit sign-off and PR provenance attestations.
- Clarified maintainer ownership, trademark/identity guidance, and protected review surfaces.
- Hardened frontend auth so query-string tokens only unlock `WS /ws/`, while HTTP requests still require headers.
- Kept the dashboard security code only in tab memory and cleared legacy browser storage artifacts.
- Updated the Debian packaging workflow and docs to publish `.deb` assets from `main` into GitHub Releases.

## 0.1.0

- Initial SniffHound package scaffold.
- Native packet capture pipeline, SQLite persistence, runtime docs, and frontend integration.
