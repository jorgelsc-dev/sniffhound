#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python3}"
PACKAGE_NAME="${PACKAGE_NAME:-sniffhound}"
DIST_DIR="${DIST_DIR:-$ROOT_DIR/dist}"
BUILD_DIR="${BUILD_DIR:-$ROOT_DIR/build/deb}"
PACKAGE_ROOT="$BUILD_DIR/$PACKAGE_NAME"
DEBIAN_DIR="$PACKAGE_ROOT/DEBIAN"
INSTALL_ROOT="$PACKAGE_ROOT/usr/lib/$PACKAGE_NAME"
VENDOR_DIR="$INSTALL_ROOT/vendor"
BIN_DIR="$PACKAGE_ROOT/usr/bin"
DOC_DIR="$PACKAGE_ROOT/usr/share/doc/$PACKAGE_NAME"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

require_command "$PYTHON_BIN"
require_command dpkg-deb
require_command sha256sum

if [[ ! -d frontend/dist ]]; then
  echo "frontend/dist is missing. Run 'cd frontend && npm ci && npm run build' before building the Debian package." >&2
  exit 1
fi

PACKAGE_VERSION="$("$PYTHON_BIN" - <<'PY'
from pathlib import Path

namespace = {}
exec(Path("sniffhound/__init__.py").read_text(encoding="utf-8"), namespace)
print(namespace["__version__"])
PY
)"

echo "[build] Preparing Debian package layout..."
rm -rf "$BUILD_DIR"
mkdir -p "$DIST_DIR"
rm -f "$DIST_DIR"/"${PACKAGE_NAME}"_*.deb "$DIST_DIR"/"${PACKAGE_NAME}"_*.deb.sha256
install -d "$DEBIAN_DIR" "$INSTALL_ROOT" "$VENDOR_DIR" "$BIN_DIR" "$DOC_DIR"

echo "[build] Installing Python application into staging root..."
"$PYTHON_BIN" -m pip install --disable-pip-version-check --no-compile --target "$VENDOR_DIR" .

find "$VENDOR_DIR" -type d -name "__pycache__" -exec rm -rf {} +
find "$VENDOR_DIR" -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete

if find "$VENDOR_DIR" -type f \( -name "*.so" -o -name "*.pyd" \) | grep -q .; then
  PACKAGE_ARCH="$(dpkg --print-architecture)"
else
  PACKAGE_ARCH="all"
fi

cat > "$DEBIAN_DIR/control" <<EOF
Package: $PACKAGE_NAME
Version: $PACKAGE_VERSION
Section: net
Priority: optional
Architecture: $PACKAGE_ARCH
Maintainer: JorgelSC Dev
Depends: python3 (>= 3.12)
Homepage: https://github.com/jorgelsc-dev/sniffhound
Description: Native Python network sniffer with bundled web dashboard
 SniffHound captures local traffic, persists runtime data in SQLite, and
 serves the bundled dashboard and API from a single process.
EOF

cat > "$INSTALL_ROOT/launcher.py" <<'EOF'
from __future__ import annotations

import runpy
import site
import sys
from pathlib import Path

INSTALL_ROOT = Path(__file__).resolve().parent
site.addsitedir(str(INSTALL_ROOT / "vendor"))
sys.argv[0] = "sniffhound"
runpy.run_module("sniffhound.manage", run_name="__main__", alter_sys=True)
EOF

cat > "$BIN_DIR/sniffhound" <<'EOF'
#!/bin/sh
set -eu

exec /usr/bin/python3 /usr/lib/sniffhound/launcher.py "$@"
EOF

chmod 0755 "$BIN_DIR/sniffhound"
install -m 0644 README.md "$DOC_DIR/README.md"
install -m 0644 LICENSE "$DOC_DIR/LICENSE"

PACKAGE_FILE="$DIST_DIR/${PACKAGE_NAME}_${PACKAGE_VERSION}_${PACKAGE_ARCH}.deb"

echo "[build] Building $PACKAGE_FILE..."
dpkg-deb --build --root-owner-group "$PACKAGE_ROOT" "$PACKAGE_FILE" >/dev/null

(
  cd "$DIST_DIR"
  sha256sum "$(basename "$PACKAGE_FILE")" > "$(basename "$PACKAGE_FILE").sha256"
)

echo "[build] Created $PACKAGE_FILE"
