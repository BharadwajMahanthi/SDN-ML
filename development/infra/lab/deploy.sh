#!/usr/bin/env bash
# Ship the sdnguard source and lab scripts to the host. Small and explicit:
# a tar of two directories, base64'd through SSM, no S3 bucket and no
# inbound port. Keeps the lab reproducible from a checkout alone.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"

PAYLOAD="$(mktemp -d)"
trap 'rm -rf "$PAYLOAD"' EXIT
mkdir -p "$PAYLOAD/src"
cp -R "$ROOT/development/src/sdnguard" "$PAYLOAD/src/"
cp "$HERE"/*.py "$HERE"/*.sh "$PAYLOAD/" 2>/dev/null || true
find "$PAYLOAD" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true

TARBALL="$(mktemp)"; trap 'rm -rf "$PAYLOAD" "$TARBALL"' EXIT
tar -czf "$TARBALL" -C "$PAYLOAD" .
SIZE=$(wc -c < "$TARBALL" | tr -d ' ')
echo "[deploy] payload ${SIZE} bytes"
[ "$SIZE" -lt 200000 ] || { echo "[deploy] payload too large for SSM inline" >&2; exit 1; }

B64="$(base64 < "$TARBALL" | tr -d '\n')"
"$HERE/remote.sh" "
set -e
mkdir -p /opt/sdnguard
echo '$B64' | base64 -d | tar -xz -C /opt/sdnguard
chmod +x /opt/sdnguard/*.sh 2>/dev/null || true
echo deployed: \$(find /opt/sdnguard/src -name '*.py' | wc -l) python files
/opt/sdnguard/venv/bin/python -c 'import sys; sys.path.insert(0,\"/opt/sdnguard/src\"); import sdnguard.domain, sdnguard.controller.app; print(\"core imports OK\")'
/opt/sdnguard/venv/bin/python -c 'import sys; sys.path.insert(0,\"/opt/sdnguard/src\"); import sdnguard.adapter.osken; print(\"osken adapter imports OK\")'
"
