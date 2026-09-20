#!/usr/bin/env bash
# Ship the Annulon/sdnguard source and lab scripts to the host.
#
# Transferred in base64 chunks over SSM Run Command. SSM caps a single
# invocation's parameters at 97 KB, and the tree outgrew that once the annulon
# package appeared. Chunking keeps the transfer inside the existing access
# path -- no S3 bucket, no extra IAM grant, no inbound port.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
CHUNK_BYTES="${SDNGUARD_CHUNK_BYTES:-50000}"

PAYLOAD="$(mktemp -d)"
TARBALL="$(mktemp)"
CHUNKDIR="$(mktemp -d)"
trap 'rm -rf "$PAYLOAD" "$TARBALL" "$CHUNKDIR"' EXIT

# Ship every package under development/src, not a named list. A hand-kept list
# silently stops shipping a package the day a new one is added, which is what
# happened when annulon appeared.
mkdir -p "$PAYLOAD/src"
for pkg in "$ROOT"/development/src/*/; do
  [ -d "$pkg" ] || continue
  # Strip the trailing slash: `cp -R dir/ dest/` copies the *contents*, which
  # flattens every package into src/ and breaks the import path.
  cp -R "${pkg%/}" "$PAYLOAD/src/"
done
cp "$HERE"/*.py "$HERE"/*.sh "$PAYLOAD/" 2>/dev/null || true
find "$PAYLOAD" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
find "$PAYLOAD" -name '*.pyc' -delete 2>/dev/null || true

tar -czf "$TARBALL" -C "$PAYLOAD" .
echo "[deploy] payload $(wc -c < "$TARBALL" | tr -d ' ') bytes"

base64 < "$TARBALL" | tr -d '\n' > "$CHUNKDIR/all.b64"
split -b "$CHUNK_BYTES" "$CHUNKDIR/all.b64" "$CHUNKDIR/part."
PARTS=("$CHUNKDIR"/part.*)
echo "[deploy] ${#PARTS[@]} chunk(s) of up to ${CHUNK_BYTES} base64 bytes"

"$HERE/remote.sh" 'rm -rf /opt/sdnguard/.incoming && mkdir -p /opt/sdnguard/.incoming && echo staged' >/dev/null

index=0
for part in "${PARTS[@]}"; do
  index=$((index + 1))
  "$HERE/remote.sh" "printf '%s' '$(cat "$part")' >> /opt/sdnguard/.incoming/payload.b64" >/dev/null
  printf '\r[deploy] sent chunk %d/%d' "$index" "${#PARTS[@]}"
done
echo

# Verify the reassembled bytes before trusting them: a truncated chunk would
# otherwise surface later as a confusing import error.
LOCAL_SHA="$(shasum -a 256 "$TARBALL" | awk '{print $1}')"
"$HERE/remote.sh" "
set -e
cd /opt/sdnguard/.incoming
base64 -d payload.b64 > payload.tgz
REMOTE_SHA=\$(sha256sum payload.tgz | awk '{print \$1}')
if [ \"\$REMOTE_SHA\" != \"$LOCAL_SHA\" ]; then
  echo \"TRANSFER CORRUPT: \$REMOTE_SHA != $LOCAL_SHA\" >&2
  exit 1
fi
echo 'transfer verified'
rm -rf /opt/sdnguard/src
tar -xzf payload.tgz -C /opt/sdnguard
chmod +x /opt/sdnguard/*.sh 2>/dev/null || true
rm -rf /opt/sdnguard/.incoming
echo \"deployed: \$(find /opt/sdnguard/src -name '*.py' | wc -l) python files\"
echo \"packages: \$(ls -1 /opt/sdnguard/src | tr '\n' ' ')\"
/opt/sdnguard/venv/bin/python -c 'import sys; sys.path.insert(0,\"/opt/sdnguard/src\"); import annulon.collectors.proc_connector, annulon.finding; print(\"annulon imports OK\")'
/opt/sdnguard/venv/bin/python -c 'import sys; sys.path.insert(0,\"/opt/sdnguard/src\"); import sdnguard.adapter.osken; print(\"sdnguard imports OK\")'
"
