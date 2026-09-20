#!/usr/bin/env bash
# Pull an evidence directory back from the lab host.
# JSON/JSONL only: raw captures stay on the host by policy.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REMOTE_DIR="${1:?usage: fetch_evidence.sh <remote-dir> <local-dir>}"
LOCAL_DIR="${2:?usage: fetch_evidence.sh <remote-dir> <local-dir>}"
mkdir -p "$LOCAL_DIR"
B64="$("$HERE/remote.sh" "cd $REMOTE_DIR && tar -czf - --exclude='*.pcap' --exclude='*.log' . | base64 -w0" \
       | grep -v '^---' | tr -d '\n ')"
echo "$B64" | base64 -d | tar -xz -C "$LOCAL_DIR"
echo "[fetch] $REMOTE_DIR -> $LOCAL_DIR"
ls -1 "$LOCAL_DIR"
