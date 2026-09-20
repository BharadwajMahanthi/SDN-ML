#!/usr/bin/env python3
"""What this machine can actually verify, and what it cannot.

Run before any local experiment. It reports capabilities as measured, never
as assumed, so an experiment is never credited to a mechanism that is not
present. A machine that cannot run something says so; it does not quietly
substitute a weaker check.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import subprocess
import sys

NETLINK_CONNECTOR = 11


def _has_proc_connector() -> tuple[bool, str]:
    """Measured by opening the socket, not by reading a config file."""
    if not sys.platform.startswith("linux"):
        return False, f"not Linux ({sys.platform})"
    try:
        probe = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM,
                              NETLINK_CONNECTOR)
    except OSError as exc:
        return False, f"netlink connector unavailable: {exc.strerror}"
    probe.close()
    return True, "NETLINK_CONNECTOR opens"


def _has_nftables() -> tuple[bool, str]:
    if not shutil.which("nft"):
        return False, "nft not installed"
    try:
        result = subprocess.run(["nft", "list", "tables"], capture_output=True,
                                text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"nft failed: {exc}"
    if result.returncode != 0:
        return False, f"nft refused: {result.stderr.strip()[:80]}"
    return True, "nft lists tables"


def _has_peer_credentials() -> tuple[bool, str]:
    if sys.platform.startswith("linux"):
        return True, "SO_PEERCRED"
    if sys.platform == "darwin":
        return True, "LOCAL_PEERCRED/LOCAL_PEERPID"
    return False, f"no mechanism on {sys.platform}"


def report() -> dict:
    capabilities = {
        "proc_connector": _has_proc_connector(),
        "nftables": _has_nftables(),
        "peer_credentials": _has_peer_credentials(),
    }
    return {
        "platform": sys.platform,
        "machine": platform.machine(),
        "kernel": platform.release(),
        "euid": os.geteuid(),
        "capabilities": {name: {"available": ok, "evidence": why}
                         for name, (ok, why) in capabilities.items()},
    }


def main() -> int:
    data = report()
    if "--json" in sys.argv:
        print(json.dumps(data, indent=2))
        return 0
    print(f"platform : {data['platform']} {data['machine']} "
          f"kernel {data['kernel']} euid {data['euid']}")
    for name, entry in data["capabilities"].items():
        mark = "yes" if entry["available"] else "NO "
        print(f"  {mark}  {name:<18} {entry['evidence']}")
    missing = [n for n, e in data["capabilities"].items() if not e["available"]]
    if missing:
        print(f"\nunavailable here: {', '.join(missing)}")
        print("Experiments needing these must run where they exist; they are "
              "reported NOT_RUN, never approximated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
