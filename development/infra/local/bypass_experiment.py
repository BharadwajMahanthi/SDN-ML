#!/usr/bin/env python3
"""How would an attacker get around this specific containment rule?

The previous experiment showed that a `meta skuid` drop rule stops a target
uid reaching a destination. That is one blocked TCP connection. It does not
establish "egress restricted", and the gap between those two statements is
where a real attacker lives.

So this run attacks the mechanism from every direction it plausibly fails:

* **shared uid** -- two unrelated processes under one uid. Makes the
  documented `skuid` limitation physical rather than a sentence in a docstring.
* **IPv6** -- an IPv4-scoped rule in an `inet` table. If v6 stays open, then
  "egress restricted" is simply the wrong claim.
* **established connections** -- a socket opened before the rule existed.
* **fork/exec** -- a child process, and an execed binary.
* **alternate destination** -- confirms scoping is real and not accidental.
* **unscoped rule** -- what changes when no destination is named.

Every result is reported as measured. A bypass that works is a finding about
Annulon, recorded as such; the point of running this is to find them.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

# The package tree lives in different places depending on where this runs:
# mounted at /annulon in the Docker lab, unpacked to /opt/sdnguard/src on the
# AWS reference host. Hard-coding one of them made the experiment
# non-portable, and a reference run that cannot execute is not evidence about
# the reference platform.
for _candidate in (os.environ.get("ANNULON_SRC"),
                   "/annulon/development/src", "/opt/sdnguard/src"):
    if _candidate and os.path.isdir(os.path.join(_candidate, "annulon")):
        sys.path.insert(0, _candidate)
        break
else:
    raise SystemExit("cannot locate the annulon package; set ANNULON_SRC")

from annulon.response.contract import (                             # noqa: E402
    ActionRequest, ActionType, Target, TargetKind,
)
from annulon.response.nftables import NftablesEnforcer, Ownership   # noqa: E402

TARGET_UID = 1500
SHARER_USER, TARGET_USER = "annulon-sharer", "annulon-victim"
OTHER_UID, OTHER_USER = 1600, "annulon-bystander"
HOST_ID, BOOT_ID = "annulon-lab", "boot-local"


def sh(argv: list[str], timeout: float = 30) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)


def ensure_user(name: str, uid: int) -> None:
    if sh(["/usr/bin/id", "-u", name]).returncode == 0:
        return
    result = sh(["/usr/sbin/useradd", "-u", str(uid), "-o", "-M",
                 "-s", "/usr/sbin/nologin", name])
    if result.returncode != 0:
        raise SystemExit(f"cannot create {name}: {result.stderr[:160]}")


CONNECT = (
    "import socket,sys\n"
    "fam = socket.AF_INET6 if {v6} else socket.AF_INET\n"
    "s=socket.socket(fam); s.settimeout(4)\n"
    "try:\n"
    "    s.connect(({host!r},{port}))\n"
    "    print('OPEN')\n"
    "except Exception as e: print(type(e).__name__)\n"
    "finally: s.close()\n")


def probe(user: str, host: str, port: int, *, v6: bool = False) -> str:
    """One connection attempt under a given uid, in its own process."""
    script = CONNECT.format(host=host, port=port, v6=v6)
    result = sh(["/usr/bin/setpriv", "--reuid", user, "--regid", "nogroup",
                 "--clear-groups", "/usr/bin/python3", "-c", script], timeout=25)
    return result.stdout.strip() or f"probe-failed:{result.stderr.strip()[:60]}"


def probe_forked(user: str, host: str, port: int) -> str:
    """Connect from a forked child, and from an execed binary.

    A rule matching the socket's owning uid should follow both, since neither
    fork nor a plain exec changes the uid.
    """
    script = (
        "import os,socket,sys,subprocess\n"
        "pid=os.fork()\n"
        "if pid==0:\n"
        "    s=socket.socket(); s.settimeout(4)\n"
        "    try: s.connect((%r,%d)); print('fork:OPEN')\n"
        "    except Exception as e: print('fork:'+type(e).__name__)\n"
        "    finally:\n"
        "        s.close(); sys.stdout.flush(); os._exit(0)\n"
        "os.waitpid(pid,0)\n"
        "r=subprocess.run([sys.executable,'-c',%r],capture_output=True,text=True)\n"
        "print('exec:'+r.stdout.strip())\n" % (
            host, port, CONNECT.format(host=host, port=port, v6=False)))
    result = sh(["/usr/bin/setpriv", "--reuid", user, "--regid", "nogroup",
                 "--clear-groups", "/usr/bin/python3", "-c", script], timeout=30)
    return result.stdout.strip().replace("\n", " | ") or "probe-failed"


def try_setuid(user: str) -> str:
    """Can the contained uid become another uid to escape the rule?

    It should not be able to: changing uid needs privilege it does not have.
    Measured rather than asserted, because "cannot" is the whole claim.
    """
    script = ("import os\n"
              "try:\n"
              "    os.setuid(%d); print('SETUID-SUCCEEDED-uid-now-%%d' %% os.getuid())\n"
              "except PermissionError: print('PermissionError')\n"
              "except Exception as e: print(type(e).__name__)\n" % OTHER_UID)
    result = sh(["/usr/bin/setpriv", "--reuid", user, "--regid", "nogroup",
                 "--clear-groups", "/usr/bin/python3", "-c", script], timeout=20)
    return result.stdout.strip()


class Listener(threading.Thread):
    """A v6 listener on ::1, so IPv6 can be measured without a v6 network."""

    def __init__(self, port: int) -> None:
        super().__init__(daemon=True)
        self.port = port
        self.ready = threading.Event()
        self._stop = threading.Event()

    def run(self) -> None:
        server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(("::1", self.port))
            server.listen(8)
            server.settimeout(0.5)
        except OSError:
            self.ready.set()
            return
        self.ready.set()
        while not self._stop.is_set():
            try:
                connection, _ = server.accept()
                connection.close()
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                break
        server.close()

    def stop(self) -> None:
        self._stop.set()


def _request(destination: str | None, request_id: str) -> ActionRequest:
    return ActionRequest(
        request_id=request_id,
        action_type=ActionType.TEMPORARY_EGRESS_RESTRICTION,
        target=Target(TargetKind.SERVICE_UID, HOST_ID, BOOT_ID,
                      str(TARGET_UID), TARGET_USER),
        duration=timedelta(minutes=5), reason="bypass experiment",
        finding_id="finding-00000002",
        requested_at=datetime.now(timezone.utc),
        requesting_component="annulon-core",
        destination_cidr=f"{destination}/32" if destination else None)


def run(destination: str, port: int) -> dict:
    enforcer = NftablesEnforcer()
    ensure_user(TARGET_USER, TARGET_UID)
    ensure_user(OTHER_USER, OTHER_UID)
    ensure_user(SHARER_USER, TARGET_UID)          # -o: same uid, different name

    v6_port = 19998
    listener = Listener(v6_port)
    listener.start()
    listener.ready.wait(timeout=5)

    report: dict = {"environment": {
        "enforcement_kernel": f"Linux {os.uname().release}",
        "machine": os.uname().machine, "mechanism": "Linux nftables meta skuid",
        "destination": destination, "port": port}}

    try:
        # --- baseline, every path open -------------------------------------
        report["baseline"] = {
            "target_v4": probe(TARGET_USER, destination, port),
            "sharer_v4": probe(SHARER_USER, destination, port),
            "other_v4": probe(OTHER_USER, destination, port),
            "target_v6_loopback": probe(TARGET_USER, "::1", v6_port, v6=True),
        }

        # An established connection, opened *before* the rule exists, and
        # owned by the TARGET uid. The first version of this used a socket
        # belonging to this root process, which `meta skuid 1500` never
        # matches -- it measured nothing and looked like a bypass.
        holder = _hold_connection(TARGET_USER, destination, port)

        # --- apply an IPv4-scoped rule --------------------------------------
        enforcer.ensure_structure()
        scoped_id = "req-bypass-v4-scoped-0001"
        applied = enforcer.apply(_request(destination, scoped_id),
                                 expires_at=datetime.now(timezone.utc)
                                 + timedelta(minutes=5))
        report["scoped_rule"] = {"outcome": applied.outcome.value,
                                 "resource": applied.resource.identifier
                                 if applied.resource else None}

        report["with_ipv4_scoped_rule"] = {
            "target_v4_to_blocked_destination": probe(TARGET_USER, destination, port),
            "SHARED_UID_different_process": probe(SHARER_USER, destination, port),
            "unrelated_uid": probe(OTHER_USER, destination, port),
            "IPV6_loopback": probe(TARGET_USER, "::1", v6_port, v6=True),
            "alternate_destination_v4": probe(TARGET_USER, "127.0.0.1", 9),
            "fork_and_exec": probe_forked(TARGET_USER, destination, port),
            "setuid_escape_attempt": try_setuid(TARGET_USER),
        }
        report["established_connection"] = _resume_connection(holder)
        enforcer.release(applied.resource)

        # --- apply an unscoped rule, no destination named --------------------
        unscoped_id = "req-bypass-unscoped-0001"
        applied2 = enforcer.apply(_request(None, unscoped_id),
                                  expires_at=datetime.now(timezone.utc)
                                  + timedelta(minutes=5))
        report["with_unscoped_rule"] = {
            "target_v4": probe(TARGET_USER, destination, port),
            "IPV6_loopback": probe(TARGET_USER, "::1", v6_port, v6=True),
            "unrelated_uid": probe(OTHER_USER, destination, port),
        }
        enforcer.release(applied2.resource)

        report["after_release"] = {
            "target_v4": probe(TARGET_USER, destination, port),
            "IPV6_loopback": probe(TARGET_USER, "::1", v6_port, v6=True),
        }
        report["findings"] = _interpret(report)
    finally:
        listener.stop()
        try:
            for record in enforcer.rules():
                if record.ownership is Ownership.OWNED:
                    enforcer.release(record.resource)
            enforcer.remove_own_table()
        except Exception as exc:                        # noqa: BLE001
            report["teardown_warning"] = str(exc)[:200]
    return report


_HOLDER = """
import socket, sys
s = socket.socket(); s.settimeout(5)
try:
    s.connect((%r, %d))
except Exception as e:
    print('CONNECT-FAILED:' + type(e).__name__, flush=True); raise SystemExit(1)
print('CONNECTED', flush=True)
sys.stdin.readline()                      # wait until the rule is in place
try:
    s.sendall(b'GET / HTTP/1.0\\r\\n\\r\\n')
    data = s.recv(64)
    print('USABLE' if data else 'EMPTY', flush=True)
except Exception as e:
    print(type(e).__name__, flush=True)
finally:
    s.close()
"""


def _hold_connection(user: str, host: str, port: int) -> subprocess.Popen | None:
    """Open a connection as ``user`` and keep it open across rule application."""
    process = subprocess.Popen(
        ["/usr/bin/setpriv", "--reuid", user, "--regid", "nogroup",
         "--clear-groups", "/usr/bin/python3", "-c", _HOLDER % (host, port)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    first = process.stdout.readline().strip()
    if first != "CONNECTED":
        process.kill()
        return None
    return process


def _resume_connection(process) -> dict:
    """Use the pre-existing connection now that the rule is installed."""
    if process is None:
        return {"opened_before_rule": False,
                "note": "no baseline connection could be established"}
    try:
        process.stdin.write("go\n")
        process.stdin.flush()
        outcome = process.stdout.readline().strip()
        process.wait(timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        process.kill()
        return {"opened_before_rule": True, "outcome": "probe-failed"}
    return {"opened_before_rule": True, "outcome": outcome,
            "still_usable_after_rule": outcome == "USABLE",
            "owned_by": "target uid"}


def _interpret(report: dict) -> list[dict]:
    """State what each measurement means for the capability claim."""
    scoped = report.get("with_ipv4_scoped_rule", {})
    findings = []
    if scoped.get("SHARED_UID_different_process") != "OPEN":
        findings.append({
            "id": "shared-uid", "severity": "by-design-limitation",
            "observed": scoped.get("SHARED_UID_different_process"),
            "meaning": "An unrelated process sharing the target uid is also "
                       "contained. skuid scopes by uid, not by workload, so a "
                       "shared service account means collateral containment."})
    if scoped.get("IPV6_loopback") == "OPEN":
        findings.append({
            "id": "ipv6-bypass", "severity": "capability-scope",
            "observed": "OPEN",
            "meaning": "An IPv4-scoped rule does not restrict IPv6. The "
                       "capability is IPv4 egress restriction and must be "
                       "named that way until v6 is enforced."})
    if report.get("with_unscoped_rule", {}).get("IPV6_loopback") != "OPEN":
        findings.append({
            "id": "unscoped-covers-v6", "severity": "informational",
            "observed": report["with_unscoped_rule"].get("IPV6_loopback"),
            "meaning": "An unscoped rule in the inet family covers both "
                       "address families."})
    established = report.get("established_connection", {})
    if established.get("opened_before_rule"):
        findings.append({
            "id": "established-connections",
            "severity": ("capability-scope" if established.get("still_usable_after_rule")
                         else "informational"),
            "observed": established.get("outcome"),
            "meaning": ("A connection opened before the rule keeps working, so "
                        "containment stops new connections only -- an existing "
                        "C2 channel survives."
                        if established.get("still_usable_after_rule") else
                        "A connection opened before the rule stops working, so "
                        "the drop applies to established flows as well.")})
    if "SETUID-SUCCEEDED" in str(scoped.get("setuid_escape_attempt", "")):
        findings.append({
            "id": "setuid-escape", "severity": "HIGH",
            "observed": scoped.get("setuid_escape_attempt"),
            "meaning": "The contained uid changed identity and escaped the "
                       "rule."})
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    print(json.dumps(run(args.destination, args.port), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
