#!/usr/bin/env python3
"""IPv6 egress containment, physically.

`SAFE-IPV6-01` has been open since KF-38, where measurement showed an
IPv4-scoped rule leaves IPv6 wide open. The capability was renamed to *IPv4*
egress restriction rather than claiming more than was true. This closes it
by enforcing and verifying the v6 case, and by checking the property KF-38
was really about: that the rule covers the family the traffic is actually on.

A ULA address on a dummy interface is used rather than loopback, because
`::1` is a protected destination — the broker refuses to restrict it, which
is correct and would make the experiment untestable against the real policy.
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

for _candidate in (os.environ.get("ANNULON_SRC"),
                   "/annulon/development/src", "/opt/sdnguard/src"):
    if _candidate and os.path.isdir(os.path.join(_candidate, "annulon")):
        sys.path.insert(0, _candidate)
        break
else:
    raise SystemExit("cannot locate the annulon package; set ANNULON_SRC")

from annulon.response.contract import (                                 # noqa: E402
    ActionRequest, ActionType, Target, TargetKind,
)
from annulon.response.nftables import (                                 # noqa: E402
    Coverage, NftablesEnforcer, Ownership, coverage_for,
)
from annulon.response.policy import ProtectedScopes                     # noqa: E402

UID, USER = 1500, "annulon-v6"
BYSTANDER_UID, BYSTANDER = 1600, "annulon-v6-other"
ULA = "fd00:a11:c0de::1"
IFACE = "annulon6"


def sh(argv, timeout: float = 60, **kw):
    return subprocess.run(argv, capture_output=True, text=True,
                          timeout=timeout, **kw)


def ensure_user(name: str, uid: int) -> None:
    if sh(["/usr/bin/id", "-u", name]).returncode != 0:
        sh(["/usr/sbin/useradd", "-u", str(uid), "-o", "-M",
            "-s", "/usr/sbin/nologin", name])


def setup_interface() -> bool:
    """A dummy interface with a ULA address: non-loopback, and ours."""
    sh(["ip", "link", "add", IFACE, "type", "dummy"])
    sh(["ip", "link", "set", IFACE, "up"])
    added = sh(["ip", "-6", "addr", "add", f"{ULA}/128", "dev", IFACE])
    time.sleep(0.5)          # duplicate address detection
    shown = sh(["ip", "-6", "addr", "show", "dev", IFACE])
    return ULA in shown.stdout


def teardown_interface() -> None:
    sh(["ip", "link", "del", IFACE])


class V6Service(threading.Thread):
    def __init__(self, address: str) -> None:
        super().__init__(daemon=True)
        self._socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((address, 0))
        self._socket.listen(32)
        self.port = self._socket.getsockname()[1]
        self.accepted = 0
        self._stop = threading.Event()

    def run(self) -> None:
        self._socket.settimeout(0.2)
        while not self._stop.is_set():
            try:
                connection, _ = self._socket.accept()
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                break
            self.accepted += 1
            connection.close()

    def stop(self) -> None:
        self._stop.set()
        self._socket.close()


def probe(user: str, address: str, port: int, timeout: float = 4.0) -> str:
    script = ("import socket\n"
              "s=socket.socket(socket.AF_INET6); s.settimeout(%r)\n"
              "try: s.connect((%r,%d)); print('OPEN')\n"
              "except Exception as e: print(type(e).__name__)\n"
              "finally: s.close()\n" % (timeout, address, port))
    result = sh(["/usr/bin/setpriv", "--reuid", user, "--regid", "nogroup",
                 "--clear-groups", "/usr/bin/python3", "-c", script],
                timeout=timeout + 10)
    return result.stdout.strip() or f"probe-failed:{result.stderr.strip()[:60]}"


def _request(request_id: str, destination: str, port: int) -> ActionRequest:
    return ActionRequest(
        request_id=request_id,
        action_type=ActionType.TEMPORARY_EGRESS_RESTRICTION,
        target=Target(TargetKind.SERVICE_UID, "lab", "boot", str(UID), USER),
        duration=timedelta(minutes=5), reason="ipv6 containment experiment",
        finding_id="finding-00000006",
        requested_at=datetime.now(timezone.utc),
        requesting_component="annulon-core",
        destination_cidr=f"{destination}/128", destination_port=port)


def run() -> dict:
    report: dict = {"environment": {
        "kernel": os.uname().release, "machine": os.uname().machine}}
    if not NftablesEnforcer.available():
        return {"completion": "EVIDENCE_INCOMPLETE", "reason": "nft absent"}

    ensure_user(USER, UID)
    ensure_user(BYSTANDER, BYSTANDER_UID)
    if not setup_interface():
        return {"completion": "EVIDENCE_INCOMPLETE",
                "reason": "could not configure an IPv6 address to test against"}

    enforcer = NftablesEnforcer()
    enforcer.ensure_structure()
    service = V6Service(ULA)
    service.start()
    time.sleep(0.3)

    try:
        report["baseline"] = {
            "target": probe(USER, ULA, service.port),
            "bystander": probe(BYSTANDER, ULA, service.port),
            "service_accepted": service.accepted,
        }

        # The protections must cover v6 before anything is enforced over it.
        scopes = ProtectedScopes()
        report["protected_scopes_cover_ipv6"] = {
            cidr: scopes.covers_destination(cidr) for cidr in
            ("::1/128", "fd00:ec2::254/128", "::ffff:127.0.0.1/128",
             "fe80::1/128", f"{ULA}/128")}

        report["coverage_declared"] = {
            "ipv6_destination": coverage_for(f"{ULA}/128").value,
            "ipv4_destination": coverage_for("10.0.0.1/32").value,
            "unscoped": coverage_for(None).value,
        }

        result = enforcer.apply(_request("req-ipv6-containment-01", ULA,
                                         service.port),
                                expires_at=datetime.now(timezone.utc)
                                + timedelta(minutes=5))
        record = enforcer.find("req-ipv6-containment-01")
        report["rule_evidence"] = None if record is None else {
            "handle": record.handle, "ownership": record.ownership.value,
            "uid": record.uid, "comment": record.comment}
        report["apply_detail"] = result.detail

        report["traffic_during"] = {
            "target": probe(USER, ULA, service.port),
            "bystander": probe(BYSTANDER, ULA, service.port),
        }

        if record is not None:
            enforcer.release(record.resource)
        report["traffic_after"] = {"target": probe(USER, ULA, service.port)}
        report["rule_removed"] = enforcer.find("req-ipv6-containment-01") is None

        report["verdict"] = _verdict(report)
    finally:
        try:
            for rule in enforcer.rules():
                if rule.ownership is Ownership.OWNED:
                    enforcer.release(rule.resource)
            enforcer.remove_own_table()
        except Exception as exc:                            # noqa: BLE001
            report["teardown_warning"] = str(exc)[:200]
        service.stop()
        teardown_interface()
    return report


def _verdict(report: dict) -> dict:
    checks = {
        "baseline_reachable_over_ipv6": report["baseline"]["target"] == "OPEN",
        "ipv6_management_paths_protected": all(
            report["protected_scopes_cover_ipv6"][c] for c in
            ("::1/128", "fd00:ec2::254/128", "::ffff:127.0.0.1/128",
             "fe80::1/128")),
        "ordinary_ipv6_destination_still_containable":
            not report["protected_scopes_cover_ipv6"][f"{ULA}/128"],
        "coverage_named_ipv6_only":
            report["coverage_declared"]["ipv6_destination"] == "ipv6_only",
        "rule_owned": (report.get("rule_evidence") or {}).get("ownership") == "owned",
        "ipv6_traffic_blocked": report["traffic_during"]["target"] != "OPEN",
        "bystander_unaffected": report["traffic_during"]["bystander"] == "OPEN",
        "traffic_restored": report["traffic_after"]["target"] == "OPEN",
        "rule_removed": report.get("rule_removed", False),
    }
    checks["completion"] = ("COMPLETE" if all(v for k, v in checks.items())
                            else "EVIDENCE_INCOMPLETE")
    return checks


def main() -> int:
    argparse.ArgumentParser(description=__doc__).parse_args()
    report = run()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("verdict", {}).get("completion") == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
