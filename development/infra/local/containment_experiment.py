#!/usr/bin/env python3
"""The first real Annulon containment, end to end, against a live kernel.

Runs inside the Linux lab. Drives the full authorized chain --

    ActionRequest -> broker authorization -> backend -> nftables -> traffic

-- and refuses to call any of it successful on the strength of a return
code. The broker saying a rule was installed is control-plane evidence; a
connection that used to succeed and now times out is data-plane evidence, and
only the two together support a containment claim.

Controls, all required, all reported separately:

* **negative control** -- the identical traffic scenario with no action
  applied must succeed, or the harness itself is what is failing;
* **non-target control** -- an unrelated uid must keep working while the
  target is blocked, or the containment is not scoped;
* **management safety** -- the broker must still answer during containment;
* **expiry** -- traffic must return, verified against both the rule state and
  real traffic after the deadline, not inferred from a sleep.

Completion follows ADR-029: a run where a component failed is
EVIDENCE_INCOMPLETE, never a negative result.
"""

from __future__ import annotations

import argparse
import json
import os
import pwd
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

from annulon.response import ipc                                    # noqa: E402
from annulon.response.broker import Broker, BrokerConfig, BrokerServer  # noqa: E402
from annulon.response.client import BrokerClient, ResponseOutcome   # noqa: E402
from annulon.response.contract import Target, TargetKind            # noqa: E402
from annulon.response.nftables import (                             # noqa: E402
    NftablesEnforcer, NftablesUnavailable, Ownership,
)
from annulon.response.policy import BrokerPolicy                    # noqa: E402
from annulon.response.verification import (                         # noqa: E402
    ContainmentEvidence, assess,
)

TARGET_UID, CONTROL_UID = 1500, 1600
TARGET_USER, CONTROL_USER = "annulon-victim", "annulon-bystander"
HOST_ID, BOOT_ID = "annulon-lab", "boot-local"


class Incomplete(Exception):
    """The harness could not produce evidence either way."""


# -- workload identities ----------------------------------------------------

def ensure_user(name: str, uid: int) -> None:
    try:
        pwd.getpwnam(name)
        return
    except KeyError:
        pass
    result = subprocess.run(
        ["/usr/sbin/useradd", "-u", str(uid), "-M", "-s", "/usr/sbin/nologin", name],
        capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise Incomplete(f"cannot create {name}: {result.stderr.strip()[:120]}")


def probe(user: str, host: str, port: int, timeout: float = 4.0) -> str:
    """Attempt one TCP connection as ``user``. Returns OPEN or a failure kind.

    Runs as a separate process under a different uid, because ``meta skuid``
    matches the uid that owns the sending socket. Probing from this process
    would measure the wrong identity entirely.
    """
    script = (
        "import socket,sys\n"
        "s=socket.socket(); s.settimeout(%r)\n"
        "try:\n"
        "    s.connect((%r,%d)); print('OPEN')\n"
        "except Exception as e: print(type(e).__name__)\n"
        "finally: s.close()\n" % (timeout, host, port))
    result = subprocess.run(
        ["/usr/bin/setpriv", "--reuid", user, "--regid", "nogroup",
         "--clear-groups", "/usr/bin/python3", "-c", script],
        capture_output=True, text=True, timeout=timeout + 10)
    if result.returncode != 0:
        raise Incomplete(f"probe as {user} failed to run: "
                         f"{result.stderr.strip()[:160]}")
    return result.stdout.strip()


# -- the experiment ---------------------------------------------------------

def run(destination: str, port: int, ttl_seconds: int) -> dict:
    report: dict = {"environment": {
        "host": "macOS" if os.environ.get("ANNULON_HOST_OS") == "darwin" else "unknown",
        "enforcement_kernel": f"Linux {os.uname().release}",
        "machine": os.uname().machine,
        "mechanism": "Linux nftables",
        "destination": destination, "port": port, "ttl_seconds": ttl_seconds,
    }}

    if not NftablesEnforcer.available():
        raise Incomplete("nft is not present in this lab image")
    enforcer = NftablesEnforcer()
    ensure_user(TARGET_USER, TARGET_UID)
    ensure_user(CONTROL_USER, CONTROL_UID)

    report["foreign_tables_before"] = list(enforcer.foreign_tables())

    # --- negative control: no action at all --------------------------------
    # Run first. If traffic does not work without containment, nothing later
    # in this run means anything.
    negative = {"target": probe(TARGET_USER, destination, port),
                "control": probe(CONTROL_USER, destination, port)}
    report["negative_control"] = negative
    if negative["target"] != "OPEN" or negative["control"] != "OPEN":
        raise Incomplete(f"negative control did not pass: {negative}")

    # --- the broker, with the real backend ---------------------------------
    run_dir = Path("/run/annulon")
    run_dir.mkdir(parents=True, mode=0o750, exist_ok=True)
    config = BrokerConfig(
        host_id=HOST_ID, boot_id=BOOT_ID,
        socket_path=str(run_dir / "broker.sock"),
        journal_path=Path("/var/lib/annulon/actions.jsonl"),
        caller_uids={os.getuid(): "annulon-core"})
    policy = BrokerPolicy(
        permitted_uids=frozenset({TARGET_UID}),
        authorized_callers=frozenset({"annulon-core"}),
        max_ttl=timedelta(seconds=max(ttl_seconds, 60)))
    broker = Broker(config, policy, enforcer=enforcer)
    server = BrokerServer(broker, config, sweep_interval=0.5)
    server.start()
    serving = threading.Thread(
        target=lambda: [server.serve_once(0.2) for _ in iter(int, 1)],
        daemon=True)
    serving.start()

    try:
        client = BrokerClient(config.socket_path, timeout=10.0)
        report["baseline"] = {"target": probe(TARGET_USER, destination, port),
                              "control": probe(CONTROL_USER, destination, port)}
        if report["baseline"]["target"] != "OPEN":
            raise Incomplete("baseline target traffic did not succeed")

        # --- authorized containment ----------------------------------------
        target = Target(TargetKind.SERVICE_UID, HOST_ID, BOOT_ID,
                        str(TARGET_UID), TARGET_USER)
        result = client.request_egress_restriction(
            target, duration=timedelta(seconds=ttl_seconds),
            reason="first physical containment experiment",
            finding_id="finding-00000001", destination_cidr=f"{destination}/32")
        report["authorization"] = {
            "outcome": result.outcome.value, "request_id": result.request_id,
            "reasons": [r.value for r in result.reasons],
            "expires_at": result.expires_at.isoformat() if result.expires_at else None}
        if result.outcome is not ResponseOutcome.APPLIED:
            raise Incomplete(f"containment was not applied: {report['authorization']}")

        # --- control-plane evidence ----------------------------------------
        record = enforcer.find(result.request_id)
        report["rule_evidence"] = None if record is None else {
            "handle": record.handle, "ownership": record.ownership.value,
            "action_id": record.action_id, "uid": record.uid,
            "expires_at": record.expires_at.isoformat() if record.expires_at else None,
            "comment": record.comment}
        if record is None or record.ownership is not Ownership.OWNED:
            raise Incomplete("no provably owned rule after an applied action")

        # --- data-plane evidence -------------------------------------------
        during = {"target": probe(TARGET_USER, destination, port),
                  "control": probe(CONTROL_USER, destination, port)}
        report["traffic_during"] = during
        report["non_target_control"] = {
            "unaffected": during["control"] == "OPEN", "observed": during["control"]}

        # --- management safety ---------------------------------------------
        status = client.status()
        report["management_safety"] = {
            "broker_answers": status is not None,
            "active_actions": (status or {}).get("active_actions"),
            "loopback_reachable": _loopback_ok(),
            "foreign_tables_unchanged":
                list(enforcer.foreign_tables()) == report["foreign_tables_before"]}

        if during["target"] == "OPEN":
            # Rule installed, traffic still flowing. Reported as such, never
            # dressed up as containment.
            report["effect"] = "ACTION_EFFECT_NOT_VERIFIED"
        else:
            report["effect"] = "CONTAINED"

        # --- expiry, driven by the privileged broker ------------------------
        deadline = time.monotonic() + ttl_seconds + 20
        while time.monotonic() < deadline:
            if enforcer.find(result.request_id) is None:
                break
            time.sleep(0.5)
        rule_after = enforcer.find(result.request_id)
        after = {"target": probe(TARGET_USER, destination, port),
                 "control": probe(CONTROL_USER, destination, port)}
        report["traffic_after"] = after
        report["expiry"] = {
            "rule_removed": rule_after is None,
            "expired_by_broker": result.request_id in server.expired,
            "traffic_restored": after["target"] == "OPEN",
            # The claim is not "we waited": it is that the rule is gone from
            # the kernel and traffic measurably works again.
            "evidence": "rule state and real traffic inspected after the deadline"}

        report["foreign_tables_after"] = list(enforcer.foreign_tables())
        report["no_unrelated_state_changed"] = (
            report["foreign_tables_after"] == report["foreign_tables_before"])
        report["inspect_state"] = enforcer.inspect_state()
    finally:
        server.stop()
        try:
            for record in enforcer.rules():
                if record.ownership is Ownership.OWNED:
                    enforcer.release(record.resource)
            enforcer.remove_own_table()
        except Exception as exc:                    # noqa: BLE001
            report.setdefault("teardown_warning", str(exc)[:200])

    report["verdict"] = _verdict(report).to_dict()
    report["completion"] = report["verdict"]["completion"]
    return report


def _loopback_ok() -> bool:
    probe_socket = socket.socket()
    probe_socket.settimeout(2)
    try:
        probe_socket.connect(("127.0.0.1", 9))
    except ConnectionRefusedError:
        return True          # refused means the stack is alive
    except OSError:
        return False
    finally:
        probe_socket.close()
    return True


def _verdict(report: dict):
    """Hand the measurements to the shared verifier.

    The experiment does not decide whether containment happened; it reports
    what it measured and `annulon.response.verification` decides. Keeping
    that boundary means the harness cannot talk itself into a pass, and the
    decision logic is unit-tested separately from any lab.
    """
    rule = report.get("rule_evidence") or {}
    expiry = report.get("expiry", {})
    management = report.get("management_safety", {})
    return assess(ContainmentEvidence(
        negative_control_open=report.get("negative_control", {}).get("target") == "OPEN",
        baseline_open=report.get("baseline", {}).get("target") == "OPEN",
        rule_present=bool(rule),
        rule_ownership_proven=rule.get("ownership") == "owned",
        target_blocked=report.get("traffic_during", {}).get("target") != "OPEN",
        non_target_open=report.get("traffic_during", {}).get("control") == "OPEN",
        broker_responsive=bool(management.get("broker_answers")),
        foreign_state_unchanged=bool(report.get("no_unrelated_state_changed")),
        rule_removed_after_expiry=bool(expiry.get("rule_removed")),
        traffic_restored_after_expiry=bool(expiry.get("traffic_restored")),
        harness_errors=tuple(report.get("harness_errors", ()))))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--ttl", type=int, default=20)
    args = parser.parse_args()
    try:
        report = run(args.destination, args.port, args.ttl)
    except Incomplete as exc:
        report = {"completion": "EVIDENCE_INCOMPLETE", "reason": str(exc)}
    except (NftablesUnavailable, ipc.IpcError) as exc:
        report = {"completion": "EVIDENCE_INCOMPLETE",
                  "reason": f"{type(exc).__name__}: {exc}"}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("completion") == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
