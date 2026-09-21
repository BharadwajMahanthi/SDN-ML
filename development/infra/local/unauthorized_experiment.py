#!/usr/bin/env python3
"""An unauthorized request against the real broker and the real kernel.

Unit tests establish that the broker denies. They cannot establish that a
denial leaves the *host* untouched, because in a unit test there is no host.
This run puts syntactically valid but unauthorized requests through the live
socket to a broker wired to the real nftables backend, and then measures the
kernel and the network independently.

Three things must hold for every unauthorized request:

    DENY
    + no nftables state change
    + no traffic change

The third matters most. A denial that nevertheless perturbed the ruleset --
a chain created, a table left behind, a half-built rule -- would mean the
attacker had achieved something by asking, even though the answer was no.

A positive control runs last: one *authorized* request must still work. An
experiment where nothing is ever permitted proves only that the broker is
broken.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, "/annulon/development/src")

from annulon.response.broker import Broker, BrokerConfig, BrokerServer  # noqa: E402
from annulon.response.client import BrokerClient, ResponseOutcome       # noqa: E402
from annulon.response.contract import (                                 # noqa: E402
    ActionRequest, ActionType, ContractError, Target, TargetKind,
)
from annulon.response.nftables import NftablesEnforcer, Ownership       # noqa: E402
from annulon.response.policy import BrokerPolicy                        # noqa: E402

PERMITTED_UID, OTHER_UID, PROTECTED_UID = 1500, 1600, 0
TARGET_USER = "annulon-victim"
HOST_ID, BOOT_ID = "annulon-lab", "boot-local"


def sh(argv, timeout=30):
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)


def ensure_user(name, uid):
    if sh(["/usr/bin/id", "-u", name]).returncode != 0:
        sh(["/usr/sbin/useradd", "-u", str(uid), "-o", "-M",
            "-s", "/usr/sbin/nologin", name])


def probe(user, host, port, timeout=4.0):
    script = ("import socket\n"
              "s=socket.socket(); s.settimeout(%r)\n"
              "try: s.connect((%r,%d)); print('OPEN')\n"
              "except Exception as e: print(type(e).__name__)\n"
              "finally: s.close()\n" % (timeout, host, port))
    result = sh(["/usr/bin/setpriv", "--reuid", user, "--regid", "nogroup",
                 "--clear-groups", "/usr/bin/python3", "-c", script],
                timeout=timeout + 10)
    return result.stdout.strip()


def full_ruleset() -> str:
    """The entire ruleset, as JSON, for byte-comparison before and after.

    Deliberately the *whole* thing rather than just Annulon's table: the
    claim is that a denial changes nothing anywhere, and only comparing our
    own table would miss a rule landing somewhere else.
    """
    result = sh(["/usr/sbin/nft", "-j", "list", "ruleset"])
    return result.stdout


#: Syntactically valid requests that policy must refuse. Each is something a
#: compromised core would plausibly try, and each names why it is refused.
def unauthorized_cases(destination: str):
    base = dict(
        duration=timedelta(minutes=5), reason="unauthorized attempt",
        finding_id="finding-00000003",
        requested_at=datetime.now(timezone.utc),
        requesting_component="annulon-core")

    def target(uid, service="workload"):
        return Target(TargetKind.SERVICE_UID, HOST_ID, BOOT_ID, str(uid), service)

    return [
        ("root_uid", dict(base, request_id="req-unauth-root-00001",
                          action_type=ActionType.TEMPORARY_EGRESS_RESTRICTION,
                          target=target(PROTECTED_UID),
                          destination_cidr=f"{destination}/32")),
        ("uid_outside_allowlist", dict(base, request_id="req-unauth-uid-000001",
                                       action_type=ActionType.TEMPORARY_EGRESS_RESTRICTION,
                                       target=target(4242),
                                       destination_cidr=f"{destination}/32")),
        ("protected_service_name", dict(base, request_id="req-unauth-sshd-00001",
                                        action_type=ActionType.TEMPORARY_EGRESS_RESTRICTION,
                                        target=target(PERMITTED_UID, "sshd"),
                                        destination_cidr=f"{destination}/32")),
        ("metadata_endpoint", dict(base, request_id="req-unauth-imds-00001",
                                   action_type=ActionType.TEMPORARY_EGRESS_RESTRICTION,
                                   target=target(PERMITTED_UID),
                                   destination_cidr="169.254.169.254/32")),
        ("whole_internet", dict(base, request_id="req-unauth-world-0001",
                                action_type=ActionType.TEMPORARY_EGRESS_RESTRICTION,
                                target=target(PERMITTED_UID),
                                destination_cidr="0.0.0.0/0")),
        ("ttl_beyond_policy", dict(base, request_id="req-unauth-ttl-000001",
                                   action_type=ActionType.TEMPORARY_EGRESS_RESTRICTION,
                                   target=target(PERMITTED_UID),
                                   duration=timedelta(hours=1),
                                   destination_cidr=f"{destination}/32")),
        ("stale_request", dict(base, request_id="req-unauth-stale-0001",
                               action_type=ActionType.TEMPORARY_EGRESS_RESTRICTION,
                               target=target(PERMITTED_UID),
                               requested_at=datetime.now(timezone.utc)
                               - timedelta(minutes=30),
                               destination_cidr=f"{destination}/32")),
        ("wrong_boot", dict(base, request_id="req-unauth-boot-00001",
                            action_type=ActionType.TEMPORARY_EGRESS_RESTRICTION,
                            target=Target(TargetKind.SERVICE_UID, HOST_ID,
                                          "a-different-boot", str(PERMITTED_UID),
                                          "workload"),
                            destination_cidr=f"{destination}/32")),
    ]


def run(destination: str, port: int) -> dict:
    enforcer = NftablesEnforcer()
    ensure_user(TARGET_USER, PERMITTED_UID)
    ensure_user("annulon-bystander", OTHER_UID)
    enforcer.ensure_structure()

    run_dir = Path("/run/annulon")
    run_dir.mkdir(parents=True, mode=0o750, exist_ok=True)
    config = BrokerConfig(
        host_id=HOST_ID, boot_id=BOOT_ID,
        socket_path=str(run_dir / "broker.sock"),
        journal_path=Path("/var/lib/annulon/unauth.jsonl"),
        caller_uids={os.getuid(): "annulon-core"})
    policy = BrokerPolicy(
        permitted_uids=frozenset({PERMITTED_UID}),
        authorized_callers=frozenset({"annulon-core"}),
        max_ttl=timedelta(minutes=10))
    broker = Broker(config, policy, enforcer=enforcer)
    server = BrokerServer(broker, config, sweep_interval=0.5)
    server.start()
    threading.Thread(target=lambda: [server.serve_once(0.2) for _ in iter(int, 1)],
                     daemon=True).start()

    report: dict = {"environment": {
        "enforcement_kernel": f"Linux {os.uname().release}",
        "machine": os.uname().machine, "mechanism": "Linux nftables"},
        "cases": {}}

    try:
        client = BrokerClient(config.socket_path, timeout=10.0)
        ruleset_before = full_ruleset()
        traffic_before = probe(TARGET_USER, destination, port)
        report["traffic_before"] = traffic_before

        for name, fields in unauthorized_cases(destination):
            try:
                request = ActionRequest(**fields)
            except ContractError as exc:
                report["cases"][name] = {
                    "result": "refused_by_contract",
                    "detail": type(exc).__name__,
                    "ruleset_unchanged": True, "traffic_unchanged": True}
                continue
            result = client.send(request)
            ruleset_after = full_ruleset()
            traffic_after = probe(TARGET_USER, destination, port)
            report["cases"][name] = {
                "outcome": result.outcome.value,
                "denied": result.outcome is ResponseOutcome.DENIED,
                "reasons": [r.value for r in result.reasons],
                "ruleset_unchanged": ruleset_after == ruleset_before,
                "traffic_unchanged": traffic_after == traffic_before,
                "owned_rules_after": [r.action_id for r in enforcer.rules()
                                      if r.ownership is Ownership.OWNED],
            }

        # --- positive control -------------------------------------------
        # Without this, "everything was denied" could equally mean the
        # broker is simply broken.
        authorized = client.request_egress_restriction(
            Target(TargetKind.SERVICE_UID, HOST_ID, BOOT_ID,
                   str(PERMITTED_UID), "workload"),
            duration=timedelta(seconds=20), reason="positive control",
            finding_id="finding-00000004",
            destination_cidr=f"{destination}/32")
        report["positive_control"] = {
            "outcome": authorized.outcome.value,
            "applied": authorized.outcome is ResponseOutcome.APPLIED,
            "traffic_during": probe(TARGET_USER, destination, port),
            "owned_rules": [r.action_id for r in enforcer.rules()
                            if r.ownership is Ownership.OWNED]}
        if authorized.outcome is ResponseOutcome.APPLIED:
            record = enforcer.find(authorized.request_id)
            if record is not None:
                enforcer.release(record.resource)

        report["verdict"] = _verdict(report)
    finally:
        server.stop()
        try:
            for record in enforcer.rules():
                if record.ownership is Ownership.OWNED:
                    enforcer.release(record.resource)
            enforcer.remove_own_table()
        except Exception as exc:                        # noqa: BLE001
            report["teardown_warning"] = str(exc)[:200]
    return report


def _verdict(report: dict) -> dict:
    cases = report["cases"]
    denied = all(c.get("denied") or c.get("result") == "refused_by_contract"
                 for c in cases.values())
    ruleset_clean = all(c.get("ruleset_unchanged") for c in cases.values())
    traffic_clean = all(c.get("traffic_unchanged") for c in cases.values())
    no_rules = all(not c.get("owned_rules_after") for c in cases.values())
    positive = report.get("positive_control", {}).get("applied", False)
    contained = report.get("positive_control", {}).get("traffic_during") != "OPEN"
    passed = all([denied, ruleset_clean, traffic_clean, no_rules, positive,
                  contained])
    return {
        "all_unauthorized_denied": denied,
        "ruleset_never_changed": ruleset_clean,
        "traffic_never_changed": traffic_clean,
        "no_rule_ever_created_by_a_denial": no_rules,
        "positive_control_applied": positive,
        "positive_control_contained": contained,
        "completion": "COMPLETE" if passed else "EVIDENCE_INCOMPLETE",
        "cases_examined": len(cases)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    report = run(args.destination, args.port)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("verdict", {}).get("completion") == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
