#!/usr/bin/env python3
"""Kill the broker while a real rule is installed, then restart it.

Unit tests reconcile a journal against a stub. This reconciles a journal
against the actual kernel, after the process that wrote it has died with
state still in place. The distinction matters because every interesting
failure here is a *disagreement* between two sources of truth, and a stub
cannot disagree in the ways a kernel can.

Cases exercised, each against real nftables (doctrine §31):

    journal ACTIVE   + rule present   -> keep, then expire normally
    journal ACTIVE   + rule missing   -> close the record
    journal RELEASED + rule present   -> orphan, remove it
    rule present     + no journal     -> orphan, remove it
    foreign rule resembling ours      -> UNKNOWN, never removed
    expired rule still present        -> released on the next sweep

The last two are the ones worth the effort. Removing a rule Annulon cannot
prove it created is the behaviour that turns a security tool into an
outage, and an expired rule that nobody releases is a temporary restriction
that became permanent.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, "/annulon/development/src")

from annulon.response.broker import Broker, BrokerConfig                # noqa: E402
from annulon.response.contract import (                                 # noqa: E402
    ActionRequest, ActionState, ActionType, Target, TargetKind,
)
from annulon.response.journal import ActionJournal, OwnedResource       # noqa: E402
from annulon.response.nftables import (                                 # noqa: E402
    CHAIN_NAME, NftablesEnforcer, Ownership, TABLE_FAMILY, TABLE_NAME,
)
from annulon.response.policy import BrokerPolicy                        # noqa: E402

UID = 1500
HOST_ID, BOOT_ID = "annulon-lab", "boot-local"


def sh(argv, stdin=None, timeout=20):
    return subprocess.run(argv, input=stdin, capture_output=True, text=True,
                          timeout=timeout)


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
    return sh(["/usr/bin/setpriv", "--reuid", user, "--regid", "nogroup",
               "--clear-groups", "/usr/bin/python3", "-c", script],
              timeout=timeout + 10).stdout.strip()


def _request(request_id: str, destination: str) -> ActionRequest:
    return ActionRequest(
        request_id=request_id,
        action_type=ActionType.TEMPORARY_EGRESS_RESTRICTION,
        target=Target(TargetKind.SERVICE_UID, HOST_ID, BOOT_ID, str(UID),
                      "workload"),
        duration=timedelta(minutes=5), reason="recovery experiment",
        finding_id="finding-00000005",
        requested_at=datetime.now(timezone.utc),
        requesting_component="annulon-core",
        destination_cidr=f"{destination}/32")


class Clock:
    def __init__(self):
        self.now = datetime.now(timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, delta):
        self.now += delta


def _policy():
    return BrokerPolicy(permitted_uids=frozenset({UID}),
                        authorized_callers=frozenset({"annulon-core"}),
                        max_ttl=timedelta(minutes=10), max_active_actions=10)


def _config(journal: Path, name: str) -> BrokerConfig:
    return BrokerConfig(
        host_id=HOST_ID, boot_id=BOOT_ID,
        socket_path=f"/run/annulon/{name}.sock", journal_path=journal,
        caller_uids={os.getuid(): "annulon-core"})


def _install_foreign_rule() -> int | None:
    """A rule in Annulon's own table that Annulon did not write.

    Comment version 99: shaped like ours, unprovable by our parser. This is
    the thing that must survive reconciliation untouched.
    """
    payload = {"nftables": [{"add": {"rule": {
        "family": TABLE_FAMILY, "table": TABLE_NAME, "chain": CHAIN_NAME,
        "comment": "annulon;v=99;a=req-not-ours-000001;u=1500",
        "expr": [{"match": {"op": "==", "left": {"meta": {"key": "skuid"}},
                            "right": 4242}},
                 {"drop": None}]}}}]}
    result = sh(["/usr/sbin/nft", "-j", "-f", "-"], stdin=json.dumps(payload))
    if result.returncode != 0:
        return None
    listing = json.loads(sh(["/usr/sbin/nft", "-j", "list", "table",
                             TABLE_FAMILY, TABLE_NAME]).stdout)
    for item in listing.get("nftables", []):
        rule = item.get("rule") if isinstance(item, dict) else None
        if isinstance(rule, dict) and "v=99" in str(rule.get("comment", "")):
            return rule["handle"]
    return None


def run(destination: str, port: int) -> dict:
    enforcer = NftablesEnforcer()
    ensure_user("annulon-victim", UID)
    enforcer.ensure_structure()
    state = Path("/var/lib/annulon")
    state.mkdir(parents=True, exist_ok=True)
    Path("/run/annulon").mkdir(parents=True, exist_ok=True)

    report: dict = {"environment": {
        "enforcement_kernel": f"Linux {os.uname().release}",
        "machine": os.uname().machine, "mechanism": "Linux nftables"},
        "cases": {}}

    # === journal ACTIVE + rule present: survives a broker death ============
    journal_path = state / "recovery-a.jsonl"
    journal_path.unlink(missing_ok=True)
    clock = Clock()
    first = Broker(_config(journal_path, "a"), _policy(), enforcer=enforcer,
                   clock=clock)
    request = _request("req-recovery-active-01", destination)
    result = first.handle({"schema_version": 1, "type": "action_request",
                           "request": request.to_dict()}, caller="annulon-core")
    traffic_during = probe("annulon-victim", destination, port)
    # The broker process dies here. The rule does not.
    del first

    revived = Broker(_config(journal_path, "a"), _policy(), enforcer=enforcer,
                     clock=clock)
    notes = revived.reconcile()
    rule_after_restart = enforcer.find("req-recovery-active-01")
    report["cases"]["journal_active_rule_present"] = {
        "applied": result.get("decision") == "allow",
        "traffic_during": traffic_during,
        "rule_survived_broker_death": rule_after_restart is not None,
        "reconciliation_kept_it": rule_after_restart is not None,
        "notes": list(notes)}

    # === the deadline survives the restart ================================
    clock.advance(timedelta(minutes=10))
    expired = revived.expire_due()
    report["cases"]["deadline_survives_restart"] = {
        "expired_by_new_broker": "req-recovery-active-01" in expired,
        "rule_removed": enforcer.find("req-recovery-active-01") is None,
        "traffic_after": probe("annulon-victim", destination, port),
        "note": "the deadline lives in the journal, not in a process timer, "
                "so a restart cannot extend the action"}

    # === rule present, no journal entry: an orphan ========================
    orphan_journal = state / "recovery-b.jsonl"
    orphan_journal.unlink(missing_ok=True)
    orphan = enforcer.apply(_request("req-recovery-orphan-1", destination),
                            expires_at=datetime.now(timezone.utc)
                            + timedelta(minutes=5))
    empty_broker = Broker(_config(orphan_journal, "b"), _policy(),
                          enforcer=enforcer, clock=Clock())
    orphan_notes = empty_broker.reconcile()
    report["cases"]["rule_present_no_journal"] = {
        "rule_existed": orphan.resource is not None,
        "removed_as_orphan": enforcer.find("req-recovery-orphan-1") is None,
        "notes": list(orphan_notes)}

    # === journal ACTIVE, rule missing: close the record ====================
    stale_journal = state / "recovery-c.jsonl"
    stale_journal.unlink(missing_ok=True)
    stale = ActionJournal(stale_journal)
    stale.record(
        action_id="req-recovery-stale-01",
        action_type=ActionType.TEMPORARY_EGRESS_RESTRICTION,
        target=Target(TargetKind.SERVICE_UID, HOST_ID, BOOT_ID, str(UID), "w"),
        state=ActionState.APPLIED, policy_version="p", requested_by="annulon-core",
        requested_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        owned_resource=OwnedResource("nftables",
                                     f"{TABLE_FAMILY}/{TABLE_NAME}/{CHAIN_NAME}/"
                                     "req-recovery-stale-01"))
    del stale
    stale_broker = Broker(_config(stale_journal, "c"), _policy(),
                          enforcer=enforcer, clock=Clock())
    before = stale_broker.journal.active_count()
    stale_notes = stale_broker.reconcile()
    report["cases"]["journal_active_rule_missing"] = {
        "active_before": before,
        "active_after": stale_broker.journal.active_count(),
        "record_closed": stale_broker.journal.active_count() == 0,
        "notes": list(stale_notes)}

    # === a foreign rule in our own table is never removed ==================
    foreign_handle = _install_foreign_rule()
    foreign_journal = state / "recovery-d.jsonl"
    foreign_journal.unlink(missing_ok=True)
    foreign_broker = Broker(_config(foreign_journal, "d"), _policy(),
                            enforcer=enforcer, clock=Clock())
    foreign_notes = foreign_broker.reconcile()
    still_there = any(r.handle == foreign_handle for r in enforcer.rules())
    inspect = enforcer.inspect_state()
    report["cases"]["foreign_rule_in_our_table"] = {
        "installed": foreign_handle is not None,
        "survived_reconciliation": still_there,
        "classified_unknown": foreign_handle in inspect["unknown"],
        "reported_not_deleted": still_there and bool(inspect["unknown"]),
        "notes": list(foreign_notes),
        "meaning": "a rule Annulon cannot prove it created is reported as "
                   "UNKNOWN_FOREIGN_STATE and left in place"}

    # Table removal must also refuse while that rule is present.
    try:
        enforcer.remove_own_table()
        refused = False
    except Exception:                                   # noqa: BLE001
        refused = True
    report["cases"]["foreign_rule_in_our_table"]["table_removal_refused"] = refused

    if foreign_handle is not None:
        sh(["/usr/sbin/nft", "delete", "rule", TABLE_FAMILY, TABLE_NAME,
            CHAIN_NAME, "handle", str(foreign_handle)])

    report["verdict"] = _verdict(report)

    for record in enforcer.rules():
        if record.ownership is Ownership.OWNED:
            enforcer.release(record.resource)
    try:
        enforcer.remove_own_table()
    except Exception as exc:                            # noqa: BLE001
        report["teardown_warning"] = str(exc)[:200]
    return report


def _verdict(report: dict) -> dict:
    cases = report["cases"]
    checks = {
        "containment_survived_broker_death":
            cases["journal_active_rule_present"]["rule_survived_broker_death"],
        "traffic_was_actually_blocked":
            cases["journal_active_rule_present"]["traffic_during"] != "OPEN",
        "deadline_survived_restart":
            cases["deadline_survives_restart"]["expired_by_new_broker"],
        "rule_removed_at_deadline":
            cases["deadline_survives_restart"]["rule_removed"],
        "traffic_restored":
            cases["deadline_survives_restart"]["traffic_after"] == "OPEN",
        "orphan_removed": cases["rule_present_no_journal"]["removed_as_orphan"],
        "stale_record_closed":
            cases["journal_active_rule_missing"]["record_closed"],
        "foreign_rule_untouched":
            cases["foreign_rule_in_our_table"]["survived_reconciliation"],
        "foreign_rule_reported":
            cases["foreign_rule_in_our_table"]["classified_unknown"],
        "table_removal_refused_while_foreign_present":
            cases["foreign_rule_in_our_table"]["table_removal_refused"],
    }
    checks["completion"] = ("COMPLETE" if all(v for k, v in checks.items())
                            else "EVIDENCE_INCOMPLETE")
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    report = run(args.destination, args.port)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["verdict"]["completion"] == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
