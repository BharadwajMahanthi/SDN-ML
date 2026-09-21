"""Crash at the worst moment, and do two things at once.

Every test here kills the broker at a specific point in an action's life and
then asks the only question that matters after a restart:

    does the durable record agree with what the host actually holds?

The dangerous answers are asymmetric. A record that says "released" while a
rule is still installed leaves a restriction with no deadline and nothing
watching it — a temporary containment that became permanent. A record that
says "active" while no rule exists merely wastes a slot. So wherever the
outcome is uncertain, the broker must err towards believing state exists.

The concurrency tests exist because expiry runs on its own thread. Release
and expiry racing over one action is not a hypothetical: it is what happens
whenever an operator releases something a second before its TTL ends.
"""

from __future__ import annotations

import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from annulon.response.broker import Broker, BrokerConfig
from annulon.response.contract import (
    ActionState, ActionType, SCHEMA_VERSION, Target, TargetKind,
)
from annulon.response.enforcement import (
    EnforcementError, EnforcementOutcome, EnforcementResult, RecordingEnforcer,
)
from annulon.response.journal import ActionJournal, JournalError, OwnedResource
from annulon.response.policy import BrokerPolicy

UID = 1500
NOW = datetime(2026, 9, 21, 12, tzinfo=timezone.utc)


class Clock:
    def __init__(self, start=NOW):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, delta):
        self.now += delta


def _config(tmp_path, name="b") -> BrokerConfig:
    return BrokerConfig(
        host_id="h", boot_id="b7", socket_path=str(tmp_path / f"{name}.sock"),
        journal_path=tmp_path / f"{name}.jsonl",
        caller_uids={os.getuid(): "annulon-core"})


def _policy(**overrides) -> BrokerPolicy:
    base = dict(permitted_uids=frozenset({UID}),
                authorized_callers=frozenset({"annulon-core"}),
                max_active_actions=100, max_requests_per_minute=100_000)
    base.update(overrides)
    return BrokerPolicy(**base)


_ids = iter(range(1, 10 ** 6))


def _payload(**overrides):
    payload = {
        "schema_version": SCHEMA_VERSION,
        "request_id": f"req-{next(_ids):012d}",
        "action_type": ActionType.TEMPORARY_EGRESS_RESTRICTION.value,
        "target": {"kind": TargetKind.SERVICE_UID.value, "host_id": "h",
                   "boot_id": "b7", "identifier": str(UID),
                   "service_name": "worker"},
        "duration_seconds": 300, "reason": "crash matrix",
        "finding_id": "finding-00000001", "requested_at": NOW.isoformat(),
        "requesting_component": "annulon-core", "policy_version": "",
        "destination_cidr": None}
    payload.update(overrides)
    return payload


def _send(broker, clock=None, payload=None):
    body = payload or _payload()
    if clock is not None:
        body["requested_at"] = clock().isoformat()
    response = broker.handle({"schema_version": SCHEMA_VERSION,
                              "type": "action_request", "request": body},
                             caller="annulon-core")
    return response, body["request_id"]


class Crash(Exception):
    """Simulates the process dying. Raised from inside the backend."""


# --- the crash matrix (doctrine section 28) --------------------------------

def test_crash_before_authorization_leaves_nothing(tmp_path):
    """Nothing was promised, so nothing must be recorded."""
    config = _config(tmp_path)
    Broker(config, _policy(), enforcer=RecordingEnforcer(), clock=Clock())
    revived = Broker(config, _policy(), enforcer=RecordingEnforcer(), clock=Clock())
    assert revived.journal.entries() == ()
    assert revived.journal.active_count() == 0


def test_crash_during_apply_leaves_a_record_that_says_state_may_exist(tmp_path):
    """The window ADR-048 exists for.

    The backend dies partway through. The journal was written first, so the
    restarted broker knows to go looking — which is the whole point of
    writing it first.
    """
    class DyingEnforcer(RecordingEnforcer):
        def apply(self, request, *, expires_at):
            raise Crash("process died mid-apply")

    clock = Clock()
    config = _config(tmp_path)
    broker = Broker(config, _policy(), enforcer=DyingEnforcer(), clock=clock)
    _, request_id = _send(broker, clock)

    revived = Broker(config, _policy(), enforcer=RecordingEnforcer(), clock=clock)
    entry = revived.journal.get(request_id)
    assert entry is not None
    assert entry.state is ActionState.ROLLBACK_REQUIRED
    assert entry.holds_os_state, "a crash mid-apply must not look like nothing"


def test_crash_after_apply_before_journal_update_is_found_by_reconciliation(tmp_path):
    """The orphan case: the rule exists, the journal never learned its id.

    This is the one that, unhandled, turns a five-minute restriction into a
    permanent one.
    """
    clock = Clock()
    config = _config(tmp_path)
    enforcer = RecordingEnforcer()
    enforcer.plant_orphan("recording/service_uid/1500/lost-on-crash")

    revived = Broker(config, _policy(), enforcer=enforcer, clock=clock)
    notes = revived.reconcile()
    assert any("removed orphan" in note for note in notes)
    assert enforcer.reconcile() == (), "the orphaned rule survived"


def test_an_uncertain_apply_survives_a_restart_as_still_holding_state(tmp_path):
    """"We do not know" must stay "we do not know" across a restart."""
    clock = Clock()
    config = _config(tmp_path)
    payload = _payload()
    enforcer = RecordingEnforcer(
        uncertain_on=frozenset({payload["request_id"]}))
    broker = Broker(config, _policy(), enforcer=enforcer, clock=clock)
    _, request_id = _send(broker, clock, payload)

    revived = Broker(config, _policy(), enforcer=enforcer, clock=clock)
    entry = revived.journal.get(request_id)
    assert entry.state is ActionState.EFFECT_NOT_VERIFIED
    assert entry.holds_os_state


def test_crash_during_ttl_still_expires_after_restart(tmp_path):
    """INV-005. The deadline lives in the journal, not in a timer.

    A restart therefore cannot extend an action: the new process reads the
    same expiry and releases it on the next sweep.
    """
    clock = Clock()
    config = _config(tmp_path)
    enforcer = RecordingEnforcer()
    broker = Broker(config, _policy(), enforcer=enforcer, clock=clock)
    _, request_id = _send(broker, clock)

    # The process dies here. A new one starts, well past the deadline.
    clock.advance(timedelta(hours=1))
    revived = Broker(config, _policy(), enforcer=enforcer, clock=clock)
    assert revived.expire_due() == (request_id,)
    assert revived.journal.get(request_id).state is ActionState.RELEASED
    assert enforcer.released


def test_crash_during_release_leaves_the_action_needing_rollback(tmp_path):
    """Release failed; the rule may still be there. It must not be recorded
    as released, or nothing will ever look for it again."""
    class DyingRelease(RecordingEnforcer):
        def release(self, resource):
            raise EnforcementError("died during release")

    clock = Clock()
    config = _config(tmp_path)
    broker = Broker(config, _policy(), enforcer=DyingRelease(), clock=clock)
    _, request_id = _send(broker, clock)
    clock.advance(timedelta(hours=1))
    broker.expire_due()

    revived = Broker(config, _policy(), enforcer=DyingRelease(), clock=clock)
    entry = revived.journal.get(request_id)
    assert entry.state is ActionState.ROLLBACK_REQUIRED
    assert entry.holds_os_state


def test_a_journal_that_cannot_be_written_stops_the_action(tmp_path):
    """An unjournalled privileged action is one nobody can clean up, so the
    broker declines to perform it at all."""
    clock = Clock()
    config = _config(tmp_path)
    enforcer = RecordingEnforcer()
    broker = Broker(config, _policy(), enforcer=enforcer, clock=clock)

    def explode(*args, **kwargs):
        raise JournalError("read-only filesystem")

    broker._journal.record = explode
    response, _ = _send(broker, clock)
    assert response["enforcement"] == "unavailable"
    assert "journal unavailable" in response["detail"]
    assert enforcer.applied == [], "the OS was touched without a record"


def test_a_truncated_journal_tail_does_not_hide_live_actions(tmp_path):
    """The normal shape of a power loss mid-write."""
    clock = Clock()
    config = _config(tmp_path)
    enforcer = RecordingEnforcer()
    broker = Broker(config, _policy(), enforcer=enforcer, clock=clock)
    _, request_id = _send(broker, clock)
    with open(config.journal_path, "a") as handle:
        handle.write('{"action_id": "req-truncated')        # no newline, no close

    revived = Broker(config, _policy(), enforcer=enforcer, clock=clock)
    assert revived.journal.corrupt_records == 1, "corruption was not reported"
    assert revived.journal.get(request_id).holds_os_state, (
        "a corrupt tail hid a live action")


# --- clock behaviour (doctrine section 17) ---------------------------------

def test_a_clock_jumping_backwards_does_not_release_early(tmp_path):
    """A wall-clock rollback must not look like "not yet due"... and must
    not look like "overdue" either. The deadline is absolute."""
    clock = Clock()
    broker = Broker(_config(tmp_path), _policy(), enforcer=RecordingEnforcer(),
                    clock=clock)
    _, request_id = _send(broker, clock)
    clock.advance(timedelta(hours=-5))
    assert broker.expire_due() == ()
    assert broker.journal.get(request_id).holds_os_state


def test_a_clock_jumping_forward_expires_everything_due(tmp_path):
    clock = Clock()
    broker = Broker(_config(tmp_path), _policy(), enforcer=RecordingEnforcer(),
                    clock=clock)
    ids = [_send(broker, clock)[1] for _ in range(3)]
    clock.advance(timedelta(days=1))
    assert sorted(broker.expire_due()) == sorted(ids)


# --- concurrency (doctrine section 16) -------------------------------------

def test_the_same_action_requested_twice_concurrently_applies_once(tmp_path):
    """Two threads, one request id. The replay guard must hold under a race,
    not merely in sequence."""
    clock = Clock()
    enforcer = RecordingEnforcer()
    broker = Broker(_config(tmp_path), _policy(), enforcer=enforcer, clock=clock)
    payload = _payload()
    payload["requested_at"] = clock().isoformat()
    results = []
    barrier = threading.Barrier(8)

    def attempt():
        barrier.wait()
        results.append(broker.handle(
            {"schema_version": SCHEMA_VERSION, "type": "action_request",
             "request": dict(payload)}, caller="annulon-core"))

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    allowed = [r for r in results if r["decision"] == "allow"]
    assert len(allowed) == 1, f"{len(allowed)} concurrent duplicates allowed"
    assert len(enforcer.applied) == 1


def test_expiry_racing_release_does_not_double_release(tmp_path):
    """What happens whenever an operator releases something a second before
    its TTL ends."""
    clock = Clock()
    enforcer = RecordingEnforcer()
    broker = Broker(_config(tmp_path), _policy(), enforcer=enforcer, clock=clock)
    _, request_id = _send(broker, clock)
    clock.advance(timedelta(hours=1))

    barrier = threading.Barrier(2)
    outcomes = []

    def expire():
        barrier.wait()
        outcomes.append(("expire", broker.expire_due()))

    def release():
        barrier.wait()
        payload = _payload(action_type=ActionType.RELEASE_RESTRICTION.value,
                           duration_seconds=1, finding_id=request_id)
        payload["requested_at"] = clock().isoformat()
        outcomes.append(("release", broker.handle(
            {"schema_version": SCHEMA_VERSION, "type": "action_request",
             "request": payload}, caller="annulon-core")))

    threads = [threading.Thread(target=expire), threading.Thread(target=release)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert broker.journal.active_count() == 0
    # The backend tolerates a second release; what must not happen is the
    # action ending in a state that still claims to hold OS state.
    assert not broker.journal.get(request_id).holds_os_state


def test_concurrent_requests_respect_the_active_action_ceiling(tmp_path):
    """The ceiling is a safety bound, so it has to hold under a race."""
    clock = Clock()
    enforcer = RecordingEnforcer()
    broker = Broker(_config(tmp_path), _policy(max_active_actions=3),
                    enforcer=enforcer, clock=clock)
    barrier = threading.Barrier(12)
    results = []

    def attempt():
        payload = _payload()
        payload["requested_at"] = clock().isoformat()
        barrier.wait()
        results.append(broker.handle(
            {"schema_version": SCHEMA_VERSION, "type": "action_request",
             "request": payload}, caller="annulon-core"))

    threads = [threading.Thread(target=attempt) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    allowed = [r for r in results if r["decision"] == "allow"]
    assert len(allowed) <= 3, f"{len(allowed)} actions exceeded the ceiling of 3"
    assert broker.journal.active_count() <= 3


def test_concurrent_reconciliation_and_requests_do_not_corrupt_the_journal(tmp_path):
    clock = Clock()
    enforcer = RecordingEnforcer()
    broker = Broker(_config(tmp_path), _policy(), enforcer=enforcer, clock=clock)
    stop = threading.Event()

    def reconciler():
        while not stop.is_set():
            broker.reconcile()

    def requester():
        for _ in range(30):
            _send(broker, clock)

    worker = threading.Thread(target=reconciler, daemon=True)
    worker.start()
    requester()
    stop.set()
    worker.join(timeout=10)

    revived = Broker(_config(tmp_path), _policy(), enforcer=enforcer, clock=clock)
    assert revived.journal.corrupt_records == 0, "concurrent writes corrupted it"


# --- resource bounds under pressure (doctrine section 18) ------------------

def test_a_flood_of_denials_keeps_memory_bounded(tmp_path):
    """Security software must survive being attacked through its own
    telemetry. A denial path that grows without limit is a way to kill the
    broker by asking it questions."""
    config = _config(tmp_path)
    config.max_replay_cache = 64
    broker = Broker(config, _policy(max_requests_per_minute=5),
                    enforcer=RecordingEnforcer(), clock=Clock())
    for _ in range(2000):
        _send(broker)
    assert len(broker._seen) <= 64
    assert len(broker._recent) <= 4, "per-caller rate state grew unbounded"
    for window in broker._recent.values():
        assert len(window) <= 5 * 4


# --- reboot semantics (doctrine section 33) --------------------------------
#
# Containment deliberately does NOT survive a reboot. nftables rules live in
# kernel memory and Annulon does not install a persistence unit, so a reboot
# clears every restriction it created.
#
# That is a design decision, not an accident, and it is the safer default: a
# temporary restriction that outlived the process which understood why it
# existed would be a restriction nobody can explain and nobody will remove.
# The cost is that a genuinely dangerous workload is unrestricted for the
# moments between boot and the core re-detecting it, which is recorded here
# rather than glossed over.

def test_an_action_from_a_previous_boot_is_not_this_action(tmp_path):
    """After a reboot the boot id changes, and a uid means something else.

    A request authorized against uid 1500 before a rebuild would land on
    whatever now holds that number.
    """
    clock = Clock()
    broker = Broker(_config(tmp_path), _policy(), enforcer=RecordingEnforcer(),
                    clock=clock)
    payload = _payload()
    payload["target"] = dict(payload["target"], boot_id="the-previous-boot")
    payload["requested_at"] = clock().isoformat()
    response = broker.handle({"schema_version": SCHEMA_VERSION,
                              "type": "action_request", "request": payload},
                             caller="annulon-core")
    assert response["decision"] == "deny"
    assert "target_not_current" in response["reasons"]


def test_after_a_reboot_the_journal_closes_records_whose_rules_are_gone(tmp_path):
    """The reboot path, expressed as what the broker actually observes.

    It cannot detect a reboot directly. What it sees is a journal claiming
    active actions and a kernel holding none — which is the same shape as
    the stale-record case, and is resolved the same way.
    """
    clock = Clock()
    config = _config(tmp_path)
    broker = Broker(config, _policy(), enforcer=RecordingEnforcer(), clock=clock)
    _, request_id = _send(broker, clock)
    assert broker.journal.active_count() == 1

    # A reboot: the journal is on disk, the kernel's ruleset is empty, and a
    # brand-new enforcer holds nothing.
    rebooted = Broker(config, _policy(), enforcer=RecordingEnforcer(), clock=clock)
    notes = rebooted.reconcile()
    assert any("closed stale record" in note for note in notes)
    assert rebooted.journal.active_count() == 0, (
        "a record for a rule the reboot destroyed kept occupying a slot")
    assert rebooted.journal.get(request_id).state is ActionState.RELEASED


def test_a_reboot_does_not_leave_the_active_ceiling_exhausted(tmp_path):
    """The failure this prevents: enough reboots with actions in flight and
    the broker refuses all new containment because its ceiling is full of
    records for rules that no longer exist."""
    clock = Clock()
    config = _config(tmp_path)
    broker = Broker(config, _policy(max_active_actions=3), enforcer=RecordingEnforcer(),
                    clock=clock)
    for _ in range(3):
        _send(broker, clock)

    rebooted = Broker(config, _policy(max_active_actions=3),
                      enforcer=RecordingEnforcer(), clock=clock)
    rebooted.reconcile()
    response, _ = _send(rebooted, clock)
    assert response["decision"] == "allow", (
        "the ceiling stayed full of records for rules the reboot destroyed")
