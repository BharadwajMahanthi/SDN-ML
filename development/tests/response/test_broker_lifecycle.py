"""Reconciliation, expiry boundaries and startup guards.

Written to close nineteen mutations that survived in `broker.py` — places
where a guard could be deleted or a comparison flipped with no test
noticing. Most of them were lifecycle code: the reconciliation branches, the
expiry boundary, the replay-cache bound, and the two guards that decide
whether the broker is allowed to start at all.

Doctrine §31 lists the reconciliation cases that must be explicit; they are
each a separate test here rather than one "reconcile works" assertion,
because the dangerous ones differ only in which side of the comparison is
missing.
"""

from __future__ import annotations

import os
import socket
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from annulon.response import ipc
from annulon.response.broker import Broker, BrokerConfig, BrokerServer
from annulon.response.contract import (
    ActionState, ActionType, DenyReason, SCHEMA_VERSION, Target, TargetKind,
)
from annulon.response.enforcement import (
    EnforcementOutcome, EnforcementResult, RecordingEnforcer,
)
from annulon.response.journal import OwnedResource
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
                max_active_actions=50, max_requests_per_minute=10_000)
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
        "duration_seconds": 300, "reason": "lifecycle",
        "finding_id": "finding-00000001", "requested_at": NOW.isoformat(),
        "requesting_component": "annulon-core", "policy_version": "",
        "destination_cidr": None}
    payload.update(overrides)
    return payload


def _send(broker, payload=None, clock=None):
    body = payload or _payload()
    if clock is not None:
        body["requested_at"] = clock().isoformat()
    return broker.handle({"schema_version": SCHEMA_VERSION,
                          "type": "action_request", "request": body},
                         caller="annulon-core"), body["request_id"]


# --- the envelope -----------------------------------------------------------

@pytest.mark.parametrize("version", [0, 2, 99, -1])
def test_the_envelope_schema_version_is_checked(tmp_path, version):
    """Separate from the request's own schema version.

    A valid request inside an envelope from an unknown protocol version must
    not be processed: the envelope is what says how to interpret the rest.
    """
    broker = Broker(_config(tmp_path), _policy(), enforcer=RecordingEnforcer(),
                    clock=Clock())
    response = broker.handle({"schema_version": version,
                              "type": "action_request", "request": _payload()},
                             caller="annulon-core")
    assert response["decision"] == "deny"
    assert broker._enforcer.applied == []


# --- expiry: before, exact, after ------------------------------------------

def test_expiry_is_not_due_before_the_deadline(tmp_path):
    clock = Clock()
    broker = Broker(_config(tmp_path), _policy(), enforcer=RecordingEnforcer(),
                    clock=clock)
    _, request_id = _send(broker, clock=clock)
    clock.advance(timedelta(seconds=299))
    assert broker.expire_due() == ()
    assert broker.journal.get(request_id).holds_os_state


def test_expiry_is_due_at_the_exact_deadline(tmp_path):
    """The chosen semantic, pinned: a 300-second action is over at t=300.

    `expires_at > now` keeps an action alive strictly *before* its deadline
    and releases it at the instant it arrives. Erring towards releasing
    promptly is the right direction for a temporary restriction — the
    failure to avoid is one that outlives its authorization, not one that
    ends a moment early.
    """
    clock = Clock()
    broker = Broker(_config(tmp_path), _policy(), enforcer=RecordingEnforcer(),
                    clock=clock)
    _, request_id = _send(broker, clock=clock)
    clock.advance(timedelta(seconds=300))
    assert broker.expire_due() == (request_id,)


def test_expiry_is_due_one_tick_after_the_deadline(tmp_path):
    clock = Clock()
    broker = Broker(_config(tmp_path), _policy(), enforcer=RecordingEnforcer(),
                    clock=clock)
    _, request_id = _send(broker, clock=clock)
    clock.advance(timedelta(seconds=301))
    assert broker.expire_due() == (request_id,)


def test_the_granted_duration_determines_expiry_not_the_requested_one(tmp_path):
    """The broker's grant is authoritative.

    If the requested duration were used instead, a policy that ever granted
    less than was asked would install a rule outliving its own authorization.
    """
    clock = Clock()
    broker = Broker(_config(tmp_path), _policy(), enforcer=RecordingEnforcer(),
                    clock=clock)
    response, request_id = _send(broker, clock=clock)
    granted = response["granted_duration_seconds"]
    entry = broker.journal.get(request_id)
    assert entry.expires_at == clock() + timedelta(seconds=granted)


# --- reconciliation, case by case (doctrine section 31) --------------------

def test_journal_active_and_rule_present_is_left_alone(tmp_path):
    clock = Clock()
    enforcer = RecordingEnforcer()
    config = _config(tmp_path)
    broker = Broker(config, _policy(), enforcer=enforcer, clock=clock)
    _, request_id = _send(broker, clock=clock)

    revived = Broker(config, _policy(), enforcer=enforcer, clock=clock)
    revived.reconcile()
    assert revived.journal.get(request_id).holds_os_state
    assert enforcer.released == [], "a live, journalled rule was removed"


def test_journal_active_and_rule_missing_closes_the_record(tmp_path):
    """Usually a reboot. The record must stop occupying a slot."""
    clock = Clock()
    config = _config(tmp_path)
    broker = Broker(config, _policy(), enforcer=RecordingEnforcer(), clock=clock)
    _, request_id = _send(broker, clock=clock)

    revived = Broker(config, _policy(), enforcer=RecordingEnforcer(), clock=clock)
    notes = revived.reconcile()
    assert any("closed stale record" in note for note in notes)
    assert revived.journal.active_count() == 0


def test_a_rule_with_no_journal_entry_is_removed_as_an_orphan(tmp_path):
    """The crash window between apply and journal.

    State nobody tracks is state nobody will ever remove.
    """
    enforcer = RecordingEnforcer()
    enforcer.plant_orphan("recording/service_uid/1500/orphan-1")
    broker = Broker(_config(tmp_path), _policy(), enforcer=enforcer, clock=Clock())
    notes = broker.reconcile()
    assert any("removed orphan" in note for note in notes)
    assert enforcer.reconcile() == ()


def test_a_journalled_action_with_no_resource_is_closed(tmp_path):
    """APPLYING that never reached the backend. Nothing to remove, but the
    record must not stay open forever."""
    clock = Clock()
    config = _config(tmp_path)
    broker = Broker(config, _policy(), enforcer=RecordingEnforcer(), clock=clock)
    broker.journal.record(
        action_id="req-000000000999", action_type=ActionType.TEMPORARY_EGRESS_RESTRICTION,
        target=Target(TargetKind.SERVICE_UID, "h", "b7", str(UID), "worker"),
        state=ActionState.APPLYING, policy_version="p", requested_by="annulon-core",
        requested_at=NOW, expires_at=NOW + timedelta(minutes=5))
    notes = broker.reconcile()
    assert any("closed incomplete record" in note for note in notes), notes
    entry = broker.journal.get("req-000000000999")
    assert entry.state is ActionState.RELEASED
    assert entry.detail == "no resource was ever recorded"
    assert broker.journal.active_count() == 0


def test_an_orphan_that_cannot_be_removed_is_reported_not_forgotten(tmp_path):
    """Doctrine §32: safety beats cleanup convenience."""
    from annulon.response.enforcement import EnforcementError

    class StubbornEnforcer(RecordingEnforcer):
        def release(self, resource):
            raise EnforcementError("cannot remove")

    enforcer = StubbornEnforcer()
    enforcer.plant_orphan("recording/service_uid/1500/stuck")
    broker = Broker(_config(tmp_path), _policy(), enforcer=enforcer, clock=Clock())
    notes = broker.reconcile()
    assert any("could not be removed" in note for note in notes)


def test_an_expired_rule_still_present_is_released_on_the_next_sweep(tmp_path):
    clock = Clock()
    enforcer = RecordingEnforcer()
    config = _config(tmp_path)
    broker = Broker(config, _policy(), enforcer=enforcer, clock=clock)
    _, request_id = _send(broker, clock=clock)
    clock.advance(timedelta(hours=1))
    assert broker.expire_due() == (request_id,)
    assert enforcer.released


def test_a_release_that_fails_marks_rollback_required_not_released(tmp_path):
    """Reporting RELEASED when the rule is still installed would hide a rule
    that now has no deadline at all."""
    from annulon.response.enforcement import EnforcementError

    class FailingRelease(RecordingEnforcer):
        def release(self, resource):
            raise EnforcementError("release refused")

    clock = Clock()
    broker = Broker(_config(tmp_path), _policy(), enforcer=FailingRelease(),
                    clock=clock)
    _, request_id = _send(broker, clock=clock)
    clock.advance(timedelta(hours=1))
    broker.expire_due()
    entry = broker.journal.get(request_id)
    assert entry.state is ActionState.ROLLBACK_REQUIRED
    assert entry.holds_os_state


# --- release of things that are not there ----------------------------------

def test_releasing_an_unknown_action_is_answered_not_crashed(tmp_path):
    broker = Broker(_config(tmp_path), _policy(), enforcer=RecordingEnforcer(),
                    clock=Clock())
    response, _ = _send(broker, _payload(
        action_type=ActionType.RELEASE_RESTRICTION.value,
        duration_seconds=1, finding_id="finding-00000404"))
    assert response["decision"] == "allow"
    assert "no owned resource" in response.get("detail", "")


# --- bounded state ----------------------------------------------------------

def test_the_replay_cache_stays_bounded(tmp_path):
    """A hostile caller must not be able to grow broker memory without limit."""
    config = _config(tmp_path)
    config.max_replay_cache = 16
    broker = Broker(config, _policy(), enforcer=RecordingEnforcer(), clock=Clock())
    for _ in range(200):
        _send(broker)
    assert len(broker._seen) <= 16


def test_the_oldest_request_id_is_the_one_evicted(tmp_path):
    """FIFO, so the most recent -- the ones a replay would actually reuse --
    stay protected longest."""
    config = _config(tmp_path)
    config.max_replay_cache = 4
    broker = Broker(config, _policy(), enforcer=RecordingEnforcer(), clock=Clock())
    ids = [_send(broker)[1] for _ in range(6)]
    assert ids[0] not in broker._seen
    assert ids[-1] in broker._seen


def test_the_rate_window_forgets_requests_older_than_a_minute(tmp_path):
    clock = Clock()
    broker = Broker(_config(tmp_path), _policy(max_requests_per_minute=5),
                    enforcer=RecordingEnforcer(), clock=clock)
    for _ in range(5):
        _send(broker, clock=clock)
    assert broker._rate_for("annulon-core", clock()) == 5
    clock.advance(timedelta(seconds=61))
    assert broker._rate_for("annulon-core", clock()) == 0
    assert "annulon-core" not in broker._recent, "an idle caller left memory behind"


# --- backend that does not support the action ------------------------------

def test_an_action_the_backend_does_not_implement_is_not_reported_applied(tmp_path):
    """A backend that returns success for an action it does not implement
    would be the worst kind of false containment."""
    class NarrowEnforcer(RecordingEnforcer):
        def supports(self, action_type):
            return False

    broker = Broker(_config(tmp_path), _policy(), enforcer=NarrowEnforcer(),
                    clock=Clock())
    response, _ = _send(broker)
    assert response["enforcement"] == "unavailable"
    assert "does not implement" in response["detail"]


# --- startup guards ---------------------------------------------------------

def test_the_broker_refuses_to_start_unprivileged_when_configured_to(tmp_path):
    """A broker that cannot enforce what it authorizes should not pretend."""
    config = _config(tmp_path)
    config.require_privilege = True
    broker = Broker(config, _policy(), enforcer=RecordingEnforcer(), clock=Clock())
    server = BrokerServer(broker, config)
    if os.geteuid() == 0:
        pytest.skip("running as root; the guard cannot fire")
    with pytest.raises(PermissionError, match="must run privileged"):
        server.start()


def test_the_broker_refuses_to_start_without_peer_credentials(tmp_path, monkeypatch):
    """No caller identity means no boundary. Starting anyway would be
    security theatre, so it is a hard failure."""
    monkeypatch.setattr(ipc, "peer_credentials_supported", lambda: False)
    config = _config(tmp_path)
    broker = Broker(config, _policy(), enforcer=RecordingEnforcer(), clock=Clock())
    server = BrokerServer(broker, config)
    with pytest.raises(ipc.PeerIdentityUnavailable, match="will not run"):
        server.start()


# --- the expiry sweeper runs in the privileged process ---------------------

@pytest.mark.skipif(not ipc.peer_credentials_supported(),
                    reason="no peer credential mechanism on this platform")
def test_the_sweeper_expires_actions_without_the_core(tmp_path):
    """The property that stops a temporary restriction becoming permanent.

    Nothing in this test represents the core after the request is made; the
    broker expires the action on its own thread and its own clock.
    """
    import shutil
    import tempfile
    directory = Path(tempfile.mkdtemp(prefix="anlif-"))
    try:
        clock = Clock()
        config = BrokerConfig(
            host_id="h", boot_id="b7",
            socket_path=str(directory / "b.sock"),
            journal_path=directory / "b.jsonl",
            caller_uids={os.getuid(): "annulon-core"})
        enforcer = RecordingEnforcer()
        broker = Broker(config, _policy(), enforcer=enforcer, clock=clock)
        _, request_id = _send(broker, clock=clock)
        server = BrokerServer(broker, config, sweep_interval=0.05)
        server.start()
        try:
            clock.advance(timedelta(hours=1))
            deadline = threading.Event()
            for _ in range(100):
                if request_id in server.expired:
                    break
                deadline.wait(0.05)
            assert request_id in server.expired, "the sweeper never ran"
            assert enforcer.released, "the rule was never removed"
        finally:
            server.stop()
    finally:
        shutil.rmtree(directory, ignore_errors=True)


# --- closing the last mutation survivors -----------------------------------
#
# Each of these killed a specific surviving mutation. They are small, and
# that is the point: the mutations they kill are small edits too, and a small
# edit to a privileged component is exactly what nobody reviews carefully.

def test_the_replay_cache_holds_exactly_its_configured_size(tmp_path):
    """`> max` not `>= max`.

    An off-by-one here shrinks the replay window by one entry — harmless
    alone, but the assertion `<= 16` passed either way, so the bound was
    never actually pinned.
    """
    config = _config(tmp_path)
    config.max_replay_cache = 8
    broker = Broker(config, _policy(), enforcer=RecordingEnforcer(), clock=Clock())
    for _ in range(8):
        _send(broker)
    assert len(broker._seen) == 8, "the cache evicted before reaching its bound"
    _send(broker)
    assert len(broker._seen) == 8


def test_the_rate_window_keeps_a_timestamp_exactly_at_the_cutoff(tmp_path):
    """`window[0] < cutoff` — an entry exactly 60 seconds old still counts."""
    clock = Clock()
    broker = Broker(_config(tmp_path), _policy(), enforcer=RecordingEnforcer(),
                    clock=clock)
    _send(broker, clock=clock)
    clock.advance(timedelta(seconds=60))
    assert broker._rate_for("annulon-core", clock()) == 1
    clock.advance(timedelta(microseconds=1))
    assert broker._rate_for("annulon-core", clock()) == 0


def test_an_enforcement_failure_is_journalled(tmp_path):
    """A failed privileged action still has to leave a record.

    "Something tried and could not" is exactly what an investigation needs,
    and deleting the guard that writes it left no trace at all.
    """
    class NarrowEnforcer(RecordingEnforcer):
        def supports(self, action_type):
            return False

    broker = Broker(_config(tmp_path), _policy(), enforcer=NarrowEnforcer(),
                    clock=Clock())
    _, request_id = _send(broker)
    entry = broker.journal.get(request_id)
    assert entry is not None, "an enforcement failure left no journal record"
    assert entry.state is ActionState.FAILED
    assert "does not implement" in entry.detail


def test_an_allow_response_carries_the_deadline_and_the_resource(tmp_path):
    """The caller needs to know when the action ends and what was created.

    Both fields were omittable without any test noticing.
    """
    clock = Clock()
    broker = Broker(_config(tmp_path), _policy(), enforcer=RecordingEnforcer(),
                    clock=clock)
    response, request_id = _send(broker, clock=clock)
    assert response["decision"] == "allow"
    assert response["expires_at"] == (clock() + timedelta(seconds=300)).isoformat()
    assert request_id in response["owned_resource"]


def test_the_granted_duration_is_used_even_when_it_differs_from_the_request(tmp_path):
    """Defensive, and deliberately kept.

    Policy currently denies an over-long request rather than shortening it,
    so the two durations always match and this branch is unreachable in
    practice. It stays because the day someone adds partial grants, the
    alternative is a rule that outlives its own authorization.
    """
    from annulon.response.contract import AuthorizationDecision

    clock = Clock()
    broker = Broker(_config(tmp_path), _policy(), enforcer=RecordingEnforcer(),
                    clock=clock)
    real_evaluate = broker._policy.evaluate

    def shortened(request, **kwargs):
        decision = real_evaluate(request, **kwargs)
        if not decision.allowed:
            return decision
        return AuthorizationDecision.allow(
            request, decision.policy_version, decision.decided_at,
            timedelta(seconds=30), "granted less than requested")

    broker._policy.evaluate = shortened
    response, request_id = _send(broker, clock=clock)
    assert response["decision"] == "allow"
    entry = broker.journal.get(request_id)
    assert entry.expires_at == clock() + timedelta(seconds=30), (
        "the requested duration was used instead of the granted one")


def test_stopping_the_server_twice_is_safe(tmp_path):
    """Shutdown runs on error paths, where it may well be called twice."""
    config = _config(tmp_path)
    broker = Broker(config, _policy(), enforcer=RecordingEnforcer(), clock=Clock())
    server = BrokerServer(broker, config)
    server.stop()
    server.stop()


def test_stopping_a_server_that_never_started_is_safe(tmp_path):
    config = _config(tmp_path)
    broker = Broker(config, _policy(), enforcer=RecordingEnforcer(), clock=Clock())
    BrokerServer(broker, config).stop()


@pytest.mark.skipif(not ipc.peer_credentials_supported(),
                    reason="no peer credential mechanism on this platform")
def test_serve_forever_runs_until_stopped(tmp_path):
    """The accept loop had no test at all: removing its `not` made it exit
    immediately, and nothing noticed a broker that served nothing."""
    import shutil
    import tempfile
    directory = Path(tempfile.mkdtemp(prefix="anserve-"))
    try:
        config = BrokerConfig(
            host_id="h", boot_id="b7", socket_path=str(directory / "s.sock"),
            journal_path=directory / "s.jsonl",
            caller_uids={os.getuid(): "annulon-core"})
        broker = Broker(config, _policy(), enforcer=RecordingEnforcer(),
                        clock=Clock())
        server = BrokerServer(broker, config, sweep_interval=10)
        server.start()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            from annulon.response.client import BrokerClient
            client = BrokerClient(config.socket_path, timeout=5.0)
            assert client.status() is not None, "serve_forever answered nothing"
            assert client.status() is not None, "it served only one request"
        finally:
            server.stop()
            thread.join(timeout=5)
        assert not thread.is_alive(), "serve_forever ignored the stop signal"
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def test_serve_once_after_stop_returns_rather_than_raising(tmp_path):
    """The shutdown race, pinned.

    `stop()` clears the listener from another thread. A serving loop that
    wakes after that must see a deliberate shutdown, not a fault — the
    original code raised `RuntimeError` into the serving thread and killed
    it noisily during every clean shutdown.
    """
    config = _config(tmp_path)
    broker = Broker(config, _policy(), enforcer=RecordingEnforcer(), clock=Clock())
    server = BrokerServer(broker, config)
    server._stop.set()
    server._listener = None
    assert server.serve_once(timeout=0.01) is False


def test_serve_once_before_start_is_a_programming_error(tmp_path):
    """The other side of the same branch: not stopping, just never started."""
    config = _config(tmp_path)
    broker = Broker(config, _policy(), enforcer=RecordingEnforcer(), clock=Clock())
    server = BrokerServer(broker, config)
    with pytest.raises(RuntimeError, match="not started"):
        server.serve_once(timeout=0.01)
