"""The privileged broker over a real socket, and what a hostile caller gets.

These tests use an actual Unix domain socket with real kernel-supplied peer
credentials, not an in-memory stand-in, because the property under test is
exactly that the caller's identity comes from the kernel. A mocked socket
would assert the thing it replaced.
"""

from __future__ import annotations

import json
import os
import socket
import struct
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from annulon.response import ipc
from annulon.response.broker import (
    Broker, BrokerConfig, BrokerServer, UNKNOWN_CALLER,
)
from annulon.response.client import BrokerClient, ResponseOutcome, new_request_id
from annulon.response.contract import (
    ActionRequest, ActionState, ActionType, DenyReason, SCHEMA_VERSION,
    Target, TargetKind,
)
from annulon.response.enforcement import (
    EnforcementOutcome, RecordingEnforcer, UnavailableEnforcer,
)
from annulon.response.journal import ActionJournal, OwnedResource
from annulon.response.policy import BrokerPolicy, ProtectedScopes

HOST, BOOT = "host-alpha", "boot-7"
CONTAINABLE_UID = 1500


def _target(uid: int = CONTAINABLE_UID, service: str = "batch-worker",
            host: str = HOST, boot: str = BOOT) -> Target:
    return Target(TargetKind.SERVICE_UID, host, boot, str(uid), service)


def _policy(**overrides) -> BrokerPolicy:
    base = dict(permitted_uids=frozenset({CONTAINABLE_UID}),
                authorized_callers=frozenset({"annulon-core"}),
                max_ttl=timedelta(minutes=10), max_active_actions=4,
                max_requests_per_minute=30)
    base.update(overrides)
    return BrokerPolicy(**base)


class Clock:
    """A clock the test moves deliberately. Expiry is a time property; it
    cannot be tested by sleeping without making the suite slow and flaky."""

    def __init__(self, start: datetime | None = None) -> None:
        self.now = start or datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


@pytest.fixture
def workspace(tmp_path: Path):
    return tmp_path


def _config(tmp_path: Path, *, caller_uids=None) -> BrokerConfig:
    return BrokerConfig(
        host_id=HOST, boot_id=BOOT,
        socket_path=str(tmp_path / "run" / "broker.sock"),
        journal_path=tmp_path / "journal" / "actions.jsonl",
        caller_uids=caller_uids if caller_uids is not None
        else {os.getuid(): "annulon-core"})


def _request(clock: Clock, **overrides) -> ActionRequest:
    base = dict(request_id=new_request_id(),
                action_type=ActionType.TEMPORARY_EGRESS_RESTRICTION,
                target=_target(), duration=timedelta(minutes=5),
                reason="suspected exfiltration", finding_id="finding-00001234",
                requested_at=clock(), requesting_component="annulon-core")
    base.update(overrides)
    return ActionRequest(**base)


# --------------------------------------------------------------------------
# Experiment A -- an unauthorized caller gets nothing
# --------------------------------------------------------------------------

def test_a_caller_the_kernel_does_not_vouch_for_is_denied(workspace, ):
    """A uid absent from the broker's own map is not a caller policy knows.

    The mapping lives in broker configuration. There is no message field in
    which a caller can name itself, so this denial cannot be talked out of.
    """
    clock = Clock()
    config = _config(workspace, caller_uids={})        # nobody is authorized
    broker = Broker(config, _policy(), enforcer=RecordingEnforcer(), clock=clock)

    assert broker.caller_for(ipc.PeerCredentials(pid=1, uid=os.getuid(), gid=0)) \
        == UNKNOWN_CALLER

    response = broker.handle(
        {"schema_version": SCHEMA_VERSION, "type": "action_request",
         "request": _request(clock).to_dict()}, caller=UNKNOWN_CALLER)
    assert response["decision"] == "deny"
    assert DenyReason.CALLER_NOT_AUTHORIZED.value in response["reasons"]


def test_a_root_is_not_automatically_the_core(workspace):
    """Being privileged is not being the core.

    If root were special-cased into an authorized caller, every root-capable
    process on the host would be a valid requester -- which is most of the
    boundary gone.
    """
    broker = Broker(_config(workspace, caller_uids={}), _policy(),
                    enforcer=RecordingEnforcer())
    assert broker.caller_for(ipc.PeerCredentials(pid=1, uid=0, gid=0)) == UNKNOWN_CALLER


# --------------------------------------------------------------------------
# Experiment B -- an authorized request is applied, and journalled first
# --------------------------------------------------------------------------

def test_b_an_authorized_request_is_applied(workspace):
    clock = Clock()
    enforcer = RecordingEnforcer()
    broker = Broker(_config(workspace), _policy(), enforcer=enforcer, clock=clock)
    request = _request(clock)

    response = broker.handle(
        {"schema_version": SCHEMA_VERSION, "type": "action_request",
         "request": request.to_dict()}, caller="annulon-core")

    assert response["decision"] == "allow"
    assert response["state"] == ActionState.APPLIED.value
    assert enforcer.applied == [request.request_id]
    entry = broker.journal.get(request.request_id)
    assert entry is not None and entry.owned_resource is not None
    assert entry.expires_at == clock() + timedelta(minutes=5)


def test_b_intent_is_journalled_before_the_os_is_touched(workspace):
    """The ordering that makes crash recovery possible.

    A record written only after a successful apply is useless in exactly the
    case it exists for. This test fails the backend *during* apply and then
    asserts the journal already knew about the action.
    """
    clock = Clock()
    observed: list[str] = []

    class ObservingEnforcer(RecordingEnforcer):
        def apply(self, request, *, expires_at):
            entry = broker.journal.get(request.request_id)
            observed.append(entry.state.value if entry else "no record")
            return super().apply(request, expires_at=expires_at)

    broker = Broker(_config(workspace), _policy(),
                    enforcer=ObservingEnforcer(), clock=clock)
    broker.handle({"schema_version": SCHEMA_VERSION, "type": "action_request",
                   "request": _request(clock).to_dict()}, caller="annulon-core")
    assert observed == [ActionState.APPLYING.value], (
        "the OS was touched before the intent was durable")


def test_b_a_backend_fault_leaves_the_action_needing_rollback(workspace):
    """An unexpected fault may still have created state.

    Marking it FAILED would mean nothing goes looking for the rule. It is
    marked ROLLBACK_REQUIRED, which still counts as holding OS state.
    """
    clock = Clock()

    class FaultingEnforcer(RecordingEnforcer):
        def apply(self, request, *, expires_at):
            raise RuntimeError("backend exploded mid-apply")

    broker = Broker(_config(workspace), _policy(),
                    enforcer=FaultingEnforcer(), clock=clock)
    request = _request(clock)
    response = broker.handle(
        {"schema_version": SCHEMA_VERSION, "type": "action_request",
         "request": request.to_dict()}, caller="annulon-core")
    assert response["enforcement"] == "unavailable"
    entry = broker.journal.get(request.request_id)
    assert entry.state is ActionState.ROLLBACK_REQUIRED
    assert entry.holds_os_state


# --------------------------------------------------------------------------
# Experiment C -- an unknown action type
# --------------------------------------------------------------------------

@pytest.mark.parametrize("action", ["run_shell", "execute_command", "run_aws_cli",
                                    "raw_nftables", "", "temporary_egress_restriction "])
def test_c_an_unknown_action_type_is_refused_at_decode(workspace, action):
    """There is no action named "run a command", and asking produces a
    decode failure rather than a policy question."""
    clock = Clock()
    broker = Broker(_config(workspace), _policy(),
                    enforcer=RecordingEnforcer(), clock=clock)
    payload = _request(clock).to_dict()
    payload["action_type"] = action
    response = broker.handle(
        {"schema_version": SCHEMA_VERSION, "type": "action_request",
         "request": payload}, caller="annulon-core")
    assert response["decision"] == "deny"
    assert DenyReason.MALFORMED_REQUEST.value in response["reasons"]


def test_c_an_unknown_field_is_refused_not_ignored(workspace):
    """Silently ignoring a field lets a caller believe it asked for something.

    The dangerous version of this is a caller that sends
    ``{"authorized": true}`` and is answered as though it had not.
    """
    clock = Clock()
    broker = Broker(_config(workspace), _policy(),
                    enforcer=RecordingEnforcer(), clock=clock)
    payload = _request(clock).to_dict()
    payload["authorized"] = True
    response = broker.handle(
        {"schema_version": SCHEMA_VERSION, "type": "action_request",
         "request": payload}, caller="annulon-core")
    assert response["decision"] == "deny"


# --------------------------------------------------------------------------
# Experiment D -- protected targets and destinations
# --------------------------------------------------------------------------

@pytest.mark.parametrize("uid,service", [(0, "anything"), (1500, "sshd"),
                                         (1500, "annulon-broker"),
                                         (1500, "amazon-ssm-agent")])
def test_d_a_protected_target_is_refused(workspace, uid, service):
    """Containing these is how a security tool becomes the incident."""
    clock = Clock()
    broker = Broker(_config(workspace), _policy(), enforcer=RecordingEnforcer(),
                    clock=clock)
    response = broker.handle(
        {"schema_version": SCHEMA_VERSION, "type": "action_request",
         "request": _request(clock, target=_target(uid, service)).to_dict()},
        caller="annulon-core")
    assert response["decision"] == "deny"
    assert DenyReason.TARGET_PROTECTED.value in response["reasons"]


def test_d_a_uid_outside_the_allowlist_is_refused(workspace):
    clock = Clock()
    broker = Broker(_config(workspace), _policy(), enforcer=RecordingEnforcer(),
                    clock=clock)
    response = broker.handle(
        {"schema_version": SCHEMA_VERSION, "type": "action_request",
         "request": _request(clock, target=_target(4242)).to_dict()},
        caller="annulon-core")
    assert DenyReason.TARGET_NOT_PERMITTED.value in response["reasons"]


def test_d_a_target_from_another_boot_is_not_this_target(workspace):
    """A UID means something different after a rebuild."""
    clock = Clock()
    broker = Broker(_config(workspace), _policy(), enforcer=RecordingEnforcer(),
                    clock=clock)
    response = broker.handle(
        {"schema_version": SCHEMA_VERSION, "type": "action_request",
         "request": _request(clock, target=_target(boot="boot-6")).to_dict()},
        caller="annulon-core")
    assert DenyReason.TARGET_NOT_CURRENT.value in response["reasons"]


def test_d_a_protected_destination_is_refused(workspace):
    """Cutting the metadata endpoint leaves a host unrecoverable."""
    clock = Clock()
    broker = Broker(_config(workspace), _policy(), enforcer=RecordingEnforcer(),
                    clock=clock)
    response = broker.handle(
        {"schema_version": SCHEMA_VERSION, "type": "action_request",
         "request": _request(clock, destination_cidr="169.254.169.254/32").to_dict()},
        caller="annulon-core")
    assert DenyReason.DESTINATION_PROTECTED.value in response["reasons"]


# --------------------------------------------------------------------------
# Experiment E -- oversized TTL, replay, and rate
# --------------------------------------------------------------------------

def test_e_an_oversized_ttl_is_denied_not_silently_shortened(workspace):
    """Quietly granting less than was asked for makes the caller's record
    disagree with the broker's about what is in force."""
    clock = Clock()
    broker = Broker(_config(workspace), _policy(max_ttl=timedelta(minutes=10)),
                    enforcer=RecordingEnforcer(), clock=clock)
    response = broker.handle(
        {"schema_version": SCHEMA_VERSION, "type": "action_request",
         "request": _request(clock, duration=timedelta(minutes=59)).to_dict()},
        caller="annulon-core")
    assert response["decision"] == "deny"
    assert DenyReason.DURATION_EXCEEDS_POLICY.value in response["reasons"]


def test_e_a_replayed_request_id_is_refused(workspace):
    clock = Clock()
    enforcer = RecordingEnforcer()
    broker = Broker(_config(workspace), _policy(), enforcer=enforcer, clock=clock)
    request = _request(clock)
    message = {"schema_version": SCHEMA_VERSION, "type": "action_request",
               "request": request.to_dict()}
    assert broker.handle(dict(message), caller="annulon-core")["decision"] == "allow"
    replayed = broker.handle(dict(message), caller="annulon-core")
    assert replayed["decision"] == "deny"
    assert DenyReason.REPLAYED_REQUEST.value in replayed["reasons"]
    assert enforcer.applied == [request.request_id], "the replay reached the OS"


def test_e_a_stale_request_is_refused(workspace):
    """Bounds the window in which a captured request is worth anything."""
    clock = Clock()
    request = _request(clock)
    broker = Broker(_config(workspace), _policy(), enforcer=RecordingEnforcer(),
                    clock=clock)
    clock.advance(timedelta(minutes=5))
    response = broker.handle(
        {"schema_version": SCHEMA_VERSION, "type": "action_request",
         "request": request.to_dict()}, caller="annulon-core")
    assert DenyReason.REQUEST_EXPIRED.value in response["reasons"]


def test_e_a_future_dated_request_is_refused(workspace):
    clock = Clock()
    broker = Broker(_config(workspace), _policy(), enforcer=RecordingEnforcer(),
                    clock=clock)
    future = _request(clock, requested_at=clock() + timedelta(minutes=10))
    response = broker.handle(
        {"schema_version": SCHEMA_VERSION, "type": "action_request",
         "request": future.to_dict()}, caller="annulon-core")
    assert DenyReason.REQUEST_FROM_THE_FUTURE.value in response["reasons"]


def test_e_a_flood_of_requests_is_rate_limited(workspace):
    """A compromised core asking in a loop must not become a rule storm."""
    clock = Clock()
    broker = Broker(_config(workspace), _policy(max_requests_per_minute=5,
                                                max_active_actions=100),
                    enforcer=RecordingEnforcer(), clock=clock)
    outcomes = []
    for _ in range(12):
        outcomes.append(broker.handle(
            {"schema_version": SCHEMA_VERSION, "type": "action_request",
             "request": _request(clock).to_dict()}, caller="annulon-core"))
    limited = [o for o in outcomes
               if DenyReason.RATE_LIMIT_EXCEEDED.value in o.get("reasons", [])]
    assert limited, "the rate limit never engaged"
    assert len(limited) >= 6


def test_e_the_active_action_ceiling_holds(workspace):
    clock = Clock()
    broker = Broker(_config(workspace), _policy(max_active_actions=2),
                    enforcer=RecordingEnforcer(), clock=clock)
    responses = [broker.handle(
        {"schema_version": SCHEMA_VERSION, "type": "action_request",
         "request": _request(clock).to_dict()}, caller="annulon-core")
        for _ in range(4)]
    allowed = [r for r in responses if r["decision"] == "allow"]
    assert len(allowed) == 2
    assert any(DenyReason.TOO_MANY_ACTIVE_ACTIONS.value in r.get("reasons", [])
               for r in responses)


# --------------------------------------------------------------------------
# Experiment F -- the broker is not there
# --------------------------------------------------------------------------

def test_f_an_absent_broker_yields_enforcement_unavailable(workspace):
    """The core reports that nothing happened. It does not act instead."""
    client = BrokerClient(str(workspace / "nonexistent" / "broker.sock"),
                          timeout=1.0)
    result = client.request_egress_restriction(
        _target(), duration=timedelta(minutes=5), reason="exfiltration",
        finding_id="finding-00001234")
    assert result.outcome is ResponseOutcome.ENFORCEMENT_UNAVAILABLE
    assert not result.outcome.contained
    assert client.status() is None


def test_f_unavailable_is_distinct_from_denied():
    """Collapsing these would let an outage read as a clean policy decision."""
    assert ResponseOutcome.ENFORCEMENT_UNAVAILABLE is not ResponseOutcome.DENIED
    assert not ResponseOutcome.ENFORCEMENT_UNAVAILABLE.contained
    assert not ResponseOutcome.APPLIED.contained, (
        "applied is not verified; only measurement is containment")
    assert ResponseOutcome.VERIFIED.contained


def test_f_a_broker_with_no_backend_refuses_rather_than_pretending(workspace):
    """The worst failure is reporting containment while the host is untouched."""
    clock = Clock()
    broker = Broker(_config(workspace), _policy(),
                    enforcer=UnavailableEnforcer(), clock=clock)
    response = broker.handle(
        {"schema_version": SCHEMA_VERSION, "type": "action_request",
         "request": _request(clock).to_dict()}, caller="annulon-core")
    assert response["enforcement"] == "unavailable"
    assert response["state"] == ActionState.FAILED.value


# --------------------------------------------------------------------------
# A real socket, with real kernel-supplied peer credentials
# --------------------------------------------------------------------------

@pytest.fixture
def short_socket_dir(tmp_path):
    """A short directory for the socket path.

    ``sun_path`` is 104 bytes on Darwin and 108 on Linux, and pytest's
    ``tmp_path`` is long enough to overflow it. Discovered by a bind failure,
    not by reading the header.
    """
    import shutil
    import tempfile
    directory = tempfile.mkdtemp(prefix="anbrk-")
    try:
        yield Path(directory)
    finally:
        shutil.rmtree(directory, ignore_errors=True)


class RunningBroker:
    """A broker serving on a real socket in a background thread."""

    def __init__(self, directory: Path, policy: BrokerPolicy, clock: Clock,
                 caller_uids=None, enforcer=None):
        self.config = BrokerConfig(
            host_id=HOST, boot_id=BOOT,
            socket_path=str(directory / "broker.sock"),
            journal_path=directory / "actions.jsonl",
            caller_uids=caller_uids if caller_uids is not None
            else {os.getuid(): "annulon-core"})
        self.enforcer = enforcer or RecordingEnforcer()
        self.clock = clock
        self.broker = Broker(self.config, policy, enforcer=self.enforcer,
                             clock=clock)
        self.server = BrokerServer(self.broker, self.config)
        self._thread: threading.Thread | None = None

    def __enter__(self):
        self.server.start()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def _serve(self):
        while not self.server._stop.is_set():
            try:
                self.server.serve_once(timeout=0.1)
            except OSError:
                return

    def __exit__(self, *exc):
        self.server.stop()
        if self._thread:
            self._thread.join(timeout=2)

    def client(self) -> BrokerClient:
        # The client shares the broker's clock. Otherwise a frozen test clock
        # makes every request look stale to the broker, which is a property
        # the freshness tests assert on purpose and this fixture must not
        # trip over accidentally.
        return BrokerClient(self.config.socket_path, timeout=3.0,
                            clock=self.clock)


@pytest.mark.skipif(not ipc.peer_credentials_supported(),
                    reason="no peer credential mechanism on this platform")
def test_the_kernel_identifies_the_caller_over_a_real_socket(short_socket_dir):
    """Not a mocked socket: the uid comes from the kernel."""
    clock = Clock()
    with RunningBroker(short_socket_dir, _policy(), clock) as running:
        result = running.client().request_egress_restriction(
            _target(), duration=timedelta(minutes=5),
            reason="suspected exfiltration", finding_id="finding-00001234")
    assert result.outcome is ResponseOutcome.APPLIED
    assert running.enforcer.applied, "nothing reached the backend"


@pytest.mark.skipif(not ipc.peer_credentials_supported(),
                    reason="no peer credential mechanism on this platform")
def test_a_caller_whose_uid_is_unmapped_is_denied_over_a_real_socket(short_socket_dir):
    """The same process, the same socket -- only the broker's map changed."""
    clock = Clock()
    with RunningBroker(short_socket_dir, _policy(), clock,
                       caller_uids={os.getuid() + 12345: "annulon-core"}) as running:
        result = running.client().request_egress_restriction(
            _target(), duration=timedelta(minutes=5), reason="exfiltration",
            finding_id="finding-00001234")
        assert result.outcome is ResponseOutcome.DENIED
        assert result.denied_because_unauthorized
        assert not running.enforcer.applied


@pytest.mark.skipif(not ipc.peer_credentials_supported(),
                    reason="no peer credential mechanism on this platform")
def test_the_socket_is_not_world_accessible(short_socket_dir):
    clock = Clock()
    with RunningBroker(short_socket_dir, _policy(), clock) as running:
        mode = os.stat(running.config.socket_path).st_mode & 0o777
    assert mode == ipc.SOCKET_MODE
    assert not mode & 0o007, "the socket is reachable by any local process"


@pytest.mark.skipif(not ipc.peer_credentials_supported(),
                    reason="no peer credential mechanism on this platform")
def test_status_round_trips(short_socket_dir):
    clock = Clock()
    with RunningBroker(short_socket_dir, _policy(), clock) as running:
        status = running.client().status()
    assert status["type"] == "status"
    assert status["active_actions"] == 0
    assert status["backend"] == "recording"


def test_two_brokers_cannot_share_a_socket(short_socket_dir):
    """Silently unlinking a live socket would steal another broker's endpoint."""
    path = str(short_socket_dir / "contended.sock")
    first = ipc.bind_listener(path)
    try:
        with pytest.raises(ipc.IpcError):
            ipc.bind_listener(path)
    finally:
        first.close()


def test_a_stale_socket_file_does_not_block_startup(short_socket_dir):
    """A crash leaves the file behind; the next start must still work."""
    path = str(short_socket_dir / "stale.sock")
    ipc.bind_listener(path).close()
    assert os.path.exists(path)
    listener = ipc.bind_listener(path)          # nothing is listening: reclaimed
    listener.close()


# --------------------------------------------------------------------------
# Restart, expiry and reconciliation
# --------------------------------------------------------------------------

def test_an_action_expires_on_the_brokers_clock(workspace):
    """There is no renew message. A caller cannot extend an action."""
    clock = Clock()
    enforcer = RecordingEnforcer()
    broker = Broker(_config(workspace), _policy(), enforcer=enforcer, clock=clock)
    request = _request(clock)
    broker.handle({"schema_version": SCHEMA_VERSION, "type": "action_request",
                   "request": request.to_dict()}, caller="annulon-core")
    assert broker.journal.active_count() == 1

    clock.advance(timedelta(minutes=4))
    assert broker.expire_due() == ()

    clock.advance(timedelta(minutes=2))
    assert broker.expire_due() == (request.request_id,)
    assert broker.journal.active_count() == 0
    assert enforcer.released, "the rule was never removed"


def test_the_journal_survives_a_restart(workspace):
    """A new broker over the same journal knows what the host still holds."""
    clock = Clock()
    enforcer = RecordingEnforcer()
    config = _config(workspace)
    first = Broker(config, _policy(), enforcer=enforcer, clock=clock)
    request = _request(clock)
    first.handle({"schema_version": SCHEMA_VERSION, "type": "action_request",
                  "request": request.to_dict()}, caller="annulon-core")

    second = Broker(config, _policy(), enforcer=enforcer, clock=clock)
    assert second.journal.active_count() == 1
    entry = second.journal.get(request.request_id)
    assert entry.holds_os_state and entry.expires_at is not None


def test_a_restarted_broker_still_refuses_a_replayed_id(workspace):
    """The replay cache is rebuilt from the journal, so a restart does not
    reopen every id that was ever used."""
    clock = Clock()
    config = _config(workspace)
    enforcer = RecordingEnforcer()
    request = _request(clock)
    message = {"schema_version": SCHEMA_VERSION, "type": "action_request",
               "request": request.to_dict()}
    Broker(config, _policy(), enforcer=enforcer, clock=clock).handle(
        dict(message), caller="annulon-core")

    revived = Broker(config, _policy(), enforcer=enforcer, clock=clock)
    response = revived.handle(dict(message), caller="annulon-core")
    assert response["decision"] == "deny"
    assert DenyReason.REPLAYED_REQUEST.value in response["reasons"]


def test_reconciliation_removes_state_nobody_journalled(workspace):
    """An orphan from a crash between apply and journal.

    State nobody tracks is state nobody will ever remove, which is how a
    temporary restriction becomes permanent.
    """
    clock = Clock()
    enforcer = RecordingEnforcer()
    broker = Broker(_config(workspace), _policy(), enforcer=enforcer, clock=clock)
    enforcer.plant_orphan("recording/service_uid/1500/orphaned")

    notes = broker.reconcile()
    assert any("removed orphan" in note for note in notes)
    assert enforcer.reconcile() == ()


def test_reconciliation_closes_records_whose_state_is_gone(workspace):
    """Usually a reboot. The record must stop counting against the ceiling."""
    clock = Clock()
    enforcer = RecordingEnforcer()
    config = _config(workspace)
    broker = Broker(config, _policy(), enforcer=enforcer, clock=clock)
    request = _request(clock)
    broker.handle({"schema_version": SCHEMA_VERSION, "type": "action_request",
                   "request": request.to_dict()}, caller="annulon-core")

    revived = Broker(config, _policy(), enforcer=RecordingEnforcer(), clock=clock)
    assert revived.journal.active_count() == 1
    notes = revived.reconcile()
    assert any("closed stale record" in note for note in notes)
    assert revived.journal.active_count() == 0


def test_an_uncertain_apply_keeps_the_action_holding_os_state(workspace):
    """"We do not know" must not round to either success or failure."""
    clock = Clock()
    request = _request(clock)
    enforcer = RecordingEnforcer(uncertain_on=frozenset({request.request_id}))
    broker = Broker(_config(workspace), _policy(), enforcer=enforcer, clock=clock)
    broker.handle({"schema_version": SCHEMA_VERSION, "type": "action_request",
                   "request": request.to_dict()}, caller="annulon-core")
    entry = broker.journal.get(request.request_id)
    assert entry.state is ActionState.EFFECT_NOT_VERIFIED
    assert entry.holds_os_state, "an uncertain rule would have been leaked"


def test_a_released_action_frees_a_slot(workspace):
    clock = Clock()
    enforcer = RecordingEnforcer()
    broker = Broker(_config(workspace), _policy(max_active_actions=1),
                    enforcer=enforcer, clock=clock)
    first = _request(clock)
    broker.handle({"schema_version": SCHEMA_VERSION, "type": "action_request",
                   "request": first.to_dict()}, caller="annulon-core")
    assert broker.journal.active_count() == 1

    release = _request(clock, action_type=ActionType.RELEASE_RESTRICTION,
                       duration=timedelta(seconds=1), finding_id=first.request_id)
    response = broker.handle(
        {"schema_version": SCHEMA_VERSION, "type": "action_request",
         "request": release.to_dict()}, caller="annulon-core")
    assert response["decision"] == "allow"
    assert broker.journal.active_count() == 0
    assert enforcer.released
