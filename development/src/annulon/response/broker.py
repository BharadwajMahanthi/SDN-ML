"""The privileged broker: the only component that may act on the host.

The property this whole subsystem defends:

    compromise, malfunction, hallucination, or bad logic in the Annulon core
    must not yield arbitrary privileged operating-system execution.

The broker is what makes that structural rather than aspirational. It runs as
a separate process with the privilege; the core has none. Between them is a
Unix socket over which only typed, versioned, bounded requests pass. The core
can ask for one of two narrow things and the broker decides, using policy the
core cannot read or influence.

Concretely, a fully compromised core can do exactly this much: ask for a
time-bounded egress restriction on a UID that broker policy already permits,
at a rate broker policy already caps. It cannot name a new action, cannot
reach a protected UID or destination, cannot extend a TTL, cannot replay an
old grant, and cannot cause the broker to execute anything.

Ordering is a safety property, not an implementation detail:

1. Authenticate the caller from the kernel, never from the payload.
2. Decode strictly; reject unknown fields rather than ignoring them.
3. Evaluate policy, which starts from deny.
4. **Journal the intent before touching the OS.** A crash between journal and
   apply leaves a record saying state may exist; a crash between apply and
   journal would leave a rule nobody knows about.
5. Enforce.
6. Journal the outcome.

Steps 4 and 5 are in that order because the failure they guard against --
an unscheduled restart mid-apply -- is the one that leaves a "temporary"
restriction in place permanently.
"""

from __future__ import annotations

import collections
import enum
import os
import socket
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Mapping

from annulon.response import ipc
from annulon.response.contract import (
    ActionRequest, ActionState, ActionType, AuthorizationDecision, ContractError,
    Decision, DenyReason, SCHEMA_VERSION, Target,
)
from annulon.response.enforcement import (
    Enforcer, EnforcementError, EnforcementOutcome, UnavailableEnforcer,
)
from annulon.response.journal import ActionJournal, JournalError, OwnedResource
from annulon.response.policy import BrokerPolicy, PolicyError

__all__ = ["Broker", "BrokerConfig", "BrokerServer", "MessageType",
           "UNKNOWN_CALLER", "MAX_REPLAY_CACHE", "MAX_CONCURRENT_CONNECTIONS"]

#: Bounded so a hostile or looping caller cannot grow it without limit. It is
#: a mitigation, not a guarantee: request freshness is what actually bounds
#: the replay window, and it survives restarts, which a cache does not.
MAX_REPLAY_CACHE = 8192
#: The broker serves one request per connection and handles them one at a
#: time. A connection backlog cannot become unbounded memory.
MAX_CONCURRENT_CONNECTIONS = 16
#: What an unrecognised uid is called in the audit record. It is never a name
#: policy could match, so an unknown caller is denied by construction.
UNKNOWN_CALLER = "unknown"


class MessageType(enum.Enum):
    ACTION_REQUEST = "action_request"
    RELEASE_REQUEST = "release_request"
    STATUS_REQUEST = "status_request"


@dataclass
class BrokerConfig:
    """Broker-owned configuration. None of it is reachable from the core."""

    host_id: str
    boot_id: str
    socket_path: str
    journal_path: Path
    #: uid -> caller name. The kernel supplies the uid; this map turns it
    #: into the identity policy speaks about. A uid that is absent gets
    #: :data:`UNKNOWN_CALLER`, which no policy grants.
    caller_uids: Mapping[int, str] = field(default_factory=dict)
    max_replay_cache: int = MAX_REPLAY_CACHE
    #: Refuse to start as an unprivileged process pretending to be a broker,
    #: unless a test says otherwise.
    require_privilege: bool = False


class Broker:
    """Authorization, journalling and enforcement. No sockets.

    Separated from the transport so the decision logic can be tested
    exhaustively without a socket, and so the socket code has nothing in it
    worth attacking.
    """

    def __init__(self, config: BrokerConfig, policy: BrokerPolicy, *,
                 enforcer: Enforcer | None = None,
                 clock: Callable[[], datetime] | None = None) -> None:
        self._config = config
        self._policy = policy
        # Defaults to a backend that refuses, never to one that silently
        # does nothing: a broker reporting success while the host is
        # untouched is worse than one that reports unavailability.
        self._enforcer: Enforcer = enforcer or UnavailableEnforcer()
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._journal = ActionJournal(config.journal_path)
        self._lock = threading.Lock()
        #: Request IDs already decided, newest last. Seeded from the journal
        #: so a restart does not reopen every previously used ID.
        self._seen: collections.OrderedDict[str, None] = collections.OrderedDict()
        for action_id in self._journal.recent_request_ids(config.max_replay_cache):
            self._seen[action_id] = None
        #: Per-caller request timestamps, for the rate limit. Trimmed on
        #: every use so an idle caller cannot leave memory behind.
        self._recent: dict[str, collections.deque[datetime]] = {}
        self.reconciliation: tuple[str, ...] = ()

    # -- properties ------------------------------------------------------

    @property
    def journal(self) -> ActionJournal:
        return self._journal

    @property
    def policy(self) -> BrokerPolicy:
        return self._policy

    def caller_for(self, credentials: ipc.PeerCredentials) -> str:
        """Turn kernel-supplied credentials into a policy identity.

        Root is *not* special-cased into an authorized caller. A privileged
        local process is not automatically the Annulon core, and treating it
        as one would make every root-capable process a valid requester.
        """
        return self._config.caller_uids.get(credentials.uid, UNKNOWN_CALLER)

    # -- request handling ------------------------------------------------

    def handle(self, message: dict, *, caller: str) -> dict:
        """Decide and act on one already-decoded message.

        Returns the response body. Never raises for a bad request: a
        malformed message is answered with a denial, because a broker that
        crashes on unexpected input is a denial-of-service on containment.
        """
        try:
            kind = MessageType(message.get("type"))
        except ValueError:
            return self._malformed("unknown message type")
        if message.get("schema_version") != SCHEMA_VERSION:
            return self._malformed("unsupported schema version")
        if kind is MessageType.STATUS_REQUEST:
            return self.status()
        try:
            request = ActionRequest.from_dict(message.get("request"))
        except (ContractError, TypeError, ValueError) as exc:
            # The reason is reported, but nothing the caller sent is echoed
            # back verbatim into a privileged log line.
            return self._malformed(f"request rejected: {type(exc).__name__}")
        with self._lock:
            return self._decide_and_act(request, caller)

    def _decide_and_act(self, request: ActionRequest, caller: str) -> dict:
        now = self._clock()
        try:
            decision = self._policy.evaluate(
                request, caller=caller, now=now,
                host_id=self._config.host_id, boot_id=self._config.boot_id,
                active_actions=self._journal.active_count(),
                recent_request_rate=self._rate_for(caller, now),
                seen_request_ids=frozenset(self._seen))
        except PolicyError as exc:
            return self._denied(request.request_id,
                                (DenyReason.POLICY_UNAVAILABLE,), str(exc))
        self._remember(request.request_id)
        self._record_rate(caller, now)

        if not decision.allowed:
            # A denial is journalled too. "Something tried and was refused"
            # is exactly the record an investigation needs.
            self._journal_safely(
                action_id=request.request_id, action_type=request.action_type,
                target=request.target, state=ActionState.DENIED,
                requested_by=caller, requested_at=request.requested_at,
                detail=",".join(r.value for r in decision.reasons))
            return _response(decision, ActionState.DENIED)

        if request.action_type is ActionType.RELEASE_RESTRICTION:
            return self._release(request, decision, caller)
        return self._apply(request, decision, caller, now)

    def _apply(self, request: ActionRequest, decision: AuthorizationDecision,
               caller: str, now: datetime) -> dict:
        expires_at = now + (decision.granted_duration or request.duration)
        if not self._enforcer.supports(request.action_type):
            return self._unavailable(request, caller,
                                     "backend does not implement this action")
        # Intent is durable before the OS is touched. A crash after this
        # point leaves a record that says state may exist.
        try:
            self._journal.record(
                action_id=request.request_id, action_type=request.action_type,
                target=request.target, state=ActionState.APPLYING,
                policy_version=decision.policy_version, requested_by=caller,
                requested_at=request.requested_at, expires_at=expires_at,
                detail="intent recorded before enforcement")
        except JournalError as exc:
            # Cannot record it, so will not do it. An unjournalled privileged
            # action is one nobody can clean up.
            return self._unavailable(request, caller,
                                     f"journal unavailable: {exc}", journal=False)
        try:
            result = self._enforcer.apply(request, expires_at=expires_at)
        except EnforcementError as exc:
            self._journal_transition(request.request_id, ActionState.FAILED,
                                     detail=f"backend error: {exc}")
            return self._unavailable(request, caller, str(exc), journal=False)
        except Exception as exc:                        # noqa: BLE001
            # An unexpected backend fault may still have created state, so
            # the action is marked as requiring rollback rather than failed.
            self._journal_transition(
                request.request_id, ActionState.ROLLBACK_REQUIRED,
                detail=f"unexpected backend fault: {type(exc).__name__}")
            return self._unavailable(request, caller,
                                     "backend fault", journal=False)

        state = _state_for(result.outcome)
        self._journal_transition(request.request_id, state,
                                 activated_at=now if result.may_hold_os_state else None,
                                 owned_resource=result.resource,
                                 detail=result.detail)
        return _response(decision, state, expires_at=expires_at,
                         resource=result.resource)

    def _release(self, request: ActionRequest, decision: AuthorizationDecision,
                 caller: str) -> dict:
        """Release the action whose id is carried in ``finding_id``.

        Releasing is not itself dangerous -- it removes state rather than
        creating it -- but it still goes through policy, so that a caller
        cannot use release as an unauthenticated way to probe which actions
        exist.
        """
        target_id = request.finding_id
        entry = self._journal.get(target_id)
        if entry is None or entry.owned_resource is None:
            return _response(decision, ActionState.RELEASED,
                             detail="no owned resource for that action")
        result = self._enforcer.release(entry.owned_resource)
        state = (ActionState.RELEASED
                 if result.outcome in (EnforcementOutcome.RELEASED,
                                       EnforcementOutcome.ALREADY_ABSENT)
                 else ActionState.ROLLBACK_REQUIRED)
        self._journal_transition(target_id, state, detail=result.detail)
        self._journal_safely(
            action_id=request.request_id, action_type=request.action_type,
            target=request.target, state=ActionState.RELEASED,
            requested_by=caller, requested_at=request.requested_at,
            detail=f"released {target_id}")
        return _response(decision, state, detail=result.detail)

    # -- time-driven work ------------------------------------------------

    def expire_due(self) -> tuple[str, ...]:
        """Release every action past its deadline.

        The deadline is the broker's, derived from its own clock at
        authorization time. A caller cannot extend an action by staying
        connected, by resending, or by any other means: there is no renew
        message, and a new request is a new action with its own limit.
        """
        now = self._clock()
        expired: list[str] = []
        with self._lock:
            for entry in self._journal.unreconciled():
                if entry.expires_at is None or entry.expires_at > now:
                    continue
                if entry.owned_resource is not None:
                    try:
                        result = self._enforcer.release(entry.owned_resource)
                    except EnforcementError:
                        self._journal_transition(
                            entry.action_id, ActionState.ROLLBACK_REQUIRED,
                            detail="release failed at expiry")
                        continue
                    state = (ActionState.RELEASED
                             if result.outcome in (EnforcementOutcome.RELEASED,
                                                   EnforcementOutcome.ALREADY_ABSENT)
                             else ActionState.ROLLBACK_REQUIRED)
                else:
                    state = ActionState.RELEASED
                self._journal_transition(entry.action_id, state,
                                         detail="expired")
                expired.append(entry.action_id)
        return tuple(expired)

    def reconcile(self) -> tuple[str, ...]:
        """Reconcile journal against host state. Run once at startup.

        Two directions, both required:

        * **Owned but not journalled** -- an orphan from a crash between
          apply and journal. Removed, because state nobody tracks is state
          nobody will ever remove.
        * **Journalled but not owned** -- a record for state that is gone,
          usually a reboot. Closed, so it stops counting against the active
          limit and blocking legitimate containment.
        """
        notes: list[str] = []
        with self._lock:
            live = {r.identifier: r for r in self._enforcer.reconcile()}
            journalled = {e.owned_resource.identifier: e
                          for e in self._journal.unreconciled()
                          if e.owned_resource is not None}
            for identifier, resource in live.items():
                if identifier in journalled:
                    continue
                try:
                    self._enforcer.release(resource)
                    notes.append(f"removed orphan {identifier}")
                except EnforcementError as exc:
                    notes.append(f"orphan {identifier} could not be removed: {exc}")
            for identifier, entry in journalled.items():
                if identifier in live:
                    continue
                self._journal_transition(
                    entry.action_id, ActionState.RELEASED,
                    detail="host state absent at reconciliation")
                notes.append(f"closed stale record {entry.action_id}")
            for entry in self._journal.unreconciled():
                if entry.owned_resource is None:
                    # APPLYING with no resource: the crash window. Nothing to
                    # remove, but the record must not stay open forever.
                    self._journal_transition(
                        entry.action_id, ActionState.RELEASED,
                        detail="no resource was ever recorded")
                    notes.append(f"closed incomplete record {entry.action_id}")
        self.reconciliation = tuple(notes)
        return self.reconciliation

    def status(self) -> dict:
        active = self._journal.unreconciled()
        return {
            "schema_version": SCHEMA_VERSION, "type": "status",
            "policy_version": self._policy.version,
            "backend": self._enforcer.backend_id,
            "host_id": self._config.host_id, "boot_id": self._config.boot_id,
            "active_actions": len(active),
            "max_active_actions": self._policy.max_active_actions,
            "journal_corrupt_records": self._journal.corrupt_records,
            "replay_cache": len(self._seen),
        }

    # -- helpers ---------------------------------------------------------

    def _rate_for(self, caller: str, now: datetime) -> int:
        window = self._recent.get(caller)
        if not window:
            return 0
        cutoff = now - timedelta(minutes=1)
        while window and window[0] < cutoff:
            window.popleft()
        if not window:
            del self._recent[caller]
            return 0
        return len(window)

    def _record_rate(self, caller: str, now: datetime) -> None:
        window = self._recent.setdefault(
            caller, collections.deque(maxlen=self._policy.max_requests_per_minute * 4))
        window.append(now)

    def _remember(self, request_id: str) -> None:
        self._seen[request_id] = None
        self._seen.move_to_end(request_id)
        while len(self._seen) > self._config.max_replay_cache:
            self._seen.popitem(last=False)

    def _journal_safely(self, **kwargs) -> None:
        try:
            self._journal.record(policy_version=self._policy.version, **kwargs)
        except JournalError:
            pass          # already reported through the response

    def _journal_transition(self, action_id: str, state: ActionState,
                            **kwargs) -> None:
        try:
            self._journal.transition(action_id, state, **kwargs)
        except JournalError:
            pass

    def _malformed(self, detail: str) -> dict:
        return {"schema_version": SCHEMA_VERSION, "type": "action_response",
                "request_id": "", "decision": Decision.DENY.value,
                "reasons": [DenyReason.MALFORMED_REQUEST.value],
                "state": ActionState.DENIED.value, "detail": detail[:256]}

    def _denied(self, request_id: str, reasons: tuple[DenyReason, ...],
                detail: str) -> dict:
        return {"schema_version": SCHEMA_VERSION, "type": "action_response",
                "request_id": request_id, "decision": Decision.DENY.value,
                "reasons": [r.value for r in reasons],
                "state": ActionState.DENIED.value, "detail": detail[:256]}

    def _unavailable(self, request: ActionRequest, caller: str, detail: str,
                     *, journal: bool = True) -> dict:
        if journal:
            self._journal_safely(
                action_id=request.request_id, action_type=request.action_type,
                target=request.target, state=ActionState.FAILED,
                requested_by=caller, requested_at=request.requested_at,
                detail=detail)
        return {"schema_version": SCHEMA_VERSION, "type": "action_response",
                "request_id": request.request_id, "decision": Decision.ALLOW.value,
                "reasons": [], "state": ActionState.FAILED.value,
                "enforcement": "unavailable", "detail": detail[:256]}


def _state_for(outcome: EnforcementOutcome) -> ActionState:
    return {
        EnforcementOutcome.APPLIED: ActionState.APPLIED,
        EnforcementOutcome.VERIFIED: ActionState.EFFECT_VERIFIED,
        EnforcementOutcome.FAILED: ActionState.FAILED,
        # Uncertain keeps the action holding OS state, so reconciliation
        # will look for it. Rounding this to FAILED would leak a rule.
        EnforcementOutcome.UNCERTAIN: ActionState.EFFECT_NOT_VERIFIED,
        EnforcementOutcome.ALREADY_ABSENT: ActionState.RELEASED,
        EnforcementOutcome.RELEASED: ActionState.RELEASED,
    }[outcome]


def _response(decision: AuthorizationDecision, state: ActionState, *,
              expires_at: datetime | None = None,
              resource: OwnedResource | None = None,
              detail: str = "") -> dict:
    body = decision.to_dict()
    body.update({"schema_version": SCHEMA_VERSION, "type": "action_response",
                 "state": state.value})
    if expires_at is not None:
        body["expires_at"] = expires_at.isoformat()
    if resource is not None:
        body["owned_resource"] = resource.identifier
    if detail:
        body["detail"] = detail[:256]
    return body


class BrokerServer:
    """The socket in front of a :class:`Broker`.

    Deliberately boring: accept, read the peer's credentials, read one
    bounded message, hand it to the broker, write one response, close. One
    request per connection means a stalled client cannot hold a slot, and
    there is no session state for anything to confuse.
    """

    def __init__(self, broker: Broker, config: BrokerConfig, *,
                 sweep_interval: float = 1.0) -> None:
        self._broker = broker
        self._config = config
        self._listener: socket.socket | None = None
        self._stop = threading.Event()
        self._sweeper: threading.Thread | None = None
        self._sweep_interval = sweep_interval
        self.rejected_peers: list[str] = []
        self.expired: list[str] = []

    def start(self) -> None:
        if self._config.require_privilege and os.geteuid() != 0:
            raise PermissionError(
                "the broker must run privileged; refusing to start as a "
                "process that cannot enforce what it authorizes")
        if not ipc.peer_credentials_supported():
            # No caller identity means no boundary. Refusing to start is the
            # honest outcome; starting anyway would be security theatre.
            raise ipc.PeerIdentityUnavailable(
                "this platform cannot identify local peers; the broker will "
                "not run without caller authentication")
        self._listener = ipc.bind_listener(self._config.socket_path,
                                           backlog=MAX_CONCURRENT_CONNECTIONS)
        self._listener.settimeout(0.5)
        # Expiry runs inside the privileged process, on its own clock. If it
        # lived in the core, killing the core would make every "temporary"
        # restriction permanent -- which is precisely the failure an attacker
        # who has already compromised the core would reach for.
        self._sweeper = threading.Thread(target=self._sweep_loop, daemon=True,
                                         name="annulon-broker-expiry")
        self._sweeper.start()

    def _sweep_loop(self) -> None:
        while not self._stop.wait(self._sweep_interval):
            try:
                self.expired.extend(self._broker.expire_due())
            except Exception:                   # noqa: BLE001
                # A sweep that raises must not kill the thread; the next tick
                # tries again. A dead sweeper is a silent expiry outage.
                continue

    def serve_forever(self) -> None:
        while not self._stop.is_set():
            self.serve_once()

    def serve_once(self, timeout: float = 0.5) -> bool:
        """Handle at most one connection. Returns whether one was served."""
        # Bind the listener to a local before using it. ``stop`` may clear
        # the attribute from another thread at any point, and reading it
        # twice raced: the None check passed and ``accept`` then ran against
        # None, crashing the serving thread during shutdown.
        listener = self._listener
        if listener is None:
            if self._stop.is_set():
                return False
            raise RuntimeError("server not started")
        try:
            listener.settimeout(timeout)
            connection, _ = listener.accept()
        except (TimeoutError, socket.timeout):
            return False
        except OSError:
            return False
        with connection:
            connection.settimeout(5.0)
            try:
                credentials = ipc.peer_credentials(connection)
            except ipc.IpcError as exc:
                self.rejected_peers.append(str(exc))
                return True
            caller = self._broker.caller_for(credentials)
            try:
                message = ipc.read_message(connection)
            except ipc.IpcError as exc:
                # A decode failure is answered, not crashed on, and the
                # caller's bytes are never echoed back.
                self._reply(connection, self._broker._malformed(
                    f"undecodable: {type(exc).__name__}"))
                return True
            try:
                response = self._broker.handle(message, caller=caller)
            except Exception as exc:                    # noqa: BLE001
                # The broker holds the privilege. It answers every request,
                # including ones that reveal a defect in itself.
                response = self._broker._malformed(
                    f"broker fault: {type(exc).__name__}")
            self._reply(connection, response)
        return True

    def _reply(self, connection: socket.socket, body: dict) -> None:
        try:
            ipc.write_message(connection, body)
        except (ipc.IpcError, OSError):
            pass

    def stop(self) -> None:
        # The event is set first, so a thread that wakes between the two
        # statements sees a deliberate shutdown rather than a fault.
        self._stop.set()
        if self._sweeper is not None:
            self._sweeper.join(timeout=5)
            self._sweeper = None
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        try:
            os.unlink(self._config.socket_path)
        except OSError:
            pass
