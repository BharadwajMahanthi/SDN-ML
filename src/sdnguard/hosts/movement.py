"""The host-movement state machine.

Pure: it takes an event and a state and returns a new state plus a list of
actions. It performs no I/O, holds no clock, and imports nothing outside the
domain model, so the entire security decision is testable on a laptop with
no OVS (ADR-005).

States and the reasoning behind them
------------------------------------
``UNKNOWN`` -> ``LEARNED`` on first observation.

``LEARNED`` -> ``MOVE_OBSERVED`` when the host appears at a different port.
At this moment we have exactly one piece of evidence: the *pre-condition*.
A host that physically moves causes its old port to go down first, so a move
with no port-down signal is suspicious but not proven.

``MOVE_OBSERVED`` -> ``VALIDATING`` once a liveness probe has been issued at
the *old* location. This is the *post-condition* test: a genuinely departed
host cannot answer there.

``VALIDATING`` resolves exactly once, three ways:

* a probe reply from the old location -> ``SUSPICIOUS_MOVE``. The host never
  left, so the new location is an impostor.
* the deadline passes with no reply -> ``MOVE_ACCEPTED``, recorded as *weak*
  evidence. Absence of a reply is equally consistent with packet loss, and
  the legacy design's willingness to treat silence as proof is exactly the
  reasoning error this state machine refuses to repeat.
* the probe could not be sent or was cancelled -> ``INCONCLUSIVE``. The
  system is never forced to choose between attack and benign.

Any state -> ``UNKNOWN`` on ``switch_lost`` for the relevant switch, because
state created under a previous connection generation cannot be trusted.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, replace
from datetime import datetime

from sdnguard.domain.events import (
    MovementEvent,
    ProbeOutcome,
    ProbeRequest,
    ProbeResult,
)
from sdnguard.domain.host import HostIdentity, HostLocation, MacAddress
from sdnguard.domain.identity import DatapathId, InvalidIdentity, PortIdentity, _ValueObject

__all__ = [
    "MovementState",
    "ActionKind",
    "Action",
    "HostMovementState",
    "MovementStateMachine",
    "IllegalTransition",
]


class MovementState(enum.Enum):
    UNKNOWN = "unknown"
    LEARNED = "learned"
    MOVE_OBSERVED = "move_observed"
    VALIDATING = "validating"
    SUSPICIOUS_MOVE = "suspicious_move"
    MOVE_ACCEPTED = "move_accepted"
    INCONCLUSIVE = "inconclusive"


class ActionKind(enum.Enum):
    """What the caller should do. The machine never does these itself."""

    ISSUE_PROBE = "issue_probe"
    CANCEL_PROBE = "cancel_probe"
    EMIT_FINDING = "emit_finding"
    ACCEPT_LOCATION = "accept_location"


class IllegalTransition(Exception):
    """An event arrived in a state where it has no defined meaning.

    Raised rather than ignored: a silently dropped event is how the legacy
    implementation's unreachable branches went unnoticed for so long.
    """


@dataclass(frozen=True)
class Action(_ValueObject):
    __slots__ = ("kind", "detail", "port", "reason")
    kind: ActionKind
    detail: str
    port: PortIdentity | None
    reason: str

    @classmethod
    def of(cls, kind: ActionKind, detail: str, *,
           port: PortIdentity | None = None, reason: str = "") -> "Action":
        return cls(kind, detail, port, reason)

    def __str__(self) -> str:
        return f"{self.kind.value}({self.detail})"


@dataclass(frozen=True)
class HostMovementState(_ValueObject):
    """Per-host state. Immutable; every transition produces a new value."""

    __slots__ = ("identity", "state", "current", "pending_from",
                 "probe_id", "port_down_seen", "evidence", "generation")
    identity: HostIdentity
    state: MovementState
    current: HostLocation | None
    pending_from: HostLocation | None
    probe_id: str | None
    port_down_seen: bool
    evidence: tuple[str, ...]
    generation: int

    @classmethod
    def unknown(cls, identity: HostIdentity) -> "HostMovementState":
        return cls(identity, MovementState.UNKNOWN, None, None, None,
                   False, (), 0)

    @property
    def mac(self) -> MacAddress:
        return self.identity.mac

    @property
    def is_resolved(self) -> bool:
        return self.state in (MovementState.SUSPICIOUS_MOVE,
                              MovementState.MOVE_ACCEPTED,
                              MovementState.INCONCLUSIVE)

    @property
    def has_outstanding_probe(self) -> bool:
        return self.state is MovementState.VALIDATING and self.probe_id is not None

    def with_evidence(self, *items: str) -> "HostMovementState":
        return replace(self, evidence=self.evidence + tuple(items))

    def __str__(self) -> str:
        return f"{self.mac} {self.state.value}"


@dataclass
class MovementStateMachine:
    """Pure transition function plus a bounded per-host state map."""

    max_hosts: int = 8192
    _states: dict[MacAddress, HostMovementState] = field(default_factory=dict)

    # -- queries ---------------------------------------------------------

    def state_of(self, mac: MacAddress) -> MovementState:
        entry = self._states.get(mac)
        return entry.state if entry else MovementState.UNKNOWN

    def get(self, mac: MacAddress) -> HostMovementState | None:
        return self._states.get(mac)

    def __len__(self) -> int:
        return len(self._states)

    def outstanding_probes(self) -> dict[str, MacAddress]:
        return {s.probe_id: mac for mac, s in self._states.items()
                if s.has_outstanding_probe}

    # -- events ----------------------------------------------------------

    def on_observation(self, identity: HostIdentity, location: HostLocation,
                       generation: int = 0) -> tuple[HostMovementState, list[Action]]:
        """A host was seen at ``location``."""
        entry = self._states.get(identity.mac)
        if entry is None:
            if len(self._states) >= self.max_hosts:
                raise IllegalTransition(
                    f"movement machine holds {len(self._states)} hosts "
                    f"(limit {self.max_hosts})")
            entry = replace(HostMovementState.unknown(identity),
                            state=MovementState.LEARNED, current=location,
                            generation=generation)
            return self._store(entry), [
                Action.of(ActionKind.ACCEPT_LOCATION, str(location.port),
                          port=location.port, reason="first sighting")]

        if entry.current is not None and entry.current.port == location.port:
            # Same port. Any pending validation is now moot: the host is
            # demonstrably here, which is where we already thought it was.
            actions: list[Action] = []
            if entry.has_outstanding_probe:
                actions.append(Action.of(ActionKind.CANCEL_PROBE, entry.probe_id,
                                         reason="host re-observed at current port"))
            entry = replace(entry, state=MovementState.LEARNED, current=location,
                            pending_from=None, probe_id=None)
            return self._store(entry), actions

        if entry.state is MovementState.VALIDATING:
            # Movement while a probe is outstanding. Do not start a second
            # one; invariant (2) is exactly one outstanding probe per host.
            entry = entry.with_evidence(
                f"further movement to {location.port} while validating")
            return self._store(replace(entry, current=location)), []

        previous = entry.current
        entry = replace(entry, state=MovementState.MOVE_OBSERVED,
                        pending_from=previous, current=location)
        evidence = [f"moved {previous.port} -> {location.port}" if previous
                    else f"appeared at {location.port}"]
        if not entry.port_down_seen:
            evidence.append(
                "no port-down signal was observed at the previous port")
        entry = entry.with_evidence(*evidence)
        return self._store(entry), [
            Action.of(ActionKind.ISSUE_PROBE,
                      str(previous.port) if previous else "",
                      port=previous.port if previous else None,
                      reason="verify the host is no longer at its old location")]

    def on_port_down(self, mac: MacAddress,
                     port: PortIdentity) -> HostMovementState | None:
        """A port carrying this host went down: the migration pre-condition.

        Returns ``None`` for a host we do not track. Recording port-down for
        an unknown host would let an attacker pre-seed the pre-condition for
        a MAC before ever presenting it.
        """
        entry = self._states.get(mac)
        if entry is None:
            return None
        if entry.current is not None and entry.current.port == port:
            entry = replace(entry, port_down_seen=True).with_evidence(
                f"port-down observed at {port}")
            return self._store(entry)
        return entry

    def on_probe_issued(self, mac: MacAddress,
                        probe: ProbeRequest) -> tuple[HostMovementState, list[Action]]:
        entry = self._require(mac)
        if entry.state is not MovementState.MOVE_OBSERVED:
            raise IllegalTransition(
                f"probe issued for {mac} in state {entry.state.value}; "
                "only MOVE_OBSERVED expects one")
        entry = replace(entry, state=MovementState.VALIDATING,
                        probe_id=probe.correlation_id).with_evidence(
                            f"probe {probe.correlation_id[:8]} issued to "
                            f"{probe.target_port}")
        return self._store(entry), []

    def on_probe_result(self, mac: MacAddress,
                        result: ProbeResult) -> tuple[HostMovementState, list[Action]]:
        entry = self._require(mac)
        if entry.state is not MovementState.VALIDATING:
            raise IllegalTransition(
                f"probe result for {mac} in state {entry.state.value}; "
                "only VALIDATING awaits one")
        if entry.probe_id != result.correlation_id:
            raise IllegalTransition(
                f"probe result {result.correlation_id[:8]} does not match the "
                f"outstanding probe {(entry.probe_id or '')[:8]} for {mac}")

        if result.outcome is ProbeOutcome.REPLIED:
            entry = replace(entry, state=MovementState.SUSPICIOUS_MOVE,
                            probe_id=None).with_evidence(
                "host replied at its previous location after moving")
            return self._store(entry), [
                Action.of(ActionKind.EMIT_FINDING, "host_location_hijack",
                          port=entry.current.port if entry.current else None,
                          reason="the host never left its old location")]

        if result.outcome is ProbeOutcome.EXPIRED:
            entry = replace(entry, state=MovementState.MOVE_ACCEPTED,
                            probe_id=None, pending_from=None).with_evidence(
                "no reply at the previous location before the deadline "
                "(weak evidence: equally consistent with packet loss)")
            actions = [Action.of(ActionKind.ACCEPT_LOCATION,
                                 str(entry.current.port) if entry.current else "",
                                 port=entry.current.port if entry.current else None,
                                 reason="old location did not answer")]
            if not entry.port_down_seen:
                actions.append(Action.of(
                    ActionKind.EMIT_FINDING, "host_moved_without_port_down",
                    port=entry.current.port if entry.current else None,
                    reason="migration pre-condition was not satisfied"))
            return self._store(entry), actions

        # UNDELIVERABLE or CANCELLED: we learned nothing either way.
        entry = replace(entry, state=MovementState.INCONCLUSIVE,
                        probe_id=None).with_evidence(
            f"probe {result.outcome.value}: no conclusion is available")
        return self._store(entry), [
            Action.of(ActionKind.EMIT_FINDING, "probe_unresolved",
                      port=entry.current.port if entry.current else None,
                      reason="validation could not complete")]

    def on_switch_lost(self, dpid: DatapathId) -> list[MacAddress]:
        """Invalidate everything anchored to a departed switch."""
        affected: list[MacAddress] = []
        for mac, entry in list(self._states.items()):
            touches = any(loc is not None and loc.port.datapath_id == dpid
                          for loc in (entry.current, entry.pending_from))
            if touches:
                affected.append(mac)
                del self._states[mac]
        return sorted(affected)

    def forget(self, mac: MacAddress) -> bool:
        return self._states.pop(mac, None) is not None

    # -- helpers ---------------------------------------------------------

    def _require(self, mac: MacAddress) -> HostMovementState:
        entry = self._states.get(mac)
        if entry is None:
            raise IllegalTransition(f"no movement state for {mac}")
        return entry

    def _store(self, entry: HostMovementState) -> HostMovementState:
        self._states[entry.mac] = entry
        return entry

    # -- movement event construction -------------------------------------

    def to_event(self, mac: MacAddress, observed_at: datetime,
                 concurrent_locations: int = 1) -> MovementEvent:
        """Build the domain event describing the move now being validated."""
        entry = self._require(mac)
        if entry.pending_from is None or entry.current is None:
            raise InvalidIdentity(f"{mac} has no pending movement")
        return MovementEvent.of(entry.identity, entry.pending_from, entry.current,
                                observed_at, port_down_seen=entry.port_down_seen,
                                concurrent_locations=concurrent_locations)
