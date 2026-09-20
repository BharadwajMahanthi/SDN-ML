"""Movement, probe, finding and policy event types.

These are the values that flow through the security core:

    HostObservation -> MovementEvent -> ProbeRequest/ProbeResult
                    -> SecurityFinding -> EnforcementDecision

Every one is immutable, every one is serialisable, and none of them import an
OpenFlow library (ADR-005).

Two deliberate departures from the legacy design are encoded in the types
themselves rather than left to convention:

1. A probe carries a mandatory ``deadline`` and a single-use ``nonce``. The
   legacy prober had neither, so no reply could be authenticated and no
   unanswered probe was ever resolved.
2. ``Verdict`` has an explicit ``INCONCLUSIVE`` member. Absence of a probe
   reply is equally consistent with packet loss, so the system is never
   forced to choose between "attack" and "benign".
"""

from __future__ import annotations

import enum
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final

from sdnguard.domain.host import HostIdentity, HostLocation
from sdnguard.domain.identity import InvalidIdentity, PortIdentity, _ValueObject

__all__ = [
    "MovementEvent",
    "ProbeMethod",
    "ProbeRequest",
    "ProbeOutcome",
    "ProbeResult",
    "Verdict",
    "Severity",
    "FindingKind",
    "SecurityFinding",
    "EnforcementAction",
    "EnforcementDecision",
    "new_correlation_id",
]

_NONCE_BYTES: Final = 16


def new_correlation_id() -> str:
    """An unguessable, single-use correlation token.

    Unguessable matters: a correlation id that an on-segment attacker can
    predict lets them forge a probe reply, which would turn the liveness
    check into a way to *manufacture* a false hijack verdict.
    """
    return secrets.token_hex(_NONCE_BYTES)


def _require_aware(moment: datetime, name: str) -> None:
    if not isinstance(moment, datetime):
        raise InvalidIdentity(f"{name} must be a datetime")
    if moment.tzinfo is None:
        raise InvalidIdentity(f"{name} must be timezone-aware")


# -- movement --------------------------------------------------------------


@dataclass(frozen=True)
class MovementEvent(_ValueObject):
    """A known host has been observed at a location other than its current one."""

    __slots__ = ("identity", "previous", "current", "observed_at",
                 "port_down_seen", "concurrent_locations")
    identity: HostIdentity
    previous: HostLocation
    current: HostLocation
    observed_at: datetime
    port_down_seen: bool
    concurrent_locations: int

    def __post_init__(self) -> None:
        if not isinstance(self.identity, HostIdentity):
            raise InvalidIdentity("identity must be a HostIdentity")
        for name in ("previous", "current"):
            if not isinstance(getattr(self, name), HostLocation):
                raise InvalidIdentity(f"{name} must be a HostLocation")
        _require_aware(self.observed_at, "observed_at")
        if self.previous.port == self.current.port:
            raise InvalidIdentity(
                "a movement event requires two different ports; "
                "a repeat sighting at the same port is not movement")
        if not isinstance(self.port_down_seen, bool):
            raise InvalidIdentity("port_down_seen must be a bool")
        if not isinstance(self.concurrent_locations, int) or self.concurrent_locations < 1:
            raise InvalidIdentity("concurrent_locations must be a positive int")

    @classmethod
    def of(cls, identity: HostIdentity, previous: HostLocation,
           current: HostLocation, observed_at: datetime, *,
           port_down_seen: bool = False,
           concurrent_locations: int = 1) -> "MovementEvent":
        return cls(identity, previous, current, observed_at,
                   port_down_seen, concurrent_locations)

    @property
    def elapsed_seconds(self) -> float:
        """Time between the last sighting at the old port and this one."""
        return (self.current.last_seen - self.previous.last_seen).total_seconds()

    @property
    def is_multi_location(self) -> bool:
        """The legacy implementation silently ignored hosts with more than one
        prior attachment point. Being in several places at once is the signal,
        not a reason to skip the host."""
        return self.concurrent_locations > 1

    def __str__(self) -> str:
        return f"{self.identity} {self.previous.port} -> {self.current.port}"


# -- probes ----------------------------------------------------------------


class ProbeMethod(enum.Enum):
    ARP = "arp"
    ICMP = "icmp"


class ProbeOutcome(enum.Enum):
    REPLIED = "replied"          # host answered at the old location
    EXPIRED = "expired"          # deadline passed with no reply
    UNDELIVERABLE = "undeliverable"   # switch or port gone before sending
    CANCELLED = "cancelled"      # superseded, e.g. switch disconnected


@dataclass(frozen=True)
class ProbeRequest(_ValueObject):
    """A liveness probe aimed at a host's *previous* location."""

    __slots__ = ("correlation_id", "identity", "target_port", "method",
                 "issued_at", "deadline")
    correlation_id: str
    identity: HostIdentity
    target_port: PortIdentity
    method: ProbeMethod
    issued_at: datetime
    deadline: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.correlation_id, str) or len(self.correlation_id) < 16:
            raise InvalidIdentity(
                "correlation_id must be an unguessable string of at least 16 chars")
        if not isinstance(self.identity, HostIdentity):
            raise InvalidIdentity("identity must be a HostIdentity")
        if not isinstance(self.target_port, PortIdentity):
            raise InvalidIdentity("target_port must be a PortIdentity")
        if not isinstance(self.method, ProbeMethod):
            raise InvalidIdentity("method must be a ProbeMethod")
        _require_aware(self.issued_at, "issued_at")
        _require_aware(self.deadline, "deadline")
        if self.deadline <= self.issued_at:
            raise InvalidIdentity(
                "deadline must be after issued_at; a probe without a future "
                "deadline can never be resolved, which is how the legacy "
                "implementation leaked probe state forever")

    @classmethod
    def create(cls, identity: HostIdentity, target_port: PortIdentity,
               issued_at: datetime, timeout: timedelta,
               method: ProbeMethod = ProbeMethod.ARP) -> "ProbeRequest":
        if timeout <= timedelta(0):
            raise InvalidIdentity("probe timeout must be positive")
        return cls(new_correlation_id(), identity, target_port, method,
                   issued_at, issued_at + timeout)

    def is_expired_at(self, moment: datetime) -> bool:
        _require_aware(moment, "moment")
        return moment >= self.deadline

    def __str__(self) -> str:
        return f"probe {self.correlation_id[:8]} -> {self.target_port} ({self.method.value})"


@dataclass(frozen=True)
class ProbeResult(_ValueObject):
    """The single, final resolution of one probe."""

    __slots__ = ("correlation_id", "outcome", "resolved_at", "detail")
    correlation_id: str
    outcome: ProbeOutcome
    resolved_at: datetime
    detail: str

    def __post_init__(self) -> None:
        if not isinstance(self.correlation_id, str) or not self.correlation_id:
            raise InvalidIdentity("correlation_id required")
        if not isinstance(self.outcome, ProbeOutcome):
            raise InvalidIdentity("outcome must be a ProbeOutcome")
        _require_aware(self.resolved_at, "resolved_at")
        if not isinstance(self.detail, str):
            raise InvalidIdentity("detail must be a str")

    @classmethod
    def of(cls, correlation_id: str, outcome: ProbeOutcome,
           resolved_at: datetime, detail: str = "") -> "ProbeResult":
        return cls(correlation_id, outcome, resolved_at, detail)

    @property
    def host_was_still_present(self) -> bool:
        return self.outcome is ProbeOutcome.REPLIED

    def __str__(self) -> str:
        return f"probe {self.correlation_id[:8]} {self.outcome.value}"


# -- findings --------------------------------------------------------------


class Verdict(enum.Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    INCONCLUSIVE = "inconclusive"


class Severity(enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingKind(enum.Enum):
    HOST_LOCATION_HIJACK = "host_location_hijack"
    HOST_MOVED_WITHOUT_PORT_DOWN = "host_moved_without_port_down"
    HOST_MULTI_LOCATION = "host_multi_location"
    LINK_FABRICATION = "link_fabrication"
    HOST_TRAFFIC_FROM_SWITCH_PORT = "host_traffic_from_switch_port"
    PROBE_UNRESOLVED = "probe_unresolved"


@dataclass(frozen=True)
class SecurityFinding(_ValueObject):
    """Machine-readable detector output.

    The legacy module's only output was ``logger.warn``, so no consumer could
    act on a detection and the collection scripts had nothing to collect
    (L-09). Findings are the replacement: typed, identified, serialisable,
    and carrying the evidence that produced them.
    """

    __slots__ = ("finding_id", "kind", "verdict", "severity", "identity",
                 "port", "detected_at", "evidence", "summary")
    finding_id: str
    kind: FindingKind
    verdict: Verdict
    severity: Severity
    identity: HostIdentity
    port: PortIdentity
    detected_at: datetime
    evidence: tuple[str, ...]
    summary: str

    def __post_init__(self) -> None:
        if not isinstance(self.finding_id, str) or not self.finding_id:
            raise InvalidIdentity("finding_id required")
        if not isinstance(self.kind, FindingKind):
            raise InvalidIdentity("kind must be a FindingKind")
        if not isinstance(self.verdict, Verdict):
            raise InvalidIdentity("verdict must be a Verdict")
        if not isinstance(self.severity, Severity):
            raise InvalidIdentity("severity must be a Severity")
        if not isinstance(self.identity, HostIdentity):
            raise InvalidIdentity("identity must be a HostIdentity")
        if not isinstance(self.port, PortIdentity):
            raise InvalidIdentity("port must be a PortIdentity")
        _require_aware(self.detected_at, "detected_at")
        if not isinstance(self.evidence, tuple) or not all(
                isinstance(e, str) for e in self.evidence):
            raise InvalidIdentity("evidence must be a tuple of strings")
        if not self.evidence:
            raise InvalidIdentity(
                "a finding must cite at least one piece of evidence; an "
                "unsupported assertion is not a detection")
        if not isinstance(self.summary, str) or not self.summary:
            raise InvalidIdentity("summary required")

    @classmethod
    def create(cls, kind: FindingKind, verdict: Verdict, severity: Severity,
               identity: HostIdentity, port: PortIdentity, detected_at: datetime,
               evidence: tuple[str, ...] | list[str], summary: str) -> "SecurityFinding":
        return cls(new_correlation_id(), kind, verdict, severity, identity,
                   port, detected_at, tuple(evidence), summary)

    def to_dict(self) -> dict:
        """Stable serialisation for evidence bundles and the P12 API."""
        return {
            "finding_id": self.finding_id,
            "kind": self.kind.value,
            "verdict": self.verdict.value,
            "severity": self.severity.value,
            "mac": str(self.identity.mac),
            "ip": str(self.identity.ip) if self.identity.ip else None,
            "port": str(self.port),
            "detected_at": self.detected_at.isoformat(),
            "evidence": list(self.evidence),
            "summary": self.summary,
        }

    def __str__(self) -> str:
        return f"[{self.severity.value}] {self.kind.value} {self.verdict.value}: {self.summary}"


# -- policy ----------------------------------------------------------------


class EnforcementAction(enum.Enum):
    OBSERVE = "observe"          # record only; the default
    ALERT = "alert"
    RATE_LIMIT = "rate_limit"
    QUARANTINE = "quarantine"
    DROP = "drop"


@dataclass(frozen=True)
class EnforcementDecision(_ValueObject):
    """What policy decided to do about a finding.

    ``scope`` and ``expires_at`` are mandatory for anything beyond OBSERVE /
    ALERT: an enforcement action with no scope and no expiry is an outage
    waiting to happen, and a security tool that causes outages is itself a
    security problem.
    """

    __slots__ = ("decision_id", "finding_id", "action", "scope",
                 "decided_at", "expires_at", "reason", "reversible")
    decision_id: str
    finding_id: str
    action: EnforcementAction
    scope: PortIdentity | None
    decided_at: datetime
    expires_at: datetime | None
    reason: str
    reversible: bool

    def __post_init__(self) -> None:
        if not isinstance(self.action, EnforcementAction):
            raise InvalidIdentity("action must be an EnforcementAction")
        if not isinstance(self.finding_id, str) or not self.finding_id:
            raise InvalidIdentity("finding_id required")
        _require_aware(self.decided_at, "decided_at")
        if not isinstance(self.reason, str) or not self.reason:
            raise InvalidIdentity("reason required")
        if self.action in {EnforcementAction.OBSERVE, EnforcementAction.ALERT}:
            return
        if self.scope is None:
            raise InvalidIdentity(
                f"{self.action.value} requires an explicit scope; unscoped "
                "enforcement cannot be reasoned about or rolled back")
        if self.expires_at is None:
            raise InvalidIdentity(
                f"{self.action.value} requires an expiry; enforcement that "
                "never expires becomes a permanent outage after a false positive")
        _require_aware(self.expires_at, "expires_at")
        if self.expires_at <= self.decided_at:
            raise InvalidIdentity("expires_at must be after decided_at")
        if not self.reversible:
            raise InvalidIdentity(
                f"{self.action.value} must be reversible; see ACCEPTANCE_CRITERIA")

    @classmethod
    def observe(cls, finding_id: str, decided_at: datetime,
                reason: str = "observe-only mode") -> "EnforcementDecision":
        return cls(new_correlation_id(), finding_id, EnforcementAction.OBSERVE,
                   None, decided_at, None, reason, True)

    @classmethod
    def create(cls, finding_id: str, action: EnforcementAction,
               decided_at: datetime, reason: str, *,
               scope: PortIdentity | None = None,
               ttl: timedelta | None = None,
               reversible: bool = True) -> "EnforcementDecision":
        expires = decided_at + ttl if ttl is not None else None
        return cls(new_correlation_id(), finding_id, action, scope,
                   decided_at, expires, reason, reversible)

    @property
    def is_enforcing(self) -> bool:
        return self.action not in {EnforcementAction.OBSERVE, EnforcementAction.ALERT}

    def is_expired_at(self, moment: datetime) -> bool:
        return self.expires_at is not None and moment >= self.expires_at

    def __str__(self) -> str:
        return f"{self.action.value} for {self.finding_id[:8]}: {self.reason}"
