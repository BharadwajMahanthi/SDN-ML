"""What a response is allowed to be, defined before anything can perform one.

The property this module exists to make structural rather than procedural:

    a component may *request* an action; it may not *authorize* one.

So :class:`ActionRequest` has no field in which a caller can assert that its
request is permitted. There is nowhere to write ``authorized=true``. The only
type that carries an authorization outcome is
:class:`AuthorizationDecision`, and it is produced by the broker from a
request plus broker-owned policy -- never carried in from outside.

That shape is deliberate. A boolean on the request would eventually be
trusted by something, and then a compromised or simply buggy core would have
arbitrary privileged execution. Making the field absent is cheaper to defend
than making it ignored.

There are also no ``RunShell``, ``ExecuteCommand`` or equivalent action
types, and no free-text command anywhere in the contract. A broker that
accepts a command string is an RPC wrapper around root with extra steps.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

__all__ = [
    "SCHEMA_VERSION", "ActionType", "TargetKind", "Target", "ActionRequest",
    "Decision", "DenyReason", "AuthorizationDecision", "ActionState",
    "ContractError", "MAX_REASON_CHARS", "MAX_TTL",
]

SCHEMA_VERSION = 1
MAX_REASON_CHARS = 256
MAX_TTL = timedelta(hours=1)
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,63}$")
_NAME = re.compile(r"^[a-z][a-z0-9_-]{1,63}$")


class ContractError(ValueError):
    """A request that cannot be represented safely."""


class ActionType(enum.Enum):
    """Every action the broker can be asked for, exhaustively.

    Starting with one. Adding a type is a deliberate act with its own policy,
    its own OS implementation and its own tests; an open-ended action space
    is how a containment tool becomes a remote execution service.
    """

    #: Restrict a specific workload's outbound network access, for a bounded
    #: time. Reversible, scoped, and the only implemented action today.
    TEMPORARY_EGRESS_RESTRICTION = "temporary_egress_restriction"
    #: Release one previously applied restriction early.
    RELEASE_RESTRICTION = "release_restriction"


class TargetKind(enum.Enum):
    """What an action can be aimed at.

    A PID is deliberately absent. PIDs are reused, and a privileged action
    authorized against PID 1234 may land on an entirely different process by
    the time it is applied. Only identities whose continued validity can be
    checked at apply time are permitted.
    """

    SERVICE_UID = "service_uid"      # a dedicated service account on one host
    # Future kinds -- cgroup, container, systemd unit, workload identity --
    # are not declared here. Declaring an unimplemented target kind invites
    # a policy that appears to cover something it cannot.


@dataclass(frozen=True)
class Target:
    """Who the action applies to, in terms the broker can re-verify."""

    kind: TargetKind
    host_id: str
    boot_id: str
    identifier: str
    service_name: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.kind, TargetKind):
            raise ContractError("kind must be a TargetKind")
        for name in ("host_id", "boot_id", "identifier"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ContractError(f"{name} is required")
            if len(value) > 128:
                raise ContractError(f"{name} exceeds 128 characters")
            # Path and shell metacharacters have no business in an identity
            # that will be compared against OS state.
            if any(c in value for c in "/\\;|&$`\n\r\0'\" "):
                raise ContractError(f"{name} contains a forbidden character")
        if self.kind is TargetKind.SERVICE_UID and not self.identifier.isdigit():
            raise ContractError("a service_uid target identifier must be numeric")

    @property
    def uid(self) -> int | None:
        return int(self.identifier) if self.identifier.isdigit() else None

    def same_boot(self, host_id: str, boot_id: str) -> bool:
        """A target authorized in a previous boot is not this target.

        Checked at apply time: a UID means something different after a
        rebuild, and an action carried across a reboot would be aimed at
        whatever now holds that number.
        """
        return self.host_id == host_id and self.boot_id == boot_id

    def to_dict(self) -> dict:
        return {"kind": self.kind.value, "host_id": self.host_id,
                "boot_id": self.boot_id, "identifier": self.identifier,
                "service_name": self.service_name}

    @staticmethod
    def from_dict(raw: object) -> "Target":
        if not isinstance(raw, dict):
            raise ContractError("target must be an object")
        try:
            kind = TargetKind(raw.get("kind"))
        except ValueError as exc:
            raise ContractError(f"unknown target kind {raw.get('kind')!r}") from exc
        return Target(kind, str(raw.get("host_id", "")), str(raw.get("boot_id", "")),
                      str(raw.get("identifier", "")), str(raw.get("service_name", "")))

    def __str__(self) -> str:
        label = self.service_name or self.identifier
        return f"{self.kind.value}:{label}@{self.host_id}"


@dataclass(frozen=True)
class ActionRequest:
    """What the core asks for.

    Note what is *not* here: no authorization flag, no priority that could be
    read as urgency-overrides-policy, no command, no raw rule text, and no
    destination expressed as anything the broker cannot validate. The request
    is a question, and the broker owns the answer.
    """

    request_id: str
    action_type: ActionType
    target: Target
    duration: timedelta
    reason: str
    finding_id: str
    requested_at: datetime
    requesting_component: str
    policy_version: str = ""
    #: An optional narrowing of scope. Absent means "all egress for the
    #: target", which broker policy may refuse as too broad.
    destination_cidr: str | None = None
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not _ID.match(self.request_id):
            raise ContractError(f"malformed request_id {self.request_id!r}")
        if not isinstance(self.action_type, ActionType):
            raise ContractError("action_type must be an ActionType")
        if not isinstance(self.target, Target):
            raise ContractError("target must be a Target")
        if not isinstance(self.duration, timedelta):
            raise ContractError("duration must be a timedelta")
        if self.duration <= timedelta(0):
            raise ContractError("duration must be positive")
        if not self.reason or len(self.reason) > MAX_REASON_CHARS:
            raise ContractError("reason required, and bounded")
        if not _ID.match(self.finding_id):
            raise ContractError("finding_id must reference a real finding")
        if self.requested_at.tzinfo is None:
            raise ContractError("requested_at must be timezone-aware")
        if not _NAME.match(self.requesting_component):
            raise ContractError("requesting_component must be a simple name")
        if self.destination_cidr is not None:
            _validate_cidr(self.destination_cidr)

    @property
    def expires_at(self) -> datetime:
        return self.requested_at + self.duration

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "action_type": self.action_type.value,
            "target": self.target.to_dict(),
            "duration_seconds": int(self.duration.total_seconds()),
            "reason": self.reason,
            "finding_id": self.finding_id,
            "requested_at": self.requested_at.isoformat(),
            "requesting_component": self.requesting_component,
            "policy_version": self.policy_version,
            "destination_cidr": self.destination_cidr,
        }

    @staticmethod
    def from_dict(raw: object) -> "ActionRequest":
        if not isinstance(raw, dict):
            raise ContractError("request must be an object")
        if raw.get("schema_version") != SCHEMA_VERSION:
            raise ContractError(
                f"unsupported request schema {raw.get('schema_version')!r}")
        # An unknown field is refused rather than ignored: a caller that
        # believes it sent something meaningful must not be silently
        # misunderstood by a privileged component.
        unknown = set(raw) - {
            "schema_version", "request_id", "action_type", "target",
            "duration_seconds", "reason", "finding_id", "requested_at",
            "requesting_component", "policy_version", "destination_cidr"}
        if unknown:
            raise ContractError(f"unknown request field(s): {sorted(unknown)}")
        try:
            action_type = ActionType(raw.get("action_type"))
        except ValueError as exc:
            raise ContractError(
                f"unknown action_type {raw.get('action_type')!r}") from exc
        seconds = raw.get("duration_seconds")
        if not isinstance(seconds, int) or isinstance(seconds, bool):
            raise ContractError("duration_seconds must be an integer")
        if not 0 < seconds <= 86_400:
            raise ContractError("duration_seconds out of representable range")
        try:
            requested_at = datetime.fromisoformat(str(raw.get("requested_at")))
        except ValueError as exc:
            raise ContractError("malformed requested_at") from exc
        return ActionRequest(
            request_id=str(raw.get("request_id", "")), action_type=action_type,
            target=Target.from_dict(raw.get("target")),
            duration=timedelta(seconds=seconds), reason=str(raw.get("reason", "")),
            finding_id=str(raw.get("finding_id", "")), requested_at=requested_at,
            requesting_component=str(raw.get("requesting_component", "")),
            policy_version=str(raw.get("policy_version", "")),
            destination_cidr=(str(raw["destination_cidr"])
                              if raw.get("destination_cidr") else None))


class Decision(enum.Enum):
    ALLOW = "allow"
    DENY = "deny"


class DenyReason(enum.Enum):
    """Why a request was refused. Every value is a check the broker performs
    independently of anything the caller asserted."""

    UNKNOWN_ACTION_TYPE = "unknown_action_type"
    UNKNOWN_TARGET_KIND = "unknown_target_kind"
    CALLER_NOT_AUTHORIZED = "caller_not_authorized"
    TARGET_PROTECTED = "target_protected"
    TARGET_NOT_CURRENT = "target_not_current"
    TARGET_NOT_PERMITTED = "target_not_permitted"
    DURATION_EXCEEDS_POLICY = "duration_exceeds_policy"
    TOO_MANY_ACTIVE_ACTIONS = "too_many_active_actions"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    REPLAYED_REQUEST = "replayed_request"
    REQUEST_EXPIRED = "request_expired"
    REQUEST_FROM_THE_FUTURE = "request_from_the_future"
    MALFORMED_REQUEST = "malformed_request"
    SCOPE_TOO_BROAD = "scope_too_broad"
    DESTINATION_PROTECTED = "destination_protected"
    POLICY_UNAVAILABLE = "policy_unavailable"


@dataclass(frozen=True)
class AuthorizationDecision:
    """The broker's answer. Constructed only on the broker side.

    ``allow`` is a classmethod rather than a constructor argument so that an
    ALLOW cannot be produced by deserialising attacker-supplied data: there
    is no ``from_dict`` that yields one.
    """

    request_id: str
    decision: Decision
    reasons: tuple[DenyReason, ...]
    policy_version: str
    decided_at: datetime
    detail: str = ""
    granted_duration: timedelta | None = None

    def __post_init__(self) -> None:
        if self.decision is Decision.DENY and not self.reasons:
            raise ContractError("a denial must state at least one reason")
        if self.decision is Decision.ALLOW and self.reasons:
            raise ContractError("an allow cannot carry denial reasons")
        if self.decision is Decision.ALLOW and self.granted_duration is None:
            raise ContractError("an allow must state the duration granted")

    @classmethod
    def allow(cls, request: ActionRequest, policy_version: str,
              decided_at: datetime, granted: timedelta,
              detail: str = "") -> "AuthorizationDecision":
        return cls(request.request_id, Decision.ALLOW, (), policy_version,
                   decided_at, detail, granted)

    @classmethod
    def deny(cls, request_id: str, reasons: tuple[DenyReason, ...],
             policy_version: str, decided_at: datetime,
             detail: str = "") -> "AuthorizationDecision":
        return cls(request_id, Decision.DENY, tuple(reasons), policy_version,
                   decided_at, detail, None)

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW

    def to_dict(self) -> dict:
        return {"request_id": self.request_id, "decision": self.decision.value,
                "reasons": [r.value for r in self.reasons],
                "policy_version": self.policy_version,
                "decided_at": self.decided_at.isoformat(), "detail": self.detail,
                "granted_duration_seconds": (
                    int(self.granted_duration.total_seconds())
                    if self.granted_duration else None)}


class ActionState(enum.Enum):
    """Lifecycle of an action the broker accepted.

    ``APPLIED`` and ``EFFECT_VERIFIED`` are separate states on purpose. The
    broker saying a rule was installed is one piece of evidence; an
    independent measurement that traffic actually stopped is another, and the
    second is the one that matters.
    """

    REQUESTED = "requested"
    DENIED = "denied"
    AUTHORIZED = "authorized"
    APPLYING = "applying"
    APPLIED = "applied"
    EFFECT_VERIFIED = "effect_verified"
    EFFECT_NOT_VERIFIED = "effect_not_verified"
    EXPIRING = "expiring"
    RELEASED = "released"
    ROLLBACK_REQUIRED = "rollback_required"
    FAILED = "failed"

    @property
    def is_terminal(self) -> bool:
        return self in (ActionState.DENIED, ActionState.RELEASED,
                        ActionState.FAILED)

    @property
    def holds_os_state(self) -> bool:
        """Whether an OS resource may currently exist for this action.

        Drives reconciliation: any state here means the broker must look for
        an owned rule on startup.
        """
        return self in (ActionState.APPLYING, ActionState.APPLIED,
                        ActionState.EFFECT_VERIFIED,
                        ActionState.EFFECT_NOT_VERIFIED,
                        ActionState.EXPIRING, ActionState.ROLLBACK_REQUIRED)


def _validate_cidr(value: str) -> None:
    import ipaddress
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ContractError(f"malformed destination_cidr {value!r}") from exc
