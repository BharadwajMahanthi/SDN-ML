"""What a network observation is, defined before anything produces one.

Two properties this module exists to make structural.

**An observation says only what was actually seen.** There is no
``NETWORK_CONNECTION`` event meaning "something networky happened". A
``connect()`` that returned ``EINPROGRESS`` is a *pending* attempt, not an
established connection, and the two have separate operations. That
distinction is not pedantry: measurement showed every one of 500 successful
Python connections returned ``EINPROGRESS``, because ``settimeout()`` puts
the socket in non-blocking mode (ADR-053). A contract that could not express
the difference would have reported all 500 as failures.

**A wrong attribution is worse than no observation.** So process identity is
never a bare PID. It carries host, boot and process-instance identity, and
where the sensor could not establish those, the observation says so through
:class:`AttributionConfidence` rather than presenting a guess as a fact.

Everything is strictly typed on the way in. KF-36 was four ALLOW-producing
defects that all came from ``str()`` and ``int()`` being helpful with the
wrong type; that lesson applies to every decoder in this system, not only the
privileged one.
"""

from __future__ import annotations

import enum
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from annulon.identity import EntityRef

__all__ = [
    "SCHEMA_VERSION", "NetworkOperation", "Transport", "AddressFamily",
    "Direction", "ConnectionOutcome", "AttributionConfidence", "ProcessRef",
    "Endpoint", "NetworkObservation", "NetworkContractError",
    "SocketSemantic", "MAX_COMM_CHARS", "outcome_for_errno",
]

SCHEMA_VERSION = 1
MAX_COMM_CHARS = 64
#: ``\Z`` rather than ``$``. In Python ``$`` also matches immediately before
#: a trailing newline, so ``^...$`` accepted "worker\n" -- a control
#: character reaching logs and identity fields through a validator that
#: looked correct. Same family as KF-01, where ``\b`` failed after an
#: underscore. ``fullmatch`` semantics are made explicit here instead.
_COMM = re.compile(r"\A[\x20-\x7e]{1,64}\Z")
_ID = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class NetworkContractError(ValueError):
    """An observation that cannot be represented honestly."""


class NetworkOperation(enum.Enum):
    """Exactly what the kernel told us, and nothing broader.

    Only operations the selected sensor can truthfully distinguish appear
    here. ``SEND`` and ``ACCEPT`` are deliberately absent until a mechanism
    is measured that reports them, because declaring an operation the sensor
    cannot produce invites a detector that silently never fires.
    """

    #: `connect()` was called. The destination is what the application asked
    #: for; whether it was reached is a separate observation.
    CONNECT_ATTEMPT = "connect_attempt"
    #: `connect()` returned. Carries the errno, which for a non-blocking
    #: socket is usually EINPROGRESS and means *pending*, not *failed*.
    CONNECT_RESULT = "connect_result"
    #: The socket actually reached ESTABLISHED. This is the only operation
    #: that means a connection happened.
    CONNECTION_ESTABLISHED = "connection_established"
    #: The socket left ESTABLISHED.
    CONNECTION_CLOSED = "connection_closed"


class Transport(enum.Enum):
    TCP = "tcp"
    UDP = "udp"
    OTHER = "other"


class AddressFamily(enum.Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"

    @property
    def version(self) -> int:
        return 4 if self is AddressFamily.IPV4 else 6


class Direction(enum.Enum):
    OUTBOUND = "outbound"
    INBOUND = "inbound"


class SocketSemantic(enum.Enum):
    """Which process, of several that may touch one socket, this is about.

    "Owner" is never used unqualified. A socket can be created by one
    process, connected by another after a fork, and written to by a third;
    conflating them produces an attribution that is defensible in isolation
    and wrong in the case that matters.
    """

    #: The process that called `connect()`. This is what the selected sensor
    #: reports, because the syscall tracepoint runs in that process.
    CONNECT_INITIATOR = "connect_initiator"
    #: The process that called `socket()`. Not currently observed.
    SOCKET_CREATOR = "socket_creator"
    #: Whatever process was current when the kernel changed socket state.
    #: Unreliable: that transition can run in softirq while an unrelated
    #: task is scheduled.
    CURRENT_TASK = "current_task"


class ConnectionOutcome(enum.Enum):
    """The result of a connect attempt, kept separate from success.

    ``PENDING`` exists because it is the common case for any socket with a
    timeout, and because calling it either success or failure would be a lie
    in one direction or the other.
    """

    ESTABLISHED = "established"
    PENDING = "pending"            # EINPROGRESS / EALREADY
    REFUSED = "refused"            # ECONNREFUSED
    UNREACHABLE = "unreachable"    # EHOSTUNREACH / ENETUNREACH
    TIMED_OUT = "timed_out"        # ETIMEDOUT
    PERMISSION_DENIED = "permission_denied"
    OTHER_ERROR = "other_error"
    #: The sensor saw the attempt but never saw a result. Not an error: an
    #: absence, recorded as one.
    UNKNOWN = "unknown"

    @property
    def is_established(self) -> bool:
        return self is ConnectionOutcome.ESTABLISHED


#: errno -> outcome. Anything unlisted becomes OTHER_ERROR rather than being
#: guessed at.
_ERRNO_OUTCOME = {
    0: ConnectionOutcome.ESTABLISHED,
    -115: ConnectionOutcome.PENDING,          # EINPROGRESS
    -114: ConnectionOutcome.PENDING,          # EALREADY
    -111: ConnectionOutcome.REFUSED,          # ECONNREFUSED
    -113: ConnectionOutcome.UNREACHABLE,      # EHOSTUNREACH
    -101: ConnectionOutcome.UNREACHABLE,      # ENETUNREACH
    -110: ConnectionOutcome.TIMED_OUT,        # ETIMEDOUT
    -13: ConnectionOutcome.PERMISSION_DENIED,
    -1: ConnectionOutcome.PERMISSION_DENIED,  # EPERM
}


def outcome_for_errno(value: int) -> ConnectionOutcome:
    """Map a connect return value to an outcome.

    Note what this deliberately does not do: it does not treat "not zero" as
    failure. ``EINPROGRESS`` is the usual return for a successful
    non-blocking connect, and mapping it to a failure would have misreported
    every measured connection in the sensor evaluation.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        raise NetworkContractError("a connect result must be an integer errno")
    return _ERRNO_OUTCOME.get(value, ConnectionOutcome.OTHER_ERROR)


class AttributionConfidence(enum.Enum):
    """How firmly this observation is bound to a process instance.

    The whole point of the enum is that ``PID_ONLY`` is visible. A consumer
    that treats a PID-only attribution as equivalent to an instance-bound one
    is making a mistake the data warned it about.
    """

    #: Host, boot and process-instance identity were all established, with a
    #: start time captured at or near the moment of the event.
    INSTANCE_BOUND = "instance_bound"
    #: The PID was resolved against a process table, but the process had
    #: already exited or the table was incomplete, so the binding rests on
    #: correlation rather than capture.
    CORRELATED = "correlated"
    #: Only a PID is known. It may have been reused. Never sufficient on its
    #: own for a finding about a specific workload.
    PID_ONLY = "pid_only"
    #: No process could be associated at all.
    NONE = "none"

    @property
    def sufficient_for_workload_attribution(self) -> bool:
        return self in (AttributionConfidence.INSTANCE_BOUND,
                        AttributionConfidence.CORRELATED)


@dataclass(frozen=True)
class ProcessRef:
    """Who did it, as firmly as the sensor could establish.

    ``pid`` alone is never the answer. ``pid_namespace`` is present because
    the sensor observes PIDs in its own namespace: measurement showed a
    workload that was PID 20 inside its container and PID 84658 to the
    sensor, and an attribution that ignores that is confidently wrong.
    """

    pid: int
    #: The thread group id -- the process, as opposed to the thread.
    tgid: int | None = None
    #: Kernel-reported command, truncated by the kernel to 16 bytes. Useful
    #: for humans, never an identity.
    comm: str = ""
    #: Process start time, in whatever unit the sensor could obtain. When
    #: present it is what makes a PID unambiguous across reuse.
    start_boottime_ns: int | None = None
    start_ticks: int | None = None
    #: The namespace the pid is meaningful in, as an inode number.
    pid_namespace: int | None = None
    confidence: AttributionConfidence = AttributionConfidence.PID_ONLY
    #: The Annulon entity this resolves to, once correlated.
    entity: EntityRef | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.pid, int) or isinstance(self.pid, bool):
            raise NetworkContractError("pid must be an integer")
        if self.pid < 0:
            raise NetworkContractError("pid must not be negative")
        if self.tgid is not None:
            if not isinstance(self.tgid, int) or isinstance(self.tgid, bool):
                raise NetworkContractError("tgid must be an integer")
            if self.tgid < 0:
                raise NetworkContractError("tgid must not be negative")
        if not isinstance(self.comm, str):
            raise NetworkContractError("comm must be a string")
        if self.comm and not _COMM.match(self.comm):
            raise NetworkContractError(
                "comm must be printable ASCII, at most 64 characters")
        for name in ("start_boottime_ns", "start_ticks", "pid_namespace"):
            value = getattr(self, name)
            if value is None:
                continue
            if not isinstance(value, int) or isinstance(value, bool):
                raise NetworkContractError(f"{name} must be an integer")
            if value < 0:
                raise NetworkContractError(f"{name} must not be negative")
        if not isinstance(self.confidence, AttributionConfidence):
            raise NetworkContractError(
                "confidence must be an AttributionConfidence")

    @property
    def instance_key(self) -> str | None:
        """A key that survives PID reuse, when one can be formed."""
        if self.start_boottime_ns is not None:
            return f"{self.tgid or self.pid}@{self.start_boottime_ns}"
        if self.start_ticks is not None:
            return f"{self.tgid or self.pid}@{self.start_ticks}"
        return None

    def to_dict(self) -> dict:
        return {"pid": self.pid, "tgid": self.tgid, "comm": self.comm,
                "start_boottime_ns": self.start_boottime_ns,
                "start_ticks": self.start_ticks,
                "pid_namespace": self.pid_namespace,
                "confidence": self.confidence.value,
                "instance_key": self.instance_key}


@dataclass(frozen=True)
class Endpoint:
    """One end of a flow. Addresses are parsed, never trusted as text."""

    address: str
    port: int
    family: AddressFamily

    def __post_init__(self) -> None:
        if not isinstance(self.address, str) or not self.address:
            raise NetworkContractError("address must be a non-empty string")
        if not isinstance(self.port, int) or isinstance(self.port, bool):
            raise NetworkContractError("port must be an integer")
        if not 0 <= self.port <= 65535:
            raise NetworkContractError(f"port {self.port} out of range")
        if not isinstance(self.family, AddressFamily):
            raise NetworkContractError("family must be an AddressFamily")
        try:
            parsed = ipaddress.ip_address(self.address)
        except ValueError as exc:
            raise NetworkContractError(
                f"malformed address {self.address!r}") from exc
        if parsed.version != self.family.version:
            raise NetworkContractError(
                f"address {self.address!r} is IPv{parsed.version} but family "
                f"says IPv{self.family.version}")

    @property
    def is_loopback(self) -> bool:
        return ipaddress.ip_address(self.address).is_loopback

    def __str__(self) -> str:
        if self.family is AddressFamily.IPV6:
            return f"[{self.address}]:{self.port}"
        return f"{self.address}:{self.port}"

    def to_dict(self) -> dict:
        return {"address": self.address, "port": self.port,
                "family": self.family.value}


@dataclass(frozen=True)
class NetworkObservation:
    """One thing the sensor saw, with its own uncertainty attached.

    ``destination_semantic`` is explicit because the answer differs by
    mechanism: a syscall-level observation carries the address the
    application asked for, which is *pre-NAT* and may not be where the packet
    went. Mixing that with a wire-level view would produce a record that
    means different things on different hosts.
    """

    observation_id: str
    operation: NetworkOperation
    transport: Transport
    direction: Direction
    process: ProcessRef
    local: Endpoint | None
    remote: Endpoint | None
    observed_at: datetime
    sensor_id: str
    outcome: ConnectionOutcome = ConnectionOutcome.UNKNOWN
    errno: int | None = None
    socket_semantic: SocketSemantic = SocketSemantic.CONNECT_INITIATOR
    #: Where in the stack this was observed, so pre- and post-NAT views are
    #: never silently merged.
    destination_semantic: str = "application_requested_pre_nat"
    #: Network namespace inode, when the sensor can supply it. Without it an
    #: address pair does not uniquely identify a flow on the host.
    network_namespace: int | None = None
    #: A correlation key for the socket, when one is available.
    socket_key: str = ""
    #: Set for observations produced by Annulon's own liveness probe, so they
    #: can be excluded from security interpretation without being discarded.
    is_self_test: bool = False
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not isinstance(self.observation_id, str):
            raise NetworkContractError("observation_id must be a string")
        if not _ID.match(self.observation_id):
            raise NetworkContractError(
                f"malformed observation_id {self.observation_id!r}")
        for name, expected in (("operation", NetworkOperation),
                               ("transport", Transport),
                               ("direction", Direction),
                               ("outcome", ConnectionOutcome),
                               ("socket_semantic", SocketSemantic)):
            if not isinstance(getattr(self, name), expected):
                raise NetworkContractError(
                    f"{name} must be a {expected.__name__}")
        if not isinstance(self.process, ProcessRef):
            raise NetworkContractError("process must be a ProcessRef")
        for name in ("local", "remote"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, Endpoint):
                raise NetworkContractError(f"{name} must be an Endpoint")
        if self.observed_at.tzinfo is None:
            raise NetworkContractError("observed_at must be timezone-aware")
        if not isinstance(self.sensor_id, str) or not _ID.match(self.sensor_id):
            raise NetworkContractError("sensor_id must be a simple identifier")
        if self.errno is not None and (not isinstance(self.errno, int)
                                       or isinstance(self.errno, bool)):
            raise NetworkContractError("errno must be an integer")
        if self.network_namespace is not None and (
                not isinstance(self.network_namespace, int)
                or isinstance(self.network_namespace, bool)):
            raise NetworkContractError("network_namespace must be an integer")
        if self.local is not None and self.remote is not None:
            if self.local.family is not self.remote.family:
                raise NetworkContractError(
                    "local and remote endpoints disagree about address family")
        if (self.operation is NetworkOperation.CONNECTION_ESTABLISHED
                and not self.outcome.is_established):
            # An established connection whose outcome says otherwise is a
            # record that contradicts itself.
            raise NetworkContractError(
                "a CONNECTION_ESTABLISHED observation must carry an "
                "ESTABLISHED outcome")

    @property
    def flow_key(self) -> str | None:
        """Identity used for deduplication.

        Includes the network namespace, because an address pair does not
        uniquely identify a flow on a host running containers: the same
        tuple can exist in several namespaces simultaneously.

        An unknown namespace renders as ``ns:unknown`` and is **never equal
        to any known namespace**, including zero. The previous form,
        ``self.network_namespace or 0``, collapsed "unknown" and "namespace
        0" into one key — and since the tracefs tier never populates the
        field, every observation in production landed in that bucket. A
        namespace component that is documented as the reason a tuple is
        insufficient, and then silently inert, is worse than none: it
        invites a consumer to trust an identity that was never qualified.
        Ask :attr:`flow_key_is_namespace_qualified` before relying on it.
        """
        if self.local is None or self.remote is None:
            return None
        namespace = ("ns:unknown" if self.network_namespace is None
                     else f"ns:{self.network_namespace}")
        return (f"{namespace}/{self.transport.value}/"
                f"{self.local}/{self.remote}")

    @property
    def flow_key_is_namespace_qualified(self) -> bool:
        """Whether :attr:`flow_key` identifies a flow host-wide.

        False under the tracefs tier, which observes socket state transitions
        for every namespace on the host but is given no field naming the one
        an event came from. Stamping the sensor's own namespace would be
        fabrication: the sensor is not necessarily in the namespace it is
        observing.

        When this is false, two observations sharing a `flow_key` *may* be
        different flows in different namespaces. Equality is a hint, not
        proof of identity, and a consumer that deduplicates on it is
        discarding evidence it cannot prove is redundant.
        """
        return self.network_namespace is not None

    @property
    def supports_workload_attribution(self) -> bool:
        return self.process.confidence.sufficient_for_workload_attribution

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "observation_id": self.observation_id,
            "operation": self.operation.value,
            "transport": self.transport.value,
            "direction": self.direction.value,
            "process": self.process.to_dict(),
            "local": self.local.to_dict() if self.local else None,
            "remote": self.remote.to_dict() if self.remote else None,
            "observed_at": self.observed_at.isoformat(),
            "sensor_id": self.sensor_id,
            "outcome": self.outcome.value,
            "errno": self.errno,
            "socket_semantic": self.socket_semantic.value,
            "destination_semantic": self.destination_semantic,
            "network_namespace": self.network_namespace,
            "socket_key": self.socket_key,
            "is_self_test": self.is_self_test,
            "flow_key": self.flow_key,
        }
