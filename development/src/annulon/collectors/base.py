"""The host sensor interface.

The point of this module is that the sensor decision is reversible. V2-HOST-01
evaluates candidates; whichever wins sits behind this interface, and replacing
it later touches one package.

A sensor is responsible for three things and no more:

1. producing normalised :class:`~annulon.events.Event` values,
2. reporting its own health honestly, including what it missed,
3. never blocking the caller indefinitely.

It is explicitly **not** responsible for deciding anything. A collector that
filtered by "suspiciousness" would be a detector with no evidence trail.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Iterator, Protocol, runtime_checkable

from annulon.events import Event

__all__ = ["SensorCapability", "SensorHealth", "SensorStats", "HostSensor",
           "SensorUnavailable"]


class SensorUnavailable(RuntimeError):
    """The sensor cannot run here: missing privilege, kernel support or tool.

    Raised at start, never mid-stream, so a caller can fall back to another
    candidate before it has begun trusting this one.
    """


class SensorCapability(enum.Enum):
    """What a candidate can actually observe.

    Kept explicit because the evaluation must not compare a sensor that sees
    process arguments against one that sees only PIDs as though they were
    equivalent.
    """

    PROCESS_EXEC = "process_exec"
    PROCESS_EXIT = "process_exit"
    PROCESS_FORK = "process_fork"
    PROCESS_ARGV = "process_argv"
    PROCESS_ANCESTRY = "process_ancestry"
    CREDENTIAL_CHANGE = "credential_change"
    NETWORK_CONNECT = "network_connect"
    FILE_ACCESS = "file_access"


@dataclass
class SensorStats:
    """Counters a sensor must keep. Absence of events is not evidence of
    absence of activity, so a sensor that cannot report loss is reporting a
    number nobody should trust."""

    emitted: int = 0
    dropped: int = 0
    decode_errors: int = 0
    restarts: int = 0
    sequence: int = 0

    def as_dict(self) -> dict[str, int]:
        return {"emitted": self.emitted, "dropped": self.dropped,
                "decode_errors": self.decode_errors, "restarts": self.restarts}


@dataclass
class SensorHealth:
    running: bool = False
    detail: str = ""
    stats: SensorStats = field(default_factory=SensorStats)
    #: False when the sensor cannot attest that it saw everything in scope.
    #: V2-HOST-01 measured a polling sensor missing 500 of 500 short-lived
    #: processes while reporting zero drops -- it had no way to know. A
    #: counter can only report loss the sensor noticed; structural blindness
    #: has to be declared.
    attests_completeness: bool = True
    blind_spot: str = ""

    @property
    def lossy(self) -> bool:
        """Known loss. Necessary but not sufficient: see
        :attr:`attests_completeness` for loss the sensor cannot detect."""
        return self.stats.dropped > 0 or self.stats.decode_errors > 0

    @property
    def trustworthy_absence(self) -> bool:
        """Whether "no event" from this sensor is meaningful at all.

        If this is False, silence says nothing, and a detector must not treat
        it as evidence that nothing happened.
        """
        return self.running and not self.lossy and self.attests_completeness


@runtime_checkable
class HostSensor(Protocol):
    """A source of normalised host events."""

    name: str

    def capabilities(self) -> frozenset[SensorCapability]: ...
    def requires_root(self) -> bool: ...
    def preflight(self) -> tuple[bool, str]:
        """Can this run here? Checked before starting, never assumed."""
        ...
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def health(self) -> SensorHealth: ...
    def events(self, timeout: float = 1.0) -> Iterator[Event]:
        """Yield available events. Must return rather than block forever."""
        ...
