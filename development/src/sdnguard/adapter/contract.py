"""The adapter contract: the only seam between a framework and the core.

Everything above this line is framework-specific and replaceable. Everything
below it is plain Python values (ADR-005). The contract is expressed as
Protocols so that a fake, a replay harness and a real OS-Ken adapter are
interchangeable without inheritance.

Two directions:

* **Inbound** -- the adapter calls :class:`SecurityCore` with normalised
  events. It never hands over a framework object.
* **Outbound** -- the core calls :class:`SwitchCommands` to send a probe or
  install a flow. It never constructs a framework message.

The outbound side returns a typed result rather than raising, because "the
switch went away" is an ordinary condition in this system, not an exception.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

from sdnguard.domain.events import ProbeRequest
from sdnguard.domain.host import HostObservation
from sdnguard.domain.identity import DatapathId, PortIdentity, _ValueObject

__all__ = [
    "PortStatus",
    "SwitchConnected",
    "SwitchDisconnected",
    "PortChanged",
    "LinkObserved",
    "SendOutcome",
    "SendResult",
    "SwitchCommands",
    "SecurityCore",
    "OpenFlowAdapter",
]


class PortStatus(enum.Enum):
    UP = "up"
    DOWN = "down"
    ADDED = "added"
    REMOVED = "removed"


@dataclass(frozen=True)
class SwitchConnected(_ValueObject):
    __slots__ = ("dpid", "ports", "at", "generation")
    dpid: DatapathId
    ports: tuple[PortIdentity, ...]
    at: datetime
    generation: int


@dataclass(frozen=True)
class SwitchDisconnected(_ValueObject):
    __slots__ = ("dpid", "at", "generation")
    dpid: DatapathId
    at: datetime
    generation: int


@dataclass(frozen=True)
class PortChanged(_ValueObject):
    __slots__ = ("port", "status", "at", "generation")
    port: PortIdentity
    status: PortStatus
    at: datetime
    generation: int


@dataclass(frozen=True)
class LinkObserved(_ValueObject):
    """An LLDP frame seen arriving on ``receiving_port``.

    ``claimed_source`` is what the frame *asserts*, which is precisely what a
    fabricated link lies about. Keeping the two separate is what lets the
    detector compare a claim against an observation.
    """

    __slots__ = ("receiving_port", "claimed_source", "at", "generation")
    receiving_port: PortIdentity
    claimed_source: PortIdentity | None
    at: datetime
    generation: int


class SendOutcome(enum.Enum):
    SENT = "sent"
    NO_SUCH_SWITCH = "no_such_switch"
    NO_SUCH_PORT = "no_such_port"
    PORT_DOWN = "port_down"
    STALE_GENERATION = "stale_generation"
    TRANSPORT_ERROR = "transport_error"


@dataclass(frozen=True)
class SendResult(_ValueObject):
    """Typed result. 'The switch went away' is ordinary here, not exceptional."""

    __slots__ = ("outcome", "detail")
    outcome: SendOutcome
    detail: str

    @classmethod
    def ok(cls, detail: str = "") -> "SendResult":
        return cls(SendOutcome.SENT, detail)

    @classmethod
    def failed(cls, outcome: SendOutcome, detail: str = "") -> "SendResult":
        if outcome is SendOutcome.SENT:
            raise ValueError("failed() requires a failure outcome")
        return cls(outcome, detail)

    @property
    def sent(self) -> bool:
        return self.outcome is SendOutcome.SENT


@runtime_checkable
class SwitchCommands(Protocol):
    """Outbound: what the core may ask the network to do."""

    def send_probe(self, probe: ProbeRequest, *, generation: int) -> SendResult:
        """Emit a liveness probe out ``probe.target_port`` only."""
        ...

    def ports_of(self, dpid: DatapathId) -> tuple[PortIdentity, ...]:
        ...

    def is_connected(self, dpid: DatapathId) -> bool:
        ...


@runtime_checkable
class SecurityCore(Protocol):
    """Inbound: what the adapter tells the core. Normalised values only."""

    def on_switch_connected(self, event: SwitchConnected) -> None: ...
    def on_switch_disconnected(self, event: SwitchDisconnected) -> None: ...
    def on_port_changed(self, event: PortChanged) -> None: ...
    def on_host_observation(self, observation: HostObservation,
                            generation: int) -> None: ...
    def on_link_observed(self, event: LinkObserved) -> None: ...


@runtime_checkable
class OpenFlowAdapter(Protocol):
    """A source of events and a sink for commands."""

    def attach(self, core: SecurityCore) -> None: ...
    def commands(self) -> SwitchCommands: ...
