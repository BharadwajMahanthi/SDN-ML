"""An in-memory adapter that behaves like a switch fabric, with no OVS.

This is not a mock in the "assert it was called" sense. It maintains real
switch and port state, refuses to send to a port that is down or to a switch
that has gone away, and tracks connection generations -- so a test can
reproduce reconnect races, undeliverable probes and port flaps deterministically.

Its second job is to be the yardstick: the real OS-Ken adapter must satisfy
the same contract, and the conformance suite runs against both.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sdnguard.adapter.contract import (
    LinkObserved,
    PortChanged,
    PortStatus,
    SecurityCore,
    SendOutcome,
    SendResult,
    SwitchConnected,
    SwitchDisconnected,
)
from sdnguard.domain.events import ProbeRequest
from sdnguard.domain.host import HostIdentity, HostObservation
from sdnguard.domain.identity import DatapathId, PortIdentity

__all__ = ["FakeSwitch", "FakeAdapter", "SentProbe"]


@dataclass
class FakeSwitch:
    dpid: DatapathId
    ports: dict[PortIdentity, bool] = field(default_factory=dict)  # port -> is_up
    connected: bool = True
    generation: int = 1


@dataclass(frozen=True)
class SentProbe:
    probe: ProbeRequest
    at: datetime


class FakeAdapter:
    """Implements both halves of the contract."""

    def __init__(self, *, now: datetime | None = None) -> None:
        self._now = now or datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc)
        self._switches: dict[DatapathId, FakeSwitch] = {}
        self._core: SecurityCore | None = None
        self.sent: list[SentProbe] = []

    # -- test controls ---------------------------------------------------

    @property
    def now(self) -> datetime:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += timedelta(seconds=seconds)

    def attach(self, core: SecurityCore) -> None:
        self._core = core

    def commands(self) -> "FakeAdapter":
        return self

    def _emit(self, method: str, *args) -> None:
        if self._core is not None:
            getattr(self._core, method)(*args)

    # -- fabric simulation -----------------------------------------------

    def connect_switch(self, dpid: DatapathId, port_numbers: list[int]) -> int:
        existing = self._switches.get(dpid)
        generation = existing.generation + 1 if existing else 1
        ports = {PortIdentity.of(dpid.value, n): True for n in port_numbers}
        self._switches[dpid] = FakeSwitch(dpid, ports, True, generation)
        self._emit("on_switch_connected",
                   SwitchConnected(dpid, tuple(sorted(ports)), self._now, generation))
        return generation

    def disconnect_switch(self, dpid: DatapathId) -> None:
        switch = self._switches.get(dpid)
        if switch is None:
            return
        switch.connected = False
        self._emit("on_switch_disconnected",
                   SwitchDisconnected(dpid, self._now, switch.generation))

    def set_port(self, port: PortIdentity, up: bool) -> None:
        switch = self._switches.get(port.datapath_id)
        if switch is None or port not in switch.ports:
            return
        switch.ports[port] = up
        self._emit("on_port_changed",
                   PortChanged(port, PortStatus.UP if up else PortStatus.DOWN,
                               self._now, switch.generation))

    def add_port(self, port: PortIdentity) -> None:
        """A port that appears after the handshake -- the case legacy missed."""
        switch = self._switches.get(port.datapath_id)
        if switch is None:
            return
        switch.ports[port] = True
        self._emit("on_port_changed",
                   PortChanged(port, PortStatus.ADDED, self._now, switch.generation))

    def host_traffic(self, identity: HostIdentity, port: PortIdentity, *,
                     source: str = "arp", broadcast: bool = False) -> None:
        switch = self._switches.get(port.datapath_id)
        generation = switch.generation if switch else 0
        self._emit("on_host_observation",
                   HostObservation.of(identity, port, self._now, source, broadcast),
                   generation)

    def lldp(self, receiving_port: PortIdentity,
             claimed_source: PortIdentity | None = None) -> None:
        switch = self._switches.get(receiving_port.datapath_id)
        generation = switch.generation if switch else 0
        self._emit("on_link_observed",
                   LinkObserved(receiving_port, claimed_source, self._now, generation))

    # -- SwitchCommands --------------------------------------------------

    def send_probe(self, probe: ProbeRequest, *, generation: int) -> SendResult:
        port = probe.target_port
        switch = self._switches.get(port.datapath_id)
        if switch is None or not switch.connected:
            return SendResult.failed(SendOutcome.NO_SUCH_SWITCH, str(port.datapath_id))
        if switch.generation != generation:
            return SendResult.failed(
                SendOutcome.STALE_GENERATION,
                f"probe issued under generation {generation}, switch is at "
                f"{switch.generation}")
        if port not in switch.ports:
            return SendResult.failed(SendOutcome.NO_SUCH_PORT, str(port))
        if not switch.ports[port]:
            return SendResult.failed(SendOutcome.PORT_DOWN, str(port))
        self.sent.append(SentProbe(probe, self._now))
        return SendResult.ok(f"probe {probe.correlation_id[:8]} out {port}")

    def ports_of(self, dpid: DatapathId) -> tuple[PortIdentity, ...]:
        switch = self._switches.get(dpid)
        return tuple(sorted(switch.ports)) if switch else ()

    def is_connected(self, dpid: DatapathId) -> bool:
        switch = self._switches.get(dpid)
        return bool(switch and switch.connected)

    def generation_of(self, dpid: DatapathId) -> int:
        switch = self._switches.get(dpid)
        return switch.generation if switch else 0
