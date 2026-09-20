"""Port classification and per-host port-down evidence.

Recovered from ``PortProperty.java``. Two mechanisms live here, and the
second is the one the legacy code made hard to see:

**Port typing.** A port that has emitted LLDP is a switch-to-switch port; a
port that has emitted host traffic is a host port. LLDP arriving on a *host*
port is the link-fabrication signature.

**Port-down evidence.** ``PortProperty.hosts`` was a ``Map<MAC, Boolean>``
where the boolean meant "a port-down signal was observed for this host". That
is the pre-condition half of the host-migration check: a host that physically
moves causes its old port to go down first, so a host that "moved" while its
old port stayed up is suspicious.

Three defects are fixed by construction:

* ``switchRemoved`` was a no-op, so port state was never reclaimed. Here a
  switch removal drops all of its ports.
* ports appearing after ``switchAdded`` were never tracked. Here a port is
  registered on first observation.
* the maps were unbounded. Here every collection has an explicit limit and
  rejects growth rather than consuming memory silently.

Standard library only (ADR-005).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, replace
from typing import Final, Iterator

from sdnguard.domain.host import MacAddress
from sdnguard.domain.identity import DatapathId, InvalidIdentity, PortIdentity, _ValueObject

__all__ = [
    "PortType",
    "ClassificationConflict",
    "PortRecord",
    "PortRegistry",
    "PortRegistryFull",
    "DEFAULT_MAX_PORTS",
    "DEFAULT_MAX_HOSTS_PER_PORT",
]

DEFAULT_MAX_PORTS: Final = 4096
DEFAULT_MAX_HOSTS_PER_PORT: Final = 64


class PortType(enum.Enum):
    """What kind of device is behind a port, as far as we have observed."""

    UNKNOWN = "unknown"     # nothing observed yet (legacy called this ANY)
    HOST = "host"
    SWITCH = "switch"


class ClassificationConflict(enum.Enum):
    """A classification attempt that contradicts what was already observed.

    Returned rather than raised: these are security *signals*, and the caller
    decides what they mean. Raising would make ordinary traffic exceptional.
    """

    NONE = "none"
    LLDP_ON_HOST_PORT = "lldp_on_host_port"
    HOST_TRAFFIC_ON_SWITCH_PORT = "host_traffic_on_switch_port"


class PortRegistryFull(Exception):
    """A bounded collection refused to grow. State exhaustion is an attack
    surface, so the refusal is explicit rather than a silent eviction."""


@dataclass(frozen=True)
class PortRecord(_ValueObject):
    """Immutable snapshot of one port's security-relevant state.

    ``hosts`` maps a MAC to whether a port-down signal has been observed for
    it at this port -- the legacy ``Map<MAC, Boolean>``, named so its meaning
    is not left to the reader.
    """

    __slots__ = ("port", "port_type", "hosts", "is_up")
    port: PortIdentity
    port_type: PortType
    hosts: frozenset[tuple[MacAddress, bool]]
    is_up: bool

    def __post_init__(self) -> None:
        if not isinstance(self.port, PortIdentity):
            raise InvalidIdentity("port must be a PortIdentity")
        if not isinstance(self.port_type, PortType):
            raise InvalidIdentity("port_type must be a PortType")

    @classmethod
    def new(cls, port: PortIdentity) -> "PortRecord":
        return cls(port, PortType.UNKNOWN, frozenset(), True)

    # -- queries ---------------------------------------------------------

    @property
    def host_macs(self) -> frozenset[MacAddress]:
        return frozenset(mac for mac, _ in self.hosts)

    def knows_host(self, mac: MacAddress) -> bool:
        return mac in self.host_macs

    def port_down_seen_for(self, mac: MacAddress) -> bool:
        """Was a port-down signal observed for this host at this port?

        Returns False for an unknown host: absence of evidence is not
        evidence of a shutdown.
        """
        for known, flag in self.hosts:
            if known == mac:
                return flag
        return False

    # -- transitions (all return a new record) ---------------------------

    def _with_hosts(self, hosts: frozenset[tuple[MacAddress, bool]]) -> "PortRecord":
        return replace(self, hosts=hosts)

    def observe_lldp(self) -> tuple["PortRecord", ClassificationConflict]:
        if self.port_type is PortType.HOST:
            # Link fabrication: a host port cannot legitimately emit LLDP.
            return self, ClassificationConflict.LLDP_ON_HOST_PORT
        return replace(self, port_type=PortType.SWITCH), ClassificationConflict.NONE

    def observe_host(self, mac: MacAddress, *, max_hosts: int) -> tuple[
            "PortRecord", ClassificationConflict]:
        conflict = (ClassificationConflict.HOST_TRAFFIC_ON_SWITCH_PORT
                    if self.port_type is PortType.SWITCH
                    else ClassificationConflict.NONE)
        others = frozenset((m, f) for m, f in self.hosts if m != mac)
        if mac not in self.host_macs and len(others) >= max_hosts:
            raise PortRegistryFull(
                f"{self.port} already tracks {len(others)} hosts (limit {max_hosts})")
        # Seeing traffic from a host clears any prior port-down evidence: the
        # host is demonstrably present here again.
        record = self._with_hosts(others | {(mac, False)})
        if conflict is ClassificationConflict.NONE:
            record = replace(record, port_type=PortType.HOST)
        return record, conflict

    def observe_port_down(self) -> "PortRecord":
        """Mark every host on this port as having a port-down signal."""
        return replace(self, is_up=False,
                       hosts=frozenset((m, True) for m, _ in self.hosts))

    def observe_port_up(self) -> "PortRecord":
        return replace(self, is_up=True)

    def forget_host(self, mac: MacAddress) -> "PortRecord":
        return self._with_hosts(frozenset((m, f) for m, f in self.hosts if m != mac))

    def __str__(self) -> str:
        state = "up" if self.is_up else "down"
        return f"{self.port} {self.port_type.value} {state} hosts={len(self.hosts)}"


class PortRegistry:
    """Bounded registry of port records, keyed by value-semantic identity."""

    def __init__(self, *, max_ports: int = DEFAULT_MAX_PORTS,
                 max_hosts_per_port: int = DEFAULT_MAX_HOSTS_PER_PORT) -> None:
        if max_ports < 1 or max_hosts_per_port < 1:
            raise ValueError("limits must be positive")
        self._max_ports = max_ports
        self._max_hosts_per_port = max_hosts_per_port
        self._records: dict[PortIdentity, PortRecord] = {}

    # -- lifecycle -------------------------------------------------------

    def register(self, port: PortIdentity) -> PortRecord:
        """Idempotent. Ports discovered after the switch handshake are
        registered on first sight, which the legacy code never did."""
        existing = self._records.get(port)
        if existing is not None:
            return existing
        if len(self._records) >= self._max_ports:
            raise PortRegistryFull(
                f"registry holds {len(self._records)} ports (limit {self._max_ports})")
        record = PortRecord.new(port)
        self._records[port] = record
        return record

    def get(self, port: PortIdentity) -> PortRecord | None:
        return self._records.get(port)

    def remove_switch(self, dpid: DatapathId) -> int:
        """Drop every port of a departed switch. Legacy's switchRemoved was a
        no-op with a TODO, so state accumulated for the process lifetime."""
        doomed = [p for p in self._records if p.datapath_id == dpid]
        for port in doomed:
            del self._records[port]
        return len(doomed)

    def ports_of(self, dpid: DatapathId) -> list[PortIdentity]:
        return sorted(p for p in self._records if p.datapath_id == dpid)

    # -- observations ----------------------------------------------------

    def observe_lldp(self, port: PortIdentity) -> ClassificationConflict:
        record, conflict = self.register(port).observe_lldp()
        self._records[port] = record
        return conflict

    def observe_host(self, port: PortIdentity, mac: MacAddress) -> ClassificationConflict:
        record, conflict = self.register(port).observe_host(
            mac, max_hosts=self._max_hosts_per_port)
        self._records[port] = record
        return conflict

    def observe_port_down(self, port: PortIdentity) -> PortRecord:
        record = self.register(port).observe_port_down()
        self._records[port] = record
        return record

    def observe_port_up(self, port: PortIdentity) -> PortRecord:
        record = self.register(port).observe_port_up()
        self._records[port] = record
        return record

    def port_down_seen_for(self, port: PortIdentity, mac: MacAddress) -> bool:
        record = self._records.get(port)
        return record.port_down_seen_for(mac) if record else False

    def type_of(self, port: PortIdentity) -> PortType:
        record = self._records.get(port)
        return record.port_type if record else PortType.UNKNOWN

    # -- introspection ---------------------------------------------------

    def __len__(self) -> int:
        return len(self._records)

    def __contains__(self, port: object) -> bool:
        return port in self._records

    def __iter__(self) -> Iterator[PortRecord]:
        return iter(sorted(self._records.values(), key=lambda r: r.port))

    @property
    def capacity(self) -> tuple[int, int]:
        return self._max_ports, self._max_hosts_per_port
