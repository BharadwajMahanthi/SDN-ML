"""Inter-switch links discovered from LLDP.

A link is an unordered pair of switch ports. Modelling it as unordered
matters: LLDP is observed once per direction, and treating (a,b) and (b,a)
as different links would double-count the topology and make a fabricated
one-directional link look like an ordinary half-discovered real one.

The security question this module answers is narrow: *is a claimed link
consistent with what we have observed about its endpoints?* A link whose
endpoint is a known host port is the link-fabrication signature.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterator

from sdnguard.domain.identity import DatapathId, InvalidIdentity, PortIdentity, _ValueObject
from sdnguard.topology.ports import PortRegistry, PortType

__all__ = ["Link", "LinkRegistry", "LinkRegistryFull"]


class LinkRegistryFull(Exception):
    """Bounded registry refused to grow."""


@dataclass(frozen=True)
class Link(_ValueObject):
    """An unordered pair of switch ports, normalised so that ``a <= b``."""

    __slots__ = ("a", "b", "first_seen", "last_seen")
    a: PortIdentity
    b: PortIdentity
    first_seen: datetime
    last_seen: datetime

    def __post_init__(self) -> None:
        for name in ("a", "b"):
            if not isinstance(getattr(self, name), PortIdentity):
                raise InvalidIdentity(f"{name} must be a PortIdentity")
        if self.a == self.b:
            raise InvalidIdentity("a link cannot connect a port to itself")
        if self.a > self.b:
            raise InvalidIdentity(
                "endpoints must be normalised with a <= b; use Link.between()")
        for name in ("first_seen", "last_seen"):
            if getattr(self, name).tzinfo is None:
                raise InvalidIdentity(f"{name} must be timezone-aware")

    @classmethod
    def between(cls, one: PortIdentity, other: PortIdentity, moment: datetime) -> "Link":
        lo, hi = (one, other) if one <= other else (other, one)
        return cls(lo, hi, moment, moment)

    @property
    def endpoints(self) -> tuple[PortIdentity, PortIdentity]:
        return self.a, self.b

    @property
    def is_self_loop_switch(self) -> bool:
        """Both ends on the same switch. Legitimate in some fabrics, but
        worth surfacing rather than silently accepting."""
        return self.a.datapath_id == self.b.datapath_id

    def touches(self, port: PortIdentity) -> bool:
        return port in (self.a, self.b)

    def touches_switch(self, dpid: DatapathId) -> bool:
        return dpid in (self.a.datapath_id, self.b.datapath_id)

    def refreshed(self, moment: datetime) -> "Link":
        if moment < self.last_seen:
            raise InvalidIdentity("refresh moment precedes last_seen")
        return Link(self.a, self.b, self.first_seen, moment)

    def __str__(self) -> str:
        return f"{self.a} <-> {self.b}"


class LinkRegistry:
    """Bounded set of discovered links."""

    def __init__(self, *, max_links: int = 1024) -> None:
        if max_links < 1:
            raise ValueError("max_links must be positive")
        self._max = max_links
        self._links: dict[tuple[PortIdentity, PortIdentity], Link] = {}

    def observe(self, one: PortIdentity, other: PortIdentity,
                moment: datetime) -> Link:
        link = Link.between(one, other, moment)
        key = link.endpoints
        existing = self._links.get(key)
        if existing is not None:
            link = existing.refreshed(moment)
        elif len(self._links) >= self._max:
            raise LinkRegistryFull(
                f"registry holds {len(self._links)} links (limit {self._max})")
        self._links[key] = link
        return link

    def get(self, one: PortIdentity, other: PortIdentity) -> Link | None:
        lo, hi = (one, other) if one <= other else (other, one)
        return self._links.get((lo, hi))

    def remove_switch(self, dpid: DatapathId) -> int:
        doomed = [k for k, link in self._links.items() if link.touches_switch(dpid)]
        for key in doomed:
            del self._links[key]
        return len(doomed)

    def remove_port(self, port: PortIdentity) -> int:
        doomed = [k for k, link in self._links.items() if link.touches(port)]
        for key in doomed:
            del self._links[key]
        return len(doomed)

    def links_of(self, dpid: DatapathId) -> list[Link]:
        return sorted((l for l in self._links.values() if l.touches_switch(dpid)),
                      key=lambda l: l.endpoints)

    def inconsistent_endpoints(self, ports: PortRegistry) -> list[tuple[Link, PortIdentity]]:
        """Links whose endpoint is a port we have classified as a host port.

        This is the link-fabrication check expressed over topology state
        rather than over a single packet, so it also catches a link that was
        accepted before the endpoint was known to be a host port.
        """
        offenders: list[tuple[Link, PortIdentity]] = []
        for link in sorted(self._links.values(), key=lambda l: l.endpoints):
            for endpoint in link.endpoints:
                if ports.type_of(endpoint) is PortType.HOST:
                    offenders.append((link, endpoint))
        return offenders

    def __len__(self) -> int:
        return len(self._links)

    def __iter__(self) -> Iterator[Link]:
        return iter(sorted(self._links.values(), key=lambda l: l.endpoints))
