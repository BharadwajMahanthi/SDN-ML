"""The host table: one authority for where each host has been seen.

The legacy implementation kept two disconnected host views -- upstream
``DeviceManagerImpl`` and ``PortManager.mac_port`` -- and the second was
populated only from non-broadcast frames, so ARP never reached it. There is
one table here, and a broadcast ARP is an ordinary observation.

Three properties this table must have that the legacy one did not:

* **Bounded.** Hosts, and locations per host, have explicit limits. Refusal
  is explicit; there is no silent eviction, because an attacker who can
  force eviction can flush a victim's record and erase the evidence of their
  own move.
* **Ordered.** Observations arrive out of order. The table never rewrites
  history to accommodate a late packet; it records the sighting and reports
  that it was late.
* **Multi-location aware.** A host seen at two ports at once is the central
  signal, not an inconvenience to be collapsed away.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Final, Iterator

from sdnguard.domain.host import HostIdentity, HostLocation, HostObservation, MacAddress
from sdnguard.domain.identity import InvalidIdentity, PortIdentity, _ValueObject

__all__ = [
    "ObservationEffect",
    "ObservationResult",
    "HostRecord",
    "HostTable",
    "HostTableFull",
    "DEFAULT_MAX_HOSTS",
    "DEFAULT_MAX_LOCATIONS",
]

DEFAULT_MAX_HOSTS: Final = 8192
DEFAULT_MAX_LOCATIONS: Final = 4


class HostTableFull(Exception):
    """A bounded collection refused to grow rather than evicting silently."""


class ObservationEffect(enum.Enum):
    """What an observation did to the table."""

    LEARNED = "learned"              # first sighting of this host
    REFRESHED = "refreshed"          # same port, later time
    MOVED = "moved"                  # different port, now the primary location
    ADDITIONAL_LOCATION = "additional_location"  # seen at a second port concurrently
    LATE = "late"                    # older than what we already hold
    IDENTITY_ENRICHED = "identity_enriched"      # same port, IP learned


@dataclass(frozen=True)
class ObservationResult(_ValueObject):
    """Outcome of applying one observation. Returned rather than raised so a
    caller can decide what a movement *means* without exception control flow."""

    __slots__ = ("effect", "record", "previous_location")
    effect: ObservationEffect
    record: "HostRecord"
    previous_location: HostLocation | None

    @property
    def is_movement(self) -> bool:
        return self.effect in (ObservationEffect.MOVED,
                               ObservationEffect.ADDITIONAL_LOCATION)


@dataclass(frozen=True)
class HostRecord(_ValueObject):
    """Everything the table knows about one host.

    ``locations`` is ordered most-recently-seen first. The head is the
    primary location; anything after it is a concurrent sighting that has not
    yet aged out.
    """

    __slots__ = ("identity", "locations", "first_learned", "observation_count")
    identity: HostIdentity
    locations: tuple[HostLocation, ...]
    first_learned: datetime
    observation_count: int

    def __post_init__(self) -> None:
        if not isinstance(self.identity, HostIdentity):
            raise InvalidIdentity("identity must be a HostIdentity")
        # An empty tuple is permitted only as the transient value produced by
        # without_stale(keep_primary=False); the update path always adds a
        # location before the record is stored.
        if not isinstance(self.locations, tuple):
            raise InvalidIdentity("locations must be a tuple")

    @property
    def mac(self) -> MacAddress:
        return self.identity.mac

    @property
    def primary(self) -> HostLocation:
        return self.locations[0]

    @property
    def port(self) -> PortIdentity:
        return self.primary.port

    @property
    def concurrent_locations(self) -> int:
        return len(self.locations)

    @property
    def is_multi_homed(self) -> bool:
        """Seen at more than one port without the others ageing out. This is
        the signal; the legacy code skipped exactly this case."""
        return len(self.locations) > 1

    def location_at(self, port: PortIdentity) -> HostLocation | None:
        return next((l for l in self.locations if l.port == port), None)

    def without_stale(self, now: datetime, ttl: timedelta, *,
                      keep_primary: bool = True) -> "HostRecord":
        """Drop locations older than ``ttl``.

        ``keep_primary`` distinguishes two genuinely different needs. During
        routine pruning the primary is kept, because forgetting a host
        entirely is the table's decision and not a location's. When a *new*
        location is about to be added, the old primary is droppable: the host
        has demonstrably moved, and retaining a stale sighting would make an
        ordinary relocation look like concurrent multi-homing.
        """
        candidates = self.locations if not keep_primary else self.locations[1:]
        kept = [l for l in candidates if now - l.last_seen <= ttl]
        if keep_primary:
            kept = [self.locations[0]] + kept
        if not kept:
            kept = []
        return replace(self, locations=tuple(kept)) if kept else self._empty()

    def _empty(self) -> "HostRecord":
        """A record with no surviving locations cannot exist; the caller is
        adding one, so hand back a marker the update path completes."""
        return replace(self, locations=())

    def __str__(self) -> str:
        extra = f" (+{len(self.locations) - 1} more)" if self.is_multi_homed else ""
        return f"{self.identity} at {self.primary.port}{extra}"


class HostTable:
    """Bounded, ordered, multi-location-aware host table."""

    def __init__(self, *, max_hosts: int = DEFAULT_MAX_HOSTS,
                 max_locations: int = DEFAULT_MAX_LOCATIONS,
                 location_ttl: timedelta = timedelta(minutes=5)) -> None:
        if max_hosts < 1 or max_locations < 1:
            raise ValueError("limits must be positive")
        if location_ttl <= timedelta(0):
            raise ValueError("location_ttl must be positive")
        self._max_hosts = max_hosts
        self._max_locations = max_locations
        self._ttl = location_ttl
        self._records: dict[MacAddress, HostRecord] = {}

    # -- observation -----------------------------------------------------

    def observe(self, observation: HostObservation) -> ObservationResult:
        if not isinstance(observation, HostObservation):
            raise InvalidIdentity("observe() takes a HostObservation")
        existing = self._records.get(observation.mac)
        if existing is None:
            return self._learn(observation)
        return self._update(existing, observation)

    def _learn(self, observation: HostObservation) -> ObservationResult:
        if len(self._records) >= self._max_hosts:
            raise HostTableFull(
                f"table holds {len(self._records)} hosts (limit {self._max_hosts}); "
                "refusing rather than evicting, so an attacker cannot flush a "
                "victim's record")
        record = HostRecord(observation.identity, (observation.to_location(),),
                            observation.observed_at, 1)
        self._store(observation.mac, record)
        return ObservationResult(ObservationEffect.LEARNED, record, None)

    def _update(self, existing: HostRecord,
                observation: HostObservation) -> ObservationResult:
        moment = observation.observed_at
        known = existing.location_at(observation.port)

        # A late observation never rewrites history. It is reported so the
        # caller can decide; silently reordering would let a delayed replay
        # look like a fresh sighting.
        newest = max(l.last_seen for l in existing.locations)
        if moment < newest and (known is None or moment < known.last_seen):
            return ObservationResult(ObservationEffect.LATE, existing,
                                     existing.primary)

        identity = existing.identity
        enriched = False
        if observation.ip is not None and identity.ip != observation.ip:
            identity = identity.with_ip(observation.ip)
            enriched = True

        if known is not None:
            refreshed = known.refreshed(moment)
            others = [l for l in existing.locations if l.port != observation.port]
            ordered = self._order((refreshed, *others))
            record = replace(existing, identity=identity, locations=ordered,
                             observation_count=existing.observation_count + 1)
            self._store(observation.mac, record)
            effect = (ObservationEffect.IDENTITY_ENRICHED if enriched
                      else ObservationEffect.REFRESHED)
            if record.port != existing.port:
                effect = ObservationEffect.MOVED
            return ObservationResult(effect, record, existing.primary)

        # A port we have not seen this host on before.
        pruned = existing.without_stale(moment, self._ttl, keep_primary=False)
        new_location = HostLocation.at(observation.port, moment)
        combined = self._order((new_location, *pruned.locations))
        if len(combined) > self._max_locations:
            combined = combined[: self._max_locations]
        record = replace(pruned, identity=identity, locations=combined,
                         observation_count=existing.observation_count + 1)
        self._store(observation.mac, record)
        effect = (ObservationEffect.ADDITIONAL_LOCATION
                  if len(combined) > 1 else ObservationEffect.MOVED)
        return ObservationResult(effect, record, existing.primary)

    def _store(self, mac: MacAddress, record: HostRecord) -> HostRecord:
        """The one place records enter the table, so the non-empty-location
        invariant is enforced even though HostRecord itself tolerates the
        transient empty value produced by without_stale(keep_primary=False)."""
        if not record.locations:
            raise InvalidIdentity(
                "refusing to store a host record with no location")
        self._records[mac] = record
        return record

    @staticmethod
    def _order(locations: tuple[HostLocation, ...]) -> tuple[HostLocation, ...]:
        """Most recently seen first; ties broken by port for determinism."""
        return tuple(sorted(locations, key=lambda l: (-l.last_seen.timestamp(), l.port)))

    # -- queries ---------------------------------------------------------

    def get(self, mac: MacAddress) -> HostRecord | None:
        return self._records.get(mac)

    def location_of(self, mac: MacAddress) -> PortIdentity | None:
        record = self._records.get(mac)
        return record.port if record else None

    def hosts_on(self, port: PortIdentity) -> list[HostRecord]:
        return sorted((r for r in self._records.values()
                       if r.location_at(port) is not None),
                      key=lambda r: r.mac)

    def multi_homed(self) -> list[HostRecord]:
        return sorted((r for r in self._records.values() if r.is_multi_homed),
                      key=lambda r: r.mac)

    # -- maintenance -----------------------------------------------------

    def expire(self, now: datetime, ttl: timedelta | None = None) -> int:
        """Drop hosts whose primary location has not been seen within ``ttl``."""
        horizon = ttl or self._ttl
        doomed = [mac for mac, r in self._records.items()
                  if now - r.primary.last_seen > horizon]
        for mac in doomed:
            del self._records[mac]
        return len(doomed)

    def prune_locations(self, now: datetime) -> int:
        """Drop stale secondary locations without forgetting hosts."""
        dropped = 0
        for mac, record in list(self._records.items()):
            pruned = record.without_stale(now, self._ttl)
            dropped += record.concurrent_locations - pruned.concurrent_locations
            self._records[mac] = pruned
        return dropped

    def forget(self, mac: MacAddress) -> bool:
        return self._records.pop(mac, None) is not None

    def forget_port(self, port: PortIdentity) -> int:
        """Remove a port from every host, forgetting hosts left with none.
        Used when a switch or port goes away."""
        removed = 0
        for mac, record in list(self._records.items()):
            kept = tuple(l for l in record.locations if l.port != port)
            if len(kept) == record.concurrent_locations:
                continue
            removed += 1
            if kept:
                self._records[mac] = replace(record, locations=kept)
            else:
                del self._records[mac]
        return removed

    # -- introspection ---------------------------------------------------

    def __len__(self) -> int:
        return len(self._records)

    def __contains__(self, mac: object) -> bool:
        return mac in self._records

    def __iter__(self) -> Iterator[HostRecord]:
        return iter(sorted(self._records.values(), key=lambda r: r.mac))

    @property
    def capacity(self) -> tuple[int, int]:
        return self._max_hosts, self._max_locations
