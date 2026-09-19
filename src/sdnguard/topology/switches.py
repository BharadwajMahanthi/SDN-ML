"""Switch connection lifecycle.

The legacy controller had no concept of a connection *generation*. A switch
that dropped and reconnected kept all of its old state, and an in-flight
event from the previous connection was indistinguishable from a current one.
That matters for security: a probe issued before a reconnect must not be
resolved by a reply that arrives after it, because the port it was aimed at
may now be a different physical link.

Every connection therefore gets a monotonically increasing generation, and
anything holding switch state records the generation it was created under.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Iterator

from sdnguard.domain.identity import DatapathId, InvalidIdentity, _ValueObject

__all__ = ["SwitchState", "SwitchRecord", "SwitchRegistry", "SwitchRegistryFull"]


class SwitchState(enum.Enum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"


class SwitchRegistryFull(Exception):
    """Bounded registry refused to grow."""


@dataclass(frozen=True)
class SwitchRecord(_ValueObject):
    __slots__ = ("dpid", "state", "generation", "changed_at", "connect_count")
    dpid: DatapathId
    state: SwitchState
    generation: int
    changed_at: datetime
    connect_count: int

    def __post_init__(self) -> None:
        if not isinstance(self.dpid, DatapathId):
            raise InvalidIdentity("dpid must be a DatapathId")
        if not isinstance(self.state, SwitchState):
            raise InvalidIdentity("state must be a SwitchState")
        if self.generation < 1:
            raise InvalidIdentity("generation starts at 1")
        if self.changed_at.tzinfo is None:
            raise InvalidIdentity("changed_at must be timezone-aware")

    @property
    def is_connected(self) -> bool:
        return self.state is SwitchState.CONNECTED

    def __str__(self) -> str:
        return f"{self.dpid} {self.state.value} gen={self.generation}"


class SwitchRegistry:
    """Tracks which switches are connected, and under which generation."""

    def __init__(self, *, max_switches: int = 256) -> None:
        if max_switches < 1:
            raise ValueError("max_switches must be positive")
        self._max = max_switches
        self._records: dict[DatapathId, SwitchRecord] = {}

    def connect(self, dpid: DatapathId, moment: datetime) -> SwitchRecord:
        """Register a connection. A reconnect bumps the generation so that
        state created under the previous connection can be recognised as stale."""
        existing = self._records.get(dpid)
        if existing is None:
            if len(self._records) >= self._max:
                raise SwitchRegistryFull(
                    f"registry holds {len(self._records)} switches (limit {self._max})")
            record = SwitchRecord(dpid, SwitchState.CONNECTED, 1, moment, 1)
        else:
            record = replace(
                existing,
                state=SwitchState.CONNECTED,
                generation=existing.generation + 1,
                changed_at=moment,
                connect_count=existing.connect_count + 1,
            )
        self._records[dpid] = record
        return record

    def disconnect(self, dpid: DatapathId, moment: datetime) -> SwitchRecord | None:
        existing = self._records.get(dpid)
        if existing is None:
            return None
        record = replace(existing, state=SwitchState.DISCONNECTED, changed_at=moment)
        self._records[dpid] = record
        return record

    def forget(self, dpid: DatapathId) -> bool:
        return self._records.pop(dpid, None) is not None

    def get(self, dpid: DatapathId) -> SwitchRecord | None:
        return self._records.get(dpid)

    def generation_of(self, dpid: DatapathId) -> int | None:
        record = self._records.get(dpid)
        return record.generation if record else None

    def is_current(self, dpid: DatapathId, generation: int) -> bool:
        """Is state created under ``generation`` still valid?

        False for an unknown switch, a disconnected switch, or a stale
        generation -- the three cases that must invalidate in-flight work.
        """
        record = self._records.get(dpid)
        return bool(record and record.is_connected and record.generation == generation)

    def connected(self) -> list[DatapathId]:
        return sorted(d for d, r in self._records.items() if r.is_connected)

    def __len__(self) -> int:
        return len(self._records)

    def __contains__(self, dpid: object) -> bool:
        return dpid in self._records

    def __iter__(self) -> Iterator[SwitchRecord]:
        return iter(sorted(self._records.values(), key=lambda r: r.dpid))
