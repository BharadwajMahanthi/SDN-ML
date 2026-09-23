"""Resolve a pid into a workload identity, and say how well it went.

The tracefs tier reports a pid. Policy is written about workloads. Bridging
those means reading `/proc/<pid>`, which races the process: a short-lived
connection is often made by something that has already exited, and by the
time anything looks, the number may belong to a different process entirely.

That race is the whole reason this is a separate, explicit step rather than
a field the normaliser fills in. Three outcomes, and the difference between
them is the difference between an accusation and a guess:

* the process is still there and its start time matches what was recorded at
  event time -> ``CORRELATED``, safe to name a workload;
* the process is gone -> stays ``PID_ONLY``, no entity, and the detector
  will decline to accuse anyone;
* the process is there but its start time disagrees with the event ->
  ``PID_ONLY`` as well, because the pid has been reused and reading that
  process's uid would attribute one workload's connection to another.

The third case is the one worth the code. It is also the one that cannot be
tested by watching it work, so it is driven directly in tests.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path

from annulon.identity import EntityKind, EntityRef
from annulon.network.contract import (
    AttributionConfidence, NetworkObservation, ProcessRef,
)

__all__ = ["WorkloadResolver", "ResolutionStats", "ProcessFacts"]


@dataclass(frozen=True)
class ProcessFacts:
    """What `/proc` said about a pid at the moment it was read."""

    pid: int
    uid: int
    start_ticks: int


@dataclass
class ResolutionStats:
    resolved: int = 0
    process_gone: int = 0
    start_time_mismatch: int = 0
    unreadable: int = 0
    not_attempted: int = 0

    def to_dict(self) -> dict:
        return {"resolved": self.resolved, "process_gone": self.process_gone,
                "start_time_mismatch": self.start_time_mismatch,
                "unreadable": self.unreadable,
                "not_attempted": self.not_attempted}


class WorkloadResolver:
    """Best-effort pid -> workload, with the failure modes counted.

    Deliberately conservative: every path that cannot *prove* the pid still
    belongs to the process that made the connection leaves the observation
    exactly as it arrived. Nothing here upgrades confidence on a hope.
    """

    def __init__(self, *, host_id: str, boot_id: str,
                 proc_root: str | Path = "/proc") -> None:
        self._host_id = host_id
        self._boot_id = boot_id
        self._proc = Path(proc_root)
        self.stats = ResolutionStats()

    def read_facts(self, pid: int) -> ProcessFacts | None:
        """Read uid and start time for a pid, or ``None`` if it is gone."""
        if pid <= 0:
            return None
        directory = self._proc / str(pid)
        try:
            stat = (directory / "stat").read_text()
            status = (directory / "status").read_text()
        except (OSError, ValueError):
            return None
        try:
            # Field 22 is start time in clock ticks. Split after the last
            # ')' because a process name may itself contain parentheses.
            start_ticks = int(stat.rsplit(")", 1)[1].split()[19])
        except (IndexError, ValueError):
            return None
        uid = None
        for line in status.splitlines():
            if line.startswith("Uid:"):
                try:
                    uid = int(line.split()[1])       # the real uid
                except (IndexError, ValueError):
                    return None
                break
        if uid is None:
            return None
        return ProcessFacts(pid=pid, uid=uid, start_ticks=start_ticks)

    def resolve(self, observation: NetworkObservation,
                *, expected_start_ticks: int | None = None) -> NetworkObservation:
        """Return the observation with a workload identity, if one is provable.

        ``expected_start_ticks`` is what was known about the process at event
        time. When it is supplied and disagrees with what `/proc` now says,
        the pid has been reused and the observation is returned untouched —
        naming the current occupant's workload would attribute one
        workload's connection to another.
        """
        if not isinstance(observation, NetworkObservation):
            return observation
        process = observation.process
        if process.confidence is AttributionConfidence.NONE or process.pid <= 0:
            # Interrupt context already discarded the pid; there is nothing
            # here to resolve and inventing one would undo that decision.
            self.stats.not_attempted += 1
            return observation

        facts = self.read_facts(process.pid)
        if facts is None:
            self.stats.process_gone += 1
            return observation

        recorded = (expected_start_ticks if expected_start_ticks is not None
                    else process.start_ticks)
        if recorded is not None and recorded != facts.start_ticks:
            self.stats.start_time_mismatch += 1
            return observation

        self.stats.resolved += 1
        resolved = replace(
            process,
            start_ticks=facts.start_ticks,
            # WORKLOAD, not PROCESS_INSTANCE: a uid is the service-account
            # identity containment can act on, and it may cover several
            # processes. Calling it a process instance would claim a
            # precision the uid does not have.
            entity=EntityRef(EntityKind.WORKLOAD,
                             f"host={self._host_id};boot={self._boot_id}",
                             str(facts.uid)),
            confidence=AttributionConfidence.CORRELATED)
        return replace(observation, process=resolved)

    def resolve_all(self, observations) -> list[NetworkObservation]:
        return [self.resolve(o) for o in observations]
