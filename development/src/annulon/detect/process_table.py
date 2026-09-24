"""A live process table, so identity is captured before the process exits.

Measured on the reference host: resolving a network event's pid by reading
`/proc` afterwards succeeded 34 times and found the process already gone 30
times. Nearly half of short-lived connections could not be attributed, and
the observation stayed correct but weak (KF-49).

The `/proc` read is late by construction. The process connector is not: it
delivers a fork or exec notification *while the process is running*, which
is the moment its uid and start time can still be read. This table is fed by
that stream and keeps what it learned, so a network event arriving after the
process has exited still resolves.

That is why this, rather than eBPF, is the strongest **justified** tier
today. eBPF would capture `start_boottime` inside the kernel at the instant
of the connect, which is strictly better and removes the last race. It also
costs a compiler, BTF and a maintained probe. This reuses a sensor that has
already been physically validated on the reference profile and needs
nothing new — so it is what the evidence supports building now, and
`NETWORK_TELEMETRY_EBPF` stays an honest NOT_RUN rather than a plan nobody
has measured.

**PID reuse is handled by generation, not by hope.** The table keeps a short
history per pid, each entry carrying the window it was alive for. A lookup
takes the event's timestamp and returns the generation that was running
*then*. A pid whose current occupant started after the event does not answer
for it.
"""

from __future__ import annotations

import threading
import time
from bisect import insort
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone

from annulon.agent.enrichment import ProcessDetails, enrich_pid
from annulon.identity import EntityKind, EntityRef
from annulon.network.contract import (
    AttributionConfidence, NetworkObservation, ProcessRef,
)

__all__ = ["ProcessRecord", "ProcessTable", "ProcessTableStats",
           "MAX_TRACKED_PROCESSES", "DEFAULT_RETENTION"]

#: Bounded, because a table fed by every fork on a busy host is otherwise a
#: memory attack reachable by anyone who can start processes.
MAX_TRACKED_PROCESSES = 32_768
#: How long an exited process stays resolvable. Long enough that a network
#: event delayed through the queue still finds its process, short enough
#: that the table does not become a log.
DEFAULT_RETENTION = timedelta(minutes=10)


def _as_int(value) -> int | None:
    """A `/proc` field as an integer, or ``None`` when it is not one."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


@dataclass(frozen=True)
class ProcessRecord:
    """One generation of one pid, and when it was alive."""

    pid: int
    uid: int | None
    start_ticks: int | None
    comm: str
    exe: str
    first_seen: datetime
    exited_at: datetime | None = None
    #: True when `/proc` could be read while the process still existed. A
    #: record built after the fact is weaker and says so.
    enriched_live: bool = True

    def alive_at(self, moment: datetime, *,
                 tolerance: timedelta = timedelta(seconds=2)) -> bool:
        """Whether this generation was running at ``moment``.

        The tolerance covers clock reconstruction: a network observation's
        time is rebuilt from boot time plus a trace timestamp, and boot time
        has one-second resolution. It is slack on *our* arithmetic, not a
        grace period -- a generation that exited long before the event still
        does not answer for it.
        """
        if moment + tolerance < self.first_seen:
            return False
        if self.exited_at is not None and moment - tolerance > self.exited_at:
            return False
        return True

    @property
    def instance_key(self) -> str | None:
        if self.start_ticks is None:
            return None
        return f"{self.pid}@{self.start_ticks}"

    def to_dict(self) -> dict:
        return {"pid": self.pid, "uid": self.uid,
                "start_ticks": self.start_ticks, "comm": self.comm,
                "first_seen": self.first_seen.isoformat(),
                "exited_at": self.exited_at.isoformat() if self.exited_at else None,
                "enriched_live": self.enriched_live,
                "instance_key": self.instance_key}


@dataclass
class ProcessTableStats:
    observed_starts: int = 0
    observed_exits: int = 0
    enriched_live: int = 0
    enrichment_failed: int = 0
    evicted_for_age: int = 0
    evicted_for_size: int = 0
    resolved_from_table: int = 0
    resolved_from_proc: int = 0
    unresolved: int = 0
    generation_mismatch: int = 0

    def to_dict(self) -> dict:
        return dict(vars(self))


class ProcessTable:
    """Process identity, captured early and kept briefly.

    Thread-safe because the connector feeds it from its own reader while the
    network pipeline reads it.
    """

    def __init__(self, *, host_id: str, boot_id: str,
                 retention: timedelta = DEFAULT_RETENTION,
                 max_processes: int = MAX_TRACKED_PROCESSES,
                 proc_root: str = "/proc",
                 clock=None) -> None:
        self._host_id = host_id
        self._boot_id = boot_id
        self._retention = retention
        self._max = max_processes
        self._proc_root = proc_root
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        #: pid -> generations, oldest first. A list because pid reuse is the
        #: whole point; a dict keyed by pid alone would overwrite the
        #: generation that the event in flight belongs to.
        self._by_pid: dict[int, list[ProcessRecord]] = {}
        self._lock = threading.Lock()
        self.stats = ProcessTableStats()

    # -- being fed --------------------------------------------------------

    def note_start(self, pid: int, *, when: datetime | None = None) -> ProcessRecord | None:
        """Record a process the connector just told us about.

        Enrichment happens here, immediately, because here is the only place
        the process is known to exist. Everything downstream reads the record
        rather than `/proc`.
        """
        if not isinstance(pid, int) or pid <= 0:
            return None
        moment = when or self._clock()
        self.stats.observed_starts += 1
        details = enrich_pid(pid, capture_argv=False, root=self._proc_root)
        # `complete` also covers argv and exe, which are deliberately not
        # captured here. What attribution needs is a uid and a start time,
        # so that is what "live" means -- requiring `complete` would discard
        # a perfectly usable identity because an unrelated field was absent.
        live = details.uid is not None and details.start_ticks is not None
        if live:
            self.stats.enriched_live += 1
        else:
            # The process was gone before we could read it. Recorded anyway:
            # knowing a pid existed at a time is weaker than knowing its uid,
            # and still better than nothing.
            self.stats.enrichment_failed += 1
        record = ProcessRecord(
            pid=pid, uid=details.uid,
            # `enrich_pid` returns the raw `/proc` field, which is text. The
            # contract requires an integer, and coercing at the boundary is
            # right here where the value is read -- passing a string onward
            # would fail in whichever consumer happened to touch it first.
            start_ticks=_as_int(details.start_ticks),
            comm=details.comm or "", exe=details.exe or "",
            first_seen=moment, enriched_live=live)
        with self._lock:
            generations = self._by_pid.setdefault(pid, [])
            generations.append(record)
            # Two live generations of one pid cannot both be current; the
            # older one must have exited even if we missed the notification.
            if len(generations) > 1 and generations[-2].exited_at is None:
                generations[-2] = replace(generations[-2], exited_at=moment)
            if len(generations) > 4:
                del generations[0]
        self._evict(moment)
        return record

    def note_credential_change(self, pid: int, *,
                               when: datetime | None = None) -> ProcessRecord | None:
        """A process changed uid. That is a new identity, not an edit.

        The connector reports `PROC_EVENT_UID` separately from exec, and a
        process that drops privilege mid-life has two identities across its
        lifetime. Overwriting the uid in place would retroactively
        re-attribute connections it made *before* the change, which is the
        same error as answering for a reused pid.

        So the current generation is closed and a new one opened. A lookup
        by event time then lands on whichever identity was in force.
        """
        moment = when or self._clock()
        details = enrich_pid(pid, capture_argv=False, root=self._proc_root)
        if details.uid is None:
            return None
        with self._lock:
            generations = self._by_pid.get(pid)
            if generations and generations[-1].uid == details.uid:
                return generations[-1]          # nothing actually changed
            if generations and generations[-1].exited_at is None:
                generations[-1] = replace(generations[-1], exited_at=moment)
        return self.note_start(pid, when=moment)

    def note_exit(self, pid: int, *, when: datetime | None = None) -> None:
        moment = when or self._clock()
        self.stats.observed_exits += 1
        with self._lock:
            generations = self._by_pid.get(pid)
            if not generations:
                return
            if generations[-1].exited_at is None:
                generations[-1] = replace(generations[-1], exited_at=moment)

    def ingest(self, event) -> None:
        """Feed a process-sensor event straight in.

        Accepts anything carrying a `kind` ending in `.exec`, `.fork` or
        `.exit` and a pid, so the table is not coupled to one sensor's event
        class.
        """
        kind = str(getattr(event, "kind", "") or
                   (event.get("kind", "") if isinstance(event, dict) else ""))
        attributes = getattr(event, "attributes", None)
        if attributes is None and isinstance(event, dict):
            attributes = event.get("attributes", {})
        pid = (attributes or {}).get("pid")
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            return
        if kind.endswith(".exit"):
            self.note_exit(pid)
        elif kind.endswith(".credential_change"):
            self.note_credential_change(pid)
        elif kind.endswith((".exec", ".fork")):
            self.note_start(pid)

    # -- being read -------------------------------------------------------

    def lookup(self, pid: int, moment: datetime) -> ProcessRecord | None:
        """The generation of ``pid`` that was running at ``moment``."""
        with self._lock:
            generations = list(self._by_pid.get(pid, ()))
        if not generations:
            return None
        matching = [r for r in generations if r.alive_at(moment)]
        if not matching:
            # The pid is known, but no generation covers this time. That is
            # a reuse boundary, and answering with the current occupant would
            # attribute one workload's connection to another.
            self.stats.generation_mismatch += 1
            return None
        # The newest generation that could have been running.
        return matching[-1]

    def resolve(self, observation: NetworkObservation, *,
                fall_back_to_proc: bool = True) -> NetworkObservation:
        """Attach a workload identity, preferring the table over `/proc`.

        A table hit is `CORRELATED` and carries the start time recorded while
        the process was alive. A `/proc` fallback is for processes that
        predate the table -- it can only succeed if the process still exists,
        which is the case the table exists to stop depending on.
        """
        if not isinstance(observation, NetworkObservation):
            return observation
        process = observation.process
        if process.confidence is AttributionConfidence.NONE or process.pid <= 0:
            return observation

        record = self.lookup(process.pid, observation.observed_at)
        if record is not None and record.uid is not None:
            self.stats.resolved_from_table += 1
            return replace(observation, process=replace(
                process, start_ticks=record.start_ticks,
                comm=record.comm[:64] or process.comm,
                entity=EntityRef(EntityKind.WORKLOAD,
                                 f"host={self._host_id};boot={self._boot_id}",
                                 str(record.uid)),
                confidence=AttributionConfidence.CORRELATED))

        if not fall_back_to_proc:
            self.stats.unresolved += 1
            return observation

        details = enrich_pid(process.pid, capture_argv=False,
                             root=self._proc_root)
        if details.uid is None:
            self.stats.unresolved += 1
            return observation
        # The process is still alive but the table never saw it start, so it
        # predates the agent. Usable, and no stronger than CORRELATED.
        self.stats.resolved_from_proc += 1
        return replace(observation, process=replace(
            process, start_ticks=_as_int(details.start_ticks),
            entity=EntityRef(EntityKind.WORKLOAD,
                             f"host={self._host_id};boot={self._boot_id}",
                             str(details.uid)),
            confidence=AttributionConfidence.CORRELATED))

    def resolve_all(self, observations, **kwargs) -> list[NetworkObservation]:
        return [self.resolve(o, **kwargs) for o in observations]

    # -- bounds -----------------------------------------------------------

    def _evict(self, now: datetime) -> None:
        cutoff = now - self._retention
        with self._lock:
            for pid in list(self._by_pid):
                generations = [
                    r for r in self._by_pid[pid]
                    if r.exited_at is None or r.exited_at > cutoff]
                if generations:
                    self._by_pid[pid] = generations
                else:
                    del self._by_pid[pid]
                    self.stats.evicted_for_age += 1
            # A hard ceiling as well as an age bound: a burst of short-lived
            # processes can exceed the size limit long before anything ages
            # out, and an unbounded table is a memory attack.
            while len(self._by_pid) > self._max:
                oldest = min(self._by_pid,
                             key=lambda p: self._by_pid[p][-1].first_seen)
                del self._by_pid[oldest]
                self.stats.evicted_for_size += 1

    @property
    def tracked(self) -> int:
        with self._lock:
            return len(self._by_pid)

    def health(self) -> dict:
        resolved = self.stats.resolved_from_table + self.stats.resolved_from_proc
        attempted = resolved + self.stats.unresolved
        return {
            "tracked_processes": self.tracked,
            "stats": self.stats.to_dict(),
            "attribution_rate": (round(resolved / attempted, 4)
                                 if attempted else None),
            "limitation": "a process that starts and connects before its "
                          "start notification is processed is still "
                          "unattributable; only an in-kernel capture at the "
                          "moment of the connect removes that window",
        }
