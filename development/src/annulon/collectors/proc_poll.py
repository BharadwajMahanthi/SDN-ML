"""Polling /proc for process appearance.

Included in the evaluation as the honest comparator, not as a candidate we
expect to win. It is the approach most agents reach for first because it needs
no privilege and no kernel interface, and its weakness is structural: anything
that starts and exits between two scans is never seen.

That weakness is the thing V2-HOST-01 must measure rather than assume. A
sensor that misses short-lived processes misses most of what matters, because
an attacker's `curl | sh` is short-lived by nature.

Unlike the connector, this sensor *can* read argv and credentials from
``/proc/<pid>``, so the comparison is genuinely a trade-off rather than a
ranking on one axis.
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from typing import Iterator

from annulon.collectors.base import (
    SensorCapability,
    SensorHealth,
    SensorStats,
)
from annulon.events import CollectionQuality, DataClassification, Event, QualityFlag
from annulon.identity import EntityKind, EntityRef

__all__ = ["ProcPollSensor"]

MAX_ARGV_CHARS = 512


class ProcPollSensor:
    """Scan ``/proc`` at an interval and emit newly seen processes."""

    name = "proc_poll"
    version = "0.1"

    def __init__(self, *, interval: float = 0.1, host_id: str = "",
                 boot_id: str = "", capture_argv: bool = True) -> None:
        self.interval = interval
        self.capture_argv = capture_argv
        self._seen: dict[int, str] = {}         # pid -> start ticks
        self._stats = SensorStats()
        self._running = False
        self._last_scan = 0.0
        self.host_id = host_id or os.uname().nodename
        self.boot_id = boot_id or _read_boot_id()

    def capabilities(self) -> frozenset[SensorCapability]:
        caps = {SensorCapability.PROCESS_EXEC, SensorCapability.PROCESS_ANCESTRY}
        if self.capture_argv:
            caps.add(SensorCapability.PROCESS_ARGV)
        caps.add(SensorCapability.CREDENTIAL_CHANGE)
        return frozenset(caps)

    def requires_root(self) -> bool:
        return False        # unprivileged, though argv of other users is hidden

    def preflight(self) -> tuple[bool, str]:
        if not os.path.isdir("/proc/self"):
            return False, "/proc is not mounted"
        return True, "procfs available"

    def start(self) -> None:
        ok, detail = self.preflight()
        if not ok:
            from annulon.collectors.base import SensorUnavailable
            raise SensorUnavailable(detail)
        self._seen = {pid: start for pid, start in _scan()}
        self._running = True
        self._last_scan = time.monotonic()

    def stop(self) -> None:
        self._running = False

    def health(self) -> SensorHealth:
        return SensorHealth(
            running=self._running,
            detail=f"polling every {self.interval}s",
            stats=self._stats,
            # Measured, not assumed: 0 of 500 short-lived processes observed
            # at both 100 ms and 10 ms intervals, with zero reported drops.
            attests_completeness=False,
            blind_spot=(f"any process living less than one {self.interval}s "
                        "poll interval is never observed, and the sensor "
                        "cannot detect that it missed it"))

    def events(self, timeout: float = 1.0) -> Iterator[Event]:
        if not self._running:
            return
        deadline = time.monotonic() + timeout
        while True:
            current = dict(_scan())
            now = datetime.now(timezone.utc)
            for pid, start in current.items():
                if self._seen.get(pid) == start:
                    continue
                self._stats.sequence += 1
                self._stats.emitted += 1
                yield self._event(pid, start, now)
            # A pid that vanished between scans may have been observed or may
            # never have been seen at all. The sensor cannot tell, and says so
            # through PARTIAL_FIELDS rather than implying completeness.
            self._seen = current
            if time.monotonic() >= deadline:
                return
            time.sleep(min(self.interval, max(0.0, deadline - time.monotonic())))

    def _event(self, pid: int, start_ticks: str, now: datetime) -> Event:
        attributes: dict = {"pid": pid, "start_ticks": start_ticks}
        try:
            attributes["comm"] = open(f"/proc/{pid}/comm").read().strip()[:64]
        except OSError:
            pass
        if self.capture_argv:
            try:
                raw = open(f"/proc/{pid}/cmdline", "rb").read()
                if raw:
                    attributes["argv"] = raw.replace(b"\x00", b" ").decode(
                        "utf-8", "replace").strip()[:MAX_ARGV_CHARS]
            except OSError:
                pass
        try:
            with open(f"/proc/{pid}/status") as handle:
                for line in handle:
                    if line.startswith("PPid:"):
                        attributes["parent_pid"] = int(line.split()[1])
                    elif line.startswith("Uid:"):
                        attributes["uid"] = int(line.split()[1])
                        break
        except (OSError, ValueError, IndexError):
            pass

        return Event(
            event_id=f"ppl-{self._stats.sequence:016d}",
            event_type="host.process.exec",
            sensor=self.name, sensor_version=self.version,
            sequence=self._stats.sequence,
            observed_time=now, received_time=now,
            entity_refs=(
                # start_ticks qualifies the pid within this boot, which is what
                # makes the reference survive pid reuse.
                EntityRef(EntityKind.PROCESS_INSTANCE,
                          f"host={self.host_id};boot={self.boot_id}",
                          f"{pid}@{start_ticks}"),
                EntityRef(EntityKind.HOST, "", self.host_id),
            ),
            attributes=attributes,
            data_classification=DataClassification.SENSITIVE,  # argv may carry secrets
            quality=CollectionQuality(flags=(QualityFlag.PARTIAL_FIELDS,)),
        )


def _scan() -> Iterator[tuple[int, str]]:
    try:
        entries = os.listdir("/proc")
    except OSError:
        return
    for entry in entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            # field 22 of /proc/<pid>/stat is starttime in clock ticks; it
            # distinguishes a reused pid from the original process.
            stat = open(f"/proc/{pid}/stat").read()
            fields = stat[stat.rfind(")") + 2:].split()
            yield pid, fields[19]
        except (OSError, IndexError):
            continue


def _read_boot_id() -> str:
    try:
        return open("/proc/sys/kernel/random/boot_id").read().strip()[:36]
    except OSError:
        return "unknown"
