"""Enrich a process event the connector has already reported.

ADR-038 demoted ``/proc`` from discovery to enrichment, and the distinction is
the whole design. Discovery by polling misses anything short-lived, because
the process is gone before the next scan. Enrichment has the same race, but
its consequence is entirely different: we already *have* the event, so losing
the race costs detail rather than the observation.

That difference is recorded in the data. A process that exited before we
could read ``/proc`` yields an event flagged ``PARTIAL_FIELDS``, never a
silently thinner event that looks complete.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

__all__ = ["ProcessDetails", "enrich_pid", "MAX_ARGV_CHARS"]

MAX_ARGV_CHARS = 512
MAX_COMM_CHARS = 64
_PROC = "/proc"


@dataclass(frozen=True)
class ProcessDetails:
    """What /proc could tell us. Every field optional by construction: the
    process may have exited between the kernel notification and this read."""

    pid: int
    complete: bool
    comm: str | None = None
    exe: str | None = None
    argv: str | None = None
    parent_pid: int | None = None
    uid: int | None = None
    gid: int | None = None
    start_ticks: str | None = None
    cgroup: str | None = None
    missing: tuple[str, ...] = ()

    @property
    def process_key(self) -> str:
        """``pid@start_ticks`` where start time is known.

        A bare PID is reused; the start time qualifies it within the boot, so
        this is what makes a process instance reference survive PID reuse.
        When the process exited too quickly to read its start time, the key
        degrades to the PID and ``complete`` is False -- the ambiguity is
        visible rather than hidden.
        """
        return f"{self.pid}@{self.start_ticks}" if self.start_ticks else str(self.pid)


def enrich_pid(pid: int, *, capture_argv: bool = True,
               root: str = _PROC) -> ProcessDetails:
    """Read what is still there. Never raises for a process that has gone."""
    base = f"{root}/{pid}"
    missing: list[str] = []

    start_ticks = _start_ticks(base)
    if start_ticks is None:
        missing.append("start_ticks")

    comm = _read_text(f"{base}/comm", MAX_COMM_CHARS)
    if comm is None:
        missing.append("comm")

    exe = None
    try:
        exe = os.readlink(f"{base}/exe")
    except OSError:
        missing.append("exe")

    argv = None
    if capture_argv:
        raw = _read_bytes(f"{base}/cmdline")
        if raw is None:
            missing.append("argv")
        elif raw:
            argv = raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
            argv = argv[:MAX_ARGV_CHARS]

    parent_pid = uid = gid = None
    status = _read_text(f"{base}/status", 8192)
    if status is None:
        missing.append("status")
    else:
        for line in status.splitlines():
            if line.startswith("PPid:"):
                parent_pid = _int(line)
            elif line.startswith("Uid:"):
                uid = _int(line)
            elif line.startswith("Gid:"):
                gid = _int(line)
                break

    cgroup = None
    raw_cgroup = _read_text(f"{base}/cgroup", 4096)
    if raw_cgroup:
        # The last path component identifies the container or unit, which is
        # the workload attribution we actually need.
        first = raw_cgroup.splitlines()[0] if raw_cgroup.splitlines() else ""
        cgroup = first.split(":")[-1][:256] or None

    return ProcessDetails(
        pid=pid, complete=not missing, comm=comm, exe=exe, argv=argv,
        parent_pid=parent_pid, uid=uid, gid=gid, start_ticks=start_ticks,
        cgroup=cgroup, missing=tuple(missing))


def _read_text(path: str, limit: int) -> str | None:
    try:
        with open(path, "r", errors="replace") as handle:
            return handle.read(limit).strip()
    except OSError:
        return None


def _read_bytes(path: str, limit: int = 8192) -> bytes | None:
    try:
        with open(path, "rb") as handle:
            return handle.read(limit)
    except OSError:
        return None


def _start_ticks(base: str) -> str | None:
    raw = _read_text(f"{base}/stat", 4096)
    if not raw:
        return None
    try:
        # The comm field is parenthesised and may contain spaces, so parsing
        # starts after the last ')'. Field 22 (index 19 after that point) is
        # starttime in clock ticks.
        tail = raw[raw.rfind(")") + 2:].split()
        return tail[19]
    except (IndexError, ValueError):
        return None


def _int(line: str) -> int | None:
    try:
        return int(line.split()[1])
    except (IndexError, ValueError):
        return None
