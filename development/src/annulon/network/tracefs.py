"""The network sensor: three tracepoints in a ring buffer Annulon owns.

Selected by measurement over `/proc` polling and eBPF (ADR-053). The whole
mechanism is a directory, three writes and a read, which is why it needs no
compiler, no libbpf and no BCC.

Three properties carry the design.

**The buffer is private.** Creating `/sys/kernel/tracing/instances/annulon`
gives a ring buffer no other tracer shares. Annulon cannot be starved by
another tool enabling events, and cannot starve one either — which matters
because a security sensor that fights the operator's debugging tools gets
turned off.

**Loss is measured, not assumed.** `per_cpu/cpuN/stats` reports `overrun` and
`dropped events`. Every batch of observations carries the loss counters that
were true when it was produced, so a consumer can tell "nothing happened"
from "we stopped being able to see". That distinction is the one this project
keeps finding defects in.

**Three probes, because no one of them can tell the whole truth — and the
obvious one is not the primary.** The syscall entry has the right process
context and the wrong content: tracefs renders its argument as a *pointer*,
so it cannot supply a destination, a port or even an address family, and it
fires for AF_UNIX connects too. Measured, that made the interpreter's own
startup look like four network connections (KF-45).

So the primary process-attributed event is the `TCP_CLOSE -> TCP_SYN_SENT`
transition from `inet_sock_set_state`. It is IP-only by construction, carries
`saddr`, `daddr`, `sport`, `dport`, `family` and `protocol`, and runs in task
context: **35 of 35 task-context transitions carried the correct PID.** The
syscall pair is kept for the outcome errno and for attempts that never reach
SYN_SENT. Measurement also showed all 500 successful connections returned
`EINPROGRESS`, so a sensor built on the exit alone would have called every
one a failure.

What this sensor cannot do is stated in :meth:`TracefsNetworkSensor.health`
rather than left for a reader to infer: it observes PIDs in its own
namespace, it cannot capture process start time in-kernel, and the process
context on a state transition is unreliable because that can run in softirq.
"""

from __future__ import annotations

import errno as errno_module
import os
import re
import select
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from annulon.collectors.base import SensorUnavailable

__all__ = [
    "TracefsNetworkSensor", "TracefsUnavailable", "RawEvent", "LossCounters",
    "TRACEFS_ROOT", "INSTANCE_NAME", "REQUIRED_EVENTS", "DEFAULT_BUFFER_KB",
    "parse_trace_line",
]

TRACEFS_ROOT = Path("/sys/kernel/tracing")
_DEBUGFS_TRACING = Path("/sys/kernel/debug/tracing")
INSTANCE_NAME = "annulon_net"
REQUIRED_EVENTS = ("syscalls/sys_enter_connect", "syscalls/sys_exit_connect",
                   "sock/inet_sock_set_state")
#: Per-CPU, so the real allocation is this times the CPU count. Large enough
#: that an ordinary burst does not drop, small enough to bound memory.
DEFAULT_BUFFER_KB = 4096
#: The reader hands observations on through a bounded queue. Unbounded would
#: mean a slow consumer turns a traffic burst into an out-of-memory kill of
#: the security agent, which is a denial of service reachable by anyone who
#: can make network connections.
DEFAULT_QUEUE_LIMIT = 50_000


class TracefsUnavailable(SensorUnavailable):
    """This kernel or container cannot provide the sensor.

    Raised rather than degraded. A sensor that silently falls back to a
    weaker mechanism while keeping the stronger capability's name is how a
    blind spot becomes invisible.
    """


@dataclass(frozen=True)
class LossCounters:
    """What the kernel says it could not deliver.

    ``overrun`` counts events the ring buffer discarded because the reader
    was too slow. It is the honest measure of a blind window, and it travels
    with the observations rather than being queried separately, so a consumer
    cannot accidentally reason about events without it.
    """

    overrun: int = 0
    commit_overrun: int = 0
    dropped: int = 0
    #: Events the userspace queue refused because it was full. Distinct from
    #: kernel loss: this one is Annulon's own fault and is fixable by tuning.
    queue_dropped: int = 0

    @property
    def total(self) -> int:
        return self.overrun + self.commit_overrun + self.dropped + self.queue_dropped

    @property
    def lossless(self) -> bool:
        return self.total == 0

    def to_dict(self) -> dict:
        return {"overrun": self.overrun, "commit_overrun": self.commit_overrun,
                "dropped": self.dropped, "queue_dropped": self.queue_dropped,
                "total": self.total, "lossless": self.lossless}


@dataclass(frozen=True)
class RawEvent:
    """One parsed trace line, before it becomes a domain observation.

    Deliberately close to the kernel's wording. Normalisation into the
    Annulon contract happens one layer up, so the parser can be tested
    against real trace output without dragging the domain model in.
    """

    kind: str                  # sys_enter_connect | sys_exit_connect | inet_sock_set_state
    comm: str
    pid: int
    cpu: int
    timestamp: float           # seconds since boot, as tracefs reports it
    flags: str                 # e.g. "..s1." -- the 's' means softirq
    fields: dict[str, str] = field(default_factory=dict)

    @property
    def in_softirq(self) -> bool:
        """Whether this ran in interrupt context.

        tracefs writes four latency flags: irqs-off, need-resched,
        hardirq/softirq, preempt-depth. The third is `.` in normal task
        context and `s`, `h` or `H` otherwise.

        When it is not `.`, the process context is whatever task happened to
        be scheduled rather than the one responsible, so `pid` and `comm`
        must not be used for attribution. The measured case is the
        `ESTABLISHED` transition, which runs in softirq when the completing
        ACK arrives.
        """
        return len(self.flags) > 2 and self.flags[2] in "shH"

    @property
    def attributable(self) -> bool:
        """Whether this event's process context can be trusted at all."""
        return not self.in_softirq


#: A tracefs line looks like:
#:     python3-84870   [006] ..s1. 53428.750848: inet_sock_set_state: family=...
#: The comm may itself contain hyphens and spaces, so the PID is anchored from
#: the right of the comm field rather than by splitting on the first hyphen.
_LINE = re.compile(
    r"\A\s*(?P<comm>.+?)-(?P<pid>\d+)\s+"
    r"\[(?P<cpu>\d+)\]\s+(?P<flags>\S+)\s+"
    r"(?P<timestamp>\d+\.\d+):\s+(?P<kind>\w+):?\s*(?P<rest>.*)\Z")
_FIELD = re.compile(r"(\w+)=(\S+)")


def parse_trace_line(line: str) -> RawEvent | None:
    """Parse one tracefs line, or return ``None``.

    Returns ``None`` rather than raising for anything unrecognised: tracefs
    interleaves comments, lost-event notices and formats this parser does not
    know, and a sensor that dies on an unexpected line is a sensor that stops
    watching during exactly the noisy moment that matters.
    """
    if not isinstance(line, str):
        return None
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    match = _LINE.match(stripped)
    if match is None:
        return None
    try:
        pid = int(match.group("pid"))
        cpu = int(match.group("cpu"))
        timestamp = float(match.group("timestamp"))
    except (TypeError, ValueError):
        return None
    rest = match.group("rest")
    kind = match.group("kind")
    fields = dict(_FIELD.findall(rest)) if rest else {}
    if kind.startswith("sys_"):
        # tracefs prints *both* the entry and the exit of a syscall as
        # `sys_connect`; only the shape of the rest of the line distinguishes
        # them. Entry is `sys_connect(fd: 6, ...)`, exit is
        # `sys_connect -> 0x...`. Normalising here means nothing downstream
        # has to know that, and a missed distinction would silently merge an
        # attempt with its result.
        if "->" in rest:
            fields["ret"] = rest.split("->", 1)[1].strip()
            kind = f"sys_exit_{kind[4:]}"
        else:
            kind = f"sys_enter_{kind[4:]}"
    return RawEvent(kind=kind, comm=match.group("comm").strip(),
                    pid=pid, cpu=cpu, timestamp=timestamp,
                    flags=match.group("flags"), fields=fields)


class TracefsNetworkSensor:
    """Owns one tracefs instance and reads it.

    Start-up is deliberately noisy about failure: every required event is
    checked, and a missing one raises rather than leaving the sensor running
    with a silent hole in its coverage.
    """

    sensor_id = "tracefs_network"
    capability = "NETWORK_TELEMETRY_TRACEFS"

    def __init__(self, *, root: Path | None = None,
                 instance: str = INSTANCE_NAME,
                 buffer_kb: int = DEFAULT_BUFFER_KB,
                 queue_limit: int = DEFAULT_QUEUE_LIMIT) -> None:
        self._root = Path(root) if root is not None else None
        self._instance_name = instance
        self._buffer_kb = buffer_kb
        self._queue_limit = queue_limit
        self._instance: Path | None = None
        self._fd: int | None = None
        self._partial = ""
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._queue: deque[RawEvent] = deque()
        self._lock = threading.Lock()
        self._queue_dropped = 0
        self._unparsed = 0
        self._started_at: datetime | None = None
        self._reader_error: str = ""
        self._enabled_events: list[str] = []

    # -- discovery --------------------------------------------------------

    @staticmethod
    def _locate_tracefs() -> Path:
        for candidate in (TRACEFS_ROOT, _DEBUGFS_TRACING):
            if (candidate / "events").is_dir():
                return candidate
        raise TracefsUnavailable(
            "tracefs is not mounted; mount -t tracefs none "
            f"{TRACEFS_ROOT} (needs CAP_SYS_ADMIN)")

    @classmethod
    def available(cls) -> bool:
        try:
            root = cls._locate_tracefs()
        except TracefsUnavailable:
            return False
        return all((root / "events" / event).is_dir() for event in REQUIRED_EVENTS)

    @classmethod
    def missing_requirements(cls) -> tuple[str, ...]:
        """What this kernel lacks, named precisely.

        A reader needs to know *which* capability is absent, because the
        answer determines whether the fix is a mount, a kernel config or a
        different machine.
        """
        try:
            root = cls._locate_tracefs()
        except TracefsUnavailable as exc:
            return (str(exc),)
        return tuple(f"missing tracepoint {event}" for event in REQUIRED_EVENTS
                     if not (root / "events" / event).is_dir())

    # -- lifecycle --------------------------------------------------------

    def start(self) -> None:
        root = self._root or self._locate_tracefs()
        missing = self.missing_requirements()
        if missing:
            raise TracefsUnavailable(
                f"this kernel cannot support {self.capability}: {'; '.join(missing)}")
        instance = root / "instances" / self._instance_name
        try:
            instance.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise TracefsUnavailable(
                f"cannot create a private trace instance: {exc}") from exc
        self._instance = instance
        self._write(instance / "buffer_size_kb", str(self._buffer_kb))
        # Start from a clean buffer so a previous run's events cannot be
        # counted as this one's -- the stale-artifact failure from KF-22.
        self._write(instance / "trace", "")
        for event in REQUIRED_EVENTS:
            path = instance / "events" / event / "enable"
            if not path.exists():
                raise TracefsUnavailable(f"cannot enable {event}")
            self._write(path, "1")
            self._enabled_events.append(event)
        try:
            # A raw non-blocking descriptor, not a buffered file object.
            # `trace_pipe` blocks until an event arrives, and closing a
            # buffered reader from another thread while a read is in flight
            # deadlocks in CPython: `close()` waits on the same internal lock
            # the blocked `read()` holds. Observed as a hung sensor with the
            # main thread parked in `futex_wait_queue` (KF-44). With a raw fd
            # and `select`, the reader wakes on its own timeout and shutdown
            # is prompt.
            self._fd = os.open(str(instance / "trace_pipe"),
                               os.O_RDONLY | os.O_NONBLOCK)
        except OSError as exc:
            raise TracefsUnavailable(f"cannot open trace_pipe: {exc}") from exc
        self._started_at = datetime.now(timezone.utc)
        self._stop.clear()
        self._thread = threading.Thread(target=self._read_loop, daemon=True,
                                        name="annulon-network-sensor")
        self._thread.start()

    @staticmethod
    def _write(path: Path, value: str) -> None:
        try:
            with open(path, "w") as handle:
                handle.write(value)
        except OSError as exc:
            raise TracefsUnavailable(f"cannot write {path}: {exc}") from exc

    def _read_loop(self) -> None:
        fd = self._fd
        if fd is None:
            self._reader_error = "no descriptor"
            return
        try:
            while not self._stop.is_set():
                try:
                    ready, _, _ = select.select([fd], [], [], 0.2)
                except (OSError, ValueError):
                    break               # the descriptor went away: shutdown
                if not ready:
                    continue
                try:
                    chunk = os.read(fd, 1 << 16)
                except BlockingIOError:
                    continue
                except OSError as exc:
                    if exc.errno in (errno_module.EBADF, errno_module.EINTR):
                        break
                    raise
                if not chunk:
                    continue
                self._consume(chunk.decode("utf-8", errors="replace"))
        except (OSError, ValueError) as exc:
            # The reader dying must be visible in health, not silent.
            self._reader_error = f"{type(exc).__name__}: {exc}"

    def _consume(self, text: str) -> None:
        """Split a chunk into lines, holding any partial tail for the next one.

        A read can land mid-line. Parsing the fragment would discard a real
        event and count it as unparsed, quietly understating what the sensor
        saw.
        """
        self._partial += text
        *lines, self._partial = self._partial.split("\n")
        if len(self._partial) > 1 << 20:
            # A line this long is not a trace line. Drop it rather than grow
            # without bound on malformed input.
            self._partial = ""
            self._unparsed += 1
        for line in lines:
            event = parse_trace_line(line)
            if event is None:
                self._unparsed += 1
                continue
            with self._lock:
                if len(self._queue) >= self._queue_limit:
                    # Bounded, and the drop is counted. Blocking here would
                    # stall the kernel reader and turn a slow consumer into
                    # kernel-side loss instead -- the same data lost, but
                    # invisibly.
                    self._queue_dropped += 1
                    continue
                self._queue.append(event)

    def stop(self) -> None:
        self._stop.set()
        for event in self._enabled_events:
            if self._instance is not None:
                try:
                    self._write(self._instance / "events" / event / "enable", "0")
                except TracefsUnavailable:
                    pass
        self._enabled_events.clear()
        # Join first, then close. The reader owns the descriptor while it
        # runs, and closing underneath it is what deadlocked before.
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None

    def remove_instance(self) -> None:
        """Remove Annulon's own trace instance. Never touches another."""
        if self._instance is None:
            return
        try:
            os.rmdir(self._instance)
        except OSError:
            pass
        self._instance = None

    # -- reading ----------------------------------------------------------

    def drain(self, limit: int | None = None) -> list[RawEvent]:
        with self._lock:
            count = len(self._queue) if limit is None else min(limit, len(self._queue))
            return [self._queue.popleft() for _ in range(count)]

    @property
    def pending(self) -> int:
        with self._lock:
            return len(self._queue)

    def loss(self) -> LossCounters:
        """Kernel and userspace loss, read fresh from the ring buffer."""
        overrun = commit = dropped = 0
        if self._instance is not None:
            per_cpu = self._instance / "per_cpu"
            if per_cpu.is_dir():
                for cpu_dir in per_cpu.iterdir():
                    stats = cpu_dir / "stats"
                    if not stats.is_file():
                        continue
                    try:
                        text = stats.read_text()
                    except OSError:
                        continue
                    for line in text.splitlines():
                        key, _, value = line.partition(":")
                        try:
                            number = int(value.strip())
                        except ValueError:
                            continue
                        if key.strip() == "overrun":
                            overrun += number
                        elif key.strip() == "commit overrun":
                            commit += number
                        elif key.strip() == "dropped events":
                            dropped += number
        with self._lock:
            queue_dropped = self._queue_dropped
        return LossCounters(overrun, commit, dropped, queue_dropped)

    # -- health -----------------------------------------------------------

    def health(self) -> dict:
        """What this sensor can and cannot currently attest.

        ``attests_completeness`` is false whenever anything was lost, and the
        reasons are listed rather than summarised into a boolean, because an
        operator needs to know whether the blind window was the kernel's ring
        buffer or Annulon's own queue.
        """
        loss = self.loss()
        reasons: list[str] = []
        running = self._thread is not None and self._thread.is_alive()
        if not running:
            reasons.append("the reader thread is not running")
        if self._reader_error:
            reasons.append(f"the reader failed: {self._reader_error}")
        if loss.overrun or loss.commit_overrun or loss.dropped:
            reasons.append(f"the kernel ring buffer lost {loss.overrun + loss.commit_overrun + loss.dropped} event(s)")
        if loss.queue_dropped:
            reasons.append(f"the userspace queue dropped {loss.queue_dropped} event(s)")
        return {
            "sensor_id": self.sensor_id,
            "capability": self.capability,
            "running": running,
            "started_at": self._started_at.isoformat() if self._started_at else None,
            "enabled_events": list(self._enabled_events),
            "pending": self.pending,
            "unparsed_lines": self._unparsed,
            "loss": loss.to_dict(),
            # Never true merely because a thread is alive. Liveness is proved
            # separately by observing a known action; this only reports what
            # is already known to be wrong.
            "attests_completeness": running and loss.lossless and not self._reader_error,
            "degraded_reasons": reasons,
            "known_limitations": {
                "pid_namespace": "PIDs are observed in the sensor's namespace; "
                                 "a containerised workload has a different pid "
                                 "inside its own namespace",
                "process_start_time": "not available from a tracepoint, so "
                                      "process-instance identity is bound by "
                                      "correlation rather than captured at "
                                      "source",
                "softirq_context": "a socket state transition often runs in "
                                   "softirq, so its process context is "
                                   "whatever task happened to be scheduled "
                                   "rather than the one responsible; these "
                                   "events are marked unattributable",
                "pre_existing_connections": "only activity after start is "
                                            "observed; this is not a "
                                            "connection inventory",
                "udp": "not covered by these probes",
            },
        }
