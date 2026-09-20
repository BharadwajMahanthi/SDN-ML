"""Active sensor liveness: prove the sensor still works, never assume it.

A sensor reporting ``running=True`` because a socket is open is asserting
almost nothing. The socket stays open if the kernel stops delivering, if a
filter is installed underneath us, if the multicast subscription is dropped,
or if the collector thread has died while the descriptor lives on. In every
one of those cases the agent reports healthy and observes nothing -- and
downstream, "no findings" reads as "nothing happened".

That is the same failure shape as V2-HOST-01's polling sensor, arriving by a
different route: silence that looks like safety. A drop counter cannot catch
it, because there is nothing to count.

So the agent periodically proves the path end to end. It execs a marker of
its own, then checks it observed it. If the marker does not come back within
the deadline, the sensor stops attesting to completeness, which propagates
into collection health and from there into assessments (ADR-036, ADR-039).

The check is deliberately cheap and deliberately real: an actual process
through the actual pipeline, not a mocked callback.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

__all__ = ["LivenessResult", "LivenessProbe", "SensorLivenessMonitor"]


@dataclass(frozen=True)
class LivenessResult:
    probe_id: str
    observed: bool
    latency_seconds: float | None
    checked_at: datetime
    detail: str = ""

    def to_dict(self) -> dict:
        return {"probe_id": self.probe_id, "observed": self.observed,
                "latency_seconds": self.latency_seconds,
                "checked_at": self.checked_at.isoformat(), "detail": self.detail}


class LivenessProbe:
    """Executes a uniquely named marker so the resulting event is unambiguous.

    The name carries a nonce. A stale event from a previous probe cannot
    satisfy the current one, which matters because "I saw *a* process" is a
    much weaker statement than "I saw *this* process".
    """

    def __init__(self, directory: str | None = None) -> None:
        self.directory = directory or tempfile.gettempdir()
        self._path: str | None = None
        self.probe_id = ""

    def fire(self) -> str:
        self.probe_id = uuid.uuid4().hex[:16]
        self._path = os.path.join(self.directory, f"annulon-live-{self.probe_id}")
        with open(self._path, "w") as handle:
            handle.write("#!/bin/sh\nexit 0\n")
        os.chmod(self._path, 0o700)
        try:
            subprocess.run([self._path], check=False, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass
        return self.probe_id

    def matches(self, attributes: dict) -> bool:
        if not self.probe_id:
            return False
        for key in ("exe", "comm", "argv"):
            value = attributes.get(key)
            if isinstance(value, str) and self.probe_id in value:
                return True
        return False

    def cleanup(self) -> None:
        if self._path:
            try:
                os.unlink(self._path)
            except OSError:
                pass
            self._path = None


@dataclass
class SensorLivenessMonitor:
    """Runs a liveness probe on an interval and remembers what happened.

    Kept separate from the agent so it can be driven by a test clock, and so
    a deployment that genuinely cannot exec (a locked-down container) can
    disable it explicitly rather than silently always failing.
    """

    interval_seconds: float = 300.0
    deadline_seconds: float = 5.0
    enabled: bool = True
    history_limit: int = 20
    _history: list[LivenessResult] = field(default_factory=list)
    _last_run: float = field(default=0.0)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def last(self) -> LivenessResult | None:
        return self._history[-1] if self._history else None

    @property
    def history(self) -> tuple[LivenessResult, ...]:
        return tuple(self._history)

    @property
    def healthy(self) -> bool:
        """Unknown is not healthy.

        Before the first probe the monitor has no evidence either way, and
        reporting healthy on no evidence is the habit this whole module
        exists to break.
        """
        return self.last is not None and self.last.observed

    @property
    def consecutive_failures(self) -> int:
        count = 0
        for result in reversed(self._history):
            if result.observed:
                break
            count += 1
        return count

    def due(self, now: float | None = None) -> bool:
        if not self.enabled:
            return False
        moment = time.monotonic() if now is None else now
        return moment - self._last_run >= self.interval_seconds

    def run(self, drain: Callable[[], list], *, now: float | None = None,
            sleep: Callable[[float], None] = time.sleep) -> LivenessResult:
        """Fire a probe and wait, bounded, for the agent to observe it.

        ``drain`` returns whatever the agent has collected so far; the monitor
        inspects it for the marker rather than reaching into the sensor.
        """
        moment = time.monotonic() if now is None else now
        self._last_run = moment
        probe = LivenessProbe()
        started = time.monotonic()
        probe_id = probe.fire()

        observed = False
        latency: float | None = None
        deadline = started + self.deadline_seconds
        try:
            while time.monotonic() < deadline and not observed:
                for event in drain():
                    if probe.matches(getattr(event, "attributes", {}) or {}):
                        observed = True
                        latency = round(time.monotonic() - started, 4)
                        break
                if not observed:
                    sleep(0.05)
        finally:
            probe.cleanup()

        result = LivenessResult(
            probe_id=probe_id, observed=observed, latency_seconds=latency,
            checked_at=datetime.now(timezone.utc),
            detail="marker observed" if observed else
                   (f"marker not observed within {self.deadline_seconds}s; "
                    "the sensor may be open but no longer delivering"))
        with self._lock:
            self._history.append(result)
            if len(self._history) > self.history_limit:
                self._history = self._history[-self.history_limit:]
        return result

    def record_external(self, result: LivenessResult) -> None:
        """For callers that run the probe themselves, e.g. an experiment."""
        with self._lock:
            self._history.append(result)
            self._history = self._history[-self.history_limit:]
