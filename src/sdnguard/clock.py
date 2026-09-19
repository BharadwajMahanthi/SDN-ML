"""Time abstraction for the security core.

Every timeout, expiry and deadline in this system is evaluated against an
injected clock rather than against ``datetime.now()``. Two reasons, both
learned from the legacy implementation:

1. **Testability.** Retention, probe expiry and state ageing must be tested
   deterministically. Tests that sleep are slow, flaky, and quietly stop
   testing the boundary they were written for.
2. **Correctness.** Wall-clock time moves backwards -- NTP steps, VM
   migration, manual correction. Security state keyed on wall time can then
   expire early, expire never, or appear to travel backwards. Elapsed-time
   decisions therefore use a *monotonic* source, while the wall clock is used
   only for timestamps that humans and evidence bundles need to read.

The split matters: ``now()`` answers "what time is it, for the record" and
``monotonic()`` answers "how much time has passed, for a decision".
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Protocol, runtime_checkable

__all__ = ["Clock", "SystemClock", "ManualClock", "Deadline"]


@runtime_checkable
class Clock(Protocol):
    """A source of both wall-clock time and elapsed time."""

    def now(self) -> datetime:
        """Timezone-aware UTC wall-clock time, for timestamps and evidence."""
        ...

    def monotonic(self) -> float:
        """Seconds from an arbitrary origin, never decreasing. For durations."""
        ...


@dataclass(frozen=True)
class SystemClock:
    """The real clock. ``monotonic`` is immune to wall-clock adjustment."""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    def monotonic(self) -> float:
        return time.monotonic()


@dataclass
class ManualClock:
    """A clock the test drives explicitly. No sleeping, ever.

    Wall time and monotonic time advance together by default, but can be
    moved independently so that clock-regression handling is testable: a
    caller may step the wall clock backwards while monotonic time continues
    forward, which is exactly what an NTP correction looks like.
    """

    wall: datetime = field(
        default_factory=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc))
    elapsed: float = 0.0

    def __post_init__(self) -> None:
        if self.wall.tzinfo is None:
            raise ValueError("ManualClock requires a timezone-aware datetime")

    def now(self) -> datetime:
        return self.wall

    def monotonic(self) -> float:
        return self.elapsed

    # -- test controls ---------------------------------------------------

    def advance(self, seconds: float | timedelta) -> "ManualClock":
        """Move both clocks forward by the same amount."""
        delta = seconds if isinstance(seconds, timedelta) else timedelta(seconds=seconds)
        if delta < timedelta(0):
            raise ValueError(
                "advance() only moves forward; use set_wall() to simulate a "
                "wall-clock regression while monotonic time continues")
        self.wall += delta
        self.elapsed += delta.total_seconds()
        return self

    def set_wall(self, moment: datetime) -> "ManualClock":
        """Move wall time only -- forwards or backwards. Monotonic is untouched,
        which is what a real NTP step looks like to a running process."""
        if moment.tzinfo is None:
            raise ValueError("wall time must be timezone-aware")
        self.wall = moment
        return self

    def advance_monotonic(self, seconds: float) -> "ManualClock":
        """Move elapsed time only, leaving wall time frozen."""
        if seconds < 0:
            raise ValueError("monotonic time cannot move backwards")
        self.elapsed += seconds
        return self


@dataclass(frozen=True)
class Deadline:
    """A monotonic deadline.

    Built from a clock, so it survives a wall-clock step. A probe timeout
    expressed as "wall time now + 3s" can be made to expire instantly, or
    never, by an attacker or an administrator who steps the clock; one
    expressed as "monotonic now + 3s" cannot.
    """

    at: float

    @classmethod
    def after(cls, clock: Clock, seconds: float | timedelta) -> "Deadline":
        amount = seconds.total_seconds() if isinstance(seconds, timedelta) else float(seconds)
        if amount <= 0:
            raise ValueError("deadline must be in the future")
        return cls(clock.monotonic() + amount)

    def expired(self, clock: Clock) -> bool:
        return clock.monotonic() >= self.at

    def remaining(self, clock: Clock) -> float:
        return max(0.0, self.at - clock.monotonic())
