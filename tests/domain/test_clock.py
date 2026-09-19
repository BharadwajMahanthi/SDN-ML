"""Clock abstraction: deterministic time for security decisions."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest

from sdnguard.clock import Clock, Deadline, ManualClock, SystemClock

T0 = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize("clock", [SystemClock(), ManualClock()])
def test_both_clocks_satisfy_the_protocol(clock):
    assert isinstance(clock, Clock)
    assert clock.now().tzinfo is not None
    assert isinstance(clock.monotonic(), float)


def test_system_clock_is_utc_aware_and_monotonic_advances():
    c = SystemClock()
    assert c.now().tzinfo is timezone.utc
    first = c.monotonic()
    time.sleep(0.001)
    assert c.monotonic() >= first


def test_manual_clock_advances_both_sources_together():
    c = ManualClock(T0)
    c.advance(5)
    assert c.now() == T0 + timedelta(seconds=5)
    assert c.monotonic() == 5.0
    c.advance(timedelta(minutes=1))
    assert c.now() == T0 + timedelta(seconds=65)
    assert c.monotonic() == 65.0


def test_manual_clock_refuses_to_advance_backwards():
    c = ManualClock(T0)
    with pytest.raises(ValueError, match="only moves forward"):
        c.advance(-1)


def test_manual_clock_requires_aware_time():
    with pytest.raises(ValueError, match="timezone-aware"):
        ManualClock(datetime(2026, 1, 1))
    with pytest.raises(ValueError, match="timezone-aware"):
        ManualClock(T0).set_wall(datetime(2026, 1, 1))


def test_wall_clock_regression_does_not_move_monotonic_time():
    """An NTP step, a VM migration or a manual correction moves wall time and
    leaves monotonic time alone. Security decisions must follow the latter."""
    c = ManualClock(T0)
    c.advance(10)
    c.set_wall(T0 - timedelta(hours=1))
    assert c.now() == T0 - timedelta(hours=1)
    assert c.monotonic() == 10.0, "monotonic must be unaffected"
    c.advance_monotonic(5)
    assert c.monotonic() == 15.0
    assert c.now() == T0 - timedelta(hours=1), "wall time must stay frozen"


def test_monotonic_cannot_be_moved_backwards():
    with pytest.raises(ValueError, match="cannot move backwards"):
        ManualClock(T0).advance_monotonic(-1)


# -- Deadline --------------------------------------------------------------


def test_deadline_expires_exactly_at_its_moment():
    c = ManualClock(T0)
    d = Deadline.after(c, 3)
    assert not d.expired(c) and d.remaining(c) == 3.0
    c.advance(2.999)
    assert not d.expired(c)
    c.advance(0.001)
    assert d.expired(c) and d.remaining(c) == 0.0


def test_deadline_accepts_a_timedelta():
    c = ManualClock(T0)
    d = Deadline.after(c, timedelta(seconds=30))
    c.advance(30)
    assert d.expired(c)


@pytest.mark.parametrize("bad", [0, -1, timedelta(0), timedelta(seconds=-5)])
def test_deadline_must_be_in_the_future(bad):
    with pytest.raises(ValueError, match="future"):
        Deadline.after(ManualClock(T0), bad)


def test_deadline_survives_a_wall_clock_step_backwards():
    """The security property: stepping the wall clock must not resurrect an
    expired probe, nor expire a live one early."""
    c = ManualClock(T0)
    d = Deadline.after(c, 3)
    c.advance(3)
    assert d.expired(c)
    c.set_wall(T0 - timedelta(days=365))
    assert d.expired(c), "a wall-clock step must not un-expire a deadline"


def test_deadline_does_not_expire_early_on_a_wall_clock_jump_forward():
    c = ManualClock(T0)
    d = Deadline.after(c, 3)
    c.set_wall(T0 + timedelta(days=365))
    assert not d.expired(c), "a wall-clock jump must not expire a live deadline"


def test_deadline_remaining_never_goes_negative():
    c = ManualClock(T0)
    d = Deadline.after(c, 1)
    c.advance(100)
    assert d.remaining(c) == 0.0
