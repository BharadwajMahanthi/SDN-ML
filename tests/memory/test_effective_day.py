from __future__ import annotations

from datetime import date, timedelta

import pytest

from tests.memory.conftest import START, advance_to_day, checkpoint


def test_first_checkpoint_is_day_one(store):
    assert checkpoint(store).effective_day == 1


def test_consecutive_days_advance_by_one(store, clock):
    checkpoint(store)
    clock.set(START + timedelta(days=1))
    assert checkpoint(store).effective_day == 2


def test_same_day_repeated_sessions_do_not_advance(store, clock):
    checkpoint(store, session="S1")
    first = checkpoint(store, session="S2").effective_day
    second = checkpoint(store, session="S3").effective_day
    assert first == second == 1
    assert store.load_state().last_sequence == 3


def test_non_substantive_checkpoint_does_not_advance(store, clock):
    checkpoint(store)
    clock.set(START + timedelta(days=5))
    record = checkpoint(store, substantive=False, kind="housekeeping")
    assert record.effective_day == 1
    assert store.load_state().last_development_date == START.isoformat()


@pytest.mark.parametrize(
    "idle_days,expected_day,protected",
    [(0, 2, False), (1, 3, False), (19, 21, False), (20, 22, False),
     (21, 2, True), (30, 2, True), (400, 2, True)],
)
def test_idle_gap_rule(store, clock, idle_days, expected_day, protected):
    """<=20 idle days ages normally; >20 excludes the gap and advances by one."""
    checkpoint(store, session="A")
    clock.set(START + timedelta(days=idle_days + 1))
    record = checkpoint(store, session="B")
    assert record.effective_day == expected_day
    assert store.load_state().resumption_protected is protected


def test_backwards_clock_never_advances_or_deletes(store, clock):
    checkpoint(store)
    clock.set(START + timedelta(days=3))
    checkpoint(store)
    before = store.load_state()
    clock.set(START - timedelta(days=10))
    record = checkpoint(store)
    after = store.load_state()
    assert record.effective_day == before.effective_day
    assert after.clock_anomalies == 1
    assert after.last_development_date == before.last_development_date
    assert len(store.buckets()) >= 1


def test_records_land_in_the_bucket_matching_their_day(store, clock):
    advance_to_day(store, clock, 9)
    names = [b.name for b in store.buckets()]
    assert "bucket_000001_000007.jsonl" in names
    assert "bucket_000008_000014.jsonl" in names
    for bucket in store.buckets():
        records, bad, _ = store.scan_bucket(bucket.path)
        assert not bad
        for record in records:
            assert bucket.start_day <= record.effective_day <= bucket.end_day
