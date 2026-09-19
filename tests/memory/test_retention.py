from __future__ import annotations

import pytest

from tests.memory.conftest import advance_to_day, checkpoint
from tools.memory_store import RetentionBlocked


def test_nothing_is_eligible_at_effective_day_91(store, clock):
    advance_to_day(store, clock, 91)
    assert store.load_state().effective_day == 91
    assert store.eligible_buckets(store.load_state()) == []
    assert store.gc(apply=False)["eligible_buckets"] == []


def test_first_bucket_becomes_eligible_at_day_92(store, clock):
    advance_to_day(store, clock, 92)
    names = [b.name for b in store.eligible_buckets(store.load_state())]
    assert names == ["bucket_000001_000007.jsonl"]


def test_nothing_new_is_eligible_at_day_98(store, clock):
    advance_to_day(store, clock, 92)
    store.gc(apply=True)
    advance_to_day(store, clock, 98)
    assert store.eligible_buckets(store.load_state()) == []


def test_second_bucket_becomes_eligible_at_day_99(store, clock):
    advance_to_day(store, clock, 92)
    store.gc(apply=True)
    advance_to_day(store, clock, 99)
    names = [b.name for b in store.eligible_buckets(store.load_state())]
    assert names == ["bucket_000008_000014.jsonl"]


def test_active_buckets_never_exceed_thirteen(store, clock):
    advance_to_day(store, clock, 91)
    assert len(store.buckets()) == 13
    advance_to_day(store, clock, 92)
    assert len(store.buckets()) == 14, "day 92 opens bucket 14 before rotation"
    store.gc(apply=True)
    assert len(store.buckets()) == 13


def test_retained_window_is_85_to_91_days_not_a_guaranteed_91(store, clock):
    """Documented consequence of whole-week deletion; asserted so the claim
    in memory/policy.json cannot silently drift."""
    advance_to_day(store, clock, 92)
    store.gc(apply=True)
    days = [b.start_day for b in store.buckets()]
    retained = store.load_state().effective_day - min(days) + 1
    assert retained == 85
    advance_to_day(store, clock, 98)
    retained = store.load_state().effective_day - min(b.start_day for b in store.buckets()) + 1
    assert retained == 91


def test_dry_run_changes_nothing(store, clock):
    advance_to_day(store, clock, 92)
    before = [b.name for b in store.buckets()]
    manifest = store.gc(apply=False)
    assert manifest["applied"] is False
    assert [b.name for b in store.buckets()] == before
    assert store.manifest_path.is_file()


def test_apply_retires_exactly_one_bucket(store, clock):
    advance_to_day(store, clock, 92)
    manifest = store.gc(apply=True)
    assert manifest["applied"] is True
    assert manifest["retired_bucket"] == "bucket_000001_000007.jsonl"
    assert "bucket_000001_000007.jsonl" not in [b.name for b in store.buckets()]
    assert store.staged_buckets() == []


# -- resumption protection -------------------------------------------------


def _reach_92_then_long_gap(store, clock):
    from datetime import timedelta

    advance_to_day(store, clock, 92, session="OLD")
    clock.set(clock.current + timedelta(days=40))
    return checkpoint(store, session="RESUMED")


def test_first_session_after_long_gap_is_gc_protected(store, clock):
    _reach_92_then_long_gap(store, clock)
    state = store.load_state()
    assert state.resumption_protected is True
    manifest = store.gc(apply=False)
    assert manifest["blocked"] == RetentionBlocked.code
    with pytest.raises(RetentionBlocked):
        store.gc(apply=True)
    assert "bucket_000001_000007.jsonl" in [b.name for b in store.buckets()]


def test_a_later_session_may_rotate(store, clock):
    _reach_92_then_long_gap(store, clock)
    checkpoint(store, session="LATER")
    assert store.load_state().resumption_protected is False
    manifest = store.gc(apply=True)
    assert manifest["applied"] is True


def test_no_catch_up_deletion_after_a_long_idle_interval(store, clock):
    """A 40-day absence must not retire 40 days' worth of memory."""
    _reach_92_then_long_gap(store, clock)
    checkpoint(store, session="LATER")
    before = len(store.buckets())
    store.gc(apply=True)
    assert len(store.buckets()) == before - 1


# -- promotion -------------------------------------------------------------


def test_unresolved_blocker_survives_rotation(store, clock):
    checkpoint(store, blockers=[{"id": "B-1", "title": "OVS datapath unavailable",
                                 "resolved": False, "detail": "needs Linux lab"}])
    advance_to_day(store, clock, 92)
    store.gc(apply=True)
    text = (store.root / "docs" / "CURRENT_STATE.md").read_text()
    assert "OVS datapath unavailable" in text


def test_decision_survives_rotation(store, clock):
    checkpoint(store, decisions=[{"id": "ADR-1", "title": "JSONL over SQLite",
                                  "status": "accepted", "why": "atomic bucket unlink"}])
    advance_to_day(store, clock, 92)
    store.gc(apply=True)
    text = (store.root / "docs" / "DECISIONS.md").read_text()
    assert "JSONL over SQLite" in text
    assert "atomic bucket unlink" in text


def test_superseded_decision_is_not_promoted(store, clock):
    checkpoint(store, decisions=[{"id": "ADR-0", "title": "Old approach",
                                  "status": "superseded"}])
    advance_to_day(store, clock, 92)
    store.gc(apply=True)
    path = store.root / "docs" / "DECISIONS.md"
    assert not path.is_file() or "Old approach" not in path.read_text()


def test_resolved_blocker_is_not_promoted(store, clock):
    checkpoint(store, blockers=[{"id": "B-9", "title": "Already fixed", "resolved": True}])
    advance_to_day(store, clock, 92)
    store.gc(apply=True)
    path = store.root / "docs" / "CURRENT_STATE.md"
    assert not path.is_file() or "Already fixed" not in path.read_text()


def test_promotion_failure_blocks_retention(store, clock, monkeypatch):
    checkpoint(store, decisions=[{"id": "ADR-2", "title": "Must survive",
                                  "status": "accepted"}])
    advance_to_day(store, clock, 92)
    monkeypatch.setattr(store, "_append_doc", lambda *a, **k: ["<!-- promoted:missing -->"])
    with pytest.raises(RetentionBlocked, match="promotion validation failed"):
        store.gc(apply=True)
    assert "bucket_000001_000007.jsonl" in [b.name for b in store.buckets()]
