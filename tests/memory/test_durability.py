from __future__ import annotations

import json
import os

import pytest

from tests.memory.conftest import advance_to_day, checkpoint
from tools.memory_store import CorruptionBlocked, MemoryStore


def _bucket(store: MemoryStore):
    return store.buckets()[0].path


# -- partial / corrupt records --------------------------------------------


def test_partial_final_line_is_detected_then_repaired(store):
    checkpoint(store)
    checkpoint(store)
    with _bucket(store).open("a") as fh:
        fh.write('{"record_id": "truncated", "seq')      # no newline: killed mid-append

    codes = {i.code for i in store.validate()}
    assert "TRAILING_PARTIAL_RECORD" in codes
    assert "MID_FILE_CORRUPTION" not in codes

    repaired = store.repair_tail()
    assert len(repaired) == 1 and repaired[0]["records_kept"] == 2
    assert not store.validate() or "TRAILING_PARTIAL_RECORD" not in {
        i.code for i in store.validate()}
    assert len(list(store.iter_records())) == 2


def test_repair_tail_records_a_recovery_event(store):
    checkpoint(store)
    with _bucket(store).open("a") as fh:
        fh.write('{"partial')
    store.repair_tail()
    events = json.loads(store.recovery_path.read_text())["events"]
    assert events[-1]["kind"] == "tail_repair"


def test_mid_file_corruption_is_refused_not_silently_repaired(store):
    for _ in range(3):
        checkpoint(store)
    path = _bucket(store)
    lines = path.read_text().splitlines(keepends=True)
    lines[1] = "{ this is not json }\n"
    path.write_text("".join(lines))

    assert "MID_FILE_CORRUPTION" in {i.code for i in store.validate()}
    with pytest.raises(CorruptionBlocked, match="mid-file corruption"):
        store.repair_tail()
    assert "{ this is not json }" in path.read_text(), "evidence must be preserved"


def test_checkpoint_refuses_while_mid_file_corruption_exists(store):
    checkpoint(store)
    checkpoint(store)
    path = _bucket(store)
    lines = path.read_text().splitlines(keepends=True)
    lines[0] = "garbage\n"
    path.write_text("".join(lines))
    with pytest.raises(CorruptionBlocked):
        checkpoint(store)


def test_duplicate_record_id_is_reported(store):
    checkpoint(store)
    path = _bucket(store)
    line = path.read_text().splitlines()[0]
    with path.open("a") as fh:
        fh.write(line + "\n")
    codes = {i.code for i in store.validate()}
    assert "DUPLICATE_RECORD_ID" in codes
    assert "SEQUENCE_REGRESSION" in codes


def test_sequence_regression_is_reported(store):
    checkpoint(store)
    checkpoint(store)
    path = _bucket(store)
    records = [json.loads(l) for l in path.read_text().splitlines()]
    records[1]["sequence"] = 1
    records[1]["record_id"] = "distinct"
    path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in records))
    assert "SEQUENCE_REGRESSION" in {i.code for i in store.validate()}


# -- index is an accelerator, never the source of truth --------------------


def test_missing_index_loses_nothing(store):
    checkpoint(store)
    checkpoint(store)
    before = [r.record_id for r in store.iter_records()]
    store.index_path.unlink()
    assert "INDEX_MISSING" in {i.code for i in store.validate()}
    assert [r.record_id for r in store.iter_records()] == before
    with store.lock():
        store.rebuild_index()
    assert store.index_path.is_file()


def test_corrupt_index_is_detected_and_rebuildable(store):
    checkpoint(store)
    store.index_path.write_text("{not json")
    assert "INDEX_CORRUPT" in {i.code for i in store.validate()}
    with store.lock():
        index = store.rebuild_index()
    assert index["buckets"][0]["record_count"] == 1


def test_rebuilt_index_matches_journal_exactly(store, clock):
    advance_to_day(store, clock, 10)
    with store.lock():
        index = store.rebuild_index()
    total = sum(e["record_count"] for e in index["buckets"])
    assert total == len(list(store.iter_records()))
    for entry in index["buckets"]:
        assert entry["checksum"] and entry["byte_size"] > 0


def test_index_holds_no_record_bodies(store):
    checkpoint(store, next_action="a distinctive sentinel string")
    index = json.loads(store.index_path.read_text())
    assert "distinctive sentinel" not in json.dumps(index)


# -- crash points ----------------------------------------------------------


def test_crash_after_append_before_state_update_is_healed(store):
    """The journal is the commit point; state is rebuilt from it."""
    checkpoint(store)
    record = json.loads(_bucket(store).read_text().splitlines()[0])
    record["record_id"], record["sequence"] = "orphan", 99
    with _bucket(store).open("a") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")

    assert "STATE_BEHIND_JOURNAL" in {i.code for i in store.validate()}
    new = checkpoint(store)
    assert new.sequence == 100, "reconcile must not reissue a used sequence"


def test_crash_after_state_staging_before_rename_restores_the_bucket(store, clock):
    advance_to_day(store, clock, 92)
    target = "bucket_000001_000007.jsonl"
    state = store.load_state()
    state.gc_state = {"phase": "preparing", "bucket": target,
                      "staged": target + ".gc-staged", "markers": 0}
    store.save_state(state)

    outcome = store.recover_gc()
    assert outcome == "restored"
    assert target in [b.name for b in store.buckets()]
    assert store.load_state().gc_state == {}


def test_crash_after_rename_before_unlink_completes_the_rotation(store, clock):
    advance_to_day(store, clock, 92)
    target = "bucket_000001_000007.jsonl"
    staged = store.buckets_dir / (target + ".gc-staged")
    os.replace(store.buckets_dir / target, staged)
    state = store.load_state()
    state.gc_state = {"phase": "staged", "bucket": target, "staged": staged.name,
                      "markers": 0}
    store.save_state(state)

    outcome = store.recover_gc()
    assert outcome == "completed"
    assert not staged.exists()
    assert target not in [b.name for b in store.buckets()]


def test_crash_during_staging_with_file_already_gone_is_not_ambiguous(store, clock):
    advance_to_day(store, clock, 92)
    target = "bucket_000001_000007.jsonl"
    (store.buckets_dir / target).unlink()
    state = store.load_state()
    state.gc_state = {"phase": "staged", "bucket": target,
                      "staged": target + ".gc-staged", "markers": 0}
    store.save_state(state)
    assert store.recover_gc() == "completed"
    assert store.load_state().gc_state == {}


def test_interrupted_gc_is_recovered_before_the_next_checkpoint(store, clock):
    advance_to_day(store, clock, 92)
    target = "bucket_000001_000007.jsonl"
    state = store.load_state()
    state.gc_state = {"phase": "preparing", "bucket": target,
                      "staged": target + ".gc-staged", "markers": 0}
    store.save_state(state)
    checkpoint(store)
    assert store.load_state().gc_state == {}
    assert target in [b.name for b in store.buckets()]
