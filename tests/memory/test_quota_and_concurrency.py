from __future__ import annotations

import threading

import pytest

from tests.memory.conftest import advance_to_day, checkpoint
from tools.agent_session import Ownership, OwnershipConflict
from tools.memory_store import (
    ForbiddenContent, LockBusy, MemoryStore, QuotaBlocked,
)


# -- quota -----------------------------------------------------------------


def test_oversized_single_checkpoint_is_refused(store_factory):
    store = store_factory(quota_overrides={"max_record_bytes": 512})
    with pytest.raises(QuotaBlocked, match="single checkpoint"):
        checkpoint(store, next_action="x" * 2000)
    assert store.buckets() == [], "nothing may be written when validation fails"


def test_transaction_reserve_is_included_in_every_projection(store_factory):
    """The reserve must make the store refuse BEFORE the raw cap is hit,
    so GC always has room to run."""
    store = store_factory(quota_overrides={
        "total_bytes": 8192, "journal_bytes": 8192,
        "metadata_bytes": 4096, "transaction_reserve_bytes": 6144,
        "max_bucket_bytes": 8192, "max_record_bytes": 4096,
    })
    with pytest.raises(QuotaBlocked, match="transaction reserve"):
        for _ in range(50):
            checkpoint(store)
    usage = store.usage()
    assert usage["total_bytes"] < 8192


def test_quota_refusal_does_not_delete_protected_history(store_factory):
    store = store_factory(quota_overrides={
        "total_bytes": 20000, "journal_bytes": 12000, "metadata_bytes": 6000,
        "transaction_reserve_bytes": 2000, "max_bucket_bytes": 12000,
    })
    checkpoint(store, decisions=[{"id": "ADR-K", "title": "keep me", "status": "accepted"}])
    kept = len(list(store.iter_records()))
    with pytest.raises(QuotaBlocked):
        for _ in range(500):
            checkpoint(store)
    assert len(list(store.iter_records())) >= kept
    assert any("keep me" in str(r.decisions) for r in store.iter_records())


def test_exact_boundary_behaviour(store_factory, tmp_path):
    """One record must fit when usage + record + reserve == cap exactly, and
    the next must be refused. The record size is measured, not guessed."""
    import shutil

    reserve = 4096
    probe = store_factory(root=tmp_path / "probe")
    checkpoint(probe)
    usage_before = probe.usage()["total_bytes"]

    # Measure the exact size of the NEXT append on an identical copy.
    shutil.copytree(probe.root, tmp_path / "measure")
    measurer = store_factory(root=tmp_path / "measure")
    journal_before = measurer.usage()["journal_bytes"]
    checkpoint(measurer)
    record_bytes = measurer.usage()["journal_bytes"] - journal_before

    exact = usage_before + record_bytes + reserve
    tight = store_factory(root=probe.root, quota_overrides={
        "total_bytes": exact, "journal_bytes": exact, "metadata_bytes": exact,
        "transaction_reserve_bytes": reserve, "max_bucket_bytes": exact,
    })
    checkpoint(tight)                      # lands exactly on the cap
    with pytest.raises(QuotaBlocked):
        checkpoint(tight)                  # one record over


def test_per_bucket_cap_is_enforced(store_factory):
    store = store_factory(quota_overrides={"max_bucket_bytes": 900})
    with pytest.raises(QuotaBlocked, match="bucket"):
        for _ in range(50):
            checkpoint(store)


def test_stats_reports_headroom_net_of_the_reserve(store):
    checkpoint(store)
    stats = store.stats()
    q, usage = stats["quota"], stats["usage"]
    assert q["headroom_bytes"] == (
        q["total_bytes"] - usage["total_bytes"] - q["transaction_reserve_bytes"])


# -- forbidden content -----------------------------------------------------


def test_secret_in_a_checkpoint_is_refused(store):
    with pytest.raises(ForbiddenContent):
        checkpoint(store, next_action='set SUDO_PASS="hunter2trustno1" and retry')
    assert store.buckets() == []


def test_aws_key_in_evidence_ref_is_refused(store):
    with pytest.raises(ForbiddenContent):
        checkpoint(store, evidence_refs=["AKIAIOSFODNN7EXAMPLE"])


def test_ordinary_checkpoint_is_accepted(store):
    record = checkpoint(store, next_action="run tools/safe_test.py --path tests/memory")
    assert record.sequence == 1


# -- concurrency -----------------------------------------------------------


def _second_store(store: MemoryStore) -> MemoryStore:
    """A distinct process-like instance: its own file descriptors."""
    return MemoryStore(store.root, policy=store.policy, clock=store.clock)


def test_two_agents_checkpointing_simultaneously_serialise(store):
    other = _second_store(store)
    errors: list[BaseException] = []
    barrier = threading.Barrier(2)

    def worker(target: MemoryStore, agent: str) -> None:
        try:
            barrier.wait(timeout=5)
            for _ in range(10):
                target.checkpoint(session_id=agent, task_id="T", agent=agent)
        except BaseException as exc:  # noqa: BLE001 - surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(store, "claude")),
               threading.Thread(target=worker, args=(other, "codex"))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert not errors, errors
    records = list(store.iter_records())
    assert len(records) == 20
    sequences = [r.sequence for r in records]
    assert sequences == sorted(sequences) == list(range(1, 21)), "no lost update"
    assert len({r.record_id for r in records}) == 20
    assert not [i for i in store.validate()
                if i.code in {"DUPLICATE_RECORD_ID", "SEQUENCE_REGRESSION"}]


def test_checkpoint_and_gc_do_not_interleave(store, clock):
    advance_to_day(store, clock, 92)
    other = _second_store(store)
    results: list[str] = []
    errors: list[BaseException] = []
    barrier = threading.Barrier(2)

    def do_gc() -> None:
        try:
            barrier.wait(timeout=5)
            results.append("gc:" + str(store.gc(apply=True)["applied"]))
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    def do_checkpoint() -> None:
        try:
            barrier.wait(timeout=5)
            other.checkpoint(session_id="X", task_id="T", agent="codex")
            results.append("checkpoint")
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=do_gc), threading.Thread(target=do_checkpoint)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert not errors, errors
    assert len(results) == 2
    assert not [i for i in store.validate() if i.code == "MID_FILE_CORRUPTION"]


def test_lock_timeout_reports_busy_rather_than_corrupting(store):
    other = _second_store(store)
    with store.lock():
        other.policy = store.policy
        with pytest.raises(LockBusy):
            with MemoryStore(store.root, policy=store.policy,
                             clock=store.clock).lock():
                pass


# -- task ownership --------------------------------------------------------


def test_second_agent_cannot_claim_an_owned_task(store):
    Ownership(store).claim(task="P2", agent="claude", session="S1", paths=["src"])
    with pytest.raises(OwnershipConflict, match="already claimed"):
        Ownership(store).claim(task="P2", agent="codex", session="S2", paths=["docs"])


def test_overlapping_paths_are_refused(store):
    Ownership(store).claim(task="P2", agent="claude", session="S1", paths=["src/controller"])
    with pytest.raises(OwnershipConflict, match="overlaps"):
        Ownership(store).claim(task="P3", agent="codex", session="S2",
                               paths=["src/controller/openflow.py"])


def test_disjoint_paths_are_allowed_and_releasable(store):
    own = Ownership(store)
    own.claim(task="P2", agent="claude", session="S1", paths=["src/controller"])
    own.claim(task="P3", agent="codex", session="S2", paths=["src/detection"])
    assert len(own.load()["claims"]) == 2
    assert own.release(task="P2", agent="claude") is True
    assert len(own.load()["claims"]) == 1


def test_storage_accounting_is_deterministic_across_lock_cycles(store):
    """Regression (KF-06): the lock file counts toward the quota, so its
    payload must be fixed-width. A variable pid/timestamp made total usage --
    and therefore the quota boundary -- nondeterministic between runs."""
    checkpoint(store)
    sizes = set()
    for _ in range(20):
        with store.lock():
            pass
        sizes.add(store.usage()["total_bytes"])
    assert len(sizes) == 1, f"usage jittered across lock cycles: {sorted(sizes)}"
