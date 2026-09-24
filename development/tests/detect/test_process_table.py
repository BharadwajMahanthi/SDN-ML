"""The process table, attacked where it could attribute the wrong workload.

The table exists because reading `/proc` after a network event is too late:
measured, 0 of 40 short-lived processes could be attributed that way and 40
of 40 could be attributed from a table fed at exec time.

Buying that improvement introduces one new risk, and it is the serious one.
A table that remembers pids will be asked about a pid that has since been
reused, and answering with the current occupant attributes one workload's
connection to another — which is worse than the gap it replaced. Most of
what follows is about that.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from annulon.detect.process_table import (
    DEFAULT_RETENTION, ProcessRecord, ProcessTable,
)
from annulon.identity import EntityKind
from annulon.network.contract import (
    AddressFamily, AttributionConfidence, Direction, Endpoint,
    NetworkObservation, NetworkOperation, ProcessRef, Transport,
)

T0 = datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self, start=T0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds: float):
        self.now += timedelta(seconds=seconds)


def _table(tmp_path, clock=None, **kwargs) -> ProcessTable:
    return ProcessTable(host_id="h", boot_id="b", proc_root=str(tmp_path),
                        clock=clock or Clock(), **kwargs)


def _proc(tmp_path, pid: int, uid: int, start_ticks: int, comm="worker"):
    """A fake `/proc/<pid>` the table can enrich from."""
    directory = tmp_path / str(pid)
    directory.mkdir(exist_ok=True)
    (directory / "stat").write_text(
        f"{pid} ({comm}) S " + " ".join(["0"] * 18) + f" {start_ticks} "
        + " ".join(["0"] * 30))
    (directory / "status").write_text(
        f"Name:\t{comm}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
        f"Gid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
    (directory / "comm").write_text(comm + "\n")
    return directory


def _observation(pid: int, when: datetime) -> NetworkObservation:
    return NetworkObservation(
        observation_id="netobs-000000000001",
        operation=NetworkOperation.CONNECT_ATTEMPT, transport=Transport.TCP,
        direction=Direction.OUTBOUND,
        process=ProcessRef(pid=pid, tgid=pid, comm="worker",
                           confidence=AttributionConfidence.PID_ONLY),
        local=Endpoint("10.0.0.2", 51234, AddressFamily.IPV4),
        remote=Endpoint("10.0.0.3", 443, AddressFamily.IPV4),
        observed_at=when, sensor_id="tracefs_network")


# --- the improvement it exists for -----------------------------------------

def test_an_exited_process_is_still_attributable(tmp_path):
    """The whole point: identity captured at start survives the exit."""
    clock = Clock()
    table = _table(tmp_path, clock)
    _proc(tmp_path, 4242, uid=1500, start_ticks=111)
    table.note_start(4242)
    event_time = clock.now
    clock.advance(0.5)
    table.note_exit(4242)
    clock.advance(5)

    resolved = table.resolve(_observation(4242, event_time),
                             fall_back_to_proc=False)
    assert resolved.process.entity is not None
    assert resolved.process.entity.identifier == "1500"
    assert resolved.process.confidence is AttributionConfidence.CORRELATED
    assert resolved.process.start_ticks == 111


def test_the_start_ticks_are_coerced_to_an_integer(tmp_path):
    """`/proc` fields are text; the contract requires an integer. Coercing at
    the boundary keeps the failure here rather than in whichever consumer
    touches the value first."""
    table = _table(tmp_path)
    _proc(tmp_path, 7, uid=1000, start_ticks=99)
    record = table.note_start(7)
    assert record.start_ticks == 99
    assert isinstance(record.start_ticks, int)


# --- PID reuse: the risk the table introduces ------------------------------

def test_a_reused_pid_does_not_answer_for_the_earlier_generation(tmp_path):
    """The dangerous case, and the reason generations are kept.

    A network event from before the reuse must not be attributed to the
    workload that now holds the number.
    """
    clock = Clock()
    table = _table(tmp_path, clock)
    _proc(tmp_path, 4242, uid=1500, start_ticks=111)
    table.note_start(4242)
    first_event = clock.now
    clock.advance(1)
    table.note_exit(4242)

    clock.advance(30)
    _proc(tmp_path, 4242, uid=1600, start_ticks=222)   # same pid, new process
    table.note_start(4242)
    second_event = clock.now

    first = table.resolve(_observation(4242, first_event), fall_back_to_proc=False)
    second = table.resolve(_observation(4242, second_event), fall_back_to_proc=False)
    assert first.process.entity.identifier == "1500"
    assert second.process.entity.identifier == "1600"
    assert first.process.start_ticks != second.process.start_ticks


def test_an_event_from_a_gap_between_generations_is_not_attributed(tmp_path):
    """A pid that was free when the event happened belongs to nobody."""
    clock = Clock()
    table = _table(tmp_path, clock)
    _proc(tmp_path, 4242, uid=1500, start_ticks=111)
    table.note_start(4242)
    clock.advance(1)
    table.note_exit(4242)
    gap = clock.now + timedelta(seconds=30)

    clock.advance(60)
    _proc(tmp_path, 4242, uid=1600, start_ticks=222)
    table.note_start(4242)

    resolved = table.resolve(_observation(4242, gap), fall_back_to_proc=False)
    assert resolved.process.entity is None, (
        "an event from a reuse gap was attributed to a live process")
    assert table.stats.generation_mismatch >= 1


def test_an_event_before_the_process_started_is_not_attributed(tmp_path):
    clock = Clock()
    table = _table(tmp_path, clock)
    before = clock.now - timedelta(minutes=5)
    _proc(tmp_path, 4242, uid=1500, start_ticks=111)
    table.note_start(4242)
    resolved = table.resolve(_observation(4242, before), fall_back_to_proc=False)
    assert resolved.process.entity is None


def test_a_second_start_closes_the_previous_generation(tmp_path):
    """An exit notification can be missed. Two live generations of one pid is
    impossible, so the older one must be treated as gone."""
    clock = Clock()
    table = _table(tmp_path, clock)
    _proc(tmp_path, 4242, uid=1500, start_ticks=111)
    table.note_start(4242)
    clock.advance(10)
    _proc(tmp_path, 4242, uid=1600, start_ticks=222)
    table.note_start(4242)

    generations = table._by_pid[4242]
    assert generations[0].exited_at is not None, (
        "the superseded generation was left open and can still answer")


def test_the_clock_tolerance_does_not_span_a_reuse(tmp_path):
    """Slack covers timestamp reconstruction, not a different process."""
    clock = Clock()
    table = _table(tmp_path, clock)
    _proc(tmp_path, 4242, uid=1500, start_ticks=111)
    table.note_start(4242)
    clock.advance(0.2)
    table.note_exit(4242)
    exited = clock.now
    clock.advance(600)
    _proc(tmp_path, 4242, uid=1600, start_ticks=222)
    table.note_start(4242)

    long_after = exited + timedelta(seconds=300)
    assert table.resolve(_observation(4242, long_after),
                         fall_back_to_proc=False).process.entity is None


# --- what it refuses to do -------------------------------------------------

def test_an_unattributable_observation_is_left_alone(tmp_path):
    """Interrupt context already discarded the pid. Re-deriving one would
    undo that decision."""
    table = _table(tmp_path)
    observation = NetworkObservation(
        observation_id="netobs-000000000002",
        operation=NetworkOperation.CONNECT_ATTEMPT, transport=Transport.TCP,
        direction=Direction.OUTBOUND,
        process=ProcessRef(pid=0, confidence=AttributionConfidence.NONE),
        local=None, remote=Endpoint("10.0.0.3", 443, AddressFamily.IPV4),
        observed_at=T0, sensor_id="tracefs_network")
    assert table.resolve(observation) is observation


def test_an_unknown_pid_with_no_proc_entry_stays_unresolved(tmp_path):
    table = _table(tmp_path)
    resolved = table.resolve(_observation(9999, T0))
    assert resolved.process.entity is None
    assert table.stats.unresolved == 1


def test_a_process_without_a_readable_uid_is_recorded_but_not_used(tmp_path):
    """Knowing a pid existed is weaker than knowing its uid, and the table
    must not invent the difference."""
    clock = Clock()
    table = _table(tmp_path, clock)
    record = table.note_start(5555)          # no /proc entry at all
    assert record is not None
    assert record.uid is None
    assert not record.enriched_live
    assert table.resolve(_observation(5555, clock.now),
                         fall_back_to_proc=False).process.entity is None


def test_the_fallback_to_proc_is_available_for_processes_predating_the_table(tmp_path):
    """An agent that just started has an empty table and a host full of
    running processes."""
    table = _table(tmp_path)
    _proc(tmp_path, 8888, uid=1700, start_ticks=333)
    resolved = table.resolve(_observation(8888, T0))
    assert resolved.process.entity.identifier == "1700"
    assert table.stats.resolved_from_proc == 1


# --- bounds ----------------------------------------------------------------

def test_exited_processes_age_out(tmp_path):
    clock = Clock()
    table = _table(tmp_path, clock, retention=timedelta(seconds=30))
    _proc(tmp_path, 4242, uid=1500, start_ticks=111)
    table.note_start(4242)
    table.note_exit(4242)
    clock.advance(31)
    _proc(tmp_path, 4243, uid=1500, start_ticks=112)
    table.note_start(4243)                    # triggers eviction
    assert 4242 not in table._by_pid
    assert table.stats.evicted_for_age >= 1


def test_a_live_process_is_not_evicted_by_age(tmp_path):
    """Only exited generations age out. Evicting a running process would
    make its connections unattributable while it is still connecting."""
    clock = Clock()
    table = _table(tmp_path, clock, retention=timedelta(seconds=1))
    _proc(tmp_path, 4242, uid=1500, start_ticks=111)
    table.note_start(4242)
    clock.advance(600)
    _proc(tmp_path, 4243, uid=1500, start_ticks=112)
    table.note_start(4243)
    assert 4242 in table._by_pid


def test_the_table_is_bounded_by_size(tmp_path):
    """A table fed by every fork on a busy host is otherwise a memory attack
    reachable by anyone who can start processes."""
    clock = Clock()
    table = _table(tmp_path, clock, max_processes=20)
    for pid in range(1000, 1100):
        _proc(tmp_path, pid, uid=1500, start_ticks=pid)
        table.note_start(pid)
    assert table.tracked <= 20
    assert table.stats.evicted_for_size >= 1


def test_generations_per_pid_are_bounded(tmp_path):
    clock = Clock()
    table = _table(tmp_path, clock)
    for generation in range(50):
        _proc(tmp_path, 4242, uid=1500 + generation, start_ticks=generation)
        table.note_start(4242)
        clock.advance(1)
    assert len(table._by_pid[4242]) <= 4


# --- ingest ----------------------------------------------------------------

@pytest.mark.parametrize("kind", ["host.process.exec", "host.process.fork"])
def test_a_start_event_feeds_the_table(tmp_path, kind):
    table = _table(tmp_path)
    _proc(tmp_path, 4242, uid=1500, start_ticks=111)
    table.ingest({"kind": kind, "attributes": {"pid": 4242}})
    assert table.stats.observed_starts == 1


def test_an_exit_event_closes_the_generation(tmp_path):
    table = _table(tmp_path)
    _proc(tmp_path, 4242, uid=1500, start_ticks=111)
    table.ingest({"kind": "host.process.exec", "attributes": {"pid": 4242}})
    table.ingest({"kind": "host.process.exit", "attributes": {"pid": 4242}})
    assert table._by_pid[4242][-1].exited_at is not None


@pytest.mark.parametrize("event", [
    {}, {"kind": "host.process.exec"}, {"kind": "x", "attributes": {"pid": "x"}},
    {"kind": "host.process.exec", "attributes": {"pid": None}},
    {"kind": "unrelated.event", "attributes": {"pid": 1}}, None, 42, "exec"])
def test_a_malformed_event_is_ignored_rather_than_raising(tmp_path, event):
    """The table is fed from a sensor reader thread; raising there would
    stop process notifications entirely."""
    table = _table(tmp_path)
    table.ingest(event)


def test_health_reports_the_residual_limitation(tmp_path):
    """The window this does not close is stated in the data, not only in a
    docstring."""
    limitation = _table(tmp_path).health()["limitation"]
    assert "in-kernel" in limitation
