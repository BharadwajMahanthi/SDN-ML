"""Experiment completion semantics (ADR-029).

The property under test throughout: an empty, aborted, killed or truncated
run must never be readable as "nothing was detected".
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from padmavyuh.completion import (
    CompletionManifest,
    CompletionStatus,
    ExitReason,
    ExperimentRecorder,
    ManifestError,
    ProducerStatus,
    RunState,
    evaluate_run,
)

T0 = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
INCOMPLETE = CompletionStatus.EVIDENCE_INCOMPLETE
COMPLETE = CompletionStatus.COMPLETE


class FakeClock:
    def __init__(self) -> None:
        self.t = T0

    def __call__(self) -> datetime:
        self.t += timedelta(seconds=1)
        return self.t


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    d = tmp_path / "run"
    d.mkdir()
    return d


def good_run(directory: Path, run_id: str = "run-1") -> ExperimentRecorder:
    """A run that does everything right, for use as the positive control."""
    (directory / "events.jsonl").write_text('{"kind":"x"}\n')
    (directory / "ground_truth.json").write_text('{"scenario":"s"}\n')
    rec = ExperimentRecorder(directory, run_id, "scenario-a", now=FakeClock())
    rec.declare_producer("events")
    rec.declare_producer("ground_truth")
    rec.starting()
    rec.ready()
    rec.scenario_started()
    rec.producer_open("events")
    rec.scenario_completed()
    rec.producer_finalized("events")
    rec.producer_finalized("ground_truth")
    return rec


# -- the positive control --------------------------------------------------


def test_a_well_formed_run_is_complete(run_dir):
    rec = good_run(run_dir)
    manifest = rec.finalize(artifacts=("events.jsonl", "ground_truth.json"))
    assert manifest.is_complete
    status, reason = evaluate_run(run_dir, "run-1",
                                  ("events.jsonl", "ground_truth.json"))
    assert status is COMPLETE, reason


def test_the_manifest_is_written_atomically(run_dir):
    good_run(run_dir).finalize()
    assert (run_dir / "completion.json").is_file()
    assert not list(run_dir.glob("*.tmp")), "no temporary file may survive"


# -- every way a run can fail to complete ---------------------------------


def test_controller_never_ready(run_dir):
    rec = ExperimentRecorder(run_dir, "run-1", "s", now=FakeClock())
    rec.declare_producer("events")
    rec.starting()
    rec.abort("controller never listened")
    rec.finalize()
    status, reason = evaluate_run(run_dir, "run-1")
    assert status is INCOMPLETE and "aborted" in reason


def test_scenario_never_started(run_dir):
    rec = ExperimentRecorder(run_dir, "run-1", "s", now=FakeClock())
    rec.declare_producer("events")
    rec.starting()
    rec.ready()
    rec.producer_finalized("events")
    rec.finalize()
    assert evaluate_run(run_dir, "run-1")[0] is INCOMPLETE


def test_scenario_crash_is_recorded_not_lost(run_dir):
    with pytest.raises(RuntimeError):
        with ExperimentRecorder(run_dir, "run-1", "s", now=FakeClock()) as rec:
            rec.declare_producer("events")
            rec.ready()
            rec.scenario_started()
            raise RuntimeError("scenario blew up")
    status, reason = evaluate_run(run_dir, "run-1")
    assert status is INCOMPLETE
    manifest = CompletionManifest.from_dict(
        json.loads((run_dir / "completion.json").read_text()))
    assert manifest.state is RunState.CRASHED
    assert any("RuntimeError" in n for n in manifest.notes)


def test_timeout_is_not_completion(run_dir):
    rec = good_run(run_dir)
    rec.timed_out()
    rec.finalize()
    assert evaluate_run(run_dir, "run-1")[0] is INCOMPLETE


def test_forced_kill_can_never_be_complete(run_dir):
    """The ADR-029 rule: os._exit and friends are abnormal termination and
    must not be able to produce a successful manifest."""
    rec = good_run(run_dir)
    rec.killed("SIGKILL after deadline")
    manifest = rec.finalize()
    assert manifest.exit_reason is ExitReason.FORCED
    assert not manifest.is_complete
    assert evaluate_run(run_dir, "run-1")[0] is INCOMPLETE


def test_an_open_producer_blocks_completion(run_dir):
    rec = good_run(run_dir)
    rec.producer_open("events")          # a crash left it open
    assert not rec.finalize().is_complete


def test_a_failed_producer_blocks_completion(run_dir):
    rec = good_run(run_dir)
    rec.producer_failed("events", "write error")
    assert not rec.finalize().is_complete


def test_a_run_with_no_producers_is_incomplete(run_dir):
    rec = ExperimentRecorder(run_dir, "run-1", "s", now=FakeClock())
    rec.ready(); rec.scenario_started(); rec.finalize()
    assert evaluate_run(run_dir, "run-1")[0] is INCOMPLETE


# -- manifest integrity ----------------------------------------------------


def test_a_missing_manifest_is_incomplete(run_dir):
    status, reason = evaluate_run(run_dir, "run-1")
    assert status is INCOMPLETE and "no completion manifest" in reason


def test_a_process_that_exits_zero_without_a_manifest_is_incomplete(run_dir):
    """Exit status 0 is not evidence. Only the manifest is."""
    (run_dir / "events.jsonl").write_text("{}\n")
    assert evaluate_run(run_dir, "run-1")[0] is INCOMPLETE


@pytest.mark.parametrize(
    "content", ["", "{", "null", "[]", '"a string"', "123",
                '{"schema_version": 99}', '{"schema_version": 1}'])
def test_a_malformed_manifest_is_incomplete_not_a_crash(run_dir, content):
    (run_dir / "completion.json").write_text(content)
    status, _ = evaluate_run(run_dir, "run-1")
    assert status is INCOMPLETE


def test_a_manifest_from_another_run_is_rejected(run_dir):
    """Two runs must not be able to share completion state."""
    good_run(run_dir, run_id="run-OTHER").finalize()
    status, reason = evaluate_run(run_dir, "run-1")
    assert status is INCOMPLETE and "run-OTHER" in reason


def test_a_stale_manifest_from_a_previous_run_does_not_validate(run_dir):
    good_run(run_dir, run_id="run-1").finalize(artifacts=("events.jsonl",))
    assert evaluate_run(run_dir, "run-1", ("events.jsonl",))[0] is COMPLETE
    assert evaluate_run(run_dir, "run-2", ("events.jsonl",))[0] is INCOMPLETE


@pytest.mark.parametrize("bad_id", ["", " ", "../escape", "a" * 100, "x/y"])
def test_malformed_run_ids_are_refused(run_dir, bad_id):
    with pytest.raises(ValueError):
        ExperimentRecorder(run_dir, bad_id, "s")


def test_an_oversized_manifest_is_incomplete(run_dir):
    (run_dir / "completion.json").write_text("{" + " " * 200_000 + "}")
    status, reason = evaluate_run(run_dir, "run-1")
    assert status is INCOMPLETE and "size bound" in reason


# -- artifact integrity ----------------------------------------------------


def test_a_missing_required_artifact_is_incomplete(run_dir):
    good_run(run_dir).finalize(artifacts=("events.jsonl",))
    (run_dir / "events.jsonl").unlink()
    status, reason = evaluate_run(run_dir, "run-1", ("events.jsonl",))
    assert status is INCOMPLETE and "missing artifact" in reason


def test_an_artifact_changed_after_the_manifest_is_detected(run_dir):
    """Evidence altered after the run is not evidence."""
    good_run(run_dir).finalize(artifacts=("events.jsonl",))
    (run_dir / "events.jsonl").write_text('{"kind":"tampered"}\n')
    status, reason = evaluate_run(run_dir, "run-1", ("events.jsonl",))
    assert status is INCOMPLETE and "changed after" in reason


def test_a_truncated_event_stream_is_detected_by_its_hash(run_dir):
    (run_dir / "events.jsonl").write_text('{"a":1}\n{"b":2}\n{"c":3}\n')
    good_run(run_dir).finalize(artifacts=("events.jsonl",))
    (run_dir / "events.jsonl").write_text('{"a":1}\n')
    assert evaluate_run(run_dir, "run-1", ("events.jsonl",))[0] is INCOMPLETE


def test_an_unhashed_required_artifact_is_incomplete(run_dir):
    good_run(run_dir).finalize()          # no artifacts declared
    assert evaluate_run(run_dir, "run-1", ("events.jsonl",))[0] is INCOMPLETE


def test_a_declared_but_absent_artifact_is_noted(run_dir):
    rec = good_run(run_dir)
    manifest = rec.finalize(artifacts=("never_written.json",))
    assert not manifest.is_complete
    assert any("missing" in n for n in manifest.notes)


# -- the headline property -------------------------------------------------


def test_an_empty_run_is_never_clean(run_dir):
    """The single most important behaviour in this module. A run that
    produced no events must be EVIDENCE_INCOMPLETE, never 'no attack'."""
    rec = ExperimentRecorder(run_dir, "run-1", "s", now=FakeClock())
    rec.declare_producer("events")
    rec.starting()
    # nothing else happens: the controller never came up, as in KF-22
    rec.finalize()
    status, _ = evaluate_run(run_dir, "run-1")
    assert status is INCOMPLETE
    assert status is not COMPLETE


def test_only_a_complete_run_may_have_its_silence_interpreted(run_dir):
    """Expressed as the caller must use it: no findings is meaningful only
    when the run is COMPLETE."""
    (run_dir / "findings.jsonl").write_text("")
    rec = good_run(run_dir)
    rec.producer_finalized("findings")
    rec.finalize(artifacts=("findings.jsonl",))
    status, _ = evaluate_run(run_dir, "run-1", ("findings.jsonl",))
    assert status is COMPLETE
    assert (run_dir / "findings.jsonl").read_text() == ""
