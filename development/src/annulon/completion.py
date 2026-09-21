"""Experiment lifecycle and completion manifests (ADR-029).

The distinction this module exists to preserve:

    a process exited   !=   an experiment completed

KF-22 was a controller that never terminated, so the next experiment's
listener silently failed to bind and produced an empty event journal. An
empty journal is indistinguishable from "nothing was detected" -- a negative
control that failed to start would have *passed*. The remedy at the time was
``os._exit(0)``, which V2 §3 correctly identified as the same failure in a new
shape: a killed run and a completed run became indistinguishable in the
evidence.

So completion is a claim that must be earned. A run is valid only when a
manifest exists, validates, belongs to this run, and records that each
required producer finalised. Anything else is ``EVIDENCE_INCOMPLETE`` and is
never reported as an absence of findings.

Crash safety: the manifest is written to a temporary file, fsynced, then
atomically replaced. A crash mid-finalise leaves no manifest rather than a
half-written one, so the next evaluator sees an incomplete run.
"""

from __future__ import annotations

import enum
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

__all__ = [
    "SCHEMA_VERSION",
    "RunState",
    "ExitReason",
    "CompletionStatus",
    "ProducerStatus",
    "CompletionManifest",
    "ManifestError",
    "ExperimentRecorder",
    "evaluate_run",
]

SCHEMA_VERSION = 1
_RUN_ID = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
MAX_MANIFEST_BYTES = 64 * 1024


class RunState(enum.Enum):
    """Normal progression, then the ways it can end badly."""

    CREATED = "created"
    STARTING = "starting"
    READY = "ready"            # the thing under test is demonstrably up
    RUNNING = "running"        # the scenario is executing
    FINALIZING = "finalizing"
    COMPLETED = "completed"

    ABORTED = "aborted"        # a precondition failed; scenario never ran
    TIMED_OUT = "timed_out"
    CRASHED = "crashed"
    KILLED = "killed"          # forced termination, including os._exit


NORMAL_ORDER = (RunState.CREATED, RunState.STARTING, RunState.READY,
                RunState.RUNNING, RunState.FINALIZING, RunState.COMPLETED)

TERMINAL_ABNORMAL = (RunState.ABORTED, RunState.TIMED_OUT,
                     RunState.CRASHED, RunState.KILLED)


class ExitReason(enum.Enum):
    NORMAL = "normal"
    DEADLINE = "deadline"      # the run's own time limit; still orderly
    SIGNAL = "signal"
    FORCED = "forced"          # hard kill; can never yield COMPLETE
    ERROR = "error"


class CompletionStatus(enum.Enum):
    COMPLETE = "complete"
    EVIDENCE_INCOMPLETE = "evidence_incomplete"


class ProducerStatus(enum.Enum):
    NOT_STARTED = "not_started"
    OPEN = "open"
    FINALIZED = "finalized"
    FAILED = "failed"


class ManifestError(Exception):
    """A manifest could not be read or does not describe a valid run."""


@dataclass(frozen=True)
class CompletionManifest:
    run_id: str
    scenario_id: str
    started_utc: str
    ended_utc: str
    state: RunState
    exit_reason: ExitReason
    producers: dict[str, ProducerStatus]
    artifact_hashes: dict[str, str]
    readiness: dict[str, bool]
    notes: tuple[str, ...] = ()
    schema_version: int = SCHEMA_VERSION

    @property
    def status(self) -> CompletionStatus:
        """COMPLETE is earned, never assumed.

        Every condition below has a matching failure mode from real runs:
        a controller that never became ready, a scenario that never started,
        a producer left open by a crash, and a forced kill that used to look
        like success.
        """
        if self.state is not RunState.COMPLETED:
            return CompletionStatus.EVIDENCE_INCOMPLETE
        if self.exit_reason is ExitReason.FORCED:
            return CompletionStatus.EVIDENCE_INCOMPLETE
        if not self.readiness.get("controller_ready", False):
            return CompletionStatus.EVIDENCE_INCOMPLETE
        if not self.readiness.get("scenario_started", False):
            return CompletionStatus.EVIDENCE_INCOMPLETE
        if not self.producers:
            return CompletionStatus.EVIDENCE_INCOMPLETE
        if any(s is not ProducerStatus.FINALIZED for s in self.producers.values()):
            return CompletionStatus.EVIDENCE_INCOMPLETE
        return CompletionStatus.COMPLETE

    @property
    def is_complete(self) -> bool:
        return self.status is CompletionStatus.COMPLETE

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "started_utc": self.started_utc,
            "ended_utc": self.ended_utc,
            "state": self.state.value,
            "exit_reason": self.exit_reason.value,
            "completion_status": self.status.value,
            "producers": {k: v.value for k, v in sorted(self.producers.items())},
            "readiness": dict(sorted(self.readiness.items())),
            "artifact_hashes": dict(sorted(self.artifact_hashes.items())),
            "notes": list(self.notes),
        }

    @staticmethod
    def from_dict(raw: object) -> "CompletionManifest":
        if not isinstance(raw, dict):
            raise ManifestError("manifest must be an object")
        version = raw.get("schema_version")
        if version != SCHEMA_VERSION:
            raise ManifestError(f"unsupported manifest schema {version!r}")
        try:
            run_id = raw["run_id"]
            if not isinstance(run_id, str) or not _RUN_ID.match(run_id):
                raise ManifestError(f"malformed run_id")
            producers = {
                str(k): ProducerStatus(v) for k, v in (raw.get("producers") or {}).items()
            }
            readiness = {
                str(k): bool(v) for k, v in (raw.get("readiness") or {}).items()
            }
            hashes = {
                str(k): str(v) for k, v in (raw.get("artifact_hashes") or {}).items()
            }
            return CompletionManifest(
                run_id=run_id,
                scenario_id=str(raw.get("scenario_id", "")),
                started_utc=str(raw.get("started_utc", "")),
                ended_utc=str(raw.get("ended_utc", "")),
                state=RunState(raw["state"]),
                exit_reason=ExitReason(raw["exit_reason"]),
                producers=producers,
                artifact_hashes=hashes,
                readiness=readiness,
                notes=tuple(str(n) for n in (raw.get("notes") or [])),
            )
        except ManifestError:
            raise
        except (KeyError, ValueError, TypeError, AttributeError) as exc:
            raise ManifestError(f"malformed manifest: {exc}") from exc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


class ExperimentRecorder:
    """Drives the lifecycle and writes the manifest atomically.

    Used as a context manager: an exception inside the block marks the run
    CRASHED and still writes a manifest, so a failure is recorded as a
    failure rather than leaving nothing behind to interpret.
    """

    MANIFEST_NAME = "completion.json"

    def __init__(self, directory: Path, run_id: str, scenario_id: str,
                 *, now=None) -> None:
        if not _RUN_ID.match(run_id):
            raise ValueError(f"malformed run_id {run_id!r}")
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.run_id = run_id
        self.scenario_id = scenario_id
        self._now = now or (lambda: datetime.now(timezone.utc))
        self.state = RunState.CREATED
        self.exit_reason = ExitReason.ERROR
        self.producers: dict[str, ProducerStatus] = {}
        self.readiness: dict[str, bool] = {
            "controller_ready": False, "scenario_started": False,
            "scenario_completed": False}
        self.notes: list[str] = []
        self._hashes: dict[str, str] = {}
        self.started_utc = self._now().isoformat()
        self._written = False

    # -- lifecycle -------------------------------------------------------

    def declare_producer(self, name: str) -> None:
        self.producers[name] = ProducerStatus.NOT_STARTED

    def producer_open(self, name: str) -> None:
        self.producers[name] = ProducerStatus.OPEN

    def producer_finalized(self, name: str) -> None:
        self.producers[name] = ProducerStatus.FINALIZED

    def producer_failed(self, name: str, note: str = "") -> None:
        self.producers[name] = ProducerStatus.FAILED
        if note:
            self.notes.append(note)

    def starting(self) -> None:
        self.state = RunState.STARTING

    def ready(self) -> None:
        """Only call this on positive evidence that the system under test is
        up -- never because a process was launched."""
        self.state = RunState.READY
        self.readiness["controller_ready"] = True

    def scenario_started(self) -> None:
        self.state = RunState.RUNNING
        self.readiness["scenario_started"] = True

    def scenario_completed(self) -> None:
        self.readiness["scenario_completed"] = True

    def abort(self, reason: str) -> None:
        self.state = RunState.ABORTED
        self.exit_reason = ExitReason.ERROR
        self.notes.append(reason)

    def timed_out(self) -> None:
        self.state = RunState.TIMED_OUT
        self.exit_reason = ExitReason.DEADLINE

    def killed(self, note: str = "forced termination") -> None:
        self.state = RunState.KILLED
        self.exit_reason = ExitReason.FORCED
        self.notes.append(note)

    # -- finalisation ----------------------------------------------------

    def finalize(self, exit_reason: ExitReason = ExitReason.NORMAL,
                 artifacts: tuple[str, ...] = ()) -> CompletionManifest:
        """Write the manifest atomically. Only reachable on an orderly path."""
        if self.state in TERMINAL_ABNORMAL:
            exit_reason = self.exit_reason
        else:
            self.state = RunState.FINALIZING
        for name in artifacts:
            path = self.directory / name
            if path.is_file():
                self._hashes[name] = _sha256(path)
            else:
                self.producers.setdefault(name, ProducerStatus.NOT_STARTED)
                self.notes.append(f"declared artifact missing: {name}")

        if self.state is RunState.FINALIZING:
            self.state = RunState.COMPLETED
        manifest = CompletionManifest(
            run_id=self.run_id, scenario_id=self.scenario_id,
            started_utc=self.started_utc, ended_utc=self._now().isoformat(),
            state=self.state, exit_reason=exit_reason,
            producers=dict(self.producers), artifact_hashes=dict(self._hashes),
            readiness=dict(self.readiness), notes=tuple(self.notes))
        self._write(manifest)
        return manifest

    def _write(self, manifest: CompletionManifest) -> None:
        payload = json.dumps(manifest.to_dict(), indent=2, sort_keys=True) + "\n"
        if len(payload.encode()) > MAX_MANIFEST_BYTES:
            raise ValueError("manifest exceeds its size bound")
        target = self.directory / self.MANIFEST_NAME
        tmp = target.with_suffix(".json.tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, target)
        self._written = True

    def __enter__(self) -> "ExperimentRecorder":
        self.starting()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc_type is not None and not self._written:
            self.state = RunState.CRASHED
            self.exit_reason = ExitReason.ERROR
            self.notes.append(f"exception: {exc_type.__name__}")
            self.finalize(ExitReason.ERROR)
        return False


def evaluate_run(directory: Path, expected_run_id: str,
                 required_artifacts: tuple[str, ...] = ()) -> tuple[CompletionStatus, str]:
    """The success invariant. Returns a status and a human reason.

    Never returns "no findings" -- that is a question for the evidence, and
    only a COMPLETE run is entitled to have its silence interpreted at all.
    """
    directory = Path(directory)
    path = directory / ExperimentRecorder.MANIFEST_NAME
    if not path.is_file():
        return CompletionStatus.EVIDENCE_INCOMPLETE, "no completion manifest"
    if path.stat().st_size > MAX_MANIFEST_BYTES:
        return CompletionStatus.EVIDENCE_INCOMPLETE, "manifest exceeds size bound"
    try:
        manifest = CompletionManifest.from_dict(json.loads(path.read_text()))
    except (json.JSONDecodeError, ManifestError) as exc:
        return CompletionStatus.EVIDENCE_INCOMPLETE, f"unreadable manifest: {exc}"
    if manifest.run_id != expected_run_id:
        return (CompletionStatus.EVIDENCE_INCOMPLETE,
                f"manifest belongs to run {manifest.run_id!r}, expected "
                f"{expected_run_id!r}")
    if not manifest.is_complete:
        return (CompletionStatus.EVIDENCE_INCOMPLETE,
                f"state={manifest.state.value} exit={manifest.exit_reason.value}")
    for name in required_artifacts:
        artifact = directory / name
        if not artifact.is_file():
            return CompletionStatus.EVIDENCE_INCOMPLETE, f"missing artifact {name}"
        recorded = manifest.artifact_hashes.get(name)
        if recorded is None:
            return CompletionStatus.EVIDENCE_INCOMPLETE, f"unhashed artifact {name}"
        if _sha256(artifact) != recorded:
            return (CompletionStatus.EVIDENCE_INCOMPLETE,
                    f"artifact {name} changed after the manifest was written")
    return CompletionStatus.COMPLETE, "complete"
