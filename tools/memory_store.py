"""JSONL-backed rolling project memory: locking, quota, retention, recovery.

Storage layout (all paths relative to the repository root)::

    memory/policy.json                       budgets + retention parameters
    memory/runtime/state.json                bounded control metadata
    memory/runtime/index.json                acceleration only, rebuildable
    memory/runtime/lock                       one canonical mutation lock
    memory/runtime/recovery.json             bounded recovery event log
    memory/runtime/gc_manifest.json          last GC dry-run / apply manifest
    memory/runtime/buckets/bucket_%06d_%06d.jsonl

The JSONL bucket files are the authoritative journal. ``index.json`` is an
acceleration structure and is fully reconstructible from the buckets; nothing
in this module makes correctness depend on it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Protocol
from zoneinfo import ZoneInfo

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.redact import redact

SCHEMA_VERSION = 1
BUCKET_RE = re.compile(r"\Abucket_(?P<start>\d{6})_(?P<end>\d{6})\.jsonl\Z")
STAGED_SUFFIX = ".gc-staged"


# --------------------------------------------------------------- errors


class MemoryBlocked(Exception):
    """Base for refusals. ``code`` is the stable machine-readable reason."""

    code = "MEMORY_BLOCKED"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.code}: {super().__str__()}"


class QuotaBlocked(MemoryBlocked):
    code = "MEMORY_QUOTA_BLOCKED"


class RetentionBlocked(MemoryBlocked):
    code = "RETENTION_BLOCKED"


class CorruptionBlocked(MemoryBlocked):
    code = "MEMORY_CORRUPTION_BLOCKED"


class LockBusy(MemoryBlocked):
    code = "MEMORY_LOCK_BUSY"


class ForbiddenContent(MemoryBlocked):
    code = "MEMORY_FORBIDDEN_CONTENT"


class InvalidRecord(MemoryBlocked):
    code = "MEMORY_INVALID_RECORD"


# ---------------------------------------------------------------- clock


class Clock(Protocol):
    def now_utc(self) -> datetime: ...
    def project_date(self) -> date: ...


@dataclass
class SystemClock:
    tz: str = "Asia/Kolkata"

    def now_utc(self) -> datetime:
        return datetime.now(timezone.utc)

    def project_date(self) -> date:
        return datetime.now(ZoneInfo(self.tz)).date()


@dataclass
class FakeClock:
    """Deterministic clock for retention tests. No sleeps, ever."""

    current: date
    tz: str = "Asia/Kolkata"

    def now_utc(self) -> datetime:
        return datetime(
            self.current.year, self.current.month, self.current.day,
            12, 0, 0, tzinfo=timezone.utc,
        )

    def project_date(self) -> date:
        return self.current

    def set(self, value: date) -> None:
        self.current = value


# --------------------------------------------------------------- policy


@dataclass(frozen=True)
class Quota:
    total_bytes: int
    journal_bytes: int
    metadata_bytes: int
    transaction_reserve_bytes: int
    max_record_bytes: int
    max_bucket_bytes: int


@dataclass(frozen=True)
class Retention:
    bucket_days: int
    max_active_buckets: int
    retention_effective_days: int
    idle_gap_threshold_days: int

    @property
    def eligibility_offset(self) -> int:
        """A bucket ending on day E is eligible when effective_day >= E + this."""
        return self.retention_effective_days - self.bucket_days + 1


@dataclass(frozen=True)
class MemoryPolicy:
    schema_version: int
    project_id: str
    timezone: str
    retention: Retention
    quota: Quota
    lock_timeout_seconds: float
    lock_poll_seconds: float
    durable_documents: tuple[str, ...]

    @staticmethod
    def load(path: Path) -> "MemoryPolicy":
        raw = json.loads(path.read_text())
        r, q, lk = raw["retention"], raw["quota"], raw.get("lock", {})
        return MemoryPolicy(
            schema_version=int(raw["schema_version"]),
            project_id=str(raw["project_id"]),
            timezone=str(raw.get("timezone", "Asia/Kolkata")),
            retention=Retention(
                bucket_days=int(r["bucket_days"]),
                max_active_buckets=int(r["max_active_buckets"]),
                retention_effective_days=int(r["retention_effective_days"]),
                idle_gap_threshold_days=int(r["idle_gap_threshold_days"]),
            ),
            quota=Quota(
                total_bytes=int(q["total_bytes"]),
                journal_bytes=int(q["journal_bytes"]),
                metadata_bytes=int(q["metadata_bytes"]),
                transaction_reserve_bytes=int(q["transaction_reserve_bytes"]),
                max_record_bytes=int(q["max_record_bytes"]),
                max_bucket_bytes=int(q["max_bucket_bytes"]),
            ),
            lock_timeout_seconds=float(lk.get("timeout_seconds", 30)),
            lock_poll_seconds=float(lk.get("poll_seconds", 0.05)),
            durable_documents=tuple(raw.get("durable_documents", ())),
        )


# ------------------------------------------------------------------ io


def _fsync_dir(directory: Path) -> None:
    if os.name == "nt":  # pragma: no cover - platform specific
        return
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write_text(path: Path, text: str) -> None:
    """Replace ``path`` atomically: temp file -> fsync -> os.replace -> fsync dir."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.tmp-{uuid.uuid4().hex[:8]}"
    with tmp.open("w", encoding="utf-8") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    _fsync_dir(path.parent)


def atomic_write_json(path: Path, payload: Any) -> None:
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


# ---------------------------------------------------------------- lock


class MemoryLock:
    """One canonical cross-process mutation lock.

    Uses ``fcntl.flock`` on POSIX and ``msvcrt.locking`` on Windows -- both
    are kernel-level and therefore hold between separate Claude Code and
    Codex processes, which an in-process mutex would not.
    """

    def __init__(self, path: Path, *, timeout: float, poll: float) -> None:
        self.path = path
        self.timeout = timeout
        self.poll = poll
        self._fh = None

    def __enter__(self) -> "MemoryLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("a+")
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                self._acquire()
                break
            except OSError:
                if time.monotonic() >= deadline:
                    self._fh.close()
                    self._fh = None
                    raise LockBusy(
                        f"another agent holds {self.path.name} "
                        f"(waited {self.timeout}s)"
                    ) from None
                time.sleep(self.poll)
        self._fh.seek(0)
        self._fh.truncate()
        # Fixed-width payload: the lock file counts toward the storage quota,
        # and a variable-length pid/timestamp made total usage -- and therefore
        # the quota boundary -- nondeterministic between runs.
        self._fh.write(json.dumps({
            "acquired_ns": f"{time.time_ns():019d}",
            "pid": f"{os.getpid():010d}",
        }))
        self._fh.flush()
        return self

    def __exit__(self, *exc: object) -> None:
        if self._fh is None:
            return
        try:
            self._release()
        finally:
            self._fh.close()
            self._fh = None

    def _acquire(self) -> None:
        if os.name == "nt":  # pragma: no cover - platform specific
            import msvcrt

            msvcrt.locking(self._fh.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _release(self) -> None:
        if os.name == "nt":  # pragma: no cover - platform specific
            import msvcrt

            self._fh.seek(0)
            msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)


# -------------------------------------------------------------- records


@dataclass
class Record:
    record_id: str
    sequence: int
    session_id: str
    task_id: str
    agent: str
    timestamp_utc: str
    project_date: str
    effective_day: int
    kind: str = "development"
    base_commit: str = ""
    dirty_digest: str = ""
    changed_paths: list[str] = field(default_factory=list)
    changed_symbols: list[str] = field(default_factory=list)
    tests: list[dict] = field(default_factory=list)
    decisions: list[dict] = field(default_factory=list)
    blockers: list[dict] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    next_action: str = ""
    schema_version: int = SCHEMA_VERSION

    def to_line(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":")) + "\n"

    @staticmethod
    def from_obj(obj: dict) -> "Record":
        known = {f for f in Record.__dataclass_fields__}
        return Record(**{k: v for k, v in obj.items() if k in known})

    def unresolved_blockers(self) -> list[dict]:
        return [b for b in self.blockers if not b.get("resolved", False)]


@dataclass
class State:
    schema_version: int = SCHEMA_VERSION
    project_id: str = ""
    last_development_date: str | None = None
    effective_day: int = 0
    current_bucket: str | None = None
    last_sequence: int = 0
    gc_state: dict = field(default_factory=dict)
    resumption_protected: bool = False
    resumption_session_id: str | None = None
    storage_usage: dict = field(default_factory=dict)
    clock_anomalies: int = 0

    @staticmethod
    def load(path: Path, project_id: str) -> "State":
        if not path.is_file():
            return State(project_id=project_id)
        raw = json.loads(path.read_text())
        known = {f for f in State.__dataclass_fields__}
        return State(**{k: v for k, v in raw.items() if k in known})


@dataclass
class BucketInfo:
    name: str
    path: Path
    start_day: int
    end_day: int


@dataclass
class ValidationIssue:
    code: str
    detail: str


def bucket_bounds(effective_day: int, bucket_days: int) -> tuple[int, int]:
    k = (effective_day - 1) // bucket_days
    return k * bucket_days + 1, (k + 1) * bucket_days


def bucket_name(start: int, end: int) -> str:
    return f"bucket_{start:06d}_{end:06d}.jsonl"


# --------------------------------------------------------------- store


class MemoryStore:
    """All mutations happen under one lock and leave the journal consistent."""

    def __init__(self, root: Path, *, policy: MemoryPolicy | None = None,
                 clock: Clock | None = None) -> None:
        self.root = Path(root)
        self.policy = policy or MemoryPolicy.load(self.root / "memory" / "policy.json")
        self.clock = clock or SystemClock(self.policy.timezone)
        self.runtime = self.root / "memory" / "runtime"
        self.buckets_dir = self.runtime / "buckets"
        self.state_path = self.runtime / "state.json"
        self.index_path = self.runtime / "index.json"
        self.lock_path = self.runtime / "lock"
        self.recovery_path = self.runtime / "recovery.json"
        self.manifest_path = self.runtime / "gc_manifest.json"
        self.buckets_dir.mkdir(parents=True, exist_ok=True)

    # -- plumbing --------------------------------------------------------

    def lock(self) -> MemoryLock:
        return MemoryLock(
            self.lock_path,
            timeout=self.policy.lock_timeout_seconds,
            poll=self.policy.lock_poll_seconds,
        )

    def load_state(self) -> State:
        return State.load(self.state_path, self.policy.project_id)

    def save_state(self, state: State) -> None:
        state.storage_usage = self.usage()
        atomic_write_json(self.state_path, asdict(state))

    def buckets(self) -> list[BucketInfo]:
        out = []
        for path in sorted(self.buckets_dir.glob("bucket_*.jsonl")):
            m = BUCKET_RE.match(path.name)
            if m:
                out.append(BucketInfo(path.name, path, int(m["start"]), int(m["end"])))
        return sorted(out, key=lambda b: b.start_day)

    def staged_buckets(self) -> list[Path]:
        return sorted(self.buckets_dir.glob(f"bucket_*.jsonl{STAGED_SUFFIX}"))

    def usage(self) -> dict:
        def size(p: Path) -> int:
            return p.stat().st_size if p.is_file() else 0

        journal = sum(size(b.path) for b in self.buckets())
        staged = sum(size(p) for p in self.staged_buckets())
        metadata = sum(
            size(p) for p in (self.state_path, self.index_path,
                              self.recovery_path, self.manifest_path, self.lock_path)
        )
        return {
            "journal_bytes": journal,
            "staged_bytes": staged,
            "metadata_bytes": metadata,
            "total_bytes": journal + staged + metadata,
        }

    # -- reading ---------------------------------------------------------

    def scan_bucket(self, path: Path) -> tuple[list[Record], list[int], bool]:
        """Return (records, bad_line_numbers, trailing_only).

        ``trailing_only`` is True when the sole malformed line is the final
        one and it lacks a terminating newline -- the signature of an append
        interrupted mid-write, which ``repair_tail`` may truncate.
        """
        if not path.is_file():
            return [], [], False
        raw = path.read_bytes()
        if not raw:
            return [], [], False
        text = raw.decode("utf-8", errors="replace")
        ends_with_newline = text.endswith("\n")
        lines = text.split("\n")
        if ends_with_newline:
            lines = lines[:-1]

        records: list[Record] = []
        bad: list[int] = []
        for number, line in enumerate(lines, start=1):
            if not line.strip():
                bad.append(number)
                continue
            try:
                records.append(Record.from_obj(json.loads(line)))
            except (json.JSONDecodeError, TypeError):
                bad.append(number)
        trailing_only = bad == [len(lines)] and not ends_with_newline
        return records, bad, trailing_only

    def iter_records(self) -> Iterator[Record]:
        for bucket in self.buckets():
            records, bad, _ = self.scan_bucket(bucket.path)
            if bad:
                raise CorruptionBlocked(
                    f"{bucket.name} has malformed line(s) {bad}; evidence preserved"
                )
            yield from records

    # -- validation ------------------------------------------------------

    def validate(self) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []
        state = self.load_state()
        seen_ids: set[str] = set()
        previous_sequence = 0
        max_sequence = 0

        for bucket in self.buckets():
            records, bad, trailing_only = self.scan_bucket(bucket.path)
            if bad:
                code = "TRAILING_PARTIAL_RECORD" if trailing_only else "MID_FILE_CORRUPTION"
                issues.append(ValidationIssue(code, f"{bucket.name} lines={bad}"))
            size = bucket.path.stat().st_size
            if size > self.policy.quota.max_bucket_bytes:
                issues.append(ValidationIssue(
                    "BUCKET_OVER_BUDGET", f"{bucket.name} {size}B"))
            for record in records:
                if record.record_id in seen_ids:
                    issues.append(ValidationIssue(
                        "DUPLICATE_RECORD_ID", f"{bucket.name} {record.record_id}"))
                seen_ids.add(record.record_id)
                if record.sequence <= previous_sequence:
                    issues.append(ValidationIssue(
                        "SEQUENCE_REGRESSION",
                        f"{bucket.name} seq={record.sequence} after {previous_sequence}"))
                previous_sequence = max(previous_sequence, record.sequence)
                max_sequence = max(max_sequence, record.sequence)
                if not (bucket.start_day <= record.effective_day <= bucket.end_day):
                    issues.append(ValidationIssue(
                        "RECORD_IN_WRONG_BUCKET",
                        f"{bucket.name} day={record.effective_day}"))

        if state.last_sequence < max_sequence:
            issues.append(ValidationIssue(
                "STATE_BEHIND_JOURNAL",
                f"state={state.last_sequence} journal={max_sequence}; "
                "journal is authoritative, reconcile will heal this"))
        if len(self.buckets()) > self.policy.retention.max_active_buckets:
            issues.append(ValidationIssue(
                "TOO_MANY_BUCKETS", f"{len(self.buckets())} active"))
        if not self.index_path.is_file():
            issues.append(ValidationIssue("INDEX_MISSING", "rebuildable from buckets"))
        else:
            try:
                json.loads(self.index_path.read_text())
            except json.JSONDecodeError:
                issues.append(ValidationIssue("INDEX_CORRUPT", "rebuildable from buckets"))
        if self.staged_buckets() or state.gc_state:
            issues.append(ValidationIssue(
                "GC_IN_PROGRESS", f"gc_state={state.gc_state or 'empty'}"))
        return issues

    def assert_no_corruption(self) -> None:
        for issue in self.validate():
            if issue.code == "MID_FILE_CORRUPTION":
                raise CorruptionBlocked(issue.detail)

    # -- index -----------------------------------------------------------

    def rebuild_index(self) -> dict:
        entries = []
        for bucket in self.buckets():
            records, bad, _ = self.scan_bucket(bucket.path)
            if bad:
                raise CorruptionBlocked(f"{bucket.name} lines={bad}")
            digest = hashlib.sha256(bucket.path.read_bytes()).hexdigest()
            entries.append({
                "bucket": bucket.name,
                "first_sequence": records[0].sequence if records else None,
                "last_sequence": records[-1].sequence if records else None,
                "first_effective_day": bucket.start_day,
                "last_effective_day": bucket.end_day,
                "record_count": len(records),
                "byte_size": bucket.path.stat().st_size,
                "task_ids": sorted({r.task_id for r in records if r.task_id}),
                "unresolved_marker_count": sum(len(r.unresolved_blockers()) for r in records),
                "checksum": digest,
            })
        index = {"schema_version": SCHEMA_VERSION, "buckets": entries}
        atomic_write_json(self.index_path, index)
        return index

    def reconcile(self, state: State) -> State:
        """Heal state drift from the authoritative journal. Caller holds the lock."""
        max_sequence = 0
        last_day = state.effective_day
        for bucket in self.buckets():
            records, bad, _ = self.scan_bucket(bucket.path)
            if bad:
                raise CorruptionBlocked(f"{bucket.name} lines={bad}")
            for record in records:
                max_sequence = max(max_sequence, record.sequence)
                last_day = max(last_day, record.effective_day)
        if max_sequence > state.last_sequence:
            state.last_sequence = max_sequence
        if last_day > state.effective_day:
            state.effective_day = last_day
        return state

    # -- effective-day arithmetic ---------------------------------------

    def next_effective_day(self, state: State, today: date) -> tuple[int, str]:
        """Return (effective_day, transition) applying the >20-idle-day rule."""
        if state.last_development_date is None:
            return 1, "first"
        last = date.fromisoformat(state.last_development_date)
        if today == last:
            return state.effective_day, "same_day"
        if today < last:
            # Clock regression must never age or delete memory.
            return state.effective_day, "clock_regression"
        delta = (today - last).days
        idle = delta - 1
        if idle <= self.policy.retention.idle_gap_threshold_days:
            return state.effective_day + delta, "normal"
        return state.effective_day + 1, "long_gap"

    # -- checkpoint ------------------------------------------------------

    def _validate_payload(self, payload: dict) -> str:
        line = json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
        size = len(line.encode("utf-8"))
        if size > self.policy.quota.max_record_bytes:
            raise QuotaBlocked(
                f"single checkpoint is {size}B, limit is "
                f"{self.policy.quota.max_record_bytes}B -- summarise it locally"
            )
        result = redact(line)
        if result.findings:
            kinds = sorted({f.kind for f in result.findings})
            raise ForbiddenContent(
                f"checkpoint contains probable secret material ({', '.join(kinds)}); "
                "values withheld and nothing was written"
            )
        return line

    def _check_quota(self, bucket_path: Path, line_bytes: int) -> None:
        q = self.policy.quota
        usage = self.usage()
        bucket_size = bucket_path.stat().st_size if bucket_path.is_file() else 0
        if bucket_size + line_bytes > q.max_bucket_bytes:
            raise QuotaBlocked(
                f"bucket {bucket_path.name} would reach "
                f"{bucket_size + line_bytes}B, limit {q.max_bucket_bytes}B")
        if usage["journal_bytes"] + line_bytes > q.journal_bytes:
            raise QuotaBlocked(
                f"journal would reach {usage['journal_bytes'] + line_bytes}B, "
                f"limit {q.journal_bytes}B")
        projected = usage["total_bytes"] + line_bytes + q.transaction_reserve_bytes
        if projected > q.total_bytes:
            raise QuotaBlocked(
                f"projected {projected}B (usage {usage['total_bytes']}B + record "
                f"{line_bytes}B + {q.transaction_reserve_bytes}B transaction reserve) "
                f"exceeds cap {q.total_bytes}B -- protected history was NOT deleted")

    def checkpoint(
        self,
        *,
        session_id: str,
        task_id: str,
        agent: str,
        substantive: bool = True,
        kind: str = "development",
        base_commit: str = "",
        dirty_digest: str = "",
        changed_paths: list[str] | None = None,
        changed_symbols: list[str] | None = None,
        tests: list[dict] | None = None,
        decisions: list[dict] | None = None,
        blockers: list[dict] | None = None,
        evidence_refs: list[str] | None = None,
        next_action: str = "",
    ) -> Record:
        with self.lock():
            self.assert_no_corruption()
            self.recover_gc_unlocked()
            state = self.reconcile(self.load_state())
            today = self.clock.project_date()

            if substantive:
                effective_day, transition = self.next_effective_day(state, today)
            else:
                effective_day = max(state.effective_day, 1)
                transition = "non_substantive"

            start, end = bucket_bounds(effective_day, self.policy.retention.bucket_days)
            bucket_path = self.buckets_dir / bucket_name(start, end)

            record = Record(
                record_id=uuid.uuid4().hex,
                sequence=state.last_sequence + 1,
                session_id=session_id,
                task_id=task_id,
                agent=agent,
                timestamp_utc=self.clock.now_utc().isoformat(),
                project_date=today.isoformat(),
                effective_day=effective_day,
                kind=kind,
                base_commit=base_commit,
                dirty_digest=dirty_digest,
                changed_paths=list(changed_paths or []),
                changed_symbols=list(changed_symbols or []),
                tests=list(tests or []),
                decisions=list(decisions or []),
                blockers=list(blockers or []),
                evidence_refs=list(evidence_refs or []),
                next_action=next_action,
            )
            line = self._validate_payload(asdict(record))
            self._check_quota(bucket_path, len(line.encode("utf-8")))

            # Journal append is the commit point. State follows; if the process
            # dies between them, reconcile() heals from the journal on next run.
            with bucket_path.open("a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())
            _fsync_dir(bucket_path.parent)

            state.last_sequence = record.sequence
            state.effective_day = effective_day
            state.current_bucket = bucket_path.name
            state.project_id = self.policy.project_id
            if substantive and transition != "clock_regression":
                state.last_development_date = today.isoformat()
            if transition == "clock_regression":
                state.clock_anomalies += 1
            if transition == "long_gap":
                state.resumption_protected = True
                state.resumption_session_id = session_id
            elif state.resumption_protected and state.resumption_session_id != session_id:
                state.resumption_protected = False
                state.resumption_session_id = None
            self.save_state(state)
            self.rebuild_index()
            return record

    def resume(self, *, session_id: str, agent: str, next_action: str = "") -> Record:
        """First session after a long gap: reconcile, then journal a marker."""
        return self.checkpoint(
            session_id=session_id, task_id="RESUMPTION", agent=agent,
            kind="resumption", next_action=next_action or "reconcile and continue",
        )

    # -- garbage collection ---------------------------------------------

    def eligible_buckets(self, state: State) -> list[BucketInfo]:
        offset = self.policy.retention.eligibility_offset
        return [b for b in self.buckets() if state.effective_day >= b.end_day + offset]

    def _promotion_plan(self, bucket: BucketInfo) -> dict:
        records, bad, _ = self.scan_bucket(bucket.path)
        if bad:
            raise CorruptionBlocked(f"{bucket.name} lines={bad}")
        decisions, blockers = [], []
        for record in records:
            for decision in record.decisions:
                if decision.get("status") != "superseded":
                    decisions.append({"record_id": record.record_id,
                                      "effective_day": record.effective_day, **decision})
            for blocker in record.unresolved_blockers():
                blockers.append({"record_id": record.record_id,
                                 "effective_day": record.effective_day, **blocker})
        return {
            "bucket": bucket.name,
            "record_count": len(records),
            "byte_size": bucket.path.stat().st_size,
            "decisions_to_promote": decisions,
            "unresolved_blockers_to_promote": blockers,
        }

    def _append_doc(self, relative: str, heading: str, entries: list[dict]) -> list[str]:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.is_file():
            path.write_text(f"# {Path(relative).stem.replace('_', ' ').title()}\n")
        markers = []
        chunks = [f"\n## {heading}\n"]
        for entry in entries:
            marker = f"<!-- promoted:{entry['record_id']} -->"
            markers.append(marker)
            title = entry.get("title") or entry.get("summary") or entry.get("id", "entry")
            body = entry.get("detail") or entry.get("why") or ""
            chunks.append(
                f"\n- {marker} **{title}** (effective day {entry['effective_day']})"
                + (f"\n  {body}" if body else "")
            )
        atomic_write_text(path, path.read_text() + "".join(chunks) + "\n")
        return markers

    def gc(self, *, apply: bool = False) -> dict:
        with self.lock():
            self.assert_no_corruption()
            self.recover_gc_unlocked()
            state = self.reconcile(self.load_state())
            eligible = self.eligible_buckets(state)

            manifest = {
                "generated_utc": self.clock.now_utc().isoformat(),
                "effective_day": state.effective_day,
                "eligibility_offset": self.policy.retention.eligibility_offset,
                "active_buckets": [b.name for b in self.buckets()],
                "eligible_buckets": [b.name for b in eligible],
                "applied": False,
                "plans": [self._promotion_plan(b) for b in eligible],
            }

            if state.resumption_protected:
                manifest["blocked"] = RetentionBlocked.code
                manifest["reason"] = (
                    "first session after a >"
                    f"{self.policy.retention.idle_gap_threshold_days}-day gap is "
                    "GC-protected; a later session may rotate")
                atomic_write_json(self.manifest_path, manifest)
                if apply:
                    raise RetentionBlocked(manifest["reason"])
                return manifest

            if not apply or not eligible:
                atomic_write_json(self.manifest_path, manifest)
                return manifest

            bucket = eligible[0]
            plan = manifest["plans"][0]
            markers: list[str] = []
            if plan["decisions_to_promote"]:
                markers += self._append_doc(
                    "docs/DECISIONS.md",
                    f"Promoted from {bucket.name}", plan["decisions_to_promote"])
            if plan["unresolved_blockers_to_promote"]:
                markers += self._append_doc(
                    "docs/CURRENT_STATE.md",
                    f"Unresolved blockers promoted from {bucket.name}",
                    plan["unresolved_blockers_to_promote"])

            missing = [m for m in markers
                       if not any(m in (self.root / d).read_text()
                                  for d in self.policy.durable_documents
                                  if (self.root / d).is_file())]
            if missing:
                raise RetentionBlocked(
                    f"promotion validation failed for {len(missing)} entr(ies); "
                    f"{bucket.name} retained")

            staged = bucket.path.with_name(bucket.path.name + STAGED_SUFFIX)
            state.gc_state = {"phase": "preparing", "bucket": bucket.name,
                              "staged": staged.name, "markers": len(markers)}
            self.save_state(state)

            os.replace(bucket.path, staged)
            _fsync_dir(self.buckets_dir)

            state.gc_state = {"phase": "staged", "bucket": bucket.name,
                              "staged": staged.name, "markers": len(markers)}
            self.save_state(state)

            staged.unlink()
            _fsync_dir(self.buckets_dir)

            state.gc_state = {}
            self.save_state(state)
            self.rebuild_index()

            manifest["applied"] = True
            manifest["retired_bucket"] = bucket.name
            manifest["promoted_markers"] = len(markers)
            atomic_write_json(self.manifest_path, manifest)
            return manifest

    def recover_gc_unlocked(self) -> str | None:
        """Resolve any interrupted rotation. Caller holds the lock.

        preparing + staged present -> restore (bucket survives)
        staged    + staged present -> complete the unlink
        staged    + staged absent  -> clear state, rotation already finished
        """
        state = self.load_state()
        gc_state = state.gc_state or {}
        phase = gc_state.get("phase")
        if not phase:
            return None
        staged = self.buckets_dir / gc_state.get("staged", "")
        if phase == "preparing":
            if staged.is_file():
                os.replace(staged, staged.with_name(gc_state["bucket"]))
                _fsync_dir(self.buckets_dir)
            outcome = "restored"
        elif phase == "staged":
            if staged.is_file():
                staged.unlink()
                _fsync_dir(self.buckets_dir)
            outcome = "completed"
        else:
            raise RetentionBlocked(f"unknown gc phase {phase!r}; nothing deleted")
        state.gc_state = {}
        self.save_state(state)
        self._record_recovery({"kind": "gc_recovery", "phase": phase, "outcome": outcome,
                               "bucket": gc_state.get("bucket")})
        return outcome

    def recover_gc(self) -> str | None:
        with self.lock():
            return self.recover_gc_unlocked()

    # -- tail repair -----------------------------------------------------

    def repair_tail(self, bucket_name_: str | None = None) -> list[dict]:
        """Truncate a provably incomplete FINAL record. Never touches mid-file."""
        repaired = []
        with self.lock():
            targets = [b for b in self.buckets()
                       if bucket_name_ is None or b.name == bucket_name_]
            for bucket in targets:
                records, bad, trailing_only = self.scan_bucket(bucket.path)
                if not bad:
                    continue
                if not trailing_only:
                    raise CorruptionBlocked(
                        f"{bucket.name} has mid-file corruption at lines {bad}; "
                        "refusing to repair, evidence preserved")
                raw = bucket.path.read_bytes()
                cut = raw.rfind(b"\n")
                keep = raw[: cut + 1] if cut >= 0 else b""
                tmp = bucket.path.with_suffix(".jsonl.repair-tmp")
                tmp.write_bytes(keep)
                os.replace(tmp, bucket.path)
                _fsync_dir(self.buckets_dir)
                event = {"kind": "tail_repair", "bucket": bucket.name,
                         "dropped_bytes": len(raw) - len(keep),
                         "records_kept": len(records)}
                self._record_recovery(event)
                repaired.append(event)
            if repaired:
                state = self.reconcile(self.load_state())
                self.save_state(state)
                self.rebuild_index()
        return repaired

    def _record_recovery(self, event: dict) -> None:
        events = []
        if self.recovery_path.is_file():
            try:
                events = json.loads(self.recovery_path.read_text()).get("events", [])
            except json.JSONDecodeError:
                events = []
        event = {**event, "recorded_utc": self.clock.now_utc().isoformat()}
        events.append(event)
        atomic_write_json(self.recovery_path, {"events": events[-50:]})

    # -- reporting -------------------------------------------------------

    def status(self) -> dict:
        state = self.load_state()
        buckets = self.buckets()
        return {
            "project_id": self.policy.project_id,
            "effective_day": state.effective_day,
            "last_development_date": state.last_development_date,
            "last_sequence": state.last_sequence,
            "current_bucket": state.current_bucket,
            "active_buckets": len(buckets),
            "max_active_buckets": self.policy.retention.max_active_buckets,
            "resumption_protected": state.resumption_protected,
            "gc_state": state.gc_state,
            "clock_anomalies": state.clock_anomalies,
            "usage": self.usage(),
            "eligible_for_rotation": [b.name for b in self.eligible_buckets(state)],
        }

    def stats(self) -> dict:
        counts: dict[str, int] = {}
        total = 0
        for bucket in self.buckets():
            records, bad, _ = self.scan_bucket(bucket.path)
            if bad:
                raise CorruptionBlocked(f"{bucket.name} lines={bad}")
            counts[bucket.name] = len(records)
            total += len(records)
        usage = self.usage()
        q = self.policy.quota
        return {
            "records": total,
            "per_bucket": counts,
            "usage": usage,
            "quota": {
                "total_bytes": q.total_bytes,
                "headroom_bytes": q.total_bytes - usage["total_bytes"]
                - q.transaction_reserve_bytes,
                "transaction_reserve_bytes": q.transaction_reserve_bytes,
            },
        }
