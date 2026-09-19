"""CLI for the rolling project memory shared by Claude Code and Codex.

    python tools/memory.py status
    python tools/memory.py checkpoint --session S1 --task P1-MEMORY \
        --agent claude --next "write GC tests" --changed tools/memory.py
    python tools/memory.py resume --session S9 --agent codex
    python tools/memory.py validate
    python tools/memory.py stats
    python tools/memory.py gc --dry-run
    python tools/memory.py gc --apply
    python tools/memory.py rebuild-index
    python tools/memory.py repair-tail [--bucket NAME]

Every mutating command takes the one canonical memory lock. ``repair-tail``
is narrowly scoped to a provably incomplete final JSONL record; there is no
generic destructive repair.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.memory_store import MemoryBlocked, MemoryStore


def repo_state(root: Path) -> tuple[str, str]:
    def git(*args: str) -> str:
        proc = subprocess.run(["git", *args], cwd=root, capture_output=True,
                              text=True, check=False)
        return proc.stdout.strip() if proc.returncode == 0 else ""

    commit = git("rev-parse", "--short", "HEAD")
    porcelain = git("status", "--porcelain=v1")
    digest = hashlib.sha256(porcelain.encode()).hexdigest()[:16] if porcelain else "clean"
    return commit, digest


def _json_list(values: list[str] | None, flag: str) -> list[dict]:
    out = []
    for raw in values or []:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{flag} must be JSON: {exc}") from exc
        out.append(parsed)
    return out


def cmd_status(store: MemoryStore, args) -> int:
    print(json.dumps(store.status(), indent=2, sort_keys=True))
    return 0


def cmd_stats(store: MemoryStore, args) -> int:
    print(json.dumps(store.stats(), indent=2, sort_keys=True))
    return 0


def cmd_validate(store: MemoryStore, args) -> int:
    issues = store.validate()
    print(f"VALIDATE issues={len(issues)}")
    for issue in issues:
        print(f"  {issue.code}: {issue.detail}")
    blocking = {"MID_FILE_CORRUPTION", "DUPLICATE_RECORD_ID", "SEQUENCE_REGRESSION"}
    return 1 if any(i.code in blocking for i in issues) else 0


def cmd_checkpoint(store: MemoryStore, args) -> int:
    commit, digest = repo_state(store.root)
    record = store.checkpoint(
        session_id=args.session, task_id=args.task, agent=args.agent,
        substantive=not args.no_advance,
        kind=args.kind,
        base_commit=args.base_commit or commit,
        dirty_digest=args.dirty_digest or digest,
        changed_paths=args.changed, changed_symbols=args.symbol,
        tests=_json_list(args.test, "--test"),
        decisions=_json_list(args.decision, "--decision"),
        blockers=_json_list(args.blocker, "--blocker"),
        evidence_refs=args.evidence, next_action=args.next,
    )
    print(f"CHECKPOINT {record.record_id}")
    print(f"sequence: {record.sequence}")
    print(f"effective_day: {record.effective_day}")
    print(f"bucket: {store.load_state().current_bucket}")
    return 0


def cmd_resume(store: MemoryStore, args) -> int:
    record = store.resume(session_id=args.session, agent=args.agent, next_action=args.next)
    state = store.load_state()
    print(f"RESUMPTION {record.record_id}")
    print(f"effective_day: {record.effective_day}")
    print(f"gc_protected: {state.resumption_protected}")
    return 0


def cmd_gc(store: MemoryStore, args) -> int:
    manifest = store.gc(apply=args.apply)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


def cmd_rebuild_index(store: MemoryStore, args) -> int:
    with store.lock():
        index = store.rebuild_index()
    print(f"INDEX rebuilt buckets={len(index['buckets'])}")
    return 0


def cmd_repair_tail(store: MemoryStore, args) -> int:
    repaired = store.repair_tail(args.bucket)
    print(f"REPAIR_TAIL repaired={len(repaired)}")
    for event in repaired:
        print(f"  {event['bucket']}: dropped {event['dropped_bytes']}B, "
              f"kept {event['records_kept']} records")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="memory", description=__doc__)
    p.add_argument("--root", default=".")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status").set_defaults(fn=cmd_status)
    sub.add_parser("stats").set_defaults(fn=cmd_stats)
    sub.add_parser("validate").set_defaults(fn=cmd_validate)
    sub.add_parser("rebuild-index").set_defaults(fn=cmd_rebuild_index)

    c = sub.add_parser("checkpoint")
    c.add_argument("--session", required=True)
    c.add_argument("--task", required=True)
    c.add_argument("--agent", default="claude")
    c.add_argument("--kind", default="development")
    c.add_argument("--next", default="")
    c.add_argument("--changed", action="append")
    c.add_argument("--symbol", action="append")
    c.add_argument("--test", action="append")
    c.add_argument("--decision", action="append")
    c.add_argument("--blocker", action="append")
    c.add_argument("--evidence", action="append")
    c.add_argument("--base-commit", default="")
    c.add_argument("--dirty-digest", default="")
    c.add_argument("--no-advance", action="store_true",
                   help="journal without advancing the effective-day counter")
    c.set_defaults(fn=cmd_checkpoint)

    r = sub.add_parser("resume")
    r.add_argument("--session", required=True)
    r.add_argument("--agent", default="claude")
    r.add_argument("--next", default="")
    r.set_defaults(fn=cmd_resume)

    g = sub.add_parser("gc")
    mode = g.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", dest="apply", action="store_false")
    mode.add_argument("--apply", dest="apply", action="store_true")
    g.set_defaults(fn=cmd_gc)

    t = sub.add_parser("repair-tail")
    t.add_argument("--bucket")
    t.set_defaults(fn=cmd_repair_tail)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    store = MemoryStore(Path(args.root).resolve())
    try:
        return int(args.fn(store, args))
    except MemoryBlocked as exc:
        print(str(exc), file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
