"""Task/file ownership so Claude Code and Codex do not overwrite each other.

Ownership lives in ``memory/runtime/ownership.json`` and every mutation takes
the same canonical memory lock as the journal, so two separate processes
cannot both believe they own a path.

    python tools/agent_session.py brief
    python tools/agent_session.py claim --task P2-AUDIT --agent claude --path src
    python tools/agent_session.py list
    python tools/agent_session.py release --task P2-AUDIT --agent claude
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path, PurePosixPath

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.memory_store import MemoryBlocked, MemoryStore, atomic_write_json


class OwnershipConflict(MemoryBlocked):
    code = "TASK_OWNERSHIP_CONFLICT"


def _overlaps(a: str, b: str) -> bool:
    pa, pb = PurePosixPath(a), PurePosixPath(b)
    return pa == pb or str(pa).startswith(str(pb) + "/") or str(pb).startswith(str(pa) + "/")


class Ownership:
    def __init__(self, store: MemoryStore) -> None:
        self.store = store
        self.path = store.runtime / "ownership.json"

    def load(self) -> dict:
        if not self.path.is_file():
            return {"claims": []}
        try:
            return json.loads(self.path.read_text())
        except json.JSONDecodeError:
            return {"claims": []}

    def claim(self, *, task: str, agent: str, session: str, paths: list[str]) -> dict:
        with self.store.lock():
            data = self.load()
            for existing in data["claims"]:
                if existing["task"] == task and existing["agent"] != agent:
                    raise OwnershipConflict(
                        f"task {task} is already claimed by {existing['agent']}")
                if existing["agent"] == agent and existing["task"] == task:
                    continue
                for owned in existing["paths"]:
                    for wanted in paths:
                        if _overlaps(owned, wanted):
                            raise OwnershipConflict(
                                f"path {wanted} overlaps {owned} owned by "
                                f"{existing['agent']} for task {existing['task']}")
            data["claims"] = [c for c in data["claims"]
                              if not (c["task"] == task and c["agent"] == agent)]
            claim = {"task": task, "agent": agent, "session": session,
                     "paths": sorted(paths),
                     "claimed_utc": self.store.clock.now_utc().isoformat(),
                     "base_commit_effective_day": self.store.load_state().effective_day}
            data["claims"].append(claim)
            atomic_write_json(self.path, data)
            return claim

    def release(self, *, task: str, agent: str) -> bool:
        with self.store.lock():
            data = self.load()
            before = len(data["claims"])
            data["claims"] = [c for c in data["claims"]
                              if not (c["task"] == task and c["agent"] == agent)]
            atomic_write_json(self.path, data)
            return len(data["claims"]) < before


def cmd_brief(store: MemoryStore, args) -> int:
    """Short startup briefing. Deliberately bounded: the whole journal is
    never loaded into a context window; older entries are fetched on demand."""
    status = store.status()
    print("MEMORY_BRIEF")
    print(f"project: {status['project_id']}")
    print(f"effective_day: {status['effective_day']}  "
          f"buckets: {status['active_buckets']}/{status['max_active_buckets']}")
    print(f"last_development_date: {status['last_development_date']}")
    print(f"resumption_protected: {status['resumption_protected']}")
    print(f"usage_bytes: {status['usage']['total_bytes']}")
    if status["eligible_for_rotation"]:
        print(f"rotation_eligible: {', '.join(status['eligible_for_rotation'])}")

    current = store.root / "docs" / "CURRENT_STATE.md"
    if current.is_file():
        lines = current.read_text().splitlines()[:25]
        print("--- docs/CURRENT_STATE.md (first 25 lines) ---")
        print("\n".join(lines))
    claims = Ownership(store).load()["claims"]
    print(f"open_claims: {len(claims)}")
    for claim in claims[:10]:
        print(f"  {claim['task']} -> {claim['agent']} {claim['paths']}")
    return 0


def cmd_claim(store: MemoryStore, args) -> int:
    claim = Ownership(store).claim(task=args.task, agent=args.agent,
                                   session=args.session, paths=args.path or [])
    print(f"CLAIMED {claim['task']} by {claim['agent']} paths={claim['paths']}")
    return 0


def cmd_release(store: MemoryStore, args) -> int:
    released = Ownership(store).release(task=args.task, agent=args.agent)
    print(f"RELEASED {args.task}" if released else f"NO_CLAIM {args.task}")
    return 0


def cmd_list(store: MemoryStore, args) -> int:
    print(json.dumps(Ownership(store).load(), indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agent_session", description=__doc__)
    p.add_argument("--root", default=".")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("brief").set_defaults(fn=cmd_brief)
    sub.add_parser("list").set_defaults(fn=cmd_list)
    c = sub.add_parser("claim")
    c.add_argument("--task", required=True)
    c.add_argument("--agent", default="claude")
    c.add_argument("--session", default="")
    c.add_argument("--path", action="append")
    c.set_defaults(fn=cmd_claim)
    r = sub.add_parser("release")
    r.add_argument("--task", required=True)
    r.add_argument("--agent", default="claude")
    r.set_defaults(fn=cmd_release)
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
