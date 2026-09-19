from __future__ import annotations

import json
import shutil
from datetime import date, timedelta
from pathlib import Path

import pytest

from tools.memory_store import FakeClock, MemoryPolicy, MemoryStore

START = date(2026, 1, 1)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(START)


@pytest.fixture
def store_factory(tmp_path: Path, clock: FakeClock):
    """Build a store with an optionally patched policy (for quota tests)."""

    def build(*, quota_overrides: dict | None = None, root: Path | None = None) -> MemoryStore:
        base = root or (tmp_path / "repo")
        (base / "memory").mkdir(parents=True, exist_ok=True)
        source = Path(__file__).resolve().parents[2] / "memory" / "policy.json"
        raw = json.loads(source.read_text())
        if quota_overrides:
            raw["quota"].update(quota_overrides)
        raw["lock"] = {"timeout_seconds": 5, "poll_seconds": 0.01}
        (base / "memory" / "policy.json").write_text(json.dumps(raw))
        return MemoryStore(base, policy=MemoryPolicy.load(base / "memory" / "policy.json"),
                           clock=clock)

    return build


@pytest.fixture
def store(store_factory) -> MemoryStore:
    return store_factory()


def checkpoint(store: MemoryStore, *, session="S1", task="T1", agent="claude", **kw):
    return store.checkpoint(session_id=session, task_id=task, agent=agent, **kw)


def advance_to_day(store: MemoryStore, clock: FakeClock, target_day: int,
                   *, session="S1") -> None:
    """Drive the effective-day counter to ``target_day`` one calendar day at a time."""
    while store.load_state().effective_day < target_day:
        clock.set(clock.current + timedelta(days=1))
        checkpoint(store, session=session)
