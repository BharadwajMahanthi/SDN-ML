"""Repository-wide test guard.

`tools/mutate.py` rewrites a module in place so that pytest imports the
mutated source. Its lock stops a second *mutation* run from starting, but
nothing stopped an ordinary `pytest` invocation from reading source that was
mutated at that instant — and that happened twice: once corrupting a suite
run (KF-41), and once again in V2-HOST-04E, where 21 unrelated tests failed
and passed on a re-run.

A failure that points at the wrong code costs whoever debugs it, and under
this project's doctrine a flaky security test blocks its claim. So a test run
that would read mutated source is refused loudly instead.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

_LOCK = Path(__file__).resolve().parent / ".mutate.lock"
#: The mutation tool sets this for the pytest subprocesses it drives, which
#: are the only runs that are *supposed* to see mutated source.
_MUTATION_ENV = "ANNULON_MUTATION_RUN"


def pytest_configure(config: pytest.Config) -> None:
    if not _LOCK.exists() or os.environ.get(_MUTATION_ENV) == "1":
        return
    try:
        holder = _LOCK.read_text().strip()
    except OSError:
        holder = "unknown"
    raise pytest.UsageError(
        f"refusing to run: a mutation run holds {_LOCK.name} ({holder}). "
        "tools/mutate.py rewrites source in place, so this run would import "
        "mutated code and report failures that have nothing to do with it. "
        "Wait for it to finish, or remove the lock if it is stale."
    )
