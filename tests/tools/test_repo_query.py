from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from tests.tools.fixtures import FAKE_API_KEY, FAKE_PASSWORD
from tools import repo_query
from tools.context_policy import PolicyViolation, load_policy


@pytest.fixture
def policy(fake_repo: Path):
    return load_policy(fake_repo)


def run(policy, fn, **kwargs) -> str:
    import io
    import contextlib

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn(policy, argparse.Namespace(**kwargs))
    return buf.getvalue()


# -- enumeration excludes blocked material ---------------------------------


def test_tracked_files_exclude_blocked_paths(policy):
    listed = {p.as_posix() for p in repo_query.tracked_files(policy)}
    assert "app/small.py" in listed
    for blocked in (".env", "secrets/service.pem", "patent/draft_claims.md",
                    "captures/run1.pcap", "memory/runtime/journal.jsonl"):
        assert blocked not in listed, f"{blocked} leaked into the file list"


def test_tree_never_names_a_blocked_path(policy):
    out = run(policy, repo_query.cmd_tree, path="", depth=3)
    for blocked in ("secrets", "patent", "captures", ".env"):
        assert blocked not in out


# -- §48 fixtures: blocked patent and pcap paths ---------------------------


@pytest.mark.parametrize("path", ["patent/draft_claims.md", "captures/run1.pcap"])
def test_blocked_fixture_content_cannot_be_retrieved(policy, path):
    with pytest.raises(PolicyViolation, match="blocked by policy"):
        run(policy, repo_query.cmd_lines, path=path, start=1, end=5)


def test_grep_does_not_search_blocked_files(policy):
    out = run(policy, repo_query.cmd_grep, pattern="CLAIM-P1", path=None,
              max=20, case_sensitive=True)
    assert "CLAIM-P1" not in out.replace("pattern='CLAIM-P1'", "")


# -- §48 fixture: large source file must be bounded ------------------------


def test_large_file_excerpt_is_capped(policy):
    out = run(policy, repo_query.cmd_lines, path="app/large_module.py", start=1, end=400)
    body = [l for l in out.splitlines() if l[:5].strip().isdigit()]
    assert len(body) <= policy.limits.max_source_lines
    assert "limit=100" in out


def test_function_excerpt_reports_its_bound(policy):
    out = run(policy, repo_query.cmd_function, path="app/small.py", name="alpha")
    assert "def alpha" in out
    assert "limit=" in out


def test_grep_respects_max_results(policy):
    out = run(policy, repo_query.cmd_grep, pattern="def sym_", path=None,
              max=5, case_sensitive=True)
    hits = [l for l in out.splitlines() if ":" in l and l.startswith("app/")]
    assert len(hits) <= 5
    assert "suppressed by limit" in out


# -- secrets inside readable files are still redacted ----------------------


def test_secret_in_readable_file_is_redacted_on_the_way_out(policy):
    out = run(policy, repo_query.cmd_grep, pattern="SUDO_PASS", path=None,
              max=20, case_sensitive=True)
    assert FAKE_PASSWORD not in out
    assert "REDACTED" in out


def test_api_key_in_readable_python_is_redacted(policy):
    out = run(policy, repo_query.cmd_function, path="app/creds.py", name="module") or ""
    out += run(policy, repo_query.cmd_lines, path="app/creds.py", start=1, end=10)
    assert FAKE_API_KEY not in out


# -- structural queries ----------------------------------------------------


def test_symbol_lookup(policy):
    out = run(policy, repo_query.cmd_symbol, name="alpha", path=None)
    assert "app/small.py" in out and "function alpha" in out


def test_callers_reports_enclosing_symbol(policy):
    out = run(policy, repo_query.cmd_callers, name="alpha", path=None)
    assert "in beta" in out


def test_imports(policy):
    out = run(policy, repo_query.cmd_imports, path="app/caller.py")
    assert "from app.small import alpha" in out


def test_traversal_is_refused(policy):
    with pytest.raises(PolicyViolation):
        run(policy, repo_query.cmd_lines, path="../outside.txt", start=1, end=2)
