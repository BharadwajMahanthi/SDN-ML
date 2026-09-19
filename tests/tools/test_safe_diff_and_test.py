from __future__ import annotations

import contextlib
import io
from pathlib import Path

import pytest

from tests.tools.fixtures import FAKE_PASSWORD
from tools import safe_diff, safe_test
from tools.context_policy import PolicyViolation, load_policy


@pytest.fixture
def policy(fake_repo: Path):
    return load_policy(fake_repo)


def capture(fn, *args, **kwargs) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn(*args, **kwargs)
    return buf.getvalue()


# -- safe_diff -------------------------------------------------------------


def test_summary_is_structural_not_a_diff(policy, fake_repo):
    (fake_repo / "app" / "small.py").write_text(
        "def alpha(x: int) -> int:\n    return x + 2\n\n\ndef gamma() -> None:\n    pass\n"
    )
    out = capture(safe_diff.summarise, policy, False)
    assert "DIFF_SUMMARY" in out
    assert "app/small.py" in out
    assert "+gamma" in out, "symbol-level change should be summarised"
    assert "return x + 2" not in out, "summary must not contain diff text"


def test_summary_omits_blocked_paths(policy, fake_repo):
    (fake_repo / ".env").write_text(f"DB_PASSWORD={FAKE_PASSWORD}\nEXTRA=1\n")
    out = capture(safe_diff.summarise, policy, False)
    assert FAKE_PASSWORD not in out
    assert ".env" not in out
    assert "blocked path omitted" in out


def test_show_fragment_is_bounded_and_redacted(policy, fake_repo):
    target = fake_repo / "app" / "config.sh"
    target.write_text("\n".join(f"line {i}" for i in range(500)) + f'\nSUDO_PASS="{FAKE_PASSWORD}"\n')
    out = capture(safe_diff.show, policy, "app/config.sh", False)
    assert FAKE_PASSWORD not in out
    assert len(out.splitlines()) <= policy.limits.max_diff_lines + 5
    assert "suppressed" in out


def test_show_refuses_blocked_path(policy):
    with pytest.raises(PolicyViolation):
        capture(safe_diff.show, policy, "secrets/service.pem", False)


# -- safe_test -------------------------------------------------------------


def _make_suite(root: Path, body: str) -> None:
    d = root / "tests"
    d.mkdir(parents=True, exist_ok=True)
    (d / "test_generated.py").write_text(body)


def test_result_block_reports_counts(policy, fake_repo):
    _make_suite(fake_repo, "def test_a():\n    assert True\n\n\ndef test_b():\n    assert True\n")
    summary = safe_test.collect(policy, "tests", timeout=120)
    out = capture(safe_test.render, policy, summary, "tests")
    assert "TEST_RESULT" in out and "passed: 2" in out
    assert "failures:" not in out


def test_failures_are_listed_by_nodeid_without_tracebacks(policy, fake_repo):
    _make_suite(fake_repo, "def test_ok():\n    assert True\n\n\ndef test_bad():\n    assert 1 == 2\n")
    summary = safe_test.collect(policy, "tests", timeout=120)
    out = capture(safe_test.render, policy, summary, "tests")
    assert "failed: 1" in out
    assert any("test_bad" in f for f in summary.failures)
    assert "assert 1 == 2" not in out, "traceback must require an explicit --failure request"
    assert "rerun with --failure" in out


def test_full_log_is_local_only_and_unreachable(policy, fake_repo):
    _make_suite(fake_repo, "def test_a():\n    assert True\n")
    summary = safe_test.collect(policy, "tests", timeout=120)
    out = capture(safe_test.render, policy, summary, "tests")
    assert "full_log: LOCAL_ONLY" in out
    assert policy.is_blocked(summary.log.relative_to(policy.root))
