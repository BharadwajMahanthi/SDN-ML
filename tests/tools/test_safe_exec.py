from __future__ import annotations

import contextlib
import io
import sys
from pathlib import Path

import pytest

from tests.tools.fixtures import FAKE_AWS_KEY, FAKE_PASSWORD
from tools import safe_exec
from tools.context_policy import PolicyViolation, load_policy


@pytest.fixture
def policy(fake_repo: Path):
    return load_policy(fake_repo)


def execute(policy, argv, *, tail=40, grep=None) -> str:
    code, combined, elapsed, log = safe_exec.run(policy, argv, timeout=60)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        safe_exec.report(policy, argv, code, combined, elapsed, log, tail=tail, grep=grep)
    return buf.getvalue()


def test_allowed_command_runs_and_reports_exit_code(policy):
    out = execute(policy, [sys.executable, "-c", "print('hello')"])
    assert "EXEC_RESULT" in out and "exit: 0" in out and "hello" in out


def test_nonzero_exit_is_reported_not_hidden(policy):
    out = execute(policy, [sys.executable, "-c", "import sys; sys.exit(3)"])
    assert "exit: 3" in out


@pytest.mark.parametrize("cmd", [["printenv"], ["env"], ["aws", "s3", "ls"]])
def test_denied_commands_never_execute(policy, cmd):
    with pytest.raises(PolicyViolation, match="denied by policy"):
        safe_exec.run(policy, cmd, timeout=10)


def test_blocked_path_argument_is_refused(policy):
    with pytest.raises(PolicyViolation, match="blocked path"):
        safe_exec.run(policy, ["head", ".env"], timeout=10)


def test_large_command_output_is_capped(policy):
    """§48 fixture: large command output must not flood the context window."""
    out = execute(policy, [sys.executable, "-c", "print('\\n'.join(str(i) for i in range(5000)))"])
    assert "output_lines: 5000" in out
    body = out.split("---", 1)[1].splitlines()
    assert len(body) <= policy.limits.max_command_lines + 2


def test_tail_is_clamped_to_policy_limit(policy):
    out = execute(policy, [sys.executable, "-c", "print('\\n'.join(str(i) for i in range(5000)))"],
                  tail=10_000)
    assert f"limit={policy.limits.max_command_lines}" in out


def test_grep_narrows_output(policy):
    out = execute(policy, [sys.executable, "-c", "print('alpha\\nbeta\\ngamma')"], grep="beta")
    assert "beta" in out and "gamma" not in out.split("---", 1)[1]


def test_secret_in_command_output_is_redacted(policy):
    out = execute(policy, [sys.executable, "-c", f"print('SUDO_PASS={FAKE_PASSWORD}')"])
    assert FAKE_PASSWORD not in out
    assert "REDACTED" in out


def test_aws_key_in_command_output_is_redacted(policy):
    out = execute(policy, [sys.executable, "-c", f"print('{FAKE_AWS_KEY}')"])
    assert FAKE_AWS_KEY not in out


def test_full_log_lands_in_a_blocked_directory(policy):
    _, _, _, log = safe_exec.run(policy, [sys.executable, "-c", "print('x')"], timeout=30)
    rel = log.relative_to(policy.root)
    assert policy.is_blocked(rel), "exec logs must not be retrievable through the gateway"


def test_missing_command_is_reported_not_raised(policy):
    code, combined, _, _ = safe_exec.run(policy, ["git", "--definitely-not-a-flag"], timeout=30)
    assert code != 0
