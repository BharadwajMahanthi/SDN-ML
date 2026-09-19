from __future__ import annotations

from pathlib import Path

import pytest

from tools.context_policy import PolicyViolation, load_policy


@pytest.fixture
def policy(fake_repo: Path):
    return load_policy(fake_repo)


@pytest.mark.parametrize(
    "rel",
    [
        ".env",
        "secrets/service.pem",
        "patent/draft_claims.md",
        "captures/run1.pcap",
        "memory/runtime/journal.jsonl",
        "nested/deeper/.env",
        "a/b/id_rsa",
    ],
)
def test_blocked_paths_are_refused(policy, rel):
    assert policy.is_blocked(rel)
    with pytest.raises(PolicyViolation):
        policy.check_readable(rel)
    with pytest.raises(PolicyViolation):
        policy.check_listable(rel)


@pytest.mark.parametrize("rel", ["app/small.py", "tools/context_policy.yaml"])
def test_ordinary_source_is_readable(policy, rel):
    assert policy.check_readable(rel).as_posix() == rel


def test_opaque_path_may_be_listed_but_not_read(policy, fake_repo):
    (fake_repo / "data.csv").write_text("a,b\n1,2\n")
    assert policy.check_listable("data.csv").as_posix() == "data.csv"
    with pytest.raises(PolicyViolation, match="opaque"):
        policy.check_readable("data.csv")


def test_path_traversal_is_refused(policy):
    with pytest.raises(PolicyViolation, match="escapes repository root"):
        policy.relative("../../../etc/passwd")


def test_violation_message_does_not_leak_absolute_layout(policy):
    with pytest.raises(PolicyViolation) as exc:
        policy.relative("/etc/shadow")
    assert "/etc" not in str(exc.value)


def test_symlink_escaping_root_is_refused(policy, fake_repo, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("secret-ish")
    link = fake_repo / "link.txt"
    link.symlink_to(outside)
    with pytest.raises(PolicyViolation, match="escapes repository root"):
        policy.check_readable("link.txt")


@pytest.mark.parametrize("cmd", [["printenv"], ["env"], ["aws", "s3", "ls"], ["curl", "http://x"]])
def test_denied_commands(policy, cmd):
    with pytest.raises(PolicyViolation, match="denied by policy"):
        policy.check_command(cmd)


def test_unlisted_command_is_refused(policy):
    with pytest.raises(PolicyViolation, match="not in allowed_commands"):
        policy.check_command(["rm", "-rf", "/"])


def test_allowed_command_passes(policy):
    policy.check_command(["git", "status"])


def test_limits_are_enforced_from_file(policy):
    assert policy.limits.max_source_lines == 100
    assert policy.limits.max_search_results == 20
    assert policy.limits.max_command_lines == 200
    assert policy.limits.max_diff_lines == 200


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("python3.12", "python3"),
        ("python3", "python3"),
        ("python", "python3"),
        ("python.exe", "python3"),
        ("pytest", "pytest"),
        ("java", "java"),
        ("rm", "rm"),
    ],
)
def test_command_name_normalization(raw, expected):
    from tools.context_policy import normalize_command

    assert normalize_command(raw) == expected


def test_versioned_interpreter_is_allowed(policy):
    """Regression: sys.executable is python3.12, which the raw basename
    allowlist rejected, blocking every ordinary local Python invocation."""
    policy.check_command(["/usr/bin/python3.12", "-c", "pass"])


def test_normalization_does_not_smuggle_a_denied_command(policy):
    with pytest.raises(PolicyViolation):
        policy.check_command(["python3.12.sh"])
