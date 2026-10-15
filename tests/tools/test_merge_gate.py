"""Merge gate: the KF-23 regression, exercised as a real workflow.

KF-23 was a process failure -- a branch merged while a required guard was
red. Unit-testing a boolean would not have caught it, so the central test
here drives the actual merge command in a throwaway git repository.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from tools.merge_gate import (
    FAIL,
    INCONCLUSIVE,
    MERGEABLE,
    NOT_APPLICABLE,
    NOT_RUN,
    PASS,
    SCHEMA_VERSION,
    STALE,
    CheckResult,
    Gate,
    main,
)

GIT_ID = ["-c", "user.name=gate", "-c", "user.email=gate@invalid"]


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(["git", *GIT_ID, *args], cwd=repo,
                          capture_output=True, text=True, check=True)
    return proc.stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A minimal repo with main plus a feature branch, and no gate result."""
    root = tmp_path / "repo"
    (root / "docs").mkdir(parents=True)
    (root / "memory" / "runtime" / "buckets").mkdir(parents=True)
    (root / "docs" / "CURRENT_STATE.md").write_text("# state\n")
    # The gate artifact lives under memory/runtime and must never be
    # committable: a tracked gate result could be carried between branches or
    # hand-edited into a commit. The real repository gitignores it.
    (root / ".gitignore").write_text("memory/runtime/\n")
    git(root.parent, "init", "-q", str(root))
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "base")
    git(root, "branch", "-M", "main")

    git(root, "checkout", "-q", "-b", "feat/v2-core-01-events-capabilities")
    (root / "docs" / "CURRENT_STATE.md").write_text("# state\nupdated\n")
    (root / "feature.py").write_text("VALUE = 1\n")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "feature work")

    bucket = root / "memory" / "runtime" / "buckets" / "bucket_000001_000007.jsonl"
    bucket.write_text(json.dumps({"task_id": "V2-CORE-01", "sequence": 7}) + "\n")
    git(root, "checkout", "-q", "main")
    return root


def write_gate(repo: Path, branch: str, statuses: dict[str, str],
               *, commit: str | None = None) -> Path:
    gate = Gate(repo)
    head = commit or git(repo, "rev-parse", branch)
    blocking = [f"{n}: {s}" for n, s in statuses.items()
                if s not in {PASS, NOT_APPLICABLE}]
    payload = {
        "schema_version": SCHEMA_VERSION, "task_id": "V2-CORE-01",
        "branch": branch, "head_commit": head, "generated_utc": "2026-09-20T00:00:00Z",
        "checks": [{"name": n, "status": s, "detail": "", "exit_code": 0,
                    "artifact": {}} for n, s in statuses.items()],
        "blocking": blocking, "merge_eligible": not blocking,
    }
    path = gate.path_for(branch)
    path.write_text(json.dumps(payload, indent=2))
    return path


ALL_GREEN = {
    "branch_matches_task": PASS, "working_tree_clean": PASS,
    "focused_tests": PASS, "full_suite": PASS, "framework_guards": PASS,
    "firewall_tests": PASS, "memory_checkpoint": PASS,
    "current_state_updated": PASS, "ownership_released": PASS,
}
BRANCH = "feat/v2-core-01-events-capabilities"


# -- the KF-23 regression, as a real merge ---------------------------------


def test_kf23_a_red_framework_guard_blocks_the_actual_merge(repo, capsys):
    """The exact shape of KF-23: everything green except the framework guard."""
    statuses = dict(ALL_GREEN, framework_guards=FAIL)
    write_gate(repo, BRANCH, statuses)
    before = git(repo, "rev-parse", "main")

    code = main(["--root", str(repo), "merge", BRANCH])

    assert code != 0
    assert git(repo, "rev-parse", "main") == before, "main must be untouched"
    out = capsys.readouterr()
    assert "MERGE GATE: FAIL" in out.out
    assert "framework_guards" in out.out
    assert "no override" in out.err


def test_a_fully_green_gate_merges_for_real(repo, capsys):
    write_gate(repo, BRANCH, ALL_GREEN)
    before = git(repo, "rev-parse", "main")

    code = main(["--root", str(repo), "merge", BRANCH])

    assert code == 0
    after = git(repo, "rev-parse", "main")
    assert after != before
    assert (repo / "feature.py").is_file(), "the branch's work is present on main"
    assert "feature.py" in git(repo, "diff", "--name-only", f"{before}..{after}")
    parents = git(repo, "rev-list", "--parents", "-n", "1", after).split()
    assert len(parents) == 3, "must be a --no-ff merge commit with two parents"


# -- every non-PASS status blocks -----------------------------------------


@pytest.mark.parametrize("status", [FAIL, NOT_RUN, INCONCLUSIVE, STALE])
def test_no_non_pass_status_is_merge_eligible(repo, status):
    write_gate(repo, BRANCH, dict(ALL_GREEN, full_suite=status))
    assert main(["--root", str(repo), "merge", BRANCH]) != 0


def test_a_missing_gate_result_blocks(repo, capsys):
    assert main(["--root", str(repo), "merge", BRANCH]) != 0
    assert NOT_RUN in capsys.readouterr().out


def test_a_corrupt_gate_result_blocks(repo):
    Gate(repo).path_for(BRANCH).write_text("{not json")
    assert main(["--root", str(repo), "merge", BRANCH]) != 0


def test_an_unknown_schema_version_blocks(repo):
    path = write_gate(repo, BRANCH, ALL_GREEN)
    payload = json.loads(path.read_text())
    payload["schema_version"] = 99
    path.write_text(json.dumps(payload))
    assert main(["--root", str(repo), "merge", BRANCH]) != 0


# -- staleness -------------------------------------------------------------


def test_evidence_from_an_earlier_commit_is_stale(repo, capsys):
    """A gate run, then one more commit, must not authorise the merge."""
    write_gate(repo, BRANCH, ALL_GREEN)
    git(repo, "checkout", "-q", BRANCH)
    (repo / "feature.py").write_text("VALUE = 2\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "later change never tested")
    git(repo, "checkout", "-q", "main")

    assert main(["--root", str(repo), "merge", BRANCH]) != 0
    assert STALE in capsys.readouterr().out


# -- NOT_APPLICABLE is permitted only where declared -----------------------


def test_not_applicable_is_honoured_where_the_spec_permits_it(repo):
    write_gate(repo, BRANCH, dict(ALL_GREEN, focused_tests=NOT_APPLICABLE))
    assert main(["--root", str(repo), "merge", BRANCH]) == 0


def test_not_applicable_is_refused_for_a_required_capability(repo, capsys):
    """A required guard cannot be waved through as 'doesn't apply'."""
    write_gate(repo, BRANCH, dict(ALL_GREEN, framework_guards=NOT_APPLICABLE))
    assert main(["--root", str(repo), "merge", BRANCH]) != 0
    assert "not permitted" in capsys.readouterr().out


def test_a_missing_check_is_treated_as_not_run(repo, capsys):
    partial = {k: v for k, v in ALL_GREEN.items() if k != "framework_guards"}
    write_gate(repo, BRANCH, partial)
    assert main(["--root", str(repo), "merge", BRANCH]) != 0
    assert NOT_RUN in capsys.readouterr().out


# -- pytest result interpretation -----------------------------------------


def test_all_skipped_is_inconclusive_not_pass(repo, tmp_path):
    """pytest exits 0 when every test skips. For a required capability that
    is not evidence, so it must not read as PASS."""
    suite = repo / "t"
    suite.mkdir()
    (suite / "test_skip.py").write_text(
        "import pytest\n\n@pytest.mark.skip(reason='x')\ndef test_a():\n    pass\n")
    result = Gate(repo)._pytest("focused_tests", [str(suite)])
    assert result.exit_code == 0
    assert result.status == INCONCLUSIVE


def test_no_tests_collected_is_inconclusive(repo):
    empty = repo / "empty"
    empty.mkdir()
    result = Gate(repo)._pytest("focused_tests", [str(empty)])
    assert result.status == INCONCLUSIVE


def test_a_failing_test_is_fail(repo):
    suite = repo / "t2"
    suite.mkdir()
    (suite / "test_bad.py").write_text("def test_a():\n    assert False\n")
    result = Gate(repo)._pytest("full_suite", [str(suite)])
    assert result.status == FAIL and result.exit_code != 0


def test_a_passing_test_is_pass(repo):
    suite = repo / "t3"
    suite.mkdir()
    (suite / "test_ok.py").write_text("def test_a():\n    assert True\n")
    result = Gate(repo)._pytest("full_suite", [str(suite)])
    assert result.status == PASS and result.artifact["tests"] == 1


def test_status_is_never_decided_from_stdout_text(repo):
    """The gate must not be satisfied by a process that merely prints a
    reassuring summary."""
    suite = repo / "t4"
    suite.mkdir()
    (suite / "test_liar.py").write_text(
        "def test_a():\n    print('999 passed')\n    assert False\n")
    assert Gate(repo)._pytest("full_suite", [str(suite)]).status == FAIL


# -- individual checks -----------------------------------------------------


def test_uncommitted_changes_block(repo):
    git(repo, "checkout", "-q", BRANCH)
    (repo / "scratch.txt").write_text("dirty\n")
    assert Gate(repo).check_clean().status == FAIL


def test_missing_checkpoint_blocks(repo):
    assert Gate(repo).check_checkpoint("V2-NOT-DONE").status == FAIL
    assert Gate(repo).check_checkpoint("V2-CORE-01").status == PASS


def test_open_ownership_claim_blocks(repo):
    path = repo / "memory" / "runtime" / "ownership.json"
    path.write_text(json.dumps({"claims": [{"task": "V2-CORE-01", "agent": "claude"}]}))
    assert Gate(repo).check_ownership("V2-CORE-01").status == FAIL
    path.write_text(json.dumps({"claims": []}))
    assert Gate(repo).check_ownership("V2-CORE-01").status == PASS


def test_every_git_derived_check_can_come_out_non_blocking_on_main(repo):
    """KF-56's family: a check whose predicate goes degenerate after a model
    change, and fails closed.

    Every other test here either drives one check in isolation or writes
    synthetic statuses through write_gate(), so no test ever asked the real
    checks whether a correctly-prepared commit on main can satisfy them. One
    could not, and a check that always fails looks like diligence from the
    outside -- the pressure it creates is to waive it, not to fix it.

    Prepare a commit that genuinely satisfies every git-derived check, then
    run those checks for real. The pytest-backed ones are left out because
    running the suite inside the suite is recursive, not because they are
    exempt; their ranges are not git-derived.
    """
    git(repo, "checkout", "-q", "main")
    (repo / "docs" / "CURRENT_STATE.md").write_text("# state\nmain work\n")
    (repo / "feature.py").write_text("VALUE = 2\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "work on main")

    gate = Gate(repo)
    results = [
        gate.check_branch("V2-CORE-01"),
        gate.check_clean(),
        gate.check_state_updated(None),
        gate.check_checkpoint("V2-CORE-01"),
        gate.check_ownership("V2-CORE-01"),
    ]
    blocking = [f"{r.name}={r.status} ({r.detail})"
                for r in results if r.status not in MERGEABLE]
    assert not blocking, (
        "a correctly-prepared commit on main could not satisfy: "
        + "; ".join(blocking))


def test_current_state_check_can_both_pass_and_fail_on_main(repo):
    """The gate runs against a commit on main now, so this check has to be
    able to reach PASS there.

    It could not. It diffed `merge-base main HEAD`..HEAD, which is correct
    for a branch and degenerate on main: the merge base of main and HEAD is
    HEAD, so the range was empty for every commit ever made. It failed
    closed, and the only test for it asserted FAIL on a branch, so nothing
    noticed until the gate rejected ADR-059's own commit -- which had
    updated the file two lines above where the check was reading. Assert
    both directions, on main, so the next degenerate range is caught by the
    direction that is supposed to succeed.
    """
    git(repo, "checkout", "-q", "main")
    (repo / "docs" / "CURRENT_STATE.md").write_text("# state\nmain update\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "state update on main")
    assert Gate(repo).check_state_updated(None).status == PASS

    (repo / "unrelated.py").write_text("y = 2\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "no state change on main")
    assert Gate(repo).check_state_updated(None).status == FAIL


def test_current_state_is_inconclusive_on_a_parentless_commit(repo):
    """A root commit has nothing to diff against. That is not a pass: the
    check reports INCONCLUSIVE, which is not in MERGEABLE, so it blocks."""
    root = git(repo, "rev-list", "--max-parents=0", "HEAD").split("\n")[0]
    git(repo, "checkout", "-q", "--detach", root)
    result = Gate(repo).check_state_updated(None)
    assert result.status == INCONCLUSIVE
    assert result.status not in MERGEABLE


def test_unchanged_current_state_blocks_unless_waived(repo):
    git(repo, "checkout", "-q", "-b", "feat/v2-core-01-nostate", "main")
    (repo / "other.py").write_text("x = 1\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "no state change")
    gate = Gate(repo)
    assert gate.check_state_updated(None).status == FAIL
    assert gate.check_state_updated("docs-only branch").status == NOT_APPLICABLE


def test_branch_name_must_carry_the_task_id(repo):
    git(repo, "checkout", "-q", BRANCH)
    gate = Gate(repo)
    assert gate.check_branch("V2-CORE-01").status == PASS
    assert gate.check_branch("V2-HOST-02").status == FAIL


def test_the_gate_artifact_is_not_committable(repo):
    """A tracked gate result could be carried between branches or edited into
    a commit; it must stay ignored runtime state."""
    write_gate(repo, BRANCH, ALL_GREEN)
    git(repo, "add", "-A")
    assert "memory/runtime" not in git(repo, "status", "--porcelain=v1")


def test_a_forged_merge_eligible_flag_is_ignored(repo, capsys):
    """Eligibility is re-derived from the checks, so an artifact cannot
    assert its own merge eligibility."""
    path = write_gate(repo, BRANCH, dict(ALL_GREEN, full_suite=FAIL))
    payload = json.loads(path.read_text())
    payload["merge_eligible"] = True
    payload["blocking"] = []
    path.write_text(json.dumps(payload))
    assert main(["--root", str(repo), "merge", BRANCH]) != 0
    assert "full_suite" in capsys.readouterr().out


def test_merge_refuses_when_not_on_main(repo, capsys):
    write_gate(repo, BRANCH, ALL_GREEN)
    git(repo, "checkout", "-q", BRANCH)
    assert main(["--root", str(repo), "merge", BRANCH]) != 0
    assert "must run from main" in capsys.readouterr().err


def test_a_successful_merge_deletes_the_branch(repo):
    """Repository hygiene is mechanical, not remembered. The merge commit is
    the history; a leftover branch ref only hides what is in flight."""
    write_gate(repo, BRANCH, ALL_GREEN)
    assert BRANCH in git(repo, "branch")
    assert main(["--root", str(repo), "merge", BRANCH]) == 0
    assert BRANCH not in git(repo, "branch")
    assert "Merge" in git(repo, "log", "-1", "--format=%s")


def test_a_refused_merge_leaves_the_branch_alone(repo):
    """A branch that failed its gate must survive so it can be fixed."""
    write_gate(repo, BRANCH, dict(ALL_GREEN, full_suite=FAIL))
    assert main(["--root", str(repo), "merge", BRANCH]) != 0
    assert BRANCH in git(repo, "branch")


def test_keep_branch_retains_the_ref_when_explicitly_asked(repo):
    write_gate(repo, BRANCH, ALL_GREEN)
    assert main(["--root", str(repo), "merge", BRANCH, "--keep-branch"]) == 0
    assert BRANCH in git(repo, "branch")


def test_the_archive_is_kept_as_a_tag_with_a_stated_reason():
    """The legacy tree is preserved by a tag, not a branch.

    Its commit is reachable from main's own history, so the branch ref added
    nothing while still looking like a line of development somebody might
    commit to. A tag says "this point mattered" without implying that
    (ADR-059).
    """
    from tools.verify_all import ARCHIVE_TAGS

    assert "archive/java-topoguard-research" in ARCHIVE_TAGS
    for name, reason in ARCHIVE_TAGS.items():
        assert reason and len(reason) > 20, (
            f"{name} is preserved without a stated reason")


def test_the_gate_accepts_main_as_the_working_branch():
    """Under the single-branch model there is no branch name to match, and
    the check reports NOT_APPLICABLE rather than passing silently -- a check
    that claims to have run when it did not is worse than one that abstains.
    """
    from tools.merge_gate import CHECK_SPECS

    spec = next(c for c in CHECK_SPECS if c.name == "branch_matches_task")
    assert spec.may_be_not_applicable, (
        "branch_matches_task cannot abstain, so the gate cannot run on main")


# --- tools/verify_all.py's reader of the gate artifact -----------------------
#
# Under the single-branch model the whole repository's integrity claim rests
# on one artifact: memory/runtime/gate/main.json. merge_gate.validate() is
# careful with it and refuses to trust its self-assessment. verify_all's
# reader of the same file had no tests at all, and did trust it.


def _write_main_gate(repo: Path, statuses: dict[str, str], *,
                     commit: str | None = None, **overrides) -> Path:
    """Write a gate record for main the way verify_all expects to find it."""
    from tools.merge_gate import CHECK_SPECS

    path = repo / "memory" / "runtime" / "gate" / "main.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    checks = [{"name": spec.name, "status": statuses.get(spec.name, PASS),
               "detail": ""} for spec in CHECK_SPECS]
    blocking = [f"{c['name']}: {c['status']}"
                for c in checks if c["status"] not in MERGEABLE]
    record = {
        "schema_version": SCHEMA_VERSION,
        "task_id": "V2-CORE-01",
        "branch": "main",
        "head_commit": commit or git(repo, "rev-parse", "HEAD"),
        "generated_utc": "2026-01-01T00:00:00+00:00",
        "checks": checks,
        "blocking": blocking,
        "merge_eligible": not blocking,
    }
    record.update(overrides)
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    return path


def test_verify_all_accepts_a_genuine_passing_record_for_the_tip(repo):
    from tools.verify_all import OK, check_main_tip_gated

    _write_main_gate(repo, {"focused_tests": NOT_APPLICABLE})
    result = check_main_tip_gated(repo)
    assert result.status == OK, result.detail


def test_verify_all_ignores_a_forged_merge_eligible_flag(repo):
    """The forgery merge_gate.validate() already refuses, aimed at the other
    reader of the same file.

    A record carrying a failed check but `merge_eligible: true` satisfied
    verify_all, because it read the flag instead of the checks. Editing one
    boolean in an ignored file was enough to make the repo-wide verifier
    declare main's tip gated.
    """
    from tools.verify_all import FAIL as V_FAIL
    from tools.verify_all import check_main_tip_gated

    _write_main_gate(repo, {"full_suite": FAIL},
                     merge_eligible=True, blocking=[])
    result = check_main_tip_gated(repo)
    assert result.status == V_FAIL
    assert "full_suite" in result.detail


def test_verify_all_refuses_a_record_that_omits_a_check(repo):
    """A missing check is NOT_RUN, not a pass -- deleting an entry must not
    be a way to drop a requirement."""
    from tools.verify_all import FAIL as V_FAIL
    from tools.verify_all import check_main_tip_gated

    path = _write_main_gate(repo, {})
    record = json.loads(path.read_text())
    record["checks"] = [c for c in record["checks"] if c["name"] != "full_suite"]
    record["merge_eligible"] = True
    record["blocking"] = []
    path.write_text(json.dumps(record))
    result = check_main_tip_gated(repo)
    assert result.status == V_FAIL
    assert "full_suite" in result.detail


def test_verify_all_refuses_a_forged_not_applicable_on_a_required_check(repo):
    """NOT_APPLICABLE is permitted for some checks and not others. The
    distinction has to survive being read from the file."""
    from tools.verify_all import FAIL as V_FAIL
    from tools.verify_all import check_main_tip_gated

    _write_main_gate(repo, {"full_suite": NOT_APPLICABLE},
                     merge_eligible=True, blocking=[])
    result = check_main_tip_gated(repo)
    assert result.status == V_FAIL


def test_verify_all_warns_when_the_record_names_an_earlier_commit(repo):
    """A passing record for a commit that is no longer the tip is stale
    evidence, not absent evidence -- WARN, and it must say both commits."""
    from tools.verify_all import WARN, check_main_tip_gated

    stale = git(repo, "rev-parse", "HEAD")
    (repo / "docs" / "CURRENT_STATE.md").write_text("# state\nmoved on\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "a commit the gate has not seen")
    _write_main_gate(repo, {"focused_tests": NOT_APPLICABLE}, commit=stale)
    result = check_main_tip_gated(repo)
    assert result.status == WARN
    assert stale[:8] in result.detail


def test_verify_all_refuses_an_unknown_gate_schema(repo):
    """The record's shape is versioned. An unrecognised version means the
    reader cannot know what the fields mean, which is not a pass."""
    from tools.verify_all import FAIL as V_FAIL
    from tools.verify_all import check_main_tip_gated

    _write_main_gate(repo, {}, schema_version=SCHEMA_VERSION + 1)
    assert check_main_tip_gated(repo).status == V_FAIL
