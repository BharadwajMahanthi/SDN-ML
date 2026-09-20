"""Executable merge gate.

KF-23: a branch was merged while a required framework guard was failing. The
failure was visible in the suite output and the merge proceeded anyway. A
documented rule did not stop it, so the rule is now code.

Design constraints, each from a specific way the previous process failed:

* **Decide from exit status and a result artifact, never from text.** Parsing
  "816 passed" is how an optimistic summary becomes a merge.
* **A skipped required check is not a pass.** pytest exits 0 when every test
  skips; for a required capability that is ``INCONCLUSIVE``, not ``PASS``.
* **Evidence is bound to a commit.** A gate produced against an earlier HEAD
  is ``STALE`` and cannot authorise a merge.
* **There is no override flag.** If a required check is red the merge
  subcommand refuses, and the only way forward is to fix the branch.

    python tools/merge_gate.py run --task V2-CORE-01 --focused development/tests/core
    python tools/merge_gate.py status
    python tools/merge_gate.py merge feat/v2-core-01-events-capabilities

A successful merge deletes the branch. The merge commit is the history; a
leftover ref is clutter that hides what is actually in flight.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.context_policy import default_policy

SCHEMA_VERSION = 1

PASS = "PASS"
FAIL = "FAIL"
NOT_RUN = "NOT_RUN"
INCONCLUSIVE = "INCONCLUSIVE"
STALE = "STALE"
NOT_APPLICABLE = "NOT_APPLICABLE"

MERGEABLE = {PASS, NOT_APPLICABLE}


@dataclass(frozen=True)
class CheckSpec:
    name: str
    description: str
    #: NOT_APPLICABLE is only honoured for checks that declare it permitted,
    #: so a required capability cannot be waved through as "doesn't apply".
    may_be_not_applicable: bool = False


CHECK_SPECS: tuple[CheckSpec, ...] = (
    CheckSpec("branch_matches_task", "branch name carries the task id"),
    CheckSpec("working_tree_clean", "no uncommitted changes at gate time"),
    CheckSpec("focused_tests", "tests for the code this branch changed",
              may_be_not_applicable=True),
    CheckSpec("full_suite", "the whole applicable suite"),
    CheckSpec("framework_guards", "framework-boundary guards specifically"),
    CheckSpec("firewall_tests", "context firewall still enforces its policy"),
    CheckSpec("memory_checkpoint", "a checkpoint exists for this task"),
    CheckSpec("current_state_updated", "CURRENT_STATE.md reflects the change",
              may_be_not_applicable=True),
    CheckSpec("ownership_released", "no stale task claim"),
)

GUARD_TESTS = (
    "development/tests/domain/test_no_framework_dependencies.py",
    "development/tests/integration/test_p4_pipeline.py",
)


@dataclass
class CheckResult:
    name: str
    status: str
    detail: str = ""
    exit_code: int | None = None
    artifact: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"name": self.name, "status": self.status, "detail": self.detail,
                "exit_code": self.exit_code, "artifact": self.artifact}


class Gate:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.dir = root / "memory" / "runtime" / "gate"
        self.dir.mkdir(parents=True, exist_ok=True)

    # -- git helpers -----------------------------------------------------

    def git(self, *args: str) -> tuple[int, str]:
        proc = subprocess.run(["git", *args], cwd=self.root,
                              capture_output=True, text=True, check=False)
        return proc.returncode, proc.stdout.strip()

    def head(self) -> str:
        return self.git("rev-parse", "HEAD")[1]

    def branch(self) -> str:
        return self.git("rev-parse", "--abbrev-ref", "HEAD")[1]

    def path_for(self, branch: str) -> Path:
        return self.dir / (branch.replace("/", "__") + ".json")

    # -- running pytest --------------------------------------------------

    def _pytest(self, name: str, targets: list[str]) -> CheckResult:
        """Status comes from the exit code AND the JUnit artifact.

        pytest exits 0 when everything skips and 5 when nothing is collected.
        Neither is evidence that a required capability works, so both become
        INCONCLUSIVE rather than PASS.
        """
        report = self.dir / f"{name}.junit.xml"
        if report.exists():
            report.unlink()
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", f"--junitxml={report}", *targets],
            cwd=self.root, capture_output=True, text=True, check=False)

        counts = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
        if report.exists():
            try:
                root = ET.parse(report).getroot()
                node = root if root.tag == "testsuite" else root.find("testsuite")
                if node is not None:
                    counts = {k: int(node.get(k, 0)) for k in counts}
            except ET.ParseError:
                return CheckResult(name, INCONCLUSIVE, "unparseable junit report",
                                   proc.returncode)
        else:
            return CheckResult(name, INCONCLUSIVE, "no junit artifact produced",
                               proc.returncode)

        executed = counts["tests"] - counts["skipped"]
        if proc.returncode == 5 or counts["tests"] == 0:
            return CheckResult(name, INCONCLUSIVE, "no tests collected",
                               proc.returncode, counts)
        if proc.returncode != 0 or counts["failures"] or counts["errors"]:
            return CheckResult(name, FAIL,
                               f"{counts['failures']} failed, {counts['errors']} errors",
                               proc.returncode, counts)
        if executed == 0:
            return CheckResult(name, INCONCLUSIVE,
                               "every test skipped; a required capability was not exercised",
                               proc.returncode, counts)
        return CheckResult(name, PASS, f"{executed} executed", proc.returncode, counts)

    # -- individual checks -----------------------------------------------

    def check_branch(self, task: str) -> CheckResult:
        branch = self.branch()
        slug = task.lower().replace("_", "-")
        tail = slug.split("-")[-1]
        family = "-".join(slug.split("-")[:-1])
        ok = family in branch.lower() and tail in branch.lower()
        return CheckResult("branch_matches_task", PASS if ok else FAIL,
                           f"branch={branch} task={task}")

    def check_clean(self) -> CheckResult:
        _, out = self.git("status", "--porcelain=v1")
        return CheckResult("working_tree_clean", PASS if not out else FAIL,
                           f"{len(out.splitlines())} uncommitted path(s)")

    def check_state_updated(self, waived: str | None) -> CheckResult:
        if waived:
            return CheckResult("current_state_updated", NOT_APPLICABLE, waived)
        code, base = self.git("merge-base", "main", "HEAD")
        if code != 0:
            return CheckResult("current_state_updated", INCONCLUSIVE, "no merge base")
        _, files = self.git("diff", "--name-only", f"{base}..HEAD")
        ok = "docs/CURRENT_STATE.md" in files.split("\n")
        return CheckResult("current_state_updated", PASS if ok else FAIL,
                           "CURRENT_STATE.md " + ("changed" if ok else "unchanged"))

    def check_checkpoint(self, task: str) -> CheckResult:
        buckets = sorted((self.root / "memory" / "runtime" / "buckets").glob("*.jsonl"))
        for bucket in reversed(buckets):
            for line in reversed(bucket.read_text().splitlines()):
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if record.get("task_id") == task:
                    return CheckResult("memory_checkpoint", PASS,
                                       f"sequence {record.get('sequence')}")
        return CheckResult("memory_checkpoint", FAIL, f"no checkpoint for {task}")

    def check_ownership(self, task: str) -> CheckResult:
        path = self.root / "memory" / "runtime" / "ownership.json"
        if not path.is_file():
            return CheckResult("ownership_released", PASS, "no claims file")
        try:
            claims = json.loads(path.read_text()).get("claims", [])
        except json.JSONDecodeError:
            return CheckResult("ownership_released", INCONCLUSIVE, "unreadable claims")
        held = [c for c in claims if c.get("task") == task]
        return CheckResult("ownership_released", FAIL if held else PASS,
                           f"{len(held)} open claim(s) for {task}")

    # -- gate lifecycle --------------------------------------------------

    def run(self, task: str, focused: list[str], waive_state: str | None) -> dict:
        results = [
            self.check_branch(task),
            self.check_clean(),
            self._pytest("focused_tests", focused) if focused
            else CheckResult("focused_tests", NOT_APPLICABLE, "no focused path given"),
            self._pytest("full_suite", []),
            self._pytest("framework_guards", list(GUARD_TESTS)),
            self._pytest("firewall_tests", ["tests/tools"]),
            self.check_checkpoint(task),
            self.check_state_updated(waive_state),
            self.check_ownership(task),
        ]
        return self._finalise(task, results)

    def _finalise(self, task: str, results: list[CheckResult]) -> dict:
        blocking = self.evaluate([r.to_dict() for r in results])

        gate = {
            "schema_version": SCHEMA_VERSION,
            "task_id": task,
            "branch": self.branch(),
            "head_commit": self.head(),
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "checks": [r.to_dict() for r in results],
            "blocking": blocking,
            "merge_eligible": not blocking,
        }
        path = self.path_for(gate["branch"])
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(gate, indent=2, sort_keys=True) + "\n")
        tmp.replace(path)
        return gate

    def load(self, branch: str) -> dict | None:
        path = self.path_for(branch)
        if not path.is_file():
            return None
        try:
            return json.loads(path.read_text())
        except json.JSONDecodeError:
            return None

    def validate(self, branch: str) -> tuple[bool, str, dict | None]:
        gate = self.load(branch)
        if gate is None:
            return False, f"{NOT_RUN}: no gate result for {branch}", None
        if gate.get("schema_version") != SCHEMA_VERSION:
            return False, "unsupported gate schema", gate
        code, head = self.git("rev-parse", branch)
        if code != 0:
            return False, f"unknown branch {branch}", gate
        if gate.get("head_commit") != head:
            return (False,
                    f"{STALE}: gate was produced against {gate.get('head_commit','?')[:8]}, "
                    f"branch is now at {head[:8]}", gate)
        # Re-derive eligibility from the per-check statuses rather than
        # trusting the stored boolean. A producer bug -- or a hand-edited
        # artifact -- must not be able to assert its own merge eligibility.
        blocking = self.evaluate(gate.get("checks", []))
        if blocking:
            return False, "blocked: " + "; ".join(blocking), gate
        if not gate.get("merge_eligible"):
            return False, "artifact disagrees with its own checks", gate
        return True, "gate valid", gate

    @staticmethod
    def evaluate(checks: list[dict]) -> list[str]:
        """The single place merge eligibility is decided, used by both the
        producer and the validator so they cannot drift apart."""
        by_name = {c.get("name"): c.get("status") for c in checks}
        blocking = []
        for spec in CHECK_SPECS:
            status = by_name.get(spec.name)
            if status is None:
                blocking.append(f"{spec.name}: {NOT_RUN}")
            elif status == NOT_APPLICABLE and not spec.may_be_not_applicable:
                blocking.append(f"{spec.name}: NOT_APPLICABLE is not permitted")
            elif status not in MERGEABLE:
                blocking.append(f"{spec.name}: {status}")
        return blocking

    def merge(self, branch: str, message: str | None,
              keep_branch: bool = False) -> int:
        ok, reason, gate = self.validate(branch)
        print(f"MERGE GATE: {'PASS' if ok else 'FAIL'}")
        print(f"branch: {branch}")
        if gate:
            for check in gate["checks"]:
                print(f"  {check['status']:<15} {check['name']}  {check['detail']}")
        print(f"reason: {reason}")
        if not ok:
            print("\nREADY TO MERGE: NO -- fix the branch; there is no override.",
                  file=sys.stderr)
            return 1
        current = self.branch()
        if current != "main":
            print(f"refusing: merge must run from main, currently on {current}",
                  file=sys.stderr)
            return 1
        text = message or f"Merge {branch} into main"
        code, out = self.git("merge", "--no-ff", "-m", text, branch)
        print(out)
        if code != 0:
            return code

        # Delete the branch as part of the merge, not as a habit to remember.
        # The merge commit preserves the history; a branch ref left behind is
        # only clutter, and stale refs make it harder to see what is actually
        # in flight.
        if not keep_branch:
            deleted, detail = self.git("branch", "-d", branch)
            print(detail if deleted == 0 else f"branch not deleted: {detail}")
            if deleted != 0:
                print("warning: branch retained; delete it once resolved",
                      file=sys.stderr)
        return code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="merge_gate", description=__doc__)
    parser.add_argument("--root", default=None)
    sub = parser.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run")
    r.add_argument("--task", required=True)
    r.add_argument("--focused", action="append", default=[])
    r.add_argument("--waive-current-state", default=None,
                   help="reason CURRENT_STATE.md needs no change on this branch")

    s = sub.add_parser("status")
    s.add_argument("--branch", default=None)

    m = sub.add_parser("merge")
    m.add_argument("branch")
    m.add_argument("-m", "--message", default=None)
    m.add_argument("--keep-branch", action="store_true",
                   help="retain the branch ref after merging (rarely wanted)")

    args = parser.parse_args(argv)
    root = Path(args.root).resolve() if args.root else default_policy().root
    gate = Gate(root)

    if args.cmd == "run":
        result = gate.run(args.task, args.focused, args.waive_current_state)
        for check in result["checks"]:
            print(f"  {check['status']:<15} {check['name']}  {check['detail']}")
        print(f"\nmerge_eligible: {result['merge_eligible']}")
        for reason in result["blocking"]:
            print(f"  BLOCKING  {reason}")
        return 0 if result["merge_eligible"] else 1

    if args.cmd == "status":
        branch = args.branch or gate.branch()
        ok, reason, _ = gate.validate(branch)
        print(f"{branch}: {'PASS' if ok else 'FAIL'} -- {reason}")
        return 0 if ok else 1

    return gate.merge(args.branch, args.message, args.keep_branch)


if __name__ == "__main__":
    raise SystemExit(main())
