"""Whole-system re-verification.

The premise: nothing stays verified. A guard that passed last week may have
been narrowed, a policy file edited, a package added outside a boundary, an
AWS resource left running, a branch left behind. Each is individually small
and none of them announce themselves.

So this re-checks every standing invariant in one pass, rather than trusting
that a thing verified once is still true.

    python tools/verify_all.py            # local invariants only
    python tools/verify_all.py --cloud    # also query AWS state
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.context_policy import default_policy

OK, WARN, FAIL = "OK", "WARN", "FAIL"


@dataclass
class Check:
    name: str
    status: str
    detail: str


def _run(args: list[str], root: Path, timeout: int = 900) -> tuple[int, str]:
    proc = subprocess.run(args, cwd=root, capture_output=True, text=True,
                          timeout=timeout, check=False)
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def check_tests(root: Path) -> Check:
    code, out = _run([sys.executable, "-m", "pytest", "-q", "--tb=no"], root)
    tail = out.strip().splitlines()[-1] if out.strip() else "no output"
    return Check("full_test_suite", OK if code == 0 else FAIL, tail)


def check_boundaries(root: Path) -> Check:
    """The framework boundary is the invariant most likely to erode quietly,
    because every new package is a chance to widen it by accident."""
    code, out = _run([sys.executable, "-m", "pytest", "-q", "--tb=line",
                      "development/tests/domain/test_no_framework_dependencies.py",
                      "development/tests/integration/test_p4_pipeline.py"], root)
    tail = out.strip().splitlines()[-1] if out.strip() else ""
    return Check("framework_boundaries", OK if code == 0 else FAIL, tail)


def check_firewall(root: Path) -> Check:
    code, out = _run([sys.executable, "-m", "pytest", "-q", "--tb=line",
                      "tests/tools"], root)
    tail = out.strip().splitlines()[-1] if out.strip() else ""
    return Check("context_firewall", OK if code == 0 else FAIL, tail)


def check_memory(root: Path) -> Check:
    code, out = _run([sys.executable, "tools/memory.py", "validate"], root, 120)
    return Check("project_memory", OK if code == 0 else FAIL, out.splitlines()[0]
                 if out else "")


#: Long-lived branches that are never merged and must not be deleted.
#: Exempt from the delete-on-merge rule, with the reason stated here so that
#: neither a human nor an agent tidies one away.
ARCHIVE_BRANCHES = {
    "legacy/java-topoguard-research":
        "the original Floodlight/TopoGuard tree, preserved by ADR-045",
}


def check_branches(root: Path) -> Check:
    _, out = _run(["git", "branch", "--format=%(refname:short)"], root, 60)
    branches = [b for b in out.splitlines() if b and b != "main"]
    _, merged = _run(["git", "branch", "--merged", "main",
                      "--format=%(refname:short)"], root, 60)
    _, current = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"], root, 60)
    # A freshly created branch with no commits is trivially "merged". Excluding
    # the checked-out branch keeps the check about leftovers, not work in hand.
    stale = [b for b in merged.splitlines()
             if b and b not in ("main", current.strip())
             and b not in ARCHIVE_BRANCHES]
    missing_archive = [b for b in ARCHIVE_BRANCHES if b not in branches]
    if missing_archive:
        return Check("branch_hygiene", FAIL,
                     f"archive branch(es) missing: {missing_archive}")
    if stale:
        return Check("branch_hygiene", WARN,
                     f"{len(stale)} merged branch(es) not deleted: {stale[:3]}")
    return Check("branch_hygiene", OK,
                 f"{len(branches)} working branch(es) besides main")


def check_worktree(root: Path) -> Check:
    _, out = _run(["git", "status", "--porcelain=v1"], root, 60)
    count = len([l for l in out.splitlines() if l])
    return Check("working_tree", OK if count == 0 else WARN,
                 f"{count} uncommitted path(s)")


#: Files that intentionally contain secret-shaped strings, with the reason.
#: Anything outside this set is a FAIL, not a warning -- a scan that always
#: warns is a scan everyone learns to ignore.
EXPECTED_SECRET_SHAPES = {
    "tests/tools/fixtures.py": "fabricated credentials the redactor is tested against",
    "tests/tools/test_redact.py": "the canonical AWS example, asserted to be redacted",
    "development/tests/core/test_events.py": "fuzz alphabet strings",
    "docs/KNOWN_FAILURES.md": "KF-24 documents the AWS example verbatim",
    "tests/memory/test_quota_and_concurrency.py":
        "fabricated AWS key id, asserting the memory store refuses it",
    "tools/redact.py": "the redactor's own docstring cites the AWS example",
}


def check_secrets(root: Path) -> Check:
    """Re-scan tracked text for credential shapes. The firewall protects what
    leaves the machine; this asks whether something got committed."""
    from tools.redact import redact

    _, listing = _run(["git", "ls-files"], root, 120)
    findings: list[str] = []
    for name in listing.splitlines():
        path = root / name
        if path.suffix.lower() not in {".py", ".sh", ".yaml", ".yml", ".json",
                                       ".md", ".toml", ".cfg", ".properties"}:
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        if len(text) > 400_000:
            continue
        result = redact(text)
        real = [f for f in result.findings if f.kind != "assigned_secret"]
        if real:
            findings.append(f"{name}: {sorted({f.kind for f in real})}")
    unexpected = [f for f in findings
                  if f.split(":")[0] not in EXPECTED_SECRET_SHAPES]
    if unexpected:
        return Check("committed_secrets", FAIL,
                     f"{len(unexpected)} unexpected file(s): {unexpected[:2]}")
    stale = [p for p in EXPECTED_SECRET_SHAPES
             if not any(f.startswith(p + ":") for f in findings)
             and (root / p).exists()]
    if stale:
        # An entry that no longer matches is an allowance nobody removed.
        return Check("committed_secrets", WARN,
                     f"{len(stale)} allowance(s) no longer needed: {stale[:3]}")
    return Check("committed_secrets", OK,
                 f"{len(findings)} known fixture(s), nothing unexpected")


def check_cloud(root: Path) -> list[Check]:
    checks: list[Check] = []
    base = ["aws", "--profile", "sdnguard", "--region", "ap-south-1"]
    code, out = _run(base + ["ec2", "describe-instances", "--filters",
                             "Name=instance-state-name,Values=pending,running,stopping,stopped",
                             "--query", "length(Reservations[].Instances[])",
                             "--output", "text"], root, 120)
    checks.append(Check("aws_instances", OK if out.strip() in ("0", "") else WARN,
                        f"{out.strip() or '?'} instance(s) not terminated"))
    code, out = _run(base + ["ec2", "describe-volumes", "--query",
                             "length(Volumes)", "--output", "text"], root, 120)
    checks.append(Check("aws_volumes", OK if out.strip() in ("0", "") else WARN,
                        f"{out.strip() or '?'} volume(s)"))
    code, out = _run(base + ["sts", "get-caller-identity", "--query", "Arn",
                             "--output", "text"], root, 120)
    is_temp = "assumed-role" in out
    checks.append(Check("aws_credential_type", OK if is_temp else FAIL,
                        "temporary session" if is_temp
                        else "NOT a temporary session"))
    return checks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="verify_all", description=__doc__)
    parser.add_argument("--cloud", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    root = default_policy().root

    checks = [check_worktree(root), check_branches(root), check_memory(root),
              check_firewall(root), check_boundaries(root), check_secrets(root),
              check_tests(root)]
    if args.cloud:
        checks.extend(check_cloud(root))

    failed = [c for c in checks if c.status == FAIL]
    warned = [c for c in checks if c.status == WARN]
    payload = {"checked_utc": datetime.now(timezone.utc).isoformat(),
               "checks": [c.__dict__ for c in checks],
               "failed": len(failed), "warned": len(warned)}
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print("WHOLE-SYSTEM VERIFICATION")
        for c in checks:
            print(f"  {c.status:<5} {c.name:<24} {c.detail}")
        print(f"\n{len(checks)} checks, {len(failed)} failed, {len(warned)} warned")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
