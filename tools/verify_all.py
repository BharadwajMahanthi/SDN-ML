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
import re
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

#: Files permitted to contain a private-key *header* because the body is
#: fabricated. Each entry is an allowance somebody has to justify, and a
#: stale one is reported so the list cannot quietly grow.
EXPECTED_KEY_MATERIAL = {
    "tests/tools/fixtures.py":
        "a synthetic PEM body ('NOTAREALKEY') the redactor is tested against",
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


#: Headers that mean the file *is* key material, whatever it is called. The
#: extension allowlist in ``check_secrets`` skips binary and unknown types,
#: which is how three RSA lab CA keys stayed in this repository undetected
#: until they were about to be published (KF-35). This check has no
#: extension filter on purpose.
_KEY_MATERIAL_MARKERS = (
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
)


def check_key_material(root: Path) -> Check:
    """No tracked file may contain a private key, whatever its name.

    Separate from ``check_secrets`` because that check answers "does this
    source file mention a secret" and filters to text extensions to stay
    fast. This one answers "is this file a key", which is a different
    question and cannot afford a filter: the files that matter most are
    exactly the ones an extension allowlist drops.
    """
    _, listing = _run(["git", "ls-files"], root, 120)
    offenders: list[str] = []
    for name in listing.splitlines():
        path = root / name
        try:
            if path.stat().st_size > 4_000_000:
                continue
            with open(path, "rb") as handle:
                head = handle.read(8192)
        except OSError:
            continue
        try:
            text = head.decode("utf-8", errors="replace")
        except ValueError:
            continue
        if any(marker in text for marker in _KEY_MATERIAL_MARKERS):
            offenders.append(name)
    unexpected = [name for name in offenders if name not in EXPECTED_KEY_MATERIAL]
    if unexpected:
        # The location is reported; the key body never is.
        return Check("key_material", FAIL,
                     f"{len(unexpected)} tracked file(s) contain private key "
                     f"material: {unexpected[:3]}")
    stale = [name for name in EXPECTED_KEY_MATERIAL
             if name not in offenders and (root / name).exists()]
    if stale:
        return Check("key_material", WARN,
                     f"{len(stale)} allowance(s) no longer needed: {stale[:3]}")
    return Check("key_material", OK,
                 f"no unexpected key material; {len(offenders)} known fixture(s)")


def check_invariants(root: Path) -> Check:
    """Every declared security invariant must still map to tests that exist.

    `docs/invariants.json` is the list of properties this system claims to
    hold. An invariant whose tests were renamed or deleted is worse than one
    that was never written down: the document asserts coverage that is no
    longer there, and nobody rereads it.

    This checks the mapping, not the outcome -- whether those tests *pass* is
    the full suite's job. What it catches is silent decoupling.
    """
    path = root / "docs" / "invariants.json"
    if not path.is_file():
        return Check("security_invariants", FAIL, "docs/invariants.json is missing")
    try:
        document = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return Check("security_invariants", FAIL, f"unreadable: {exc}")

    invariants = document.get("invariants")
    if not isinstance(invariants, list) or not invariants:
        return Check("security_invariants", FAIL, "no invariants declared")

    problems: list[str] = []
    for entry in invariants:
        identifier = entry.get("id", "<no id>")
        if not entry.get("statement"):
            problems.append(f"{identifier}: no statement")
        tests = entry.get("tests") or []
        if not tests:
            problems.append(f"{identifier}: no tests mapped")
        for relative in tests:
            if not (root / relative).exists():
                problems.append(f"{identifier}: missing {relative}")
    if problems:
        return Check("security_invariants", FAIL,
                     f"{len(problems)} problem(s): {problems[:3]}")
    return Check("security_invariants", OK,
                 f"{len(invariants)} invariant(s), all mapped to existing tests")


def check_capabilities(root: Path) -> Check:
    """No capability may claim SUPPORTED without evidence that exists.

    `docs/capabilities.json` is the one place that says what this system
    claims. The failure it guards against is the quiet one: a capability
    written down as SUPPORTED because it worked once, whose evidence file was
    renamed, or which was promoted from NOT_RUN by a hopeful edit. Both look
    identical in a document and neither survives this check.
    """
    path = root / "docs" / "capabilities.json"
    if not path.is_file():
        return Check("capability_claims", FAIL, "docs/capabilities.json missing")
    try:
        document = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return Check("capability_claims", FAIL, f"unreadable: {exc}")

    known_profiles = set(document.get("profiles", {}))
    problems: list[str] = []
    counts: dict[str, int] = {}
    for entry in document.get("capabilities", []):
        identifier = entry.get("id", "<no id>")
        status = entry.get("status", "")
        counts[status] = counts.get(status, 0) + 1
        if status == "SUPPORTED":
            if not entry.get("evidence"):
                problems.append(f"{identifier}: SUPPORTED with no evidence")
            if not entry.get("profiles"):
                problems.append(f"{identifier}: SUPPORTED on no profile")
            for name in entry.get("profiles", []):
                if name not in known_profiles:
                    problems.append(f"{identifier}: unknown profile {name}")
            # An evidence value that names a file must name one that is there.
            reference = str(entry.get("evidence", ""))
            for token in reference.replace(",", " ").split():
                if token.startswith("docs/") and not (root / token).exists():
                    problems.append(f"{identifier}: missing {token}")
        elif status in ("NOT_RUN", "NOT_IMPLEMENTED"):
            if entry.get("profiles"):
                problems.append(
                    f"{identifier}: {status} but claims a profile")
        elif status:
            problems.append(f"{identifier}: unknown status {status!r}")
    if problems:
        return Check("capability_claims", FAIL,
                     f"{len(problems)} problem(s): {problems[:3]}")
    summary = ", ".join(f"{k.lower()}={v}" for k, v in sorted(counts.items()))
    return Check("capability_claims", OK, summary)


#: Work before this commit predates the merge-gate discipline and is not
#: held to it. Everything after it must reach `main` through a merge.
DISCIPLINE_BEGINS = "450f20a"

#: Direct commits on `main` that are accepted despite the rule. Each is
#: pinned by hash so the allowance cannot silently widen.
MAIN_DIRECT_COMMIT_ALLOWANCES = {
    "f02ebe1": "V2-INT-01 CURRENT_STATE entry, committed to main by mistake "
               "and left in place rather than rewriting shared history; the "
               "incident is KF-54 and is what prompted this check",
}


def check_main_history(root: Path) -> Check:
    """Work reaches `main` through the merge gate, not around it.

    The gate is an executable check on a branch. Nothing stopped a commit
    landing directly on `main` and skipping it entirely -- which happened
    once, silently, and was noticed only because a later gate run reported
    `CURRENT_STATE.md unchanged` for a file that had already been updated
    (KF-54).

    A governance rule that can be bypassed without anyone noticing is a
    governance rule that will be bypassed. This looks at recent history on
    `main` and refuses anything that is neither a merge nor an explicit
    allowance.
    """
    # First-parent only: `--no-merges` alone also lists every commit that
    # arrived *through* a merge, which is the normal case and not a bypass.
    # Bounded to the era the rule applies to -- the original project history
    # predates the merge gate and is not held to it.
    code, out = _run(["git", "log", "--first-parent", "--no-merges",
                      "--format=%h %s", f"{DISCIPLINE_BEGINS}..main"],
                     root, 60)
    if code != 0:
        return Check("main_history", WARN, "cannot read main history")
    direct = []
    for line in out.splitlines():
        if not line.strip():
            continue
        short, _, subject = line.partition(" ")
        if any(short.startswith(allowed) or allowed.startswith(short)
               for allowed in MAIN_DIRECT_COMMIT_ALLOWANCES):
            continue
        direct.append(f"{short} {subject[:56]}")
    if direct:
        return Check("main_history", FAIL,
                     f"{len(direct)} commit(s) bypassed the merge gate: "
                     f"{direct[:2]}")
    return Check("main_history", OK,
                 f"recent main history is merges only, "
                 f"{len(MAIN_DIRECT_COMMIT_ALLOWANCES)} pinned allowance(s)")


def check_assurance_case(root: Path) -> Check:
    """Every artifact the assurance case cites must exist and be readable.

    The case is the document somebody would rely on. A citation that has been
    renamed, or an artifact that was never committed, turns it into an
    argument with a hole in the middle -- and the hole is invisible when
    reading it, because a missing file looks exactly like a present one in
    prose.
    """
    path = root / "docs" / "ASSURANCE_CASE.md"
    if not path.is_file():
        return Check("assurance_case", FAIL, "docs/ASSURANCE_CASE.md missing")
    text = path.read_text()
    cited = sorted(set(re.findall(r"`?(v2-[a-z0-9._-]+\.json)`?", text)))
    if not cited:
        return Check("assurance_case", FAIL, "the case cites no evidence")
    missing = [name for name in cited
               if not (root / "docs" / "evidence" / name).is_file()]
    if missing:
        return Check("assurance_case", FAIL,
                     f"{len(missing)} cited artifact(s) absent: {missing[:3]}")
    unreadable = []
    for name in cited:
        try:
            json.loads((root / "docs" / "evidence" / name).read_text())
        except (OSError, json.JSONDecodeError):
            unreadable.append(name)
    if unreadable:
        return Check("assurance_case", FAIL,
                     f"{len(unreadable)} cited artifact(s) unparseable: "
                     f"{unreadable[:3]}")
    # The scope statement is the part that keeps the case honest.
    for required in ("does **not** claim", "Not claimed",
                     "What would falsify"):
        if required not in text:
            return Check("assurance_case", FAIL,
                         f"the case no longer contains {required!r}")
    return Check("assurance_case", OK,
                 f"{len(cited)} cited artifact(s), all present and parseable")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="verify_all", description=__doc__)
    parser.add_argument("--cloud", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    root = default_policy().root

    checks = [check_worktree(root), check_branches(root), check_memory(root),
              check_firewall(root), check_boundaries(root), check_secrets(root),
              check_key_material(root), check_invariants(root),
              check_capabilities(root), check_main_history(root),
              check_assurance_case(root),
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
