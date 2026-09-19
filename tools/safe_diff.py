"""Summarise working-tree changes before disclosing any diff text.

Default output is structural: files, symbol-level changes, +/- counts.
Actual diff fragments require ``--show <path>`` and remain bounded.

  python tools/safe_diff.py
  python tools/safe_diff.py --staged
  python tools/safe_diff.py --show src/models.py
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.context_policy import Policy, PolicyViolation, default_policy
from tools.redact import redact, summarize
from tools.repo_query import _parse_quietly, _python_symbols


def _git(policy: Policy, args: list[str]) -> str:
    proc = subprocess.run(["git", *args], cwd=policy.root,
                          capture_output=True, text=True, check=False)
    return proc.stdout


def _symbol_names(text: str, rel: Path) -> set[str]:
    from pathlib import PurePosixPath
    if rel.suffix != ".py" or _parse_quietly(text) is None:
        return set()
    return {s.name for s in _python_symbols(PurePosixPath(rel.as_posix()), text)}


def summarise(policy: Policy, staged: bool) -> int:
    scope = ["--cached"] if staged else []
    numstat = _git(policy, ["diff", *scope, "--numstat"]).splitlines()
    status = dict(
        (parts[-1], parts[0])
        for line in _git(policy, ["diff", *scope, "--name-status"]).splitlines()
        if (parts := line.split("\t")) and len(parts) >= 2
    )
    print("DIFF_SUMMARY")
    print(f"scope: {'staged' if staged else 'working-tree'}")
    if not numstat:
        print("files_changed: 0")
        return 0

    total_add = total_del = 0
    shown = 0
    for line in numstat:
        added, removed, path = (line.split("\t") + ["", "", ""])[:3]
        try:
            rel = policy.check_listable(path)
        except PolicyViolation:
            print(f"  [blocked path omitted] status={status.get(path, '?')}")
            continue
        a = int(added) if added.isdigit() else 0
        d = int(removed) if removed.isdigit() else 0
        total_add += a
        total_del += d
        if shown >= policy.limits.max_search_results:
            continue
        shown += 1
        marker = status.get(path, "M")
        detail = ""
        if rel.suffix == ".py" and not policy.is_opaque(rel):
            old = _git(policy, ["show", f"HEAD:{rel.as_posix()}"])
            new_path = policy.root / rel
            new = new_path.read_text(errors="replace") if new_path.exists() else ""
            before, after = _symbol_names(old, Path(rel)), _symbol_names(new, Path(rel))
            added_syms = sorted(after - before)[:5]
            removed_syms = sorted(before - after)[:5]
            bits = []
            if added_syms:
                bits.append("+" + ",".join(added_syms))
            if removed_syms:
                bits.append("-" + ",".join(removed_syms))
            detail = f"  symbols: {'; '.join(bits)}" if bits else ""
        print(f"  {marker} {rel.as_posix()} (+{a}/-{d}){detail}")
    print(f"files_changed: {len(numstat)}  insertions: {total_add}  deletions: {total_del}")
    print("fragments: use --show <path>")
    return 0


def show(policy: Policy, path: str, staged: bool) -> int:
    rel = policy.check_readable(path)
    scope = ["--cached"] if staged else []
    text = _git(policy, ["diff", *scope, "--", rel.as_posix()])
    lines = text.splitlines()
    limit = policy.limits.max_diff_lines
    body = redact("\n".join(lines[:limit]))
    print(f"DIFF_FRAGMENT {rel.as_posix()} lines={len(lines)} limit={limit}")
    print(body.text)
    if len(lines) > limit:
        print(f"...[{len(lines) - limit} more suppressed]")
    print(summarize(body.findings))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="safe_diff", description=__doc__)
    parser.add_argument("--staged", action="store_true")
    parser.add_argument("--show")
    args = parser.parse_args(argv)
    policy = default_policy()
    try:
        return show(policy, args.show, args.staged) if args.show else summarise(policy, args.staged)
    except PolicyViolation as exc:
        print(f"POLICY_VIOLATION: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
