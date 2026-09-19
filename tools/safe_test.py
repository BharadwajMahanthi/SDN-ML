"""Run pytest and return a bounded TEST_RESULT block.

Full pytest output stays local. Failure detail is retrieved per-test, on
demand, so a broken suite cannot flood the context window.

  python tools/safe_test.py
  python tools/safe_test.py --path tests/tools
  python tools/safe_test.py --failure tests/tools/test_redact.py::test_pem
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.context_policy import Policy, default_policy
from tools.redact import redact, summarize

_COUNT = re.compile(r"(?P<n>\d+)\s+(?P<kind>passed|failed|error|errors|skipped|xfailed|xpassed)")
_FAIL_LINE = re.compile(r"^(?:FAILED|ERROR)\s+(?P<nodeid>\S+)")


@dataclass
class Summary:
    counts: dict[str, int]
    failures: list[str]
    exit_code: int
    duration: float
    log: Path


def _pytest(policy: Policy, extra: list[str], timeout: int) -> tuple[int, str, float]:
    started = time.monotonic()
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", *extra],
            cwd=policy.root, capture_output=True, text=True, timeout=timeout, check=False,
        )
        out = proc.stdout + ("\n" + proc.stderr if proc.stderr else "")
        code = proc.returncode
    except subprocess.TimeoutExpired:
        out, code = f"<pytest timeout after {timeout}s>", 124
    return code, out, time.monotonic() - started


def collect(policy: Policy, path: str | None, timeout: int) -> Summary:
    extra = ["-q", "--tb=no", "-rfE"]
    if path:
        extra.append(path)
    code, out, elapsed = _pytest(policy, extra, timeout)

    log = policy.log_dir() / f"pytest-{time.strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:6]}.log"
    log.write_text(out)

    # pytest -q does not prefix its summary line with '=', so scan every line
    # and keep the last one that parses as a count summary.
    counts: dict[str, int] = {}
    for line in out.splitlines():
        matches = list(_COUNT.finditer(line))
        if not matches:
            continue
        parsed = {
            ("error" if m.group("kind") == "errors" else m.group("kind")): int(m.group("n"))
            for m in matches
        }
        counts = parsed
    failures = [m.group("nodeid") for line in out.splitlines() if (m := _FAIL_LINE.match(line))]
    return Summary(counts, failures, code, elapsed, log)


def render(policy: Policy, summary: Summary, suite: str) -> None:
    print("TEST_RESULT")
    print(f"suite: {suite}")
    print(f"exit: {summary.exit_code}")
    print(f"duration_s: {summary.duration:.2f}")
    for kind in ("passed", "failed", "error", "skipped", "xfailed", "xpassed"):
        if kind in summary.counts:
            print(f"{kind}: {summary.counts[kind]}")
    if summary.failures:
        print("failures:")
        shown = summary.failures[: policy.limits.max_search_results]
        for nodeid in shown:
            print(f"  {nodeid}")
        if len(summary.failures) > len(shown):
            print(f"  ...[{len(summary.failures) - len(shown)} more]")
        print("detail: rerun with --failure <nodeid>")
    print(f"full_log: LOCAL_ONLY {summary.log.relative_to(policy.root)}")


def show_failure(policy: Policy, nodeid: str, timeout: int) -> int:
    code, out, _ = _pytest(policy, ["-q", "--tb=short", "--no-header", nodeid], timeout)
    lines = out.splitlines()
    limit = policy.limits.max_command_lines
    body = redact("\n".join(lines[:limit]))
    print(f"FAILURE_DETAIL nodeid={nodeid} exit={code} lines={len(lines)} limit={limit}")
    print(body.text)
    if len(lines) > limit:
        print(f"...[{len(lines) - limit} more suppressed]")
    print(summarize(body.findings))
    return code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="safe_test", description=__doc__)
    parser.add_argument("--path")
    parser.add_argument("--failure")
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args(argv)
    policy = default_policy()

    if args.failure:
        return show_failure(policy, args.failure, args.timeout)
    summary = collect(policy, args.path, args.timeout)
    render(policy, summary, args.path or "all")
    return 0 if not summary.failures and summary.exit_code in (0, 5) else 1


if __name__ == "__main__":
    raise SystemExit(main())
