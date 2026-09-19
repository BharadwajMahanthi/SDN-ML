"""Run an approved local command; return a bounded, redacted summary.

Full output is written to a local log under the policy's ``local_log_dir``
(itself a blocked path, so the log can never be fetched back wholesale).
What comes back is a summary plus a bounded tail -- retrieve more with
``--tail`` or ``--grep``, never by dumping the log.

  python tools/safe_exec.py -- pytest -q
  python tools/safe_exec.py --tail 40 -- git status --short
  python tools/safe_exec.py --grep FAILED -- pytest -q
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
import uuid
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.context_policy import Policy, PolicyViolation, default_policy
from tools.redact import redact, summarize


def screen_arguments(policy: Policy, argv: list[str]) -> None:
    """Refuse arguments that name a blocked path, even for an allowed command."""
    for arg in argv[1:]:
        if arg.startswith("-"):
            continue
        candidate = policy.root / arg
        if not candidate.exists():
            continue
        try:
            if policy.is_blocked(arg):
                raise PolicyViolation(f"argument names a blocked path: {arg}")
        except PolicyViolation:
            raise


def run(policy: Policy, argv: list[str], *, timeout: int) -> tuple[int, str, float, Path]:
    policy.check_command(argv)
    screen_arguments(policy, argv)
    started = time.monotonic()
    try:
        proc = subprocess.run(
            argv, cwd=policy.root, capture_output=True, text=True,
            timeout=timeout, check=False,
        )
        combined = proc.stdout + (("\n" + proc.stderr) if proc.stderr else "")
        code = proc.returncode
    except subprocess.TimeoutExpired:
        combined, code = f"<timeout after {timeout}s>", 124
    except FileNotFoundError:
        combined, code = f"<command not found: {argv[0]}>", 127
    elapsed = time.monotonic() - started

    log = policy.log_dir() / f"{time.strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:8]}.log"
    log.write_text(combined)
    return code, combined, elapsed, log


def report(policy: Policy, argv: list[str], code: int, combined: str,
           elapsed: float, log: Path, *, tail: int, grep: str | None) -> None:
    lines = combined.splitlines()
    limit = min(tail, policy.limits.max_command_lines)
    if grep:
        selected = [f"{i}: {l}" for i, l in enumerate(lines, 1) if grep in l]
        label = f"matching {grep!r}"
    else:
        selected = lines[-limit:]
        label = f"last {min(limit, len(lines))} of {len(lines)}"
    shown = selected[:limit]
    body = redact("\n".join(shown))
    cap = policy.limits.max_line_chars
    printable = "\n".join(
        l if len(l) <= cap else l[:cap] + " ...[truncated]" for l in body.text.splitlines()
    )

    # The command line itself can carry a credential (e.g. `mysql -pSECRET`),
    # so it is redacted like any other output rather than echoed verbatim.
    echoed = redact(" ".join(argv))

    print("EXEC_RESULT")
    print(f"command: {echoed.text}")
    print(f"exit: {code}")
    print(f"duration_s: {elapsed:.2f}")
    print(f"output_lines: {len(lines)}")
    print(f"shown: {label} (limit={limit})")
    print(f"full_log: LOCAL_ONLY {log.relative_to(policy.root)}")
    if printable:
        print("---")
        print(printable)
    if len(selected) > limit:
        print(f"...[{len(selected) - limit} more suppressed; use --grep to narrow]")
    print(summarize(body.findings + echoed.findings))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="safe_exec", description=__doc__)
    parser.add_argument("--tail", type=int, default=40)
    parser.add_argument("--grep")
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)

    command = args.command[1:] if args.command and args.command[0] == "--" else args.command
    if not command:
        parser.error("no command given (use: safe_exec.py -- <cmd> [args])")

    policy = default_policy()
    try:
        code, combined, elapsed, log = run(policy, command, timeout=args.timeout)
    except PolicyViolation as exc:
        print(f"POLICY_VIOLATION: {exc}", file=sys.stderr)
        return 2
    report(policy, command, code, combined, elapsed, log, tail=args.tail, grep=args.grep)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
