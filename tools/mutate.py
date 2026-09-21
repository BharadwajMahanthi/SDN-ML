#!/usr/bin/env python3
"""Mutation testing for security-critical decision logic.

The question this tool asks is the one a passing suite cannot answer:

    if somebody accidentally reverses, deletes or weakens a security check,
    will the tests notice?

It rewrites one AST node at a time in a target module, runs a nominated test
selection against the mutated source, and records whether the suite failed.
A mutation the suite still passes is a **survivor**: a change to security
semantics that nothing detected.

Scope is deliberately narrow. Run over a whole repository this produces
thousands of irrelevant survivors in logging and formatting, and the number
stops meaning anything. It is pointed at authorization predicates, where a
single inverted comparison is a privilege escalation.

Survivors are reported individually, never averaged into a score. "94%
killed" is not a security statement; "the protected-target check can be
deleted without any test failing" is.
"""

from __future__ import annotations

import argparse
import ast
import atexit
import json
import os
import signal
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
#: This tool rewrites the module under test **in place** so that pytest
#: imports the mutated source. That makes concurrent use actively dangerous:
#: a second test run started while a mutation is applied sees corrupted
#: source and reports failures that have nothing to do with it. Observed
#: exactly that way -- four unrelated backend tests failed while a mutation
#: run held a different module rewritten (KF-41). The lock makes it an
#: error rather than a mystery.
_LOCK = REPO / ".mutate.lock"


@dataclass
class Mutation:
    line: int
    kind: str
    original: str
    mutated: str

    def label(self) -> str:
        return f"L{self.line} {self.kind}: {self.original} -> {self.mutated}"


class _Mutator(ast.NodeTransformer):
    """Applies exactly one mutation, identified by a counter."""

    #: Comparison flips. A `<` that becomes `<=` is the classic off-by-one
    #: that turns "exceeds the limit" into "is at the limit".
    COMPARE = {ast.Lt: ast.LtE, ast.LtE: ast.Lt, ast.Gt: ast.GtE,
               ast.GtE: ast.Gt, ast.Eq: ast.NotEq, ast.NotEq: ast.Eq,
               ast.In: ast.NotIn, ast.NotIn: ast.In,
               ast.Is: ast.IsNot, ast.IsNot: ast.Is}

    def __init__(self, target: int) -> None:
        self.target = target
        self.counter = 0
        self.applied: Mutation | None = None

    def _hit(self) -> bool:
        current, self.counter = self.counter, self.counter + 1
        return current == self.target

    def visit_Compare(self, node: ast.Compare):
        self.generic_visit(node)
        if len(node.ops) == 1 and type(node.ops[0]) in self.COMPARE:
            if self._hit():
                original = type(node.ops[0])
                replacement = self.COMPARE[original]
                self.applied = Mutation(node.lineno, "comparison",
                                        original.__name__, replacement.__name__)
                node.ops = [replacement()]
        return node

    def visit_BoolOp(self, node: ast.BoolOp):
        """`and` <-> `or`. Turns "all of these must hold" into "any"."""
        self.generic_visit(node)
        if self._hit():
            replacement = ast.Or() if isinstance(node.op, ast.And) else ast.And()
            self.applied = Mutation(node.lineno, "boolop",
                                    type(node.op).__name__,
                                    type(replacement).__name__)
            node.op = replacement
        return node

    def visit_UnaryOp(self, node: ast.UnaryOp):
        """Removing a `not`. The cheapest way to invert a guard."""
        self.generic_visit(node)
        if isinstance(node.op, ast.Not) and self._hit():
            self.applied = Mutation(node.lineno, "remove-not", "not X", "X")
            return node.operand
        return node

    def visit_If(self, node: ast.If):
        """Delete a guard's body entirely -- the "check removed" mutation.

        Only for guards whose body is a single statement, which is what a
        `reasons.append(...)` denial looks like.
        """
        self.generic_visit(node)
        if len(node.body) == 1 and not node.orelse and self._hit():
            self.applied = Mutation(node.lineno, "delete-guard-body",
                                    "if ...: <stmt>", "if ...: pass")
            node.body = [ast.Pass()]
            ast.fix_missing_locations(node)
        return node


def _count(tree: ast.AST) -> int:
    mutator = _Mutator(-1)
    mutator.visit(tree)
    return mutator.counter


def _acquire_lock(module: Path) -> None:
    try:
        handle = os.open(str(_LOCK), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        raise SystemExit(
            f"another mutation run holds {_LOCK.name}. This tool rewrites "
            "source in place, so two runs -- or a run plus an ordinary test "
            "invocation -- corrupt each other. Wait, or remove the lock if "
            "it is stale.")
    os.write(handle, f"pid={os.getpid()} module={module.name}\n".encode())
    os.close(handle)


def _release_lock() -> None:
    try:
        _LOCK.unlink()
    except OSError:
        pass


def run(module: Path, tests: list[str], *, limit: int | None = None,
        quiet: bool = False) -> dict:
    source = module.read_text()
    total = _count(ast.parse(source))
    original_bytes = module.read_bytes()

    def _restore(*_args) -> None:
        """Put the module back, whatever happens -- including a signal.

        Without this, interrupting a run leaves mutated source on disk, and
        the next person to run the suite debugs a defect that was never in
        the repository.
        """
        module.write_bytes(original_bytes)
        _release_lock()

    _acquire_lock(module)
    atexit.register(_restore)
    previous_handlers = {}
    for received in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[received] = signal.signal(
            received, lambda s, f: (_restore(), sys.exit(130)))

    survivors: list[dict] = []
    killed = 0
    errored = 0
    indices = range(total if limit is None else min(total, limit))

    try:
        for index in indices:
            tree = ast.parse(source)
            mutator = _Mutator(index)
            mutated = mutator.visit(tree)
            if mutator.applied is None:
                continue
            ast.fix_missing_locations(mutated)
            try:
                text = ast.unparse(mutated)
            except Exception:                       # noqa: BLE001
                errored += 1
                continue
            module.write_bytes(text.encode())
            result = subprocess.run(
                [sys.executable, "-m", "pytest", *tests, "-x", "-q",
                 "-p", "no:cacheprovider", "--no-header"],
                capture_output=True, text=True, cwd=REPO, timeout=600,
                # These are the only pytest runs that are supposed to see
                # mutated source; the repository conftest refuses every
                # other one while the lock is held.
                env={**os.environ, "ANNULON_MUTATION_RUN": "1"})
            if result.returncode == 0:
                # Nothing noticed. This is the finding.
                survivors.append({"index": index,
                                  "mutation": mutator.applied.label(),
                                  "line": mutator.applied.line})
                if not quiet:
                    print(f"  SURVIVED  {mutator.applied.label()}", flush=True)
            else:
                killed += 1
                if not quiet:
                    print(f"  killed    {mutator.applied.label()}", flush=True)
    finally:
        module.write_bytes(original_bytes)          # always restore
        for received, handler in previous_handlers.items():
            signal.signal(received, handler)
        atexit.unregister(_restore)
        _release_lock()

    return {"module": str(module.relative_to(REPO)), "tests": tests,
            "mutations_applied": killed + len(survivors), "killed": killed,
            "survivors": survivors, "unparseable": errored}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mutate", description=__doc__)
    parser.add_argument("--module", required=True)
    parser.add_argument("--tests", nargs="+", required=True)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--allow-survivors", type=int, default=0,
                        help="known, justified survivors; anything above this "
                             "is a failure")
    args = parser.parse_args(argv)

    module = (REPO / args.module).resolve()
    if not module.is_file():
        print(f"no such module: {args.module}", file=sys.stderr)
        return 2
    report = run(module, args.tests, limit=args.limit, quiet=args.json)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"\n{report['module']}: {report['killed']} killed, "
              f"{len(report['survivors'])} survived "
              f"of {report['mutations_applied']} applied")
        for survivor in report["survivors"]:
            print(f"  UNDETECTED: {survivor['mutation']}")
    return 0 if len(report["survivors"]) <= args.allow_survivors else 1


if __name__ == "__main__":
    raise SystemExit(main())
