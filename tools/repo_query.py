"""Bounded repository gateway.

Every answer is (a) screened against the path policy, (b) truncated to the
policy limits, and (c) passed through redaction. There is no operation that
returns a whole file or a recursive source dump.

  python tools/repo_query.py tree [--path P] [--depth N]
  python tools/repo_query.py grep <pattern> [--path P] [--max N]
  python tools/repo_query.py references <name> [--path P]
  python tools/repo_query.py symbol <name>
  python tools/repo_query.py signature <name>
  python tools/repo_query.py callers <name|Class.method>
  python tools/repo_query.py function <path> <name>
  python tools/repo_query.py lines <path> <start> <end>
  python tools/repo_query.py imports <path>
  python tools/repo_query.py explicit-file <exact-path> [--start N] [--end N]
"""

from __future__ import annotations

import argparse
import ast
import re
import subprocess
import sys
import warnings
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

if __package__ in (None, ""):  # allow `python tools/repo_query.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.context_policy import Policy, PolicyViolation, default_policy
from tools.redact import redact, summarize

SOURCE_SUFFIXES = {
    ".py", ".java", ".sh", ".bash", ".yml", ".yaml", ".json", ".md",
    ".properties", ".xml", ".bat", ".zeek", ".toml", ".cfg", ".ini", ".txt",
}


@dataclass(frozen=True)
class Symbol:
    path: str
    name: str
    kind: str
    line: int
    end_line: int
    signature: str


# ---------------------------------------------------------------- file set


def tracked_files(policy: Policy) -> list[PurePosixPath]:
    """Tracked files only. Untracked scratch never becomes context by accident."""
    proc = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=policy.root, capture_output=True, text=True, check=False,
    )
    names = proc.stdout.split("\0") if proc.returncode == 0 else []
    out: list[PurePosixPath] = []
    for name in names:
        if not name:
            continue
        try:
            out.append(policy.check_listable(name))
        except PolicyViolation:
            continue
    return out


def readable_sources(policy: Policy, under: str | None = None) -> list[PurePosixPath]:
    prefix = PurePosixPath(under).as_posix().rstrip("/") if under else None
    result = []
    for rel in tracked_files(policy):
        text = rel.as_posix()
        if prefix and text != prefix and not text.startswith(prefix + "/"):
            continue
        if rel.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        try:
            policy.check_readable(rel)
        except PolicyViolation:
            continue
        result.append(rel)
    return result


def read_text(policy: Policy, rel: PurePosixPath) -> str:
    policy.check_readable(rel)
    return (policy.root / rel).read_text(errors="replace")


# ------------------------------------------------------------ output shell


class Out:
    """Collects lines, enforces the ceiling, redacts once at the end."""

    def __init__(self, policy: Policy, limit: int) -> None:
        self.policy = policy
        self.limit = limit
        self.lines: list[str] = []
        self.dropped = 0

    def add(self, line: str) -> None:
        if len(self.lines) >= self.limit:
            self.dropped += 1
            return
        cap = self.policy.limits.max_line_chars
        self.lines.append(line if len(line) <= cap else line[:cap] + " ...[line truncated]")

    def emit(self, header: str) -> None:
        body = "\n".join(self.lines)
        result = redact(body)
        print(header)
        if result.text:
            print(result.text)
        if self.dropped:
            print(f"...[{self.dropped} more suppressed by limit={self.limit}; narrow the query]")
        print(summarize(result.findings))


# ------------------------------------------------------------- symbol index


_JAVA_DECL = re.compile(
    r"^\s*(?:public|protected|private|static|final|abstract|synchronized|native|\s)*"
    r"(?:(?P<ckind>class|interface|enum)\s+(?P<cname>\w+)"
    r"|(?P<ret>[\w.<>\[\],?\s]+?)\s+(?P<mname>\w+)\s*\((?P<args>[^;{]*)\)\s*(?:throws [\w.,\s]+)?\s*\{)"
)
_SH_DECL = re.compile(r"^\s*(?:function\s+)?(?P<name>[A-Za-z_][\w-]*)\s*\(\s*\)\s*\{")


def symbols_in(policy: Policy, rel: PurePosixPath) -> list[Symbol]:
    try:
        text = read_text(policy, rel)
    except (PolicyViolation, OSError):
        return []
    suffix = rel.suffix.lower()
    if suffix == ".py":
        return _python_symbols(rel, text)
    if suffix == ".java":
        return _regex_symbols(rel, text, _JAVA_DECL, java=True)
    if suffix in {".sh", ".bash"}:
        return _regex_symbols(rel, text, _SH_DECL, java=False)
    return []


def _parse_quietly(text: str) -> ast.Module | None:
    """Parse without letting a scanned file's own SyntaxWarning reach stdout."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            return ast.parse(text)
        except (SyntaxError, ValueError):
            return None


def _python_symbols(rel: PurePosixPath, text: str) -> list[Symbol]:
    tree = _parse_quietly(text)
    if tree is None:
        return []
    found: list[Symbol] = []

    def walk(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = f"{prefix}{child.name}"
                if isinstance(child, ast.ClassDef):
                    kind, sig = "class", f"class {child.name}"
                else:
                    kind = "function"
                    args = ast.unparse(child.args)
                    sig = f"def {child.name}({args})"
                    if child.returns is not None:
                        sig += f" -> {ast.unparse(child.returns)}"
                found.append(
                    Symbol(rel.as_posix(), name, kind, child.lineno,
                           child.end_lineno or child.lineno, sig)
                )
                walk(child, f"{name}.")

    walk(tree, "")
    return found


def _regex_symbols(
    rel: PurePosixPath, text: str, pattern: re.Pattern[str], *, java: bool
) -> list[Symbol]:
    found: list[Symbol] = []
    lines = text.splitlines()
    for idx, line in enumerate(lines, start=1):
        m = pattern.match(line)
        if not m:
            continue
        if java:
            if m.group("cname"):
                name, kind = m.group("cname"), m.group("ckind")
            else:
                name, kind = m.group("mname"), "method"
                if name in {"if", "for", "while", "switch", "catch", "synchronized", "return"}:
                    continue
        else:
            name, kind = m.group("name"), "function"
        found.append(Symbol(rel.as_posix(), name, kind, idx, idx, line.strip()))
    return found


def index(policy: Policy, under: str | None = None) -> list[Symbol]:
    out: list[Symbol] = []
    for rel in readable_sources(policy, under):
        out.extend(symbols_in(policy, rel))
    return out


# --------------------------------------------------------------- commands


def cmd_tree(policy: Policy, args: argparse.Namespace) -> int:
    out = Out(policy, policy.limits.max_tree_entries)
    prefix = args.path.rstrip("/") if args.path else ""
    seen: set[str] = set()
    for rel in tracked_files(policy):
        text = rel.as_posix()
        if prefix and not text.startswith(prefix + "/") and text != prefix:
            continue
        rest = text[len(prefix) + 1:] if prefix else text
        parts = rest.split("/")
        if len(parts) > args.depth:
            entry = "/".join(parts[: args.depth]) + "/"
        else:
            entry = rest
        full = f"{prefix}/{entry}" if prefix else entry
        if full in seen:
            continue
        seen.add(full)
        flag = " [opaque]" if policy.is_opaque(rel) else ""
        out.add(f"{full}{flag}")
    out.emit(f"TREE path={prefix or '.'} depth={args.depth} entries={len(seen)}")
    return 0


def _scan(policy: Policy, pattern: re.Pattern[str], under: str | None, limit: int) -> Out:
    out = Out(policy, limit)
    for rel in readable_sources(policy, under):
        try:
            text = read_text(policy, rel)
        except (PolicyViolation, OSError):
            continue
        for idx, line in enumerate(text.splitlines(), start=1):
            if pattern.search(line):
                out.add(f"{rel.as_posix()}:{idx}: {line.strip()}")
    return out


def cmd_grep(policy: Policy, args: argparse.Namespace) -> int:
    limit = min(args.max, policy.limits.max_search_results)
    flags = 0 if args.case_sensitive else re.IGNORECASE
    out = _scan(policy, re.compile(args.pattern, flags), args.path, limit)
    out.emit(f"GREP pattern={args.pattern!r} limit={limit}")
    return 0


def cmd_references(policy: Policy, args: argparse.Namespace) -> int:
    pattern = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(args.name)}(?![A-Za-z0-9_])")
    limit = policy.limits.max_search_results
    out = _scan(policy, pattern, args.path, limit)
    out.emit(f"REFERENCES name={args.name} limit={limit}")
    return 0


def cmd_symbol(policy: Policy, args: argparse.Namespace) -> int:
    out = Out(policy, policy.limits.max_search_results)
    needle = args.name.lower()
    for sym in index(policy, args.path):
        tail = sym.name.rsplit(".", 1)[-1].lower()
        if needle == sym.name.lower() or needle == tail or needle in sym.name.lower():
            out.add(f"{sym.path}:{sym.line}-{sym.end_line} {sym.kind} {sym.name}")
    out.emit(f"SYMBOL name={args.name}")
    return 0


def cmd_signature(policy: Policy, args: argparse.Namespace) -> int:
    out = Out(policy, policy.limits.max_search_results)
    needle = args.name.lower()
    for sym in index(policy, args.path):
        if needle in sym.name.lower():
            out.add(f"{sym.path}:{sym.line} {sym.signature}")
    out.emit(f"SIGNATURE name={args.name}")
    return 0


def cmd_callers(policy: Policy, args: argparse.Namespace) -> int:
    target = args.name.rsplit(".", 1)[-1]
    pattern = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(target)}\s*\(")
    out = Out(policy, policy.limits.max_search_results)
    for rel in readable_sources(policy, args.path):
        try:
            text = read_text(policy, rel)
        except (PolicyViolation, OSError):
            continue
        syms = sorted(symbols_in(policy, rel), key=lambda s: s.line)
        for idx, line in enumerate(text.splitlines(), start=1):
            if not pattern.search(line):
                continue
            enclosing = next(
                (s.name for s in reversed(syms) if s.line <= idx <= s.end_line), "<module>"
            )
            if enclosing.rsplit(".", 1)[-1] == target and line.lstrip().startswith(("def ", "class ")):
                continue  # the definition itself
            out.add(f"{rel.as_posix()}:{idx}: in {enclosing}: {line.strip()}")
    out.emit(f"CALLERS name={args.name}")
    return 0


def cmd_function(policy: Policy, args: argparse.Namespace) -> int:
    rel = policy.check_readable(args.path)
    matches = [s for s in symbols_in(policy, rel)
               if s.name == args.name or s.name.rsplit(".", 1)[-1] == args.name]
    if not matches:
        print(f"FUNCTION {args.name} not found in {rel.as_posix()}")
        return 1
    sym = matches[0]
    lines = read_text(policy, rel).splitlines()
    limit = policy.limits.max_source_lines
    out = Out(policy, limit)
    span = lines[sym.line - 1: sym.end_line]
    for offset, line in enumerate(span):
        out.add(f"{sym.line + offset:5d}  {line}")
    out.emit(
        f"FUNCTION {rel.as_posix()}:{sym.line}-{sym.end_line} {sym.kind} {sym.name} "
        f"({len(span)} lines, limit={limit})"
    )
    return 0


def cmd_lines(policy: Policy, args: argparse.Namespace) -> int:
    rel = policy.check_readable(args.path)
    lines = read_text(policy, rel).splitlines()
    start = max(1, args.start)
    end = min(len(lines), args.end)
    limit = policy.limits.max_source_lines
    if end - start + 1 > limit:
        end = start + limit - 1
    out = Out(policy, limit)
    for idx in range(start, end + 1):
        out.add(f"{idx:5d}  {lines[idx - 1]}")
    out.emit(f"LINES {rel.as_posix()}:{start}-{end} (file has {len(lines)}, limit={limit})")
    return 0


def cmd_explicit_file(policy: Policy, args: argparse.Namespace) -> int:
    """Read ONE explicitly named file, tracked or not.

    Closes a real workflow gap: tree and grep index tracked files only, so a
    document added but not yet staged is invisible to the gateway. Discovered
    when PADMAVYUH_ARCHITECTURE_V2.md could not be read.

    The narrowness is the safety property. This reads exactly one path the
    caller names; it will not enumerate, glob or recurse. Every other control
    still applies: root containment, symlink escape, blocked and opaque
    patterns, line limits and redaction. So it removes the blind spot without
    creating a way to sweep up untracked material.
    """
    rel = policy.check_readable(args.path)
    target = policy.root / rel
    if not target.is_file():
        print(f"EXPLICIT_FILE {rel}: not a file", file=sys.stderr)
        return 1
    lines = target.read_text(errors="replace").splitlines()
    limit = policy.limits.max_source_lines
    start = max(1, args.start)
    end = min(len(lines), args.end) if args.end else len(lines)
    if end - start + 1 > limit:
        end = start + limit - 1
    out = Out(policy, limit)
    for idx in range(start, end + 1):
        out.add(f"{idx:5d}  {lines[idx - 1]}")
    tracked = _is_tracked(policy, rel)
    out.emit(f"EXPLICIT_FILE {rel}:{start}-{end} "
             f"({len(lines)} lines, tracked={tracked}, limit={limit})")
    return 0


def _is_tracked(policy: Policy, rel: PurePosixPath) -> bool:
    proc = subprocess.run(["git", "ls-files", "--error-unmatch", rel.as_posix()],
                          cwd=policy.root, capture_output=True, text=True, check=False)
    return proc.returncode == 0


def cmd_imports(policy: Policy, args: argparse.Namespace) -> int:
    rel = policy.check_readable(args.path)
    text = read_text(policy, rel)
    out = Out(policy, policy.limits.max_search_results)
    if rel.suffix == ".py":
        tree = _parse_quietly(text)
        if tree is None:
            print(f"IMPORTS {rel.as_posix()}: unparseable")
            return 1
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    out.add(f"{node.lineno}: import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                mod = "." * node.level + (node.module or "")
                names = ", ".join(a.name for a in node.names)
                out.add(f"{node.lineno}: from {mod} import {names}")
    else:
        pattern = re.compile(r"^\s*(import|#include|@load|source|require)\b")
        for idx, line in enumerate(text.splitlines(), start=1):
            if pattern.match(line):
                out.add(f"{idx}: {line.strip()}")
    out.emit(f"IMPORTS {rel.as_posix()}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="repo_query", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("tree"); t.add_argument("--path", default=""); t.add_argument("--depth", type=int, default=2); t.set_defaults(fn=cmd_tree)
    g = sub.add_parser("grep"); g.add_argument("pattern"); g.add_argument("--path"); g.add_argument("--max", type=int, default=20); g.add_argument("--case-sensitive", action="store_true"); g.set_defaults(fn=cmd_grep)
    r = sub.add_parser("references"); r.add_argument("name"); r.add_argument("--path"); r.set_defaults(fn=cmd_references)
    s = sub.add_parser("symbol"); s.add_argument("name"); s.add_argument("--path"); s.set_defaults(fn=cmd_symbol)
    sg = sub.add_parser("signature"); sg.add_argument("name"); sg.add_argument("--path"); sg.set_defaults(fn=cmd_signature)
    c = sub.add_parser("callers"); c.add_argument("name"); c.add_argument("--path"); c.set_defaults(fn=cmd_callers)
    f = sub.add_parser("function"); f.add_argument("path"); f.add_argument("name"); f.set_defaults(fn=cmd_function)
    l = sub.add_parser("lines"); l.add_argument("path"); l.add_argument("start", type=int); l.add_argument("end", type=int); l.set_defaults(fn=cmd_lines)
    i = sub.add_parser("imports"); i.add_argument("path"); i.set_defaults(fn=cmd_imports)
    e = sub.add_parser("explicit-file",
                       help="read one named file, tracked or not; never enumerates")
    e.add_argument("path")
    e.add_argument("--start", type=int, default=1)
    e.add_argument("--end", type=int, default=0)
    e.set_defaults(fn=cmd_explicit_file)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    policy = default_policy()
    try:
        return int(args.fn(policy, args))
    except PolicyViolation as exc:
        print(f"POLICY_VIOLATION: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
