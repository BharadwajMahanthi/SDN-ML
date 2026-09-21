"""No validation regex may use an anchor that admits a trailing newline.

In Python, `$` matches at the end of the string *and* immediately before a
final newline. So `re.compile(r"^[\x20-\x7e]{1,64}$")` — which reads as
"printable ASCII only" — accepts `"worker\n"`. That guard was present, looked
correct, and let a control character into an identity field (KF-43).

The same shape appeared in fourteen places across this repository, including
`identity.py`'s "no control bytes" check, the privileged action contract's id
and name patterns, and the redactor's identifier heuristic — where a trailing
newline would make a secret look like an identifier and leave it *unredacted*.

This test enforces the standard that replaced them: `\A ... \Z`, or an
explicit `fullmatch`. It is a repository-wide rule rather than a module one,
because the defect is invisible at every individual call site.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCANNED = [REPO / "development" / "src", REPO / "tools"]

#: Patterns allowed to end with `$`, each for a stated reason.
ALLOWED = {
    # Search patterns, not validators: these intentionally scan within text
    # rather than validating a whole token.
}


def _python_files() -> list[Path]:
    files: list[Path] = []
    for root in SCANNED:
        files.extend(p for p in root.rglob("*.py")
                     if "__pycache__" not in p.parts)
    return sorted(files)


def _string_of(node: ast.AST) -> str | None:
    """Recover a regex literal, including implicit concatenation."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _string_of(node.left), _string_of(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _compiled_patterns(path: Path) -> list[tuple[int, str]]:
    """Every `re.compile(...)` literal in a module, with its line."""
    try:
        tree = ast.parse(path.read_text())
    except (SyntaxError, UnicodeDecodeError):
        return []
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function = node.func
        if not (isinstance(function, ast.Attribute) and function.attr == "compile"
                and isinstance(function.value, ast.Name)
                and function.value.id == "re"):
            continue
        if not node.args:
            continue
        pattern = _string_of(node.args[0])
        if pattern is not None:
            found.append((node.lineno, pattern))
    return found


@pytest.mark.parametrize("path", _python_files(), ids=lambda p: str(p.relative_to(REPO)))
def test_no_anchored_validator_uses_a_newline_permissive_end(path: Path):
    """A pattern anchored with `^` must end with `\\Z`, never `$`.

    `^...$` is the signature of a whole-token validator, and that is exactly
    the case where `$` is wrong.
    """
    offenders = []
    for line, pattern in _compiled_patterns(path):
        if pattern in ALLOWED:
            continue
        anchored_start = pattern.startswith(("^", "\\A")) or "|^" in pattern
        if not anchored_start:
            continue                      # a search pattern, not a validator
        # Any `$` that is not escaped and not inside a character class.
        stripped = re.sub(r"\\.", "", pattern)
        stripped = re.sub(r"\[[^\]]*\]", "", stripped)
        if "$" in stripped:
            offenders.append(f"line {line}: {pattern[:70]}")
    assert not offenders, (
        f"{path.relative_to(REPO)} uses `$` in an anchored validator, which "
        f"also matches before a trailing newline (KF-43). Use \\\\Z or "
        f"fullmatch: {offenders}")


def test_the_difference_is_real_and_not_folklore():
    """Prove the hazard before enforcing the rule against it.

    A test that forbids something harmless is noise. This shows `$` genuinely
    admits the newline and `\\Z` genuinely does not.
    """
    permissive = re.compile(r"^[a-z]+$")
    strict = re.compile(r"\A[a-z]+\Z")
    assert permissive.match("worker\n"), "the premise of KF-43 no longer holds"
    assert not strict.match("worker\n")
    assert permissive.match("worker") and strict.match("worker")


def test_the_scanner_can_actually_see_a_violation(tmp_path):
    """The positive control: a guard that cannot detect its target is decor."""
    module = tmp_path / "offender.py"
    module.write_text('import re\n_X = re.compile(r"^[a-z]+$")\n')
    patterns = _compiled_patterns(module)
    assert patterns and patterns[0][1] == "^[a-z]+$"


def test_the_scanner_ignores_unanchored_search_patterns(tmp_path):
    """A `$` in a search pattern is not this defect, and flagging it would
    make the rule annoying enough to be disabled."""
    module = tmp_path / "search.py"
    module.write_text('import re\n_X = re.compile(r"foo\\\\s*$")\n')
    line, pattern = _compiled_patterns(module)[0]
    assert not pattern.startswith(("^", "\\A"))
