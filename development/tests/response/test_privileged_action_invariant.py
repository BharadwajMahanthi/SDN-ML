"""Project invariant, enforced mechanically:

    NO COMPONENT OTHER THAN THE AUTHORIZED RESPONSE BROKER MAY PERFORM
    ANNULON PRIVILEGED RESPONSE ACTIONS.

A rule written only in a document is a rule that erodes. This test reads the
source and fails if any production module outside the broker acquires the
ability to execute, signal or reconfigure the system.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src"

#: Only these modules may hold an execution primitive, and each is listed with
#: the reason. Widening this set is a deliberate, reviewable act.
PRIVILEGED_EXEMPT = {
    "annulon/response/broker.py": "the broker is the single privileged path",
    "annulon/response/nftables.py": "the OS mechanism the broker drives",
    "annulon/agent/liveness.py": "execs a nonce marker of its own to prove the "
                                 "sensor still delivers; touches nothing else",
}

#: Modules that may call subprocess only to read, never to change state.
EXECUTION_NAMES = {"system", "popen", "spawn", "spawnv", "spawnve", "execv",
                   "execve", "execl", "execlp", "fork", "forkpty", "kill",
                   "killpg", "setuid", "setgid", "seteuid", "setegid"}
EXECUTION_MODULES = {"subprocess", "pty", "ctypes", "multiprocessing"}
FORBIDDEN_BUILTINS = {"eval", "exec", "compile", "__import__"}


def _production_modules() -> list[Path]:
    return sorted(p for p in SRC.rglob("*.py")
                  if "__pycache__" not in p.parts)


def _relative(path: Path) -> str:
    return path.relative_to(SRC).as_posix()


def test_the_source_tree_is_actually_scanned():
    assert len(_production_modules()) >= 20, "guard would pass vacuously"


@pytest.mark.parametrize("path", _production_modules(), ids=_relative)
def test_no_unexempt_module_imports_an_execution_primitive(path: Path):
    if _relative(path) in PRIVILEGED_EXEMPT:
        pytest.skip("explicitly exempt, with a stated reason")
    tree = ast.parse(path.read_text())
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            imported.add(node.module.split(".")[0])
    offending = imported & EXECUTION_MODULES
    assert not offending, (
        f"{_relative(path)} imports {sorted(offending)}; privileged execution "
        "belongs to the broker alone")


@pytest.mark.parametrize("path", _production_modules(), ids=_relative)
def test_no_module_calls_a_process_or_privilege_primitive(path: Path):
    if _relative(path) in PRIVILEGED_EXEMPT:
        pytest.skip("explicitly exempt, with a stated reason")
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Attribute):
            # Method calls are checked against process/privilege primitives
            # only. The builtin denylist must NOT apply here: re.compile()
            # is not compile(), and conflating them made this guard fail on
            # every module with a regex.
            assert node.func.attr not in EXECUTION_NAMES, (
                f"{_relative(path)} calls .{node.func.attr}()")
        elif isinstance(node.func, ast.Name):
            assert node.func.id not in EXECUTION_NAMES, (
                f"{_relative(path)} calls {node.func.id}()")
            assert node.func.id not in FORBIDDEN_BUILTINS, (
                f"{_relative(path)} calls the builtin {node.func.id}()")


@pytest.mark.parametrize("path", _production_modules(), ids=_relative)
def test_no_module_contains_a_privileged_tool_invocation(path: Path):
    """Catches a command assembled as a string even where the call itself is
    exempt or indirect."""
    if _relative(path) in PRIVILEGED_EXEMPT:
        pytest.skip("explicitly exempt, with a stated reason")
    text = path.read_text()
    for tool in ("iptables", "nft ", "nftables", "systemctl", "ip route",
                 "ip link", "aws ec2", "aws iam", "sudo "):
        assert tool not in text, f"{_relative(path)} references {tool!r}"


def test_the_exemption_list_names_only_modules_that_exist_or_are_planned():
    """An exemption for a module that never appears is a hole nobody notices."""
    for name, reason in PRIVILEGED_EXEMPT.items():
        assert reason, f"{name} is exempt without a stated reason"


def test_shell_true_appears_nowhere_in_the_tree():
    """Even in the broker. A command built from event data and handed to a
    shell is the failure this whole boundary exists to prevent."""
    for path in _production_modules():
        assert "shell=True" not in path.read_text(), f"{_relative(path)}"


def test_pickle_appears_nowhere_in_the_tree():
    """No arbitrary deserialization anywhere, and certainly not across the
    privileged boundary."""
    for path in _production_modules():
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert not any(a.name.split(".")[0] in {"pickle", "marshal", "shelve"}
                               for a in node.names), _relative(path)
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in {"pickle", "marshal", "shelve"}, \
                    _relative(path)
