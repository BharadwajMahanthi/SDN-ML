"""ADR-005 enforced as a test, not as a convention.

The legacy module threaded OFPacketIn, IDevice and IOFSwitch through its
security logic, so nothing could be tested without a running controller --
a principal reason the POC was never validated. This test fails the build if
that coupling ever reappears in the security core.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

CORE = Path(__file__).resolve().parents[2] / "src" / "sdnguard"

FORBIDDEN = {
    # OpenFlow frameworks and controllers
    "ryu", "os_ken", "osken", "pox", "faucet", "floodlight",
    # switch / datapath tooling
    "ovs", "ovsdbapp", "openvswitch",
    # packet libraries: normalisation lives in the adapter, not the core
    "scapy", "dpkt", "pypacker", "kamene",
    # transport frameworks that would imply an embedded controller
    "eventlet", "gevent", "twisted", "tornado",
}


def _core_modules() -> list[Path]:
    return sorted(CORE.rglob("*.py"))


def _imported_roots(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:           # relative import, stays inside the package
                continue
            if node.module:
                roots.add(node.module.split(".")[0])
    return roots


def test_the_core_actually_contains_modules():
    assert _core_modules(), "no sdnguard modules found; the guard would pass vacuously"


@pytest.mark.parametrize("path", _core_modules(), ids=lambda p: p.name)
def test_no_framework_imports(path: Path):
    offending = _imported_roots(path) & FORBIDDEN
    assert not offending, (
        f"{path.relative_to(CORE.parent)} imports {sorted(offending)}; "
        "the security core must stay framework-independent (ADR-005)"
    )


@pytest.mark.parametrize("path", _core_modules(), ids=lambda p: p.name)
def test_core_depends_only_on_the_standard_library(path: Path):
    """Stronger than the denylist: a framework we have not thought of yet
    cannot sneak in either."""
    allowed = set(sys.stdlib_module_names) | {"sdnguard"}
    unexpected = {r for r in _imported_roots(path) if r not in allowed}
    assert not unexpected, (
        f"{path.relative_to(CORE.parent)} imports non-stdlib {sorted(unexpected)}; "
        "add it deliberately with a recorded decision, or keep it in the adapter"
    )


def test_domain_imports_cleanly_with_no_third_party_modules_loaded():
    """Importing the domain must not drag in a framework transitively."""
    import importlib

    before = set(sys.modules)
    importlib.import_module("sdnguard.domain")
    newly_loaded = {m.split(".")[0] for m in set(sys.modules) - before}
    assert not (newly_loaded & FORBIDDEN)
