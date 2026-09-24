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

# Exactly one module is permitted to import an OpenFlow framework (ADR-017).
# The list is asserted below, so widening it is a deliberate, visible act
# rather than something that happens by accident during a refactor.
FRAMEWORK_EXEMPT = {"adapter/osken.py"}

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


def _relative(path: Path) -> str:
    return path.relative_to(CORE).as_posix()


@pytest.mark.parametrize("path", _core_modules(), ids=lambda p: p.name)
def test_no_framework_imports(path: Path):
    if _relative(path) in FRAMEWORK_EXEMPT:
        pytest.skip("framework adapter, exempt by ADR-017")
    offending = _imported_roots(path) & FORBIDDEN
    assert not offending, (
        f"{_relative(path)} imports {sorted(offending)}; "
        "the security core must stay framework-independent (ADR-005)"
    )


def test_the_exemption_list_is_exactly_one_adapter_module():
    """The boundary is only meaningful if the hole in it stays small."""
    assert FRAMEWORK_EXEMPT == {"adapter/osken.py"}
    for name in FRAMEWORK_EXEMPT:
        assert (CORE / name).is_file(), f"{name} is exempted but does not exist"


def test_every_non_exempt_module_is_framework_free():
    """Belt and braces: the parametrised test skips exempt files, so this one
    asserts the population directly and would catch a silently widened list."""
    offenders = {
        _relative(path): sorted(_imported_roots(path) & FORBIDDEN)
        for path in _core_modules()
        if _relative(path) not in FRAMEWORK_EXEMPT and (_imported_roots(path) & FORBIDDEN)
    }
    assert offenders == {}


def test_the_shared_core_is_framework_free_and_sdn_free():
    """annulon must work on a plain Linux VM: no framework, and no
    dependency on the SDN package it will one day receive events from."""
    shared = CORE.parent / "annulon"
    assert shared.is_dir(), "shared package missing"
    modules = sorted(shared.rglob("*.py"))
    assert len(modules) >= 3, "guard would pass vacuously"
    allowed = set(sys.stdlib_module_names) | {"annulon"}
    #: The install path is not the runtime core. `annulon/supply` verifies
    #: release signatures, which the standard library cannot do, and it runs
    #: before the agent exists rather than alongside it. The import is lazy
    #: and its absence is a refusal, not a degradation -- but an AST guard
    #: cannot see either of those, so the allowance is stated here with the
    #: reason. What this guard protects is that the *running* agent needs
    #: nothing but Python, and that is still true.
    optional_backend = {
        "supply/manifest.py": {"cryptography"},
        "supply/install.py": {"cryptography"},
    }
    for path in modules:
        roots = _imported_roots(path)
        assert not (roots & FORBIDDEN), f"{path.name} imports a framework"
        assert "sdnguard" not in roots, (
            f"{path.name} imports sdnguard; the shared core must not depend on "
            "the SDN integration")
        relative = str(path.relative_to(shared))
        unexpected = roots - allowed - optional_backend.get(relative, set())
        assert not unexpected, f"{path.name} imports non-stdlib {sorted(unexpected)}"


def test_the_running_agent_needs_nothing_but_python():
    """The claim the allowance above must not erode.

    Whatever the install path needs, everything the agent and broker import
    at run time has to be in the standard library -- that is what makes a
    dependency-free deployment true rather than aspirational.
    """
    shared = CORE.parent / "annulon"
    allowed = set(sys.stdlib_module_names) | {"annulon"}
    runtime = [p for p in sorted(shared.rglob("*.py"))
               if "supply" not in p.parts]
    assert len(runtime) >= 10, "guard would pass vacuously"
    for path in runtime:
        unexpected = _imported_roots(path) - allowed
        assert not unexpected, (
            f"{path.relative_to(shared)} imports {sorted(unexpected)} at "
            "run time; the agent must need nothing but Python")


def test_the_exempt_adapter_is_not_imported_by_the_core():
    """os_ken must not reach the core transitively either: nothing outside the
    adapter package may import the framework-bound module."""
    importers = []
    for path in _core_modules():
        rel = _relative(path)
        if rel in FRAMEWORK_EXEMPT or rel.startswith("adapter/"):
            continue
        text = path.read_text()
        if "osken" in text:
            importers.append(rel)
    assert importers == [], f"{importers} reference the framework-bound adapter"


@pytest.mark.parametrize("path", _core_modules(), ids=lambda p: p.name)
def test_core_depends_only_on_the_standard_library(path: Path):
    if _relative(path) in FRAMEWORK_EXEMPT:
        pytest.skip("framework adapter, exempt by ADR-017")
    """Stronger than the denylist: a framework we have not thought of yet
    cannot sneak in either."""
    # Dependency direction is deliberate and one-way: the SDN integration may
    # consume the shared contracts, the shared core may never import the SDN
    # package. The reverse direction is asserted in
    # test_the_shared_core_is_framework_free_and_sdn_free.
    allowed = set(sys.stdlib_module_names) | {"sdnguard", "annulon"}
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
