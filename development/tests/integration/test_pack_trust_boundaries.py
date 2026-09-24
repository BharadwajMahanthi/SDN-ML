"""What each capability pack is allowed to reach.

These properties currently hold because nobody has written the import that
would break them. That is not the same as holding, and the difference shows
up the first time somebody adds a convenient shortcut from a detector
straight to the enforcement backend — which would be an easy, reasonable-
looking change that quietly gives every detector bug privileged reach.

The boundaries, stated once:

    sensors/detectors  ->  may produce evidence and findings
                       ->  may NOT import the response package
                       ->  may NOT hold an execution primitive

    response policy    ->  may propose an ActionRequest
                       ->  may NOT authorize one

    broker             ->  authorizes
                       ->  holds no execution primitive (ADR-046)

    enforcement backend ->  the only place privilege lives
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src"

#: Packages that observe or decide, and must never be able to act.
NON_PRIVILEGED_PACKAGES = ("sdnguard", "annulon/detect", "annulon/collectors",
                           "annulon/network")
#: The response package as a whole is off-limits to them, except for the two
#: modules that exist precisely to be the boundary and carry no authority:
#: the typed contract and the client that can only ask.
RESPONSE_IMPORTS_ALLOWED = {
    "annulon.response.contract",
    "annulon.response.client",
}
EXECUTION_MODULES = {"subprocess", "pty", "ctypes", "multiprocessing", "os.exec"}
#: `annulon/response/from_finding.py` is the proposal layer. It may build a
#: request and hand it to the client, and nothing more.
PROPOSAL_MODULE = "annulon/response/from_finding.py"


def _modules(package: str) -> list[Path]:
    root = SRC / package
    if not root.is_dir():
        return []
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


def _imports(path: Path) -> set[str]:
    try:
        tree = ast.parse(path.read_text())
    except (SyntaxError, UnicodeDecodeError):
        return set()
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            found.add(node.module)
    return found


def _relative(path: Path) -> str:
    return str(path.relative_to(SRC))


def _all_non_privileged() -> list[Path]:
    modules: list[Path] = []
    for package in NON_PRIVILEGED_PACKAGES:
        modules.extend(_modules(package))
    return modules


@pytest.mark.parametrize("path", _all_non_privileged(), ids=_relative)
def test_an_observing_pack_cannot_reach_the_response_machinery(path: Path):
    """A detector that could contain would be a detector whose bugs are
    privileged. It may name an action type; it may not perform one."""
    offending = {name for name in _imports(path)
                 if name.startswith("annulon.response")
                 and name not in RESPONSE_IMPORTS_ALLOWED}
    assert not offending, (
        f"{_relative(path)} imports {sorted(offending)}. Observing packs may "
        "use the typed contract and the asking client, nothing else.")


@pytest.mark.parametrize("path", _all_non_privileged(), ids=_relative)
def test_an_observing_pack_holds_no_execution_primitive(path: Path):
    offending = _imports(path) & EXECUTION_MODULES
    assert not offending, (
        f"{_relative(path)} imports {sorted(offending)}; privileged "
        "execution belongs to an enforcement backend alone")


def test_the_sdn_pack_cannot_reach_the_response_package_at_all():
    """Stronger than the rule above: the SDN pack has no enforcement path of
    any kind today, and its findings carry no containment response. If that
    changes it should be a deliberate, reviewed act."""
    for path in _modules("sdnguard"):
        offending = {n for n in _imports(path) if n.startswith("annulon.response")}
        assert not offending, f"{_relative(path)} now reaches {sorted(offending)}"


def test_the_sdn_bridge_never_offers_containment():
    """No SDN finding may authorise a response while fabric enforcement is
    NOT_RUN. Offering it would invite a policy layer to propose an action
    nothing can carry out."""
    from datetime import datetime, timezone

    from annulon.finding import ResponseClass
    from sdnguard.detection.deterministic import LinkFabricationDetector
    from sdnguard.domain.events import FindingKind, SecurityFinding, Verdict
    from sdnguard.domain.host import HostIdentity, MacAddress
    from sdnguard.domain.identity import DatapathId, PortIdentity, PortNumber
    from sdnguard.domain.events import Severity as SdnSeverity
    from sdnguard.v2.findings import map_finding

    port = PortIdentity(DatapathId(0xAABBCCDDEEFF), PortNumber(1))
    for verdict in Verdict:
        finding = SecurityFinding(
            finding_id="f-1", kind=FindingKind.LINK_FABRICATION,
            verdict=verdict, severity=SdnSeverity.HIGH,
            identity=HostIdentity.of(MacAddress(0xAABBCCDDEE01)), port=port,
            detected_at=datetime.now(timezone.utc),
            evidence=("probe-1",), summary="fabricated link")
        mapped = map_finding(finding)
        allowed = mapped.assessments[-1].allowed_responses
        assert ResponseClass.TEMPORARY_CONTAINMENT not in allowed, verdict


def test_the_proposal_layer_cannot_authorize():
    """It builds a request and sends it. It never constructs a decision."""
    path = SRC / PROPOSAL_MODULE
    imported = _imports(path)
    assert "annulon.response.policy" not in imported, (
        "the proposal layer imported broker policy; it would then be "
        "deciding rather than asking")
    text = path.read_text()
    assert "AuthorizationDecision" not in text
    assert "Decision.ALLOW" not in text


def test_the_broker_holds_no_execution_primitive():
    """ADR-046, restated here so the boundary set is readable in one place."""
    offending = _imports(SRC / "annulon/response/broker.py") & EXECUTION_MODULES
    assert not offending


#: The only modules allowed to spawn a process, each with its reason. This
#: mirrors `PRIVILEGED_EXEMPT` in the response invariant and is restated here
#: so the whole boundary set is readable in one place.
MAY_EXECUTE = {
    "annulon/response/nftables.py":
        "the enforcement backend -- the one place privilege lives",
    "annulon/agent/liveness.py":
        "execs a nonce marker of its own to prove the process sensor still "
        "delivers; touches nothing else",
    "annulon/supply/install.py":
        "runs the package installer, after the release signature and hash "
        "have both verified. It is the install path rather than the running "
        "agent, and it builds one fixed argv from verified inputs.",
}


def test_only_named_modules_may_execute():
    """Spawning a process is allowed in exactly two places, both justified.

    Widening this set is the single easiest way to give a detector bug
    privileged reach, so it is a list somebody has to edit deliberately.
    """
    executors = {
        _relative(path) for path in SRC.rglob("*.py")
        if "__pycache__" not in path.parts
        and _imports(path) & {"subprocess", "pty", "multiprocessing"}}
    unexpected = executors - set(MAY_EXECUTE)
    assert not unexpected, (
        f"privileged execution appeared outside the named set: "
        f"{sorted(unexpected)}")


def test_every_named_executor_still_exists():
    """A stale allowance is an allowance nobody removed."""
    for relative in MAY_EXECUTE:
        assert (SRC / relative).is_file(), f"{relative} is listed but absent"
