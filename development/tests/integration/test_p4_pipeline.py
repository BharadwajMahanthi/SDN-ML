"""P4 acceptance: observation -> movement -> validation -> finding -> decision.

The requirement is that this entire chain runs with **no OpenFlow
dependency**. Everything below is plain Python values and a manual clock, so
it executes on macOS with no OVS, no controller and no network.

This is also the negative-control discipline in miniature: the scenario
driver below knows what it is simulating, and the assertions read only the
detector's output. Nothing the driver knows is ever fed into the detector.
"""

from __future__ import annotations

import ast
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sdnguard.clock import ManualClock
from sdnguard.detection.deterministic import HostHijackDetector
from sdnguard.domain.events import EnforcementAction, FindingKind, ProbeOutcome, Verdict
from sdnguard.domain.host import HostIdentity, HostObservation, MacAddress
from sdnguard.domain.identity import DatapathId, PortIdentity
from sdnguard.hosts.movement import ActionKind, MovementStateMachine
from sdnguard.hosts.table import HostTable
from sdnguard.observability.evidence import EvidenceStore
from sdnguard.policy.engine import PolicyEngine, PolicyMode
from sdnguard.probes.manager import ProbeManager
from sdnguard.topology.ports import PortRegistry

T0 = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
DPID = DatapathId(0x0000AABBCCDDEEFF)
VICTIM_PORT = PortIdentity.of(DPID.value, 1)
ATTACKER_PORT = PortIdentity.of(DPID.value, 4)
DESK_PORT = PortIdentity.of(DPID.value, 7)
VICTIM = HostIdentity.of(MacAddress.parse("aa:bb:cc:dd:ee:01"))
MAC = VICTIM.mac


class Pipeline:
    """Wires the P4 components together. No adapter, no framework."""

    def __init__(self, *, mode: PolicyMode = PolicyMode.OBSERVE) -> None:
        self.clock = ManualClock(T0)
        self.ports = PortRegistry()
        self.hosts = HostTable()
        self.movement = MovementStateMachine()
        self.probes = ProbeManager(clock=self.clock, timeout=timedelta(seconds=3))
        self.detector = HostHijackDetector()
        self.policy = PolicyEngine(mode=mode, rules=PolicyEngine.default_rules())
        self.evidence = EvidenceStore()

    def observe(self, port: PortIdentity, *, source: str = "arp") -> None:
        moment = self.clock.now()
        observation = HostObservation.of(VICTIM, port, moment, source)
        self.ports.observe_host(port, MAC)
        result = self.hosts.observe(observation)
        state, actions = self.movement.on_observation(
            VICTIM, observation.to_location())
        for action in actions:
            if action.kind is ActionKind.ISSUE_PROBE and action.port is not None:
                probe = self.probes.issue(VICTIM, action.port)
                self.movement.on_probe_issued(MAC, probe)
            elif action.kind is ActionKind.CANCEL_PROBE:
                self.probes.cancel(MAC, "re-observed at current port")
        self.last_result = result

    def port_down(self, port: PortIdentity) -> None:
        self.ports.observe_port_down(port)
        self.movement.on_port_down(MAC, port)

    def reply_from(self, port: PortIdentity) -> None:
        outstanding = self.probes.outstanding_for(MAC)
        assert outstanding is not None, "no probe is outstanding"
        result = self.probes.correlate(outstanding.correlation_id,
                                       source_port=port, mac=MAC)
        if result is not None:
            self._resolve(result)

    def advance(self, seconds: float) -> None:
        self.clock.advance(seconds)
        for result in self.probes.expire():
            self._resolve(result)

    def _resolve(self, result) -> None:
        state, actions = self.movement.on_probe_result(MAC, result)
        record = self.hosts.get(MAC)
        findings = self.detector.from_resolution(
            state, actions, self.clock.now(),
            concurrent_locations=record.concurrent_locations if record else 1)
        for finding in findings:
            decision = self.policy.decide(finding, self.clock.now())
            self.evidence.record(finding, decision)

    # -- detector-side readouts only -------------------------------------

    @property
    def kinds(self) -> list[FindingKind]:
        return [r.finding.kind for r in self.evidence]

    @property
    def actions(self) -> list[EnforcementAction]:
        return [r.decision.action for r in self.evidence if r.decision]


# -- the acceptance chain --------------------------------------------------


def test_hijack_traverses_the_whole_chain_without_openflow():
    p = Pipeline()
    p.observe(VICTIM_PORT)                 # host learned
    p.advance(10)
    p.observe(ATTACKER_PORT)               # impostor appears -> probe issued
    p.reply_from(VICTIM_PORT)              # victim answers at its old port

    assert FindingKind.HOST_LOCATION_HIJACK in p.kinds
    record = next(r for r in p.evidence
                  if r.finding.kind is FindingKind.HOST_LOCATION_HIJACK)
    assert record.finding.verdict is Verdict.SUSPICIOUS
    assert record.finding.port == ATTACKER_PORT
    assert record.decision.action is EnforcementAction.OBSERVE
    assert record.finding.evidence, "the finding cites its evidence"


def test_benign_move_traverses_the_chain_and_accuses_nobody():
    p = Pipeline()
    p.observe(VICTIM_PORT)
    p.port_down(VICTIM_PORT)
    p.advance(30)
    p.observe(DESK_PORT)
    p.advance(4)                           # probe deadline passes, no reply

    assert FindingKind.HOST_LOCATION_HIJACK not in p.kinds
    assert FindingKind.HOST_MOVED_WITHOUT_PORT_DOWN not in p.kinds
    assert p.hosts.location_of(MAC) == DESK_PORT


def test_roam_without_port_down_is_reported_but_not_a_hijack():
    p = Pipeline()
    p.observe(VICTIM_PORT)
    p.advance(30)
    p.observe(DESK_PORT)
    p.advance(4)
    assert p.kinds == [FindingKind.HOST_MOVED_WITHOUT_PORT_DOWN]


def test_enforce_mode_produces_a_scoped_expiring_decision():
    p = Pipeline(mode=PolicyMode.ENFORCE)
    p.observe(VICTIM_PORT)
    p.advance(10)
    p.observe(ATTACKER_PORT)
    p.reply_from(VICTIM_PORT)

    record = next(r for r in p.evidence
                  if r.finding.kind is FindingKind.HOST_LOCATION_HIJACK)
    assert record.decision.action is EnforcementAction.QUARANTINE
    assert record.decision.scope == ATTACKER_PORT
    assert record.decision.expires_at is not None
    assert record.decision.reversible


def test_management_protection_survives_the_whole_chain():
    p = Pipeline(mode=PolicyMode.ENFORCE)
    p.policy.protect(ATTACKER_PORT)
    p.observe(VICTIM_PORT)
    p.advance(10)
    p.observe(ATTACKER_PORT)
    p.reply_from(VICTIM_PORT)
    assert EnforcementAction.QUARANTINE not in p.actions


def test_a_forged_reply_from_the_wrong_port_does_not_produce_a_finding():
    p = Pipeline()
    p.observe(VICTIM_PORT)
    p.advance(10)
    p.observe(ATTACKER_PORT)
    p.reply_from(DESK_PORT)                # attacker answers from elsewhere
    assert p.kinds == [], "an unmatched reply is not evidence"
    assert p.probes.outstanding_for(MAC) is not None


def test_the_evidence_bundle_is_reproducible_and_machine_readable():
    import json

    p = Pipeline()
    p.observe(VICTIM_PORT)
    p.advance(10)
    p.observe(ATTACKER_PORT)
    p.reply_from(VICTIM_PORT)
    payload = json.loads(p.evidence.to_json(label="p4-acceptance"))
    assert payload["record_count"] >= 1
    assert payload["records"][0]["finding"]["kind"]


# -- the structural requirement -------------------------------------------


def test_the_whole_p4_core_imports_no_openflow_library():
    """The P4 acceptance requirement stated literally: this chain must work
    without any OpenFlow dependency."""
    forbidden = {"ryu", "os_ken", "pox", "ovs", "scapy", "dpkt",
                 "eventlet", "gevent", "twisted", "floodlight"}
    root = Path(__file__).resolve().parents[2] / "src" / "sdnguard"

    # The P4 claim is about the *core*: the chain from observation to decision.
    # adapter/ is the framework boundary by design (ADR-005/017) and has its
    # own guard in tests/domain/test_no_framework_dependencies.py, which also
    # asserts the exemption list is exactly one file. Naming the core packages
    # explicitly keeps this test honest about what it covers.
    core_packages = ("domain", "topology", "hosts", "probes", "detection",
                     "policy", "observability", "controller", "v2")
    paths = [p for pkg in core_packages for p in (root / pkg).rglob("*.py")]
    assert len(paths) >= 12, "guard would pass vacuously"

    offenders = {}
    for path in paths:
        tree = ast.parse(path.read_text())
        roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                roots.add(node.module.split(".")[0])
        if roots & forbidden:
            offenders[str(path.relative_to(root))] = sorted(roots & forbidden)
    assert offenders == {}


def test_the_p4_core_package_list_matches_the_tree():
    """If a new core package appears, this test fails until someone decides
    whether it belongs inside the framework-free boundary. Silence here would
    mean a package could quietly escape the guard."""
    root = Path(__file__).resolve().parents[2] / "src" / "sdnguard"
    on_disk = {p.name for p in root.iterdir() if p.is_dir() and p.name != "__pycache__"}
    # v2/ maps SDN observations onto the shared Annulon contracts. It is
    # stdlib-and-annulon only, so it sits inside the framework-free core.
    accounted = {"domain", "topology", "hosts", "probes", "detection", "policy",
                 "observability", "controller", "adapter", "v2"}
    assert on_disk == accounted, (
        f"unaccounted packages: {sorted(on_disk - accounted)}; decide whether "
        "each belongs inside the framework-free core before adding it here")


def test_no_framework_module_is_loaded_after_running_the_pipeline():
    before = set(sys.modules)
    p = Pipeline()
    p.observe(VICTIM_PORT)
    p.advance(10)
    p.observe(ATTACKER_PORT)
    p.reply_from(VICTIM_PORT)
    loaded = {m.split(".")[0] for m in set(sys.modules) - before}
    assert not (loaded & {"ryu", "os_ken", "ovs", "scapy", "twisted"})


@pytest.mark.parametrize("dpid", [1, 127, 128, 2**63, 2**64 - 1])
def test_the_chain_works_across_the_full_datapath_id_space(dpid):
    """KF-07 end to end: the legacy defect was invisible with DPIDs 1-3."""
    p = Pipeline()
    old = PortIdentity.of(dpid, 1)
    new = PortIdentity.of(dpid, 4)
    p.observe(old)
    p.advance(10)
    p.observe(new)
    p.reply_from(old)
    assert FindingKind.HOST_LOCATION_HIJACK in p.kinds, f"failed for dpid {dpid}"


def test_benign_relocation_emits_no_finding_at_all():
    """The false-positive test that matters: a legitimate move with a clean
    port-down must produce silence, not a stream of low-grade noise."""
    p = Pipeline()
    p.observe(VICTIM_PORT)
    p.port_down(VICTIM_PORT)
    p.advance(30)
    p.observe(DESK_PORT)
    p.advance(4)
    assert p.kinds == []
