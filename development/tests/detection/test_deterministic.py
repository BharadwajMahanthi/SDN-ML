"""Deterministic detectors: hijack and link fabrication."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sdnguard.detection.deterministic import (
    DetectionPolicy,
    HostHijackDetector,
    LinkFabricationDetector,
)
from sdnguard.domain.events import (
    FindingKind,
    ProbeOutcome,
    ProbeRequest,
    ProbeResult,
    Severity,
    Verdict,
)
from sdnguard.domain.host import HostIdentity, HostLocation, MacAddress
from sdnguard.domain.identity import DatapathId, PortIdentity
from sdnguard.hosts.movement import MovementStateMachine
from sdnguard.topology.links import LinkRegistry
from sdnguard.topology.ports import ClassificationConflict, PortRegistry

T0 = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
DPID = DatapathId(0x0000AABBCCDDEEFF)
P1 = PortIdentity.of(DPID.value, 1)
P2 = PortIdentity.of(DPID.value, 2)
P3 = PortIdentity.of(DPID.value, 3)
IDENT = HostIdentity.of(MacAddress.parse("aa:bb:cc:dd:ee:01"))
MAC = IDENT.mac


def resolve(outcome, *, port_down=False):
    """Drive a host through a full move+validation and return (state, actions)."""
    m = MovementStateMachine()
    m.on_observation(IDENT, HostLocation.at(P1, T0))
    if port_down:
        m.on_port_down(MAC, P1)
    m.on_observation(IDENT, HostLocation.at(P2, T0 + timedelta(seconds=1)))
    probe = ProbeRequest.create(IDENT, P1, T0, timedelta(seconds=3))
    m.on_probe_issued(MAC, probe)
    return m.on_probe_result(MAC, ProbeResult.of(probe.correlation_id, outcome, T0))


@pytest.fixture
def detector() -> HostHijackDetector:
    return HostHijackDetector()


@pytest.fixture
def link_detector() -> LinkFabricationDetector:
    return LinkFabricationDetector()


# -- host hijack -----------------------------------------------------------


def test_a_probe_reply_produces_a_high_severity_hijack_finding(detector):
    state, actions = resolve(ProbeOutcome.REPLIED)
    findings = detector.from_resolution(state, actions, T0)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.kind is FindingKind.HOST_LOCATION_HIJACK
    assert finding.verdict is Verdict.SUSPICIOUS
    assert finding.severity is Severity.HIGH
    assert finding.port == P2, "the finding names the new, suspect location"
    assert any("replied at its previous location" in e for e in finding.evidence)


def test_a_clean_move_produces_no_finding(detector):
    state, actions = resolve(ProbeOutcome.EXPIRED, port_down=True)
    assert detector.from_resolution(state, actions, T0) == []
    assert detector.verdict_for(state) is Verdict.BENIGN


def test_a_move_without_port_down_is_low_severity_not_high(detector):
    """Benign wireless roaming routinely omits port-down, so the missing
    pre-condition alone must not read as an attack."""
    state, actions = resolve(ProbeOutcome.EXPIRED, port_down=False)
    findings = detector.from_resolution(state, actions, T0)
    assert len(findings) == 1
    assert findings[0].kind is FindingKind.HOST_MOVED_WITHOUT_PORT_DOWN
    assert findings[0].severity is Severity.LOW


@pytest.mark.parametrize("outcome", [ProbeOutcome.UNDELIVERABLE, ProbeOutcome.CANCELLED])
def test_an_unresolved_probe_is_inconclusive_and_informational(detector, outcome):
    state, actions = resolve(outcome)
    findings = detector.from_resolution(state, actions, T0)
    assert findings[0].kind is FindingKind.PROBE_UNRESOLVED
    assert findings[0].verdict is Verdict.INCONCLUSIVE
    assert findings[0].severity is Severity.INFO
    assert detector.verdict_for(state) is Verdict.INCONCLUSIVE


def test_multi_location_is_reported_independently_of_the_probe_outcome(detector):
    """Legacy skipped exactly this case. A host at several ports at once is
    reportable even while validation is inconclusive."""
    state, actions = resolve(ProbeOutcome.CANCELLED)
    findings = detector.from_resolution(state, actions, T0, concurrent_locations=3)
    kinds = [f.kind for f in findings]
    assert FindingKind.HOST_MULTI_LOCATION in kinds
    multi = next(f for f in findings if f.kind is FindingKind.HOST_MULTI_LOCATION)
    assert multi.severity is Severity.MEDIUM
    assert any("3 ports concurrently" in e for e in multi.evidence)


def test_the_mapping_from_actions_to_findings_is_total(detector):
    """Every EMIT_FINDING produces exactly one finding and no finding appears
    without one, so a finding can always be traced to its transition."""
    from sdnguard.hosts.movement import ActionKind

    for outcome in ProbeOutcome:
        state, actions = resolve(outcome)
        emits = [a for a in actions if a.kind is ActionKind.EMIT_FINDING]
        findings = detector.from_resolution(state, actions, T0)
        assert len(findings) == len(emits), outcome


def test_every_finding_cites_evidence(detector):
    for outcome in ProbeOutcome:
        state, actions = resolve(outcome)
        for finding in detector.from_resolution(state, actions, T0):
            assert finding.evidence, outcome
            assert all(isinstance(e, str) and e for e in finding.evidence)


def test_findings_are_machine_readable(detector):
    import json

    state, actions = resolve(ProbeOutcome.REPLIED)
    payload = detector.from_resolution(state, actions, T0)[0].to_dict()
    assert json.loads(json.dumps(payload)) == payload
    assert payload["kind"] == "host_location_hijack"


def test_severity_policy_is_configurable_in_one_place():
    quiet = HostHijackDetector(DetectionPolicy(hijack_severity=Severity.MEDIUM))
    state, actions = resolve(ProbeOutcome.REPLIED)
    assert quiet.from_resolution(state, actions, T0)[0].severity is Severity.MEDIUM


def test_a_state_with_no_location_produces_nothing(detector):
    from sdnguard.hosts.movement import HostMovementState

    assert detector.from_resolution(HostMovementState.unknown(IDENT), [], T0) == []


def test_an_unmapped_action_detail_is_a_loud_error(detector):
    """A silently ignored detail would reintroduce the legacy failure mode of
    unreachable branches nobody noticed."""
    from sdnguard.hosts.movement import Action, ActionKind

    state, _ = resolve(ProbeOutcome.REPLIED)
    bogus = [Action.of(ActionKind.EMIT_FINDING, "something_new")]
    with pytest.raises(ValueError, match="unmapped finding detail"):
        detector.from_resolution(state, bogus, T0)


# -- link fabrication ------------------------------------------------------


def test_lldp_on_a_host_port_is_high_severity(link_detector):
    finding = link_detector.from_conflict(
        ClassificationConflict.LLDP_ON_HOST_PORT, IDENT, P1, T0)
    assert finding.kind is FindingKind.LINK_FABRICATION
    assert finding.severity is Severity.HIGH
    assert finding.verdict is Verdict.SUSPICIOUS


def test_host_traffic_on_a_switch_port_is_inconclusive(link_detector):
    """B-3: the legacy intended response is unrecoverable from source, so the
    finding is emitted and no verdict is asserted."""
    finding = link_detector.from_conflict(
        ClassificationConflict.HOST_TRAFFIC_ON_SWITCH_PORT, IDENT, P1, T0)
    assert finding.kind is FindingKind.HOST_TRAFFIC_FROM_SWITCH_PORT
    assert finding.verdict is Verdict.INCONCLUSIVE
    assert any("B-3" in e for e in finding.evidence)


def test_no_conflict_produces_no_finding(link_detector):
    assert link_detector.from_conflict(
        ClassificationConflict.NONE, IDENT, P1, T0) is None


def test_topology_check_catches_a_link_accepted_before_reclassification(link_detector):
    """A per-packet check alone cannot catch this: the link was accepted while
    the endpoint was still unclassified."""
    ports = PortRegistry()
    links = LinkRegistry()
    links.observe(P1, P2, T0)
    assert link_detector.from_topology(links, ports, IDENT, T0) == []
    ports.observe_host(P1, MAC)
    findings = link_detector.from_topology(links, ports, IDENT, T0)
    assert len(findings) == 1
    assert findings[0].kind is FindingKind.LINK_FABRICATION
    assert findings[0].port == P1


def test_a_legitimate_inter_switch_link_produces_nothing(link_detector):
    ports = PortRegistry()
    links = LinkRegistry()
    ports.observe_lldp(P1)
    ports.observe_lldp(P2)
    links.observe(P1, P2, T0)
    assert link_detector.from_topology(links, ports, IDENT, T0) == []


def test_link_findings_are_deterministic_in_order(link_detector):
    ports = PortRegistry()
    links = LinkRegistry()
    for a, b in ((P3, P2), (P1, P2)):
        links.observe(a, b, T0)
    ports.observe_host(P2, MAC)
    first = [f.port for f in link_detector.from_topology(links, ports, IDENT, T0)]
    second = [f.port for f in link_detector.from_topology(links, ports, IDENT, T0)]
    assert first == second


# -- the detectors decide nothing about response --------------------------


def test_detectors_emit_findings_and_never_enforcement(detector, link_detector):
    """Deciding what to do is the policy engine's job."""
    state, actions = resolve(ProbeOutcome.REPLIED)
    findings = detector.from_resolution(state, actions, T0)
    findings.append(link_detector.from_conflict(
        ClassificationConflict.LLDP_ON_HOST_PORT, IDENT, P1, T0))
    for finding in findings:
        assert not hasattr(finding, "action")
        assert finding.verdict in set(Verdict)


def test_benign_relocation_is_not_reported_as_multi_location(detector):
    """KF-16: the host table holds the old sighting until its TTL expires.
    If the probe found the old location silent, that lingering entry is
    bookkeeping, not evidence of concurrent presence -- reporting it would
    make every ordinary relocation look multi-homed."""
    state, actions = resolve(ProbeOutcome.EXPIRED, port_down=True)
    findings = detector.from_resolution(state, actions, T0, concurrent_locations=2)
    assert [f.kind for f in findings] == []


def test_multi_location_is_still_reported_when_the_host_answered(detector):
    state, actions = resolve(ProbeOutcome.REPLIED)
    kinds = [f.kind for f in detector.from_resolution(state, actions, T0,
                                                      concurrent_locations=2)]
    assert FindingKind.HOST_MULTI_LOCATION in kinds
    assert FindingKind.HOST_LOCATION_HIJACK in kinds
