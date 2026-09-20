"""Adapter contract, fake fabric, and the controller wired to both.

Everything here runs with no OVS, no network and no OpenFlow library.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from sdnguard.adapter.contract import (
    OpenFlowAdapter,
    PortStatus,
    SecurityCore,
    SendOutcome,
    SendResult,
    SwitchCommands,
)
from sdnguard.adapter.fake import FakeAdapter
from sdnguard.clock import ManualClock
from sdnguard.controller.app import SecurityController
from sdnguard.domain.events import (
    EnforcementAction,
    FindingKind,
    ProbeRequest,
    Verdict,
)
from sdnguard.domain.host import HostIdentity, MacAddress
from sdnguard.domain.identity import DatapathId, PortIdentity
from sdnguard.policy.engine import PolicyEngine, PolicyMode

DPID = DatapathId(0x0000AABBCCDDEEFF)
OTHER = DatapathId(0x1122334455667788)
P1 = PortIdentity.of(DPID.value, 1)
P2 = PortIdentity.of(DPID.value, 2)
P4 = PortIdentity.of(DPID.value, 4)
VICTIM = HostIdentity.of(MacAddress.parse("aa:bb:cc:dd:ee:01"))
MAC = VICTIM.mac


@pytest.fixture
def adapter() -> FakeAdapter:
    return FakeAdapter()


@pytest.fixture
def controller(adapter) -> SecurityController:
    clock = ManualClock(adapter.now)
    c = SecurityController(commands=adapter.commands(), clock=clock)
    adapter.attach(c)
    c._clock_handle = clock
    return c


def advance(adapter, controller, seconds: float) -> None:
    adapter.advance(seconds)
    controller._clock_handle.advance(seconds)
    controller.tick()


# -- the contract ----------------------------------------------------------


def test_the_fake_satisfies_both_halves_of_the_contract(adapter, controller):
    assert isinstance(adapter, SwitchCommands)
    assert isinstance(adapter, OpenFlowAdapter)
    assert isinstance(controller, SecurityCore)


def test_send_result_is_typed_not_exceptional(adapter):
    """'The switch went away' is ordinary in this system, not an exception."""
    probe = ProbeRequest.create(VICTIM, P1, adapter.now, timedelta(seconds=3))
    result = adapter.send_probe(probe, generation=1)
    assert isinstance(result, SendResult)
    assert result.outcome is SendOutcome.NO_SUCH_SWITCH
    assert not result.sent


def test_send_result_rejects_a_false_failure():
    with pytest.raises(ValueError):
        SendResult.failed(SendOutcome.SENT)


@pytest.mark.parametrize(
    "setup,expected",
    [
        (lambda a: None, SendOutcome.NO_SUCH_SWITCH),
        (lambda a: a.connect_switch(DPID, [1, 2]), SendOutcome.SENT),
        (lambda a: (a.connect_switch(DPID, [2]),), SendOutcome.NO_SUCH_PORT),
        (lambda a: (a.connect_switch(DPID, [1]), a.set_port(P1, False)), SendOutcome.PORT_DOWN),
        (lambda a: (a.connect_switch(DPID, [1]), a.disconnect_switch(DPID)), SendOutcome.NO_SUCH_SWITCH),
    ],
)
def test_the_fake_models_real_send_failures(adapter, setup, expected):
    setup(adapter)
    probe = ProbeRequest.create(VICTIM, P1, adapter.now, timedelta(seconds=3))
    assert adapter.send_probe(probe, generation=1).outcome is expected


def test_a_stale_generation_cannot_send(adapter):
    adapter.connect_switch(DPID, [1])
    probe = ProbeRequest.create(VICTIM, P1, adapter.now, timedelta(seconds=3))
    adapter.connect_switch(DPID, [1])          # reconnect -> generation 2
    assert adapter.send_probe(probe, generation=1).outcome is SendOutcome.STALE_GENERATION
    assert adapter.send_probe(probe, generation=2).sent


# -- lifecycle -------------------------------------------------------------


def test_switch_connect_registers_its_ports(adapter, controller):
    adapter.connect_switch(DPID, [1, 2, 3])
    assert len(controller.ports) == 3
    assert controller.switches.is_current(DPID, 1)


def test_a_port_added_after_the_handshake_is_tracked(adapter, controller):
    """The case the legacy controller missed entirely."""
    adapter.connect_switch(DPID, [1])
    adapter.add_port(P2)
    assert P2 in controller.ports


def test_disconnect_reclaims_everything_anchored_to_the_switch(adapter, controller):
    adapter.connect_switch(DPID, [1, 2])
    adapter.connect_switch(OTHER, [1])
    adapter.host_traffic(VICTIM, P1)
    assert len(controller.ports) == 3 and len(controller.hosts) == 1

    adapter.disconnect_switch(DPID)
    assert len(controller.ports) == 1, "only the other switch's port remains"
    assert len(controller.hosts) == 0
    assert len(controller.probes) == 0


def test_reconnect_cancels_probes_from_the_previous_generation(adapter, controller):
    adapter.connect_switch(DPID, [1, 4])
    adapter.host_traffic(VICTIM, P1)
    advance(adapter, controller, 1)
    adapter.host_traffic(VICTIM, P4)                 # move -> probe issued
    assert len(controller.probes) == 1

    adapter.connect_switch(DPID, [1, 4])             # reconnect
    assert len(controller.probes) == 0, "a stale probe cannot be answered"


# -- host observation ------------------------------------------------------


def test_host_traffic_populates_the_table_and_classifies_the_port(adapter, controller):
    adapter.connect_switch(DPID, [1])
    adapter.host_traffic(VICTIM, P1)
    from sdnguard.topology.ports import PortType

    assert controller.hosts.location_of(MAC) == P1
    assert controller.ports.type_of(P1) is PortType.HOST
    assert controller.stats.observations == 1


def test_broadcast_arp_is_learned(adapter, controller):
    """KF-09 at the adapter boundary."""
    adapter.connect_switch(DPID, [1])
    adapter.host_traffic(VICTIM, P1, source="arp", broadcast=True)
    assert MAC in controller.hosts


def test_a_move_issues_a_probe_out_the_old_port_only(adapter, controller):
    adapter.connect_switch(DPID, [1, 4])
    adapter.host_traffic(VICTIM, P1)
    advance(adapter, controller, 1)
    adapter.host_traffic(VICTIM, P4)
    assert len(adapter.sent) == 1
    assert adapter.sent[0].probe.target_port == P1


def test_an_unsendable_probe_is_resolved_immediately(adapter, controller):
    """Legacy left unsendable probes outstanding forever; that is how
    probedPorts grew without bound."""
    adapter.connect_switch(DPID, [1, 4])
    adapter.host_traffic(VICTIM, P1)
    adapter.set_port(P1, False)                  # old port goes down
    advance(adapter, controller, 1)
    adapter.host_traffic(VICTIM, P4)
    assert len(controller.probes) == 0, "no orphaned probe"
    assert controller.stats.probes_undeliverable == 1
    assert FindingKind.PROBE_UNRESOLVED in [r.finding.kind for r in controller.evidence]


# -- link fabrication at the boundary -------------------------------------


def test_lldp_on_a_known_host_port_produces_a_fabrication_finding(adapter, controller):
    adapter.connect_switch(DPID, [1])
    adapter.host_traffic(VICTIM, P1)
    adapter.lldp(P1, claimed_source=PortIdentity.of(OTHER.value, 1))
    kinds = [r.finding.kind for r in controller.evidence]
    assert FindingKind.LINK_FABRICATION in kinds


def test_lldp_between_switch_ports_records_a_link(adapter, controller):
    adapter.connect_switch(DPID, [1])
    adapter.connect_switch(OTHER, [1])
    far = PortIdentity.of(OTHER.value, 1)
    adapter.lldp(P1, claimed_source=far)
    assert controller.links.get(P1, far) is not None
    assert len(controller.evidence) == 0


# -- end to end ------------------------------------------------------------


def test_hijack_end_to_end_through_the_adapter(adapter, controller):
    adapter.connect_switch(DPID, [1, 4])
    adapter.host_traffic(VICTIM, P1)
    advance(adapter, controller, 10)
    adapter.host_traffic(VICTIM, P4)             # impostor

    probe = adapter.sent[-1].probe
    assert controller.observe_probe_reply(
        probe.correlation_id, source_port=P1, mac=MAC) is True

    kinds = [r.finding.kind for r in controller.evidence]
    assert FindingKind.HOST_LOCATION_HIJACK in kinds
    record = next(r for r in controller.evidence
                  if r.finding.kind is FindingKind.HOST_LOCATION_HIJACK)
    assert record.finding.verdict is Verdict.SUSPICIOUS
    assert record.decision.action is EnforcementAction.OBSERVE


def test_benign_move_end_to_end_produces_no_finding(adapter, controller):
    adapter.connect_switch(DPID, [1, 4])
    adapter.host_traffic(VICTIM, P1)
    adapter.set_port(P1, False)                  # clean port-down first
    adapter.set_port(P1, True)
    advance(adapter, controller, 30)
    adapter.host_traffic(VICTIM, P4)
    advance(adapter, controller, 5)              # probe expires unanswered
    assert [r.finding.kind for r in controller.evidence] == []


def test_a_reply_from_the_wrong_port_does_not_correlate(adapter, controller):
    adapter.connect_switch(DPID, [1, 2, 4])
    adapter.host_traffic(VICTIM, P1)
    advance(adapter, controller, 10)
    adapter.host_traffic(VICTIM, P4)
    probe = adapter.sent[-1].probe
    assert controller.observe_probe_reply(
        probe.correlation_id, source_port=P2, mac=MAC) is False
    assert len(controller.evidence) == 0


def test_enforce_mode_reaches_a_scoped_decision(adapter):
    clock = ManualClock(adapter.now)
    controller = SecurityController(
        commands=adapter.commands(), clock=clock,
        policy=PolicyEngine(mode=PolicyMode.ENFORCE,
                            rules=PolicyEngine.default_rules()))
    adapter.attach(controller)
    adapter.connect_switch(DPID, [1, 4])
    adapter.host_traffic(VICTIM, P1)
    adapter.advance(10); clock.advance(10); controller.tick()
    adapter.host_traffic(VICTIM, P4)
    probe = adapter.sent[-1].probe
    controller.observe_probe_reply(probe.correlation_id, source_port=P1, mac=MAC)

    record = next(r for r in controller.evidence
                  if r.finding.kind is FindingKind.HOST_LOCATION_HIJACK)
    assert record.decision.action is EnforcementAction.QUARANTINE
    assert record.decision.scope == P4
    assert record.decision.expires_at is not None
    assert controller.stats.enforcements == 1


def test_health_reports_the_live_picture(adapter, controller):
    adapter.connect_switch(DPID, [1, 4])
    adapter.host_traffic(VICTIM, P1)
    health = controller.health()
    assert health["switches_connected"] == 1
    assert health["ports_tracked"] == 2
    assert health["hosts_tracked"] == 1
    assert health["enforcement_disabled"] is False


def test_the_adapter_layer_imports_no_framework():
    """ADR-017: eventlet and friends may appear only in a real adapter
    implementation, never in the contract, the fake, or the controller."""
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parents[2] / "src" / "sdnguard"
    forbidden = {"ryu", "os_ken", "eventlet", "gevent", "ovs", "scapy", "twisted"}
    checked = [p for p in (list((root / "adapter").glob("*.py"))
                           + list((root / "controller").glob("*.py")))
               if p.name != "osken.py"]
    assert len(checked) >= 4, "guard would pass vacuously"
    for path in checked:
        tree = ast.parse(path.read_text())
        roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                roots.add(node.module.split(".")[0])
        assert not (roots & forbidden), f"{path.name} imports {roots & forbidden}"


def test_disconnect_does_not_leak_hosts_on_multiple_ports(adapter, controller):
    """Regression for KF-17: the port registry was cleared before being read,
    so every host attached to the departed switch survived."""
    adapter.connect_switch(DPID, [1, 2, 4])
    adapter.host_traffic(VICTIM, P1)
    other_host = HostIdentity.of(MacAddress.parse("aa:bb:cc:dd:ee:09"))
    adapter.host_traffic(other_host, P2)
    assert len(controller.hosts) == 2

    adapter.disconnect_switch(DPID)
    assert len(controller.hosts) == 0
    assert len(controller.ports) == 0
    assert len(controller.links) == 0
