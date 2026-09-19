"""Port classification and port-down evidence."""

from __future__ import annotations

import pytest

from sdnguard.domain.host import MacAddress
from sdnguard.domain.identity import DatapathId, PortIdentity, PortNumber
from sdnguard.topology.ports import (
    ClassificationConflict,
    PortRecord,
    PortRegistry,
    PortRegistryFull,
    PortType,
)

DPID = DatapathId(0x0000AABBCCDDEEFF)
OTHER_DPID = DatapathId(0x0000AABBCCDDEE00)
P1 = PortIdentity(DPID, PortNumber(1))
P2 = PortIdentity.of(0x0000AABBCCDDEEFF, 2)
P3 = PortIdentity.of(0x0000AABBCCDDEEFF, 3)
MAC_A = MacAddress.parse("aa:bb:cc:dd:ee:01")
MAC_B = MacAddress.parse("aa:bb:cc:dd:ee:02")


@pytest.fixture
def registry() -> PortRegistry:
    return PortRegistry()


# -- classification --------------------------------------------------------


def test_a_new_port_is_unknown(registry):
    assert registry.type_of(P1) is PortType.UNKNOWN
    registry.register(P1)
    assert registry.get(P1).port_type is PortType.UNKNOWN


def test_lldp_promotes_unknown_to_switch(registry):
    assert registry.observe_lldp(P1) is ClassificationConflict.NONE
    assert registry.type_of(P1) is PortType.SWITCH


def test_host_traffic_promotes_unknown_to_host(registry):
    assert registry.observe_host(P1, MAC_A) is ClassificationConflict.NONE
    assert registry.type_of(P1) is PortType.HOST


def test_lldp_on_a_host_port_is_the_link_fabrication_signature(registry):
    registry.observe_host(P1, MAC_A)
    assert registry.observe_lldp(P1) is ClassificationConflict.LLDP_ON_HOST_PORT
    assert registry.type_of(P1) is PortType.HOST, "a conflict must not reclassify"


def test_host_traffic_on_a_switch_port_is_reported(registry):
    registry.observe_lldp(P1)
    assert registry.observe_host(P1, MAC_A) is ClassificationConflict.HOST_TRAFFIC_ON_SWITCH_PORT
    assert registry.type_of(P1) is PortType.SWITCH, "a conflict must not reclassify"


def test_conflicts_are_returned_not_raised(registry):
    """Ordinary traffic must not be exceptional; the caller decides meaning."""
    registry.observe_host(P1, MAC_A)
    result = registry.observe_lldp(P1)
    assert isinstance(result, ClassificationConflict)


def test_repeated_consistent_observations_are_idempotent(registry):
    for _ in range(5):
        assert registry.observe_lldp(P2) is ClassificationConflict.NONE
    assert registry.type_of(P2) is PortType.SWITCH
    assert len(registry) == 1


# -- port-down evidence ----------------------------------------------------


def test_port_down_marks_every_host_on_the_port(registry):
    registry.observe_host(P1, MAC_A)
    registry.observe_host(P1, MAC_B)
    assert not registry.port_down_seen_for(P1, MAC_A)
    registry.observe_port_down(P1)
    assert registry.port_down_seen_for(P1, MAC_A)
    assert registry.port_down_seen_for(P1, MAC_B)
    assert registry.get(P1).is_up is False


def test_seeing_the_host_again_clears_its_port_down_evidence(registry):
    """The host is demonstrably present here again, so the earlier shutdown
    no longer explains a later move."""
    registry.observe_host(P1, MAC_A)
    registry.observe_port_down(P1)
    assert registry.port_down_seen_for(P1, MAC_A)
    registry.observe_host(P1, MAC_A)
    assert not registry.port_down_seen_for(P1, MAC_A)


def test_port_down_evidence_is_per_host_not_per_port(registry):
    registry.observe_host(P1, MAC_A)
    registry.observe_port_down(P1)
    registry.observe_host(P1, MAC_B)          # a different host appears
    assert registry.port_down_seen_for(P1, MAC_A) is True
    assert registry.port_down_seen_for(P1, MAC_B) is False


def test_unknown_host_has_no_port_down_evidence(registry):
    """Absence of evidence is not evidence of a shutdown."""
    registry.observe_port_down(P1)
    assert registry.port_down_seen_for(P1, MAC_A) is False
    assert registry.port_down_seen_for(P3, MAC_A) is False


def test_port_up_restores_the_flag_but_not_the_evidence(registry):
    registry.observe_host(P1, MAC_A)
    registry.observe_port_down(P1)
    registry.observe_port_up(P1)
    assert registry.get(P1).is_up is True
    assert registry.port_down_seen_for(P1, MAC_A) is True, \
        "the port coming back up does not prove the host returned"


# -- switch lifecycle ------------------------------------------------------


def test_removing_a_switch_reclaims_all_of_its_ports(registry):
    """Legacy switchRemoved was a no-op with a TODO, so state accumulated for
    the process lifetime (KF-12)."""
    registry.observe_host(P1, MAC_A)
    registry.observe_host(P2, MAC_B)
    registry.observe_host(PortIdentity.of(OTHER_DPID.value, 1), MAC_A)
    assert len(registry) == 3
    assert registry.remove_switch(DPID) == 2
    assert len(registry) == 1
    assert registry.get(P1) is None


def test_removing_an_unknown_switch_is_a_no_op(registry):
    registry.observe_host(P1, MAC_A)
    assert registry.remove_switch(OTHER_DPID) == 0
    assert len(registry) == 1


def test_ports_discovered_after_the_handshake_are_tracked(registry):
    """Legacy seeded port_list only in handleSwitchAdd."""
    assert P3 not in registry
    registry.observe_host(P3, MAC_A)
    assert P3 in registry


def test_ports_of_lists_only_that_switch(registry):
    registry.observe_host(P1, MAC_A)
    registry.observe_host(P2, MAC_A)
    registry.observe_host(PortIdentity.of(OTHER_DPID.value, 9), MAC_A)
    assert registry.ports_of(DPID) == sorted([P1, P2])


# -- bounded state ---------------------------------------------------------


def test_port_count_is_bounded_and_refuses_rather_than_evicting(registry):
    """State exhaustion is an attack surface; silent eviction would let an
    attacker flush a victim's record."""
    small = PortRegistry(max_ports=3)
    for i in range(1, 4):
        small.register(PortIdentity.of(1, i))
    with pytest.raises(PortRegistryFull, match="limit 3"):
        small.register(PortIdentity.of(1, 4))
    assert len(small) == 3


def test_hosts_per_port_is_bounded(registry):
    small = PortRegistry(max_hosts_per_port=2)
    small.observe_host(P1, MAC_A)
    small.observe_host(P1, MAC_B)
    with pytest.raises(PortRegistryFull, match="limit 2"):
        small.observe_host(P1, MacAddress.parse("aa:bb:cc:dd:ee:03"))


def test_re_observing_a_known_host_does_not_count_against_the_limit(registry):
    small = PortRegistry(max_hosts_per_port=1)
    small.observe_host(P1, MAC_A)
    small.observe_host(P1, MAC_A)
    assert len(small.get(P1).hosts) == 1


def test_capacity_is_introspectable_and_limits_must_be_positive():
    assert PortRegistry(max_ports=10, max_hosts_per_port=5).capacity == (10, 5)
    with pytest.raises(ValueError):
        PortRegistry(max_ports=0)
    with pytest.raises(ValueError):
        PortRegistry(max_hosts_per_port=0)


# -- record-level immutability --------------------------------------------


def test_records_are_immutable_snapshots():
    record = PortRecord.new(P1)
    updated, _ = record.observe_host(MAC_A, max_hosts=10)
    assert record.hosts == frozenset(), "original untouched"
    assert updated.knows_host(MAC_A)
    assert updated is not record


def test_forget_host_removes_only_that_host():
    record = PortRecord.new(P1)
    record, _ = record.observe_host(MAC_A, max_hosts=10)
    record, _ = record.observe_host(MAC_B, max_hosts=10)
    record = record.forget_host(MAC_A)
    assert not record.knows_host(MAC_A) and record.knows_host(MAC_B)


def test_registry_iteration_is_deterministic(registry):
    for i in (5, 1, 3):
        registry.register(PortIdentity.of(1, i))
    assert [r.port.port.value for r in registry] == [1, 3, 5]
