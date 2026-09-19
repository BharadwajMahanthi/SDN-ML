"""Switch connection generations and inter-switch link state."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sdnguard.domain.host import MacAddress
from sdnguard.domain.identity import DatapathId, InvalidIdentity, PortIdentity, PortNumber
from sdnguard.topology.links import Link, LinkRegistry, LinkRegistryFull
from sdnguard.topology.ports import PortRegistry
from sdnguard.topology.switches import (
    SwitchRegistry,
    SwitchRegistryFull,
    SwitchState,
)

T0 = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
DPID_A = DatapathId(0x0000AABBCCDDEEFF)
DPID_B = DatapathId(0x0000AABBCCDDEE00)
PA1 = PortIdentity(DPID_A, PortNumber(1))
PB1 = PortIdentity.of(DPID_B.value, 1)
MAC = MacAddress.parse("aa:bb:cc:dd:ee:01")


# -- switch lifecycle ------------------------------------------------------


def test_first_connection_is_generation_one():
    reg = SwitchRegistry()
    record = reg.connect(DPID_A, T0)
    assert record.generation == 1 and record.connect_count == 1
    assert record.is_connected and reg.is_current(DPID_A, 1)


def test_disconnect_marks_state_without_forgetting():
    reg = SwitchRegistry()
    reg.connect(DPID_A, T0)
    record = reg.disconnect(DPID_A, T0 + timedelta(seconds=1))
    assert record.state is SwitchState.DISCONNECTED
    assert DPID_A in reg, "history is kept; forgetting is a separate decision"
    assert not reg.is_current(DPID_A, 1)


def test_reconnect_bumps_the_generation():
    """A probe issued before a reconnect must not be resolved by a reply that
    arrives after it: the port may now be a different physical link."""
    reg = SwitchRegistry()
    reg.connect(DPID_A, T0)
    reg.disconnect(DPID_A, T0 + timedelta(seconds=1))
    record = reg.connect(DPID_A, T0 + timedelta(seconds=2))
    assert record.generation == 2 and record.connect_count == 2
    assert not reg.is_current(DPID_A, 1), "stale generation must be rejected"
    assert reg.is_current(DPID_A, 2)


def test_repeated_reconnects_keep_incrementing():
    reg = SwitchRegistry()
    for i in range(1, 6):
        assert reg.connect(DPID_A, T0).generation == i
    assert not any(reg.is_current(DPID_A, g) for g in range(1, 5))
    assert reg.is_current(DPID_A, 5)


def test_unknown_switch_is_never_current():
    reg = SwitchRegistry()
    assert not reg.is_current(DPID_A, 1)
    assert reg.generation_of(DPID_A) is None
    assert reg.disconnect(DPID_A, T0) is None


def test_forget_removes_the_record():
    reg = SwitchRegistry()
    reg.connect(DPID_A, T0)
    assert reg.forget(DPID_A) is True
    assert reg.forget(DPID_A) is False
    assert len(reg) == 0


def test_connected_lists_only_live_switches():
    reg = SwitchRegistry()
    reg.connect(DPID_A, T0)
    reg.connect(DPID_B, T0)
    reg.disconnect(DPID_B, T0)
    assert reg.connected() == [DPID_A]


def test_switch_registry_is_bounded():
    reg = SwitchRegistry(max_switches=2)
    reg.connect(DatapathId(1), T0)
    reg.connect(DatapathId(2), T0)
    with pytest.raises(SwitchRegistryFull, match="limit 2"):
        reg.connect(DatapathId(3), T0)
    reg.connect(DatapathId(1), T0)  # reconnect of a known switch still allowed


def test_switch_record_validation():
    reg = SwitchRegistry()
    with pytest.raises(InvalidIdentity, match="timezone-aware"):
        reg.connect(DPID_A, datetime(2026, 9, 20))


# -- links -----------------------------------------------------------------


def test_links_are_unordered_pairs():
    """Treating (a,b) and (b,a) as distinct would double-count the topology
    and make a fabricated one-way link look half-discovered."""
    reg = LinkRegistry()
    first = reg.observe(PA1, PB1, T0)
    second = reg.observe(PB1, PA1, T0 + timedelta(seconds=1))
    assert len(reg) == 1
    assert first.endpoints == second.endpoints
    assert reg.get(PB1, PA1) is not None


def test_link_refresh_extends_last_seen_only():
    reg = LinkRegistry()
    reg.observe(PA1, PB1, T0)
    link = reg.observe(PA1, PB1, T0 + timedelta(seconds=30))
    assert link.first_seen == T0 and link.last_seen == T0 + timedelta(seconds=30)


def test_link_rejects_self_and_unnormalised_construction():
    with pytest.raises(InvalidIdentity, match="itself"):
        Link.between(PA1, PA1, T0)
    hi, lo = max(PA1, PB1), min(PA1, PB1)
    with pytest.raises(InvalidIdentity, match="normalised"):
        Link(hi, lo, T0, T0)


def test_same_switch_both_ends_is_flagged_not_rejected():
    link = Link.between(PortIdentity.of(1, 1), PortIdentity.of(1, 2), T0)
    assert link.is_self_loop_switch


def test_removing_a_switch_removes_its_links():
    reg = LinkRegistry()
    reg.observe(PA1, PB1, T0)
    reg.observe(PortIdentity.of(DPID_A.value, 2), PortIdentity.of(9, 1), T0)
    assert reg.remove_switch(DPID_A) == 2
    assert len(reg) == 0


def test_removing_a_port_removes_only_its_links():
    reg = LinkRegistry()
    reg.observe(PA1, PB1, T0)
    reg.observe(PortIdentity.of(DPID_A.value, 2), PortIdentity.of(9, 1), T0)
    assert reg.remove_port(PA1) == 1
    assert len(reg) == 1


def test_link_registry_is_bounded():
    reg = LinkRegistry(max_links=1)
    reg.observe(PA1, PB1, T0)
    with pytest.raises(LinkRegistryFull, match="limit 1"):
        reg.observe(PortIdentity.of(5, 1), PortIdentity.of(6, 1), T0)


def test_refresh_of_a_full_registry_still_works():
    """Hitting the cap must not stop us refreshing links we already hold."""
    reg = LinkRegistry(max_links=1)
    reg.observe(PA1, PB1, T0)
    assert reg.observe(PA1, PB1, T0 + timedelta(seconds=1)).last_seen > T0


# -- link/port consistency (link fabrication over topology state) ---------


def test_a_link_terminating_on_a_host_port_is_inconsistent():
    """Catches a link accepted before its endpoint was known to be a host
    port -- something a per-packet check alone cannot do."""
    ports = PortRegistry()
    links = LinkRegistry()
    links.observe(PA1, PB1, T0)
    assert links.inconsistent_endpoints(ports) == []
    ports.observe_host(PA1, MAC)
    offenders = links.inconsistent_endpoints(ports)
    assert len(offenders) == 1
    link, endpoint = offenders[0]
    assert endpoint == PA1 and link.touches(PA1)


def test_links_between_two_switch_ports_are_consistent():
    ports = PortRegistry()
    links = LinkRegistry()
    ports.observe_lldp(PA1)
    ports.observe_lldp(PB1)
    links.observe(PA1, PB1, T0)
    assert links.inconsistent_endpoints(ports) == []


def test_iteration_is_deterministic():
    reg = LinkRegistry()
    reg.observe(PortIdentity.of(3, 1), PortIdentity.of(4, 1), T0)
    reg.observe(PortIdentity.of(1, 1), PortIdentity.of(2, 1), T0)
    assert [str(l) for l in reg] == [str(l) for l in reg]
    assert list(reg)[0].a.datapath_id == DatapathId(1)
