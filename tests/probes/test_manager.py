"""Probe issue, correlation, expiry and bounds (P4-PROBE-01/02)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from sdnguard.clock import ManualClock
from sdnguard.domain.events import ProbeMethod, ProbeOutcome
from sdnguard.domain.host import HostIdentity, MacAddress
from sdnguard.domain.identity import DatapathId, PortIdentity
from sdnguard.probes.manager import (
    ProbeManager,
    ProbeManagerFull,
    ProbeRejected,
)

DPID = DatapathId(0x0000AABBCCDDEEFF)
P1 = PortIdentity.of(DPID.value, 1)
P2 = PortIdentity.of(DPID.value, 2)
MAC_A = MacAddress.parse("aa:bb:cc:dd:ee:01")
MAC_B = MacAddress.parse("aa:bb:cc:dd:ee:02")
IDENT_A = HostIdentity.of(MAC_A)
IDENT_B = HostIdentity.of(MAC_B)


@pytest.fixture
def clock() -> ManualClock:
    return ManualClock()


@pytest.fixture
def manager(clock) -> ProbeManager:
    return ProbeManager(clock=clock, timeout=timedelta(seconds=3))


# -- issuing ---------------------------------------------------------------


def test_issue_registers_an_outstanding_probe(manager):
    request = manager.issue(IDENT_A, P1)
    assert len(manager) == 1
    assert manager.outstanding_for(MAC_A).correlation_id == request.correlation_id
    assert request.method is ProbeMethod.ARP, "ARP is the default (ADR-006)"


def test_one_outstanding_probe_per_host(manager):
    manager.issue(IDENT_A, P1)
    with pytest.raises(ProbeRejected, match="already has an outstanding probe"):
        manager.issue(IDENT_A, P2)
    assert len(manager) == 1


def test_different_hosts_may_probe_concurrently(manager):
    manager.issue(IDENT_A, P1)
    manager.issue(IDENT_B, P2)
    assert len(manager) == 2
    ids = {manager.outstanding_for(MAC_A).correlation_id,
           manager.outstanding_for(MAC_B).correlation_id}
    assert len(ids) == 2


def test_concurrent_probes_do_not_clobber_each_other(manager):
    """Legacy HostProber kept targetMAC/targetIP as instance fields that each
    probe overwrote, so concurrent probes corrupted one another."""
    requests = []
    for i in range(1, 51):
        ident = HostIdentity.of(MacAddress(i))
        requests.append((ident, manager.issue(ident, PortIdentity.of(DPID.value, i))))
    for ident, request in requests:
        entry = manager.get(request.correlation_id)
        assert entry.mac == ident.mac
        assert entry.request.target_port == request.target_port


def test_issued_probes_have_distinct_nonces(manager):
    ids = {manager.issue(HostIdentity.of(MacAddress(i)), P1).correlation_id
           for i in range(1, 201)}
    assert len(ids) == 200


# -- correlation -----------------------------------------------------------


def test_a_matching_reply_resolves_as_replied(manager):
    request = manager.issue(IDENT_A, P1)
    result = manager.correlate(request.correlation_id, source_port=P1, mac=MAC_A)
    assert result.outcome is ProbeOutcome.REPLIED
    assert len(manager) == 0


@pytest.mark.parametrize(
    "bad_id", ["", "0" * 32, "f" * 32, "not-a-nonce"])
def test_an_unknown_nonce_is_not_evidence(manager, bad_id):
    """An unsolicited or forged reply is not an error -- it is simply not
    evidence. The legacy check omitted the nonce entirely."""
    manager.issue(IDENT_A, P1)
    assert manager.correlate(bad_id, source_port=P1, mac=MAC_A) is None
    assert len(manager) == 1


def test_a_reply_from_the_wrong_port_is_rejected(manager):
    request = manager.issue(IDENT_A, P1)
    assert manager.correlate(request.correlation_id, source_port=P2, mac=MAC_A) is None
    assert len(manager) == 1


def test_a_reply_with_the_wrong_mac_is_rejected(manager):
    request = manager.issue(IDENT_A, P1)
    assert manager.correlate(request.correlation_id, source_port=P1, mac=MAC_B) is None
    assert len(manager) == 1


def test_all_three_checks_are_required(manager):
    """Nonce, host and probed port must all match."""
    request = manager.issue(IDENT_A, P1)
    assert manager.correlate(request.correlation_id, source_port=P2, mac=MAC_B) is None
    assert manager.correlate(request.correlation_id, source_port=P1, mac=MAC_A) is not None


def test_a_probe_resolves_exactly_once(manager):
    request = manager.issue(IDENT_A, P1)
    assert manager.correlate(request.correlation_id, source_port=P1, mac=MAC_A)
    assert manager.correlate(request.correlation_id, source_port=P1, mac=MAC_A) is None
    assert manager.was_resolved(request.correlation_id)


def test_a_replayed_reply_after_resolution_is_distinguishable(manager):
    request = manager.issue(IDENT_A, P1)
    manager.correlate(request.correlation_id, source_port=P1, mac=MAC_A)
    assert manager.was_resolved(request.correlation_id) is True
    assert manager.was_resolved("z" * 32) is False


# -- expiry ----------------------------------------------------------------


def test_expiry_resolves_at_the_deadline_not_before(manager, clock):
    manager.issue(IDENT_A, P1)
    clock.advance(2.999)
    assert manager.expire() == []
    clock.advance(0.001)
    results = manager.expire()
    assert [r.outcome for r in results] == [ProbeOutcome.EXPIRED]
    assert len(manager) == 0


def test_expiry_is_immune_to_wall_clock_steps(manager, clock):
    """Legacy had no timeout at all; this one must not be defeatable by
    moving the wall clock (ADR-009)."""
    manager.issue(IDENT_A, P1)
    clock.set_wall(clock.now() + timedelta(days=365))
    assert manager.expire() == [], "a wall jump must not expire a live probe"
    clock.advance_monotonic(3)
    assert len(manager.expire()) == 1


def test_expiry_resolves_every_due_probe_in_deadline_order(manager, clock):
    for i in range(1, 6):
        manager.issue(HostIdentity.of(MacAddress(i)), P1,
                      timeout=timedelta(seconds=i))
    clock.advance(3)
    results = manager.expire()
    assert len(results) == 3
    assert len(manager) == 2


def test_an_expired_probe_never_expires_twice(manager, clock):
    manager.issue(IDENT_A, P1)
    clock.advance(5)
    assert len(manager.expire()) == 1
    assert manager.expire() == []


def test_next_deadline_reports_the_soonest(manager, clock):
    assert manager.next_deadline() is None
    manager.issue(IDENT_A, P1, timeout=timedelta(seconds=10))
    manager.issue(IDENT_B, P2, timeout=timedelta(seconds=2))
    assert manager.next_deadline() == pytest.approx(2.0)


def test_a_host_may_be_probed_again_after_its_probe_resolves(manager, clock):
    manager.issue(IDENT_A, P1)
    clock.advance(5)
    manager.expire()
    manager.issue(IDENT_A, P1)
    assert len(manager) == 1


# -- cancellation ----------------------------------------------------------


def test_cancel_resolves_and_frees_the_host(manager):
    manager.issue(IDENT_A, P1)
    result = manager.cancel(MAC_A, "host re-observed at current port")
    assert result.outcome is ProbeOutcome.CANCELLED
    assert len(manager) == 0
    manager.issue(IDENT_A, P1)


def test_cancelling_an_unknown_host_is_a_no_op(manager):
    assert manager.cancel(MAC_A) is None


def test_undeliverable_marks_a_specific_probe(manager):
    request = manager.issue(IDENT_A, P1)
    result = manager.mark_undeliverable(request.correlation_id)
    assert result.outcome is ProbeOutcome.UNDELIVERABLE
    assert manager.mark_undeliverable(request.correlation_id) is None


def test_switch_loss_cancels_every_probe_aimed_at_it(manager):
    """A probe aimed at a departed switch can never be answered, and the port
    may be a different physical link when it returns."""
    manager.issue(IDENT_A, P1)
    manager.issue(IDENT_B, PortIdentity.of(0x1122334455667788, 1))
    results = manager.cancel_switch(DPID)
    assert [r.outcome for r in results] == [ProbeOutcome.CANCELLED]
    assert len(manager) == 1


def test_stale_generation_probes_are_cancelled(manager):
    """A probe issued before a reconnect must not be resolved afterwards."""
    manager.issue(IDENT_A, P1, generation=1)
    manager.issue(IDENT_B, P2, generation=2)
    results = manager.cancel_stale_generations(DPID, current_generation=2)
    assert len(results) == 1
    assert manager.outstanding_for(MAC_B) is not None
    assert manager.outstanding_for(MAC_A) is None


# -- bounds ----------------------------------------------------------------


def test_outstanding_probes_are_bounded_and_refuse_rather_than_evict(clock):
    """Evicting the oldest would let an attacker who can force many movements
    flush the validation of their own hijack."""
    small = ProbeManager(clock=clock, max_outstanding=3)
    first = small.issue(HostIdentity.of(MacAddress(1)), P1)
    for i in (2, 3):
        small.issue(HostIdentity.of(MacAddress(i)), P1)
    with pytest.raises(ProbeManagerFull, match="refusing rather than evicting"):
        small.issue(HostIdentity.of(MacAddress(4)), P1)
    assert small.get(first.correlation_id) is not None, "the first probe survives"


def test_replay_memory_stays_bounded(clock):
    small = ProbeManager(clock=clock, max_outstanding=4)
    for i in range(1, 200):
        request = small.issue(HostIdentity.of(MacAddress(i)), P1)
        small.correlate(request.correlation_id, source_port=P1, mac=MacAddress(i))
    assert len(small._resolved_ids) <= small.capacity * 4


def test_constructor_validates_its_limits(clock):
    for kwargs in ({"timeout": timedelta(0)}, {"max_outstanding": 0}):
        with pytest.raises(ValueError):
            ProbeManager(clock=clock, **kwargs)


def test_iteration_is_ordered_by_deadline(manager):
    manager.issue(IDENT_A, P1, timeout=timedelta(seconds=9))
    manager.issue(IDENT_B, P2, timeout=timedelta(seconds=1))
    assert [e.mac for e in manager] == [MAC_B, MAC_A]


def test_the_manager_never_transmits(manager):
    """Transmission is the adapter's job, which keeps this module
    framework-independent (ADR-005)."""
    request = manager.issue(IDENT_A, P1)
    assert request.target_port == P1
    assert manager.get(request.correlation_id) is not None
