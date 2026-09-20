"""Movement state machine: complete transition matrix.

The machine is pure -- events in, (state, actions) out -- so every case here
runs with no network, no clock and no OVS.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sdnguard.domain.events import (
    ProbeOutcome,
    ProbeRequest,
    ProbeResult,
    new_correlation_id,
)
from sdnguard.domain.host import HostIdentity, HostLocation, MacAddress
from sdnguard.domain.identity import DatapathId, PortIdentity
from sdnguard.hosts.movement import (
    ActionKind,
    IllegalTransition,
    MovementState,
    MovementStateMachine,
)

T0 = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
DPID = DatapathId(0x0000AABBCCDDEEFF)
P1 = PortIdentity.of(DPID.value, 1)
P2 = PortIdentity.of(DPID.value, 2)
P3 = PortIdentity.of(DPID.value, 3)
OTHER = PortIdentity.of(0x1122334455667788, 1)
MAC = MacAddress.parse("aa:bb:cc:dd:ee:01")
IDENT = HostIdentity.of(MAC)


@pytest.fixture
def machine() -> MovementStateMachine:
    return MovementStateMachine()


def loc(port, offset=0):
    return HostLocation.at(port, T0 + timedelta(seconds=offset))


def kinds(actions):
    return [a.kind for a in actions]


def drive_to_validating(machine, *, port_down=False):
    machine.on_observation(IDENT, loc(P1))
    if port_down:
        machine.on_port_down(MAC, P1)
    machine.on_observation(IDENT, loc(P2, 1))
    probe = ProbeRequest.create(IDENT, P1, T0, timedelta(seconds=3))
    machine.on_probe_issued(MAC, probe)
    return probe


# -- the happy paths -------------------------------------------------------


def test_unknown_to_learned(machine):
    assert machine.state_of(MAC) is MovementState.UNKNOWN
    state, actions = machine.on_observation(IDENT, loc(P1))
    assert state.state is MovementState.LEARNED
    assert kinds(actions) == [ActionKind.ACCEPT_LOCATION]


def test_learned_to_move_observed_issues_a_probe_at_the_old_port(machine):
    machine.on_observation(IDENT, loc(P1))
    state, actions = machine.on_observation(IDENT, loc(P2, 1))
    assert state.state is MovementState.MOVE_OBSERVED
    assert kinds(actions) == [ActionKind.ISSUE_PROBE]
    assert actions[0].port == P1, "the probe targets the OLD location"
    assert state.pending_from.port == P1 and state.current.port == P2


def test_move_observed_to_validating(machine):
    probe = drive_to_validating(machine)
    state = machine.get(MAC)
    assert state.state is MovementState.VALIDATING
    assert state.probe_id == probe.correlation_id
    assert state.has_outstanding_probe


def test_reply_from_the_old_location_is_suspicious(machine):
    probe = drive_to_validating(machine)
    state, actions = machine.on_probe_result(
        MAC, ProbeResult.of(probe.correlation_id, ProbeOutcome.REPLIED, T0))
    assert state.state is MovementState.SUSPICIOUS_MOVE
    assert kinds(actions) == [ActionKind.EMIT_FINDING]
    assert actions[0].detail == "host_location_hijack"
    assert not state.has_outstanding_probe


def test_expiry_accepts_the_move_but_records_it_as_weak(machine):
    """Absence of a reply is equally consistent with packet loss. The legacy
    design's willingness to treat silence as proof is the reasoning error
    this machine refuses to repeat."""
    probe = drive_to_validating(machine, port_down=True)
    state, actions = machine.on_probe_result(
        MAC, ProbeResult.of(probe.correlation_id, ProbeOutcome.EXPIRED, T0))
    assert state.state is MovementState.MOVE_ACCEPTED
    assert kinds(actions) == [ActionKind.ACCEPT_LOCATION]
    assert any("weak evidence" in e for e in state.evidence)


def test_expiry_without_port_down_also_emits_a_finding(machine):
    """The pre-condition failed even though the post-condition passed: the
    move is accepted, and the anomaly is still reported."""
    probe = drive_to_validating(machine, port_down=False)
    state, actions = machine.on_probe_result(
        MAC, ProbeResult.of(probe.correlation_id, ProbeOutcome.EXPIRED, T0))
    assert state.state is MovementState.MOVE_ACCEPTED
    assert kinds(actions) == [ActionKind.ACCEPT_LOCATION, ActionKind.EMIT_FINDING]
    assert actions[1].detail == "host_moved_without_port_down"


@pytest.mark.parametrize("outcome", [ProbeOutcome.UNDELIVERABLE, ProbeOutcome.CANCELLED])
def test_undeliverable_or_cancelled_is_inconclusive(machine, outcome):
    """The system is never forced to choose between attack and benign."""
    probe = drive_to_validating(machine)
    state, actions = machine.on_probe_result(
        MAC, ProbeResult.of(probe.correlation_id, outcome, T0))
    assert state.state is MovementState.INCONCLUSIVE
    assert kinds(actions) == [ActionKind.EMIT_FINDING]
    assert actions[0].detail == "probe_unresolved"


# -- pre-condition evidence ------------------------------------------------


def test_port_down_is_recorded_only_for_the_current_port(machine):
    machine.on_observation(IDENT, loc(P1))
    machine.on_port_down(MAC, P3)
    assert machine.get(MAC).port_down_seen is False
    machine.on_port_down(MAC, P1)
    assert machine.get(MAC).port_down_seen is True


def test_port_down_for_an_untracked_host_is_ignored(machine):
    """Recording it would let an attacker pre-seed the pre-condition for a
    MAC before ever presenting it."""
    assert machine.on_port_down(MAC, P1) is None
    assert len(machine) == 0


def test_move_without_port_down_is_recorded_as_evidence(machine):
    machine.on_observation(IDENT, loc(P1))
    state, _ = machine.on_observation(IDENT, loc(P2, 1))
    assert any("no port-down" in e for e in state.evidence)


# -- re-observation and repeated movement ---------------------------------


def test_re_observation_at_the_current_port_clears_a_pending_probe(machine):
    probe = drive_to_validating(machine)
    state, actions = machine.on_observation(IDENT, loc(P2, 5))
    assert state.state is MovementState.LEARNED
    assert kinds(actions) == [ActionKind.CANCEL_PROBE]
    assert actions[0].detail == probe.correlation_id
    assert not state.has_outstanding_probe


def test_further_movement_while_validating_does_not_start_a_second_probe(machine):
    """Invariant: exactly one outstanding probe per host."""
    drive_to_validating(machine)
    state, actions = machine.on_observation(IDENT, loc(P3, 5))
    assert state.state is MovementState.VALIDATING
    assert actions == []
    assert len(machine.outstanding_probes()) == 1
    assert any("further movement" in e for e in state.evidence)


def test_repeated_moves_after_resolution_start_a_fresh_validation(machine):
    probe = drive_to_validating(machine)
    machine.on_probe_result(MAC, ProbeResult.of(probe.correlation_id,
                                                ProbeOutcome.EXPIRED, T0))
    state, actions = machine.on_observation(IDENT, loc(P3, 10))
    assert state.state is MovementState.MOVE_OBSERVED
    assert kinds(actions) == [ActionKind.ISSUE_PROBE]


# -- illegal transitions ---------------------------------------------------


def test_probe_result_without_a_pending_probe_is_illegal(machine):
    """A silently dropped event is how the legacy unreachable branches went
    unnoticed."""
    machine.on_observation(IDENT, loc(P1))
    with pytest.raises(IllegalTransition, match="only VALIDATING"):
        machine.on_probe_result(MAC, ProbeResult.of("c" * 32, ProbeOutcome.REPLIED, T0))


def test_probe_issued_outside_move_observed_is_illegal(machine):
    machine.on_observation(IDENT, loc(P1))
    probe = ProbeRequest.create(IDENT, P1, T0, timedelta(seconds=1))
    with pytest.raises(IllegalTransition, match="only MOVE_OBSERVED"):
        machine.on_probe_issued(MAC, probe)


def test_a_mismatched_correlation_id_is_rejected(machine):
    """A forged or stale reply must not resolve a live probe."""
    drive_to_validating(machine)
    with pytest.raises(IllegalTransition, match="does not match"):
        machine.on_probe_result(
            MAC, ProbeResult.of(new_correlation_id(), ProbeOutcome.REPLIED, T0))
    assert machine.state_of(MAC) is MovementState.VALIDATING


def test_a_duplicate_reply_cannot_resolve_twice(machine):
    """Invariant: a probe resolves exactly once."""
    probe = drive_to_validating(machine)
    result = ProbeResult.of(probe.correlation_id, ProbeOutcome.REPLIED, T0)
    machine.on_probe_result(MAC, result)
    with pytest.raises(IllegalTransition):
        machine.on_probe_result(MAC, result)


def test_events_for_an_unknown_host_are_illegal(machine):
    with pytest.raises(IllegalTransition, match="no movement state"):
        machine.on_probe_result(MAC, ProbeResult.of("c" * 32, ProbeOutcome.EXPIRED, T0))


# -- switch loss -----------------------------------------------------------


def test_switch_loss_invalidates_hosts_anchored_to_it(machine):
    machine.on_observation(IDENT, loc(P1))
    other_ident = HostIdentity.of(MacAddress.parse("aa:bb:cc:dd:ee:02"))
    machine.on_observation(other_ident, HostLocation.at(OTHER, T0))
    assert machine.on_switch_lost(DPID) == [MAC]
    assert machine.state_of(MAC) is MovementState.UNKNOWN
    assert machine.state_of(other_ident.mac) is MovementState.LEARNED


def test_switch_loss_invalidates_a_pending_old_location(machine):
    """The probe target lives on the departed switch, so validation can never
    complete and the state must not linger."""
    drive_to_validating(machine)
    assert machine.on_switch_lost(DPID) == [MAC]
    assert len(machine.outstanding_probes()) == 0


def test_switch_loss_for_an_unrelated_switch_changes_nothing(machine):
    machine.on_observation(IDENT, loc(P1))
    assert machine.on_switch_lost(DatapathId(999)) == []
    assert machine.state_of(MAC) is MovementState.LEARNED


# -- bounds and purity -----------------------------------------------------


def test_host_count_is_bounded():
    small = MovementStateMachine(max_hosts=2)
    for i in (1, 2):
        small.on_observation(HostIdentity.of(MacAddress(i)), loc(P1))
    with pytest.raises(IllegalTransition, match="limit 2"):
        small.on_observation(HostIdentity.of(MacAddress(3)), loc(P1))


def test_state_values_are_immutable(machine):
    state, _ = machine.on_observation(IDENT, loc(P1))
    import dataclasses

    with pytest.raises(dataclasses.FrozenInstanceError):
        state.state = MovementState.SUSPICIOUS_MOVE


def test_the_machine_performs_no_io(machine):
    """Every action is returned for the caller to perform, never done here."""
    machine.on_observation(IDENT, loc(P1))
    _, actions = machine.on_observation(IDENT, loc(P2, 1))
    assert all(isinstance(a.kind, ActionKind) for a in actions)
    assert machine.get(MAC).probe_id is None, "the machine does not issue probes itself"


def test_to_event_builds_the_domain_movement_event(machine):
    machine.on_observation(IDENT, loc(P1))
    machine.on_observation(IDENT, loc(P2, 1))
    event = machine.to_event(MAC, T0 + timedelta(seconds=1), concurrent_locations=2)
    assert event.previous.port == P1 and event.current.port == P2
    assert event.is_multi_location
    assert event.port_down_seen is False


# -- the full transition matrix -------------------------------------------


def test_every_state_is_reachable(machine):
    reached = {MovementState.UNKNOWN}
    m = MovementStateMachine()
    m.on_observation(IDENT, loc(P1)); reached.add(m.state_of(MAC))
    m.on_observation(IDENT, loc(P2, 1)); reached.add(m.state_of(MAC))
    probe = ProbeRequest.create(IDENT, P1, T0, timedelta(seconds=3))
    m.on_probe_issued(MAC, probe); reached.add(m.state_of(MAC))
    m.on_probe_result(MAC, ProbeResult.of(probe.correlation_id,
                                          ProbeOutcome.REPLIED, T0))
    reached.add(m.state_of(MAC))
    for outcome, expected in ((ProbeOutcome.EXPIRED, MovementState.MOVE_ACCEPTED),
                              (ProbeOutcome.CANCELLED, MovementState.INCONCLUSIVE)):
        fresh = MovementStateMachine()
        p = drive_to_validating(fresh)
        fresh.on_probe_result(MAC, ProbeResult.of(p.correlation_id, outcome, T0))
        assert fresh.state_of(MAC) is expected
        reached.add(expected)
    assert reached == set(MovementState), f"unreachable: {set(MovementState) - reached}"


def test_validating_always_leaves_on_some_resolution(machine):
    """Invariant: a probe resolves exactly once -- reply or deadline, never
    both, and never neither."""
    for outcome in ProbeOutcome:
        m = MovementStateMachine()
        probe = drive_to_validating(m)
        state, _ = m.on_probe_result(
            MAC, ProbeResult.of(probe.correlation_id, outcome, T0))
        assert state.is_resolved
        assert not state.has_outstanding_probe
