"""Benign versus adversarial movement scenarios (P4-MOVE-02).

Each scenario is written as a sequence of events with an explicit expected
outcome, so the difference between "a laptop moved desk" and "an attacker is
impersonating a host" is stated in one place and can be argued about.

Every known Java failure case from KNOWN_FAILURES.md that is expressible at
this layer appears here as a named scenario.
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
BIG_DPID = DatapathId(0xFFFFFFFFFFFFFFFF)
VICTIM_PORT = PortIdentity.of(DPID.value, 1)
ATTACKER_PORT = PortIdentity.of(DPID.value, 4)
NEW_DESK_PORT = PortIdentity.of(DPID.value, 7)
VICTIM = HostIdentity.of(MacAddress.parse("aa:bb:cc:dd:ee:01"))
MAC = VICTIM.mac


def at(port, seconds):
    return HostLocation.at(port, T0 + timedelta(seconds=seconds))


def validate(machine, target_port, *, outcome, seconds=2):
    """Issue the probe the machine asked for and deliver its resolution."""
    probe = ProbeRequest.create(VICTIM, target_port, T0 + timedelta(seconds=seconds),
                                timedelta(seconds=3))
    machine.on_probe_issued(MAC, probe)
    return machine.on_probe_result(
        MAC, ProbeResult.of(probe.correlation_id, outcome,
                            T0 + timedelta(seconds=seconds + 3)))


# -- benign scenarios ------------------------------------------------------


def test_benign_user_unplugs_and_moves_desk():
    """Port goes down first, host does not answer at the old port. This is
    the textbook legitimate migration and must produce no hijack finding."""
    m = MovementStateMachine()
    m.on_observation(VICTIM, at(VICTIM_PORT, 0))
    m.on_port_down(MAC, VICTIM_PORT)
    m.on_observation(VICTIM, at(NEW_DESK_PORT, 30))
    state, actions = validate(m, VICTIM_PORT, outcome=ProbeOutcome.EXPIRED, seconds=30)

    assert state.state is MovementState.MOVE_ACCEPTED
    assert [a.kind for a in actions] == [ActionKind.ACCEPT_LOCATION]
    assert not any(a.detail.startswith("host_location_hijack") for a in actions)


def test_benign_host_stays_put_and_keeps_talking():
    m = MovementStateMachine()
    for i in range(10):
        state, actions = m.on_observation(VICTIM, at(VICTIM_PORT, i))
    assert state.state is MovementState.LEARNED
    assert len(m.outstanding_probes()) == 0


def test_benign_wifi_roam_with_no_port_down_is_accepted_but_reported():
    """A wireless roam often produces no port-down. The move is accepted --
    the host genuinely left -- but the missing pre-condition is still
    reported, because it is a real anomaly the operator may care about."""
    m = MovementStateMachine()
    m.on_observation(VICTIM, at(VICTIM_PORT, 0))
    m.on_observation(VICTIM, at(NEW_DESK_PORT, 5))
    state, actions = validate(m, VICTIM_PORT, outcome=ProbeOutcome.EXPIRED, seconds=5)

    assert state.state is MovementState.MOVE_ACCEPTED
    details = [a.detail for a in actions]
    assert "host_moved_without_port_down" in details
    assert "host_location_hijack" not in details


def test_benign_flap_back_to_the_original_port_cancels_validation():
    m = MovementStateMachine()
    m.on_observation(VICTIM, at(VICTIM_PORT, 0))
    m.on_observation(VICTIM, at(NEW_DESK_PORT, 1))
    probe = ProbeRequest.create(VICTIM, VICTIM_PORT, T0, timedelta(seconds=3))
    m.on_probe_issued(MAC, probe)
    state, actions = m.on_observation(VICTIM, at(NEW_DESK_PORT, 2))
    assert state.state is MovementState.LEARNED
    assert [a.kind for a in actions] == [ActionKind.CANCEL_PROBE]


# -- adversarial scenarios -------------------------------------------------


def test_attack_host_location_hijack_is_detected():
    """h4 spoofs h1's MAC while h1 is still connected and answering. This is
    the attack the whole project exists to detect."""
    m = MovementStateMachine()
    m.on_observation(VICTIM, at(VICTIM_PORT, 0))
    m.on_observation(VICTIM, at(ATTACKER_PORT, 10))     # attacker appears
    state, actions = validate(m, VICTIM_PORT, outcome=ProbeOutcome.REPLIED, seconds=10)

    assert state.state is MovementState.SUSPICIOUS_MOVE
    assert [a.kind for a in actions] == [ActionKind.EMIT_FINDING]
    assert actions[0].detail == "host_location_hijack"
    assert any("replied at its previous location" in e for e in state.evidence)


def test_attack_is_still_detected_when_the_attacker_forges_a_port_down():
    """Port-down is attacker-influenceable, so satisfying the pre-condition
    must not suppress the post-condition test. This is precisely why two
    independent conditions exist."""
    m = MovementStateMachine()
    m.on_observation(VICTIM, at(VICTIM_PORT, 0))
    m.on_port_down(MAC, VICTIM_PORT)                     # forged or coincidental
    m.on_observation(VICTIM, at(ATTACKER_PORT, 10))
    state, actions = validate(m, VICTIM_PORT, outcome=ProbeOutcome.REPLIED, seconds=10)

    assert state.state is MovementState.SUSPICIOUS_MOVE
    assert actions[0].detail == "host_location_hijack"


def test_attack_rapid_flapping_does_not_spawn_unbounded_probes():
    """State exhaustion via repeated movement. Invariant: at most one
    outstanding probe per host, regardless of event rate."""
    m = MovementStateMachine()
    m.on_observation(VICTIM, at(VICTIM_PORT, 0))
    m.on_observation(VICTIM, at(ATTACKER_PORT, 1))
    probe = ProbeRequest.create(VICTIM, VICTIM_PORT, T0, timedelta(seconds=30))
    m.on_probe_issued(MAC, probe)
    for i in range(2, 200):
        port = PortIdentity.of(DPID.value, (i % 8) + 1)
        m.on_observation(VICTIM, at(port, i))
    assert len(m.outstanding_probes()) == 1
    assert m.state_of(MAC) is MovementState.VALIDATING


def test_attack_forged_probe_reply_with_a_guessed_id_is_rejected():
    """Correlation ids are unguessable precisely so this fails."""
    m = MovementStateMachine()
    m.on_observation(VICTIM, at(VICTIM_PORT, 0))
    m.on_observation(VICTIM, at(ATTACKER_PORT, 1))
    probe = ProbeRequest.create(VICTIM, VICTIM_PORT, T0, timedelta(seconds=3))
    m.on_probe_issued(MAC, probe)
    for forged in ("0" * 32, "f" * 32, new_correlation_id()):
        with pytest.raises(IllegalTransition, match="does not match"):
            m.on_probe_result(MAC, ProbeResult.of(forged, ProbeOutcome.EXPIRED, T0))
    assert m.state_of(MAC) is MovementState.VALIDATING


def test_attack_replayed_reply_cannot_resolve_a_second_validation():
    """A captured reply from an earlier validation must not satisfy a later
    one -- a single-use nonce is what prevents it."""
    m = MovementStateMachine()
    m.on_observation(VICTIM, at(VICTIM_PORT, 0))
    m.on_observation(VICTIM, at(ATTACKER_PORT, 1))
    first = ProbeRequest.create(VICTIM, VICTIM_PORT, T0, timedelta(seconds=3))
    m.on_probe_issued(MAC, first)
    captured = ProbeResult.of(first.correlation_id, ProbeOutcome.EXPIRED, T0)
    m.on_probe_result(MAC, captured)

    m.on_observation(VICTIM, at(ATTACKER_PORT, 60))
    m.on_observation(VICTIM, at(NEW_DESK_PORT, 61))
    second = ProbeRequest.create(VICTIM, ATTACKER_PORT, T0, timedelta(seconds=3))
    m.on_probe_issued(MAC, second)
    with pytest.raises(IllegalTransition, match="does not match"):
        m.on_probe_result(MAC, captured)


def test_inconclusive_when_the_probe_cannot_be_delivered():
    """Neither accused nor cleared. The legacy design had no way to express
    this and would have silently accepted the move."""
    m = MovementStateMachine()
    m.on_observation(VICTIM, at(VICTIM_PORT, 0))
    m.on_observation(VICTIM, at(ATTACKER_PORT, 1))
    state, actions = validate(m, VICTIM_PORT, outcome=ProbeOutcome.UNDELIVERABLE)
    assert state.state is MovementState.INCONCLUSIVE
    assert actions[0].detail == "probe_unresolved"


# -- legacy failure cases expressed as scenarios ---------------------------


def test_kf07_full_64_bit_datapath_ids_behave_identically():
    """The legacy reference-equality defect was invisible with DPIDs 1-3."""
    for dpid in (DatapathId(1), DatapathId(127), DatapathId(128), BIG_DPID):
        m = MovementStateMachine()
        old = PortIdentity.of(dpid.value, 1)
        new = PortIdentity.of(dpid.value, 2)
        m.on_observation(VICTIM, HostLocation.at(old, T0))
        state, actions = m.on_observation(VICTIM, HostLocation.at(new, T0 + timedelta(seconds=1)))
        assert state.state is MovementState.MOVE_OBSERVED, f"failed for dpid {dpid}"
        assert actions[0].port == old, "probe must target the old port"


def test_kf12_switch_loss_does_not_leave_orphaned_validation_state():
    m = MovementStateMachine()
    m.on_observation(VICTIM, at(VICTIM_PORT, 0))
    m.on_observation(VICTIM, at(ATTACKER_PORT, 1))
    probe = ProbeRequest.create(VICTIM, VICTIM_PORT, T0, timedelta(seconds=30))
    m.on_probe_issued(MAC, probe)
    assert len(m.outstanding_probes()) == 1
    m.on_switch_lost(DPID)
    assert len(m.outstanding_probes()) == 0
    assert len(m) == 0


def test_legacy_multi_ap_hosts_are_not_skipped():
    """Legacy acted only when getOldAP().length == 1, silently exempting the
    most suspicious case."""
    m = MovementStateMachine()
    m.on_observation(VICTIM, at(VICTIM_PORT, 0))
    m.on_observation(VICTIM, at(ATTACKER_PORT, 1))
    event = m.to_event(MAC, T0 + timedelta(seconds=1), concurrent_locations=3)
    assert event.is_multi_location
    assert m.state_of(MAC) is MovementState.MOVE_OBSERVED


@pytest.mark.parametrize(
    "scenario,outcome,port_down,expected",
    [
        ("legitimate move", ProbeOutcome.EXPIRED, True, MovementState.MOVE_ACCEPTED),
        ("roam, no port-down", ProbeOutcome.EXPIRED, False, MovementState.MOVE_ACCEPTED),
        ("hijack", ProbeOutcome.REPLIED, False, MovementState.SUSPICIOUS_MOVE),
        ("hijack despite port-down", ProbeOutcome.REPLIED, True, MovementState.SUSPICIOUS_MOVE),
        ("probe undeliverable", ProbeOutcome.UNDELIVERABLE, True, MovementState.INCONCLUSIVE),
        ("probe cancelled", ProbeOutcome.CANCELLED, False, MovementState.INCONCLUSIVE),
    ],
)
def test_decision_table(scenario, outcome, port_down, expected):
    """The complete benign/adversarial decision table in one place."""
    m = MovementStateMachine()
    m.on_observation(VICTIM, at(VICTIM_PORT, 0))
    if port_down:
        m.on_port_down(MAC, VICTIM_PORT)
    m.on_observation(VICTIM, at(ATTACKER_PORT, 5))
    state, _ = validate(m, VICTIM_PORT, outcome=outcome, seconds=5)
    assert state.state is expected, scenario
