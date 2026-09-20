"""Movement, probe, finding and policy event types."""

from __future__ import annotations

import dataclasses
import json
import pickle
from datetime import datetime, timedelta, timezone

import pytest

from sdnguard.domain.events import (
    EnforcementAction,
    EnforcementDecision,
    FindingKind,
    MovementEvent,
    ProbeMethod,
    ProbeOutcome,
    ProbeRequest,
    ProbeResult,
    SecurityFinding,
    Severity,
    Verdict,
    new_correlation_id,
)
from sdnguard.domain.host import HostIdentity, HostLocation, IPAddress, MacAddress
from sdnguard.domain.identity import InvalidIdentity, PortIdentity

T0 = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
PORT_A = PortIdentity.of(0x0000AABBCCDDEEFF, 3)
PORT_B = PortIdentity.of(0x0000AABBCCDDEEFF, 4)
IDENT = HostIdentity.of(MacAddress.parse("aa:bb:cc:dd:ee:01"),
                        IPAddress.parse("10.0.0.1"))
LOC_A = HostLocation.at(PORT_A, T0)
LOC_B = HostLocation.at(PORT_B, T0 + timedelta(seconds=5))


# -- correlation ids -------------------------------------------------------


def test_correlation_ids_are_long_and_unique():
    ids = {new_correlation_id() for _ in range(5000)}
    assert len(ids) == 5000
    assert all(len(i) == 32 for i in ids)


def test_correlation_ids_are_not_sequential():
    """Predictable tokens would let an on-segment attacker forge a probe reply
    and manufacture a false hijack verdict."""
    a, b = new_correlation_id(), new_correlation_id()
    assert abs(int(a, 16) - int(b, 16)) > 2**64


# -- MovementEvent ---------------------------------------------------------


def test_movement_event_basics():
    ev = MovementEvent.of(IDENT, LOC_A, LOC_B, T0 + timedelta(seconds=5))
    assert ev.elapsed_seconds == 5
    assert ev.port_down_seen is False
    assert ev.is_multi_location is False
    assert "->" in str(ev)


def test_same_port_is_not_movement():
    with pytest.raises(InvalidIdentity, match="two different ports"):
        MovementEvent.of(IDENT, LOC_A, HostLocation.at(PORT_A, T0), T0)


def test_multi_location_is_a_signal_not_a_skip():
    """Legacy ignored hosts with more than one prior attachment point, which
    silently exempted the most suspicious case."""
    ev = MovementEvent.of(IDENT, LOC_A, LOC_B, T0, concurrent_locations=3)
    assert ev.is_multi_location


@pytest.mark.parametrize("bad", [0, -1, "two", None])
def test_concurrent_locations_must_be_positive(bad):
    with pytest.raises(InvalidIdentity):
        MovementEvent.of(IDENT, LOC_A, LOC_B, T0, concurrent_locations=bad)


def test_movement_rejects_naive_time_and_bad_types():
    with pytest.raises(InvalidIdentity):
        MovementEvent.of(IDENT, LOC_A, LOC_B, datetime(2026, 9, 20))
    with pytest.raises(InvalidIdentity):
        MovementEvent.of("host", LOC_A, LOC_B, T0)


# -- ProbeRequest ----------------------------------------------------------


def test_probe_has_a_nonce_and_a_future_deadline():
    p = ProbeRequest.create(IDENT, PORT_A, T0, timedelta(seconds=3))
    assert len(p.correlation_id) == 32
    assert p.deadline == T0 + timedelta(seconds=3)
    assert p.method is ProbeMethod.ARP, "ARP is the default (ADR-006)"


def test_two_probes_never_share_a_nonce():
    ids = {ProbeRequest.create(IDENT, PORT_A, T0, timedelta(seconds=1)).correlation_id
           for _ in range(1000)}
    assert len(ids) == 1000


def test_probe_without_a_future_deadline_is_rejected():
    """The legacy prober had no timeout at all, so probe state leaked forever
    and 'no reply' was never resolved."""
    with pytest.raises(InvalidIdentity, match="deadline must be after"):
        ProbeRequest(new_correlation_id(), IDENT, PORT_A, ProbeMethod.ARP, T0, T0)
    with pytest.raises(InvalidIdentity, match="timeout must be positive"):
        ProbeRequest.create(IDENT, PORT_A, T0, timedelta(0))


def test_probe_rejects_a_guessable_correlation_id():
    with pytest.raises(InvalidIdentity, match="unguessable"):
        ProbeRequest("1", IDENT, PORT_A, ProbeMethod.ARP, T0, T0 + timedelta(seconds=1))


def test_probe_expiry_is_evaluated_against_an_explicit_moment():
    p = ProbeRequest.create(IDENT, PORT_A, T0, timedelta(seconds=3))
    assert not p.is_expired_at(T0 + timedelta(seconds=2, microseconds=999999))
    assert p.is_expired_at(T0 + timedelta(seconds=3))
    assert p.is_expired_at(T0 + timedelta(seconds=99))


@pytest.mark.parametrize("method", list(ProbeMethod))
def test_both_probe_methods_are_constructible(method):
    assert ProbeRequest.create(IDENT, PORT_A, T0, timedelta(seconds=1), method).method is method


# -- ProbeResult -----------------------------------------------------------


@pytest.mark.parametrize("outcome", list(ProbeOutcome))
def test_every_outcome_is_representable(outcome):
    r = ProbeResult.of("c" * 32, outcome, T0)
    assert r.outcome is outcome
    assert r.host_was_still_present is (outcome is ProbeOutcome.REPLIED)


def test_expired_probe_does_not_mean_the_host_was_absent():
    """Absence of a reply is equally consistent with packet loss."""
    assert not ProbeResult.of("c" * 32, ProbeOutcome.EXPIRED, T0).host_was_still_present


# -- SecurityFinding -------------------------------------------------------


def _finding(**kw):
    base = dict(kind=FindingKind.HOST_LOCATION_HIJACK, verdict=Verdict.SUSPICIOUS,
                severity=Severity.HIGH, identity=IDENT, port=PORT_B,
                detected_at=T0, evidence=["probe replied at old location"],
                summary="host answered at its previous port after moving")
    base.update(kw)
    return SecurityFinding.create(**base)


def test_finding_is_machine_readable():
    """Legacy output was logger.warn only, so nothing downstream could act."""
    f = _finding()
    d = f.to_dict()
    assert json.loads(json.dumps(d)) == d
    assert d["kind"] == "host_location_hijack"
    assert d["verdict"] == "suspicious"
    assert d["mac"] == "aa:bb:cc:dd:ee:01"
    assert d["port"] == "00:00:aa:bb:cc:dd:ee:ff/4"
    assert d["evidence"] == ["probe replied at old location"]


def test_a_finding_must_cite_evidence():
    with pytest.raises(InvalidIdentity, match="at least one piece of evidence"):
        _finding(evidence=[])


@pytest.mark.parametrize("verdict", list(Verdict))
def test_all_three_verdicts_exist_including_inconclusive(verdict):
    assert _finding(verdict=verdict).verdict is verdict


@pytest.mark.parametrize("kind", list(FindingKind))
def test_every_finding_kind_is_constructible(kind):
    assert _finding(kind=kind).kind is kind


def test_finding_ids_are_unique():
    assert len({_finding().finding_id for _ in range(500)}) == 500


@pytest.mark.parametrize("bad", [{"kind": "hijack"}, {"verdict": "bad"},
                                 {"severity": 3}, {"summary": ""}])
def test_finding_rejects_untyped_fields(bad):
    with pytest.raises(InvalidIdentity):
        _finding(**bad)


# -- EnforcementDecision ---------------------------------------------------


def test_observe_is_the_default_and_needs_no_scope():
    d = EnforcementDecision.observe("f" * 32, T0)
    assert d.action is EnforcementAction.OBSERVE
    assert not d.is_enforcing
    assert d.scope is None and d.expires_at is None


def test_alert_does_not_count_as_enforcement():
    d = EnforcementDecision.create("f" * 32, EnforcementAction.ALERT, T0, "notify")
    assert not d.is_enforcing


@pytest.mark.parametrize("action", [EnforcementAction.DROP,
                                    EnforcementAction.QUARANTINE,
                                    EnforcementAction.RATE_LIMIT])
def test_enforcement_requires_scope_expiry_and_reversibility(action):
    """An unscoped, non-expiring action turns a false positive into a
    permanent outage -- a security tool that causes outages is itself a
    security problem."""
    with pytest.raises(InvalidIdentity, match="scope"):
        EnforcementDecision.create("f" * 32, action, T0, "r", ttl=timedelta(minutes=5))
    with pytest.raises(InvalidIdentity, match="expiry"):
        EnforcementDecision.create("f" * 32, action, T0, "r", scope=PORT_B)
    with pytest.raises(InvalidIdentity, match="reversible"):
        EnforcementDecision.create("f" * 32, action, T0, "r", scope=PORT_B,
                                   ttl=timedelta(minutes=5), reversible=False)


def test_valid_enforcement_expires():
    d = EnforcementDecision.create("f" * 32, EnforcementAction.QUARANTINE, T0,
                                   "confirmed hijack", scope=PORT_B,
                                   ttl=timedelta(minutes=5))
    assert d.is_enforcing
    assert not d.is_expired_at(T0 + timedelta(minutes=4))
    assert d.is_expired_at(T0 + timedelta(minutes=5))


def test_expiry_must_be_after_the_decision():
    with pytest.raises(InvalidIdentity, match="after decided_at"):
        EnforcementDecision.create("f" * 32, EnforcementAction.DROP, T0, "r",
                                   scope=PORT_B, ttl=timedelta(seconds=-1))


# -- immutability and serialisation ---------------------------------------


@pytest.mark.parametrize(
    "obj",
    [
        MovementEvent.of(IDENT, LOC_A, LOC_B, T0),
        ProbeRequest.create(IDENT, PORT_A, T0, timedelta(seconds=1)),
        ProbeResult.of("c" * 32, ProbeOutcome.EXPIRED, T0),
        _finding(),
        EnforcementDecision.observe("f" * 32, T0),
    ],
)
def test_events_are_frozen_and_pickle(obj):
    with pytest.raises(dataclasses.FrozenInstanceError):
        obj.injected = "x"
    assert pickle.loads(pickle.dumps(obj)) == obj
