"""Policy engine (observe-only by default) and the structured evidence store."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from sdnguard.domain.events import (
    EnforcementAction,
    FindingKind,
    SecurityFinding,
    Severity,
    Verdict,
)
from sdnguard.domain.host import HostIdentity, MacAddress
from sdnguard.domain.identity import PortIdentity
from sdnguard.observability.evidence import EvidenceStore
from sdnguard.policy.engine import PolicyEngine, PolicyMode, PolicyRule

T0 = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
PORT = PortIdentity.of(0x0000AABBCCDDEEFF, 4)
MGMT_PORT = PortIdentity.of(0x0000AABBCCDDEEFF, 1)
IDENT = HostIdentity.of(MacAddress.parse("aa:bb:cc:dd:ee:01"))


def finding(kind=FindingKind.HOST_LOCATION_HIJACK, severity=Severity.HIGH,
            verdict=Verdict.SUSPICIOUS, port=PORT):
    return SecurityFinding.create(kind, verdict, severity, IDENT, port, T0,
                                  ("evidence",), "summary")


def enforcing() -> PolicyEngine:
    return PolicyEngine(mode=PolicyMode.ENFORCE, rules=PolicyEngine.default_rules())


# -- observe-only is the default ------------------------------------------


def test_the_default_mode_never_touches_the_network():
    decision = PolicyEngine().decide(finding(), T0)
    assert decision.action is EnforcementAction.OBSERVE
    assert not decision.is_enforcing
    assert decision.scope is None and decision.expires_at is None


@pytest.mark.parametrize("kind", list(FindingKind))
def test_observe_mode_produces_no_enforcement_for_any_finding(kind):
    decision = PolicyEngine().decide(finding(kind=kind), T0)
    assert not decision.is_enforcing


def test_alert_mode_reports_but_does_not_enforce():
    engine = PolicyEngine(mode=PolicyMode.ALERT, rules=PolicyEngine.default_rules())
    decision = engine.decide(finding(), T0)
    assert decision.action is EnforcementAction.ALERT
    assert not decision.is_enforcing


# -- enforcement requires everything to line up ---------------------------


def test_enforcement_requires_a_matching_rule():
    engine = PolicyEngine(mode=PolicyMode.ENFORCE, rules=())
    decision = engine.decide(finding(), T0)
    assert decision.action is EnforcementAction.ALERT
    assert "no enforcement rule matched" in decision.reason


def test_a_matching_rule_produces_a_scoped_expiring_reversible_decision():
    decision = enforcing().decide(finding(), T0)
    assert decision.action is EnforcementAction.QUARANTINE
    assert decision.is_enforcing
    assert decision.scope == PORT
    assert decision.expires_at == T0 + timedelta(minutes=5)
    assert decision.reversible


def test_severity_below_the_rule_threshold_does_not_enforce():
    decision = enforcing().decide(finding(severity=Severity.LOW), T0)
    assert not decision.is_enforcing


def test_an_inconclusive_verdict_never_enforces():
    """The system must not act on a finding it could not resolve."""
    decision = enforcing().decide(finding(verdict=Verdict.INCONCLUSIVE), T0)
    assert not decision.is_enforcing


@pytest.mark.parametrize(
    "kind", [k for k in FindingKind
             if k not in (FindingKind.HOST_LOCATION_HIJACK, FindingKind.LINK_FABRICATION)])
def test_default_rules_enforce_only_the_two_high_confidence_kinds(kind):
    assert not enforcing().decide(finding(kind=kind), T0).is_enforcing


# -- the emergency disable -------------------------------------------------


def test_the_kill_switch_stops_action_but_not_reporting():
    """The first thing an operator needs when a detector misfires at 3am is
    one switch that stops it touching the network."""
    engine = enforcing()
    engine.disable_enforcement("3am misfire")
    decision = engine.decide(finding(), T0)
    assert decision.action is EnforcementAction.ALERT
    assert not decision.is_enforcing
    assert "3am misfire" in decision.reason
    assert "would have applied quarantine" in decision.reason


def test_the_kill_switch_is_reversible():
    engine = enforcing()
    engine.disable_enforcement()
    assert engine.enforcement_disabled
    engine.enable_enforcement()
    assert not engine.enforcement_disabled
    assert enforcing().decide(finding(), T0).is_enforcing


# -- management-plane protection ------------------------------------------


def test_protected_ports_are_never_enforced_against():
    """Quarantining the operator's own path turns a false positive into a
    lockout with no way back in."""
    engine = enforcing()
    engine.protect(MGMT_PORT)
    decision = engine.decide(finding(port=MGMT_PORT), T0)
    assert not decision.is_enforcing
    assert "protected" in decision.reason
    assert engine.decide(finding(port=PORT), T0).is_enforcing


def test_protection_accumulates():
    engine = enforcing()
    engine.protect(MGMT_PORT)
    engine.protect(PORT)
    assert engine.is_protected(MGMT_PORT) and engine.is_protected(PORT)


# -- the engine always answers --------------------------------------------


def test_the_engine_never_raises_on_an_ordinary_finding():
    """A policy that throws on unexpected input stops producing evidence
    exactly when something unusual is happening."""
    engine = enforcing()
    for kind in FindingKind:
        for severity in Severity:
            for verdict in Verdict:
                decision = engine.decide(
                    finding(kind=kind, severity=severity, verdict=verdict), T0)
                assert decision.finding_id is not None


def test_decide_all_preserves_order():
    findings = [finding(kind=k) for k in FindingKind]
    decisions = PolicyEngine().decide_all(findings, T0)
    assert [d.finding_id for d in decisions] == [f.finding_id for f in findings]


def test_custom_rules_are_honoured():
    rule = PolicyRule(FindingKind.HOST_MULTI_LOCATION,
                      EnforcementAction.RATE_LIMIT, Severity.MEDIUM,
                      timedelta(minutes=1))
    engine = PolicyEngine(mode=PolicyMode.ENFORCE, rules=(rule,))
    decision = engine.decide(
        finding(kind=FindingKind.HOST_MULTI_LOCATION, severity=Severity.MEDIUM), T0)
    assert decision.action is EnforcementAction.RATE_LIMIT
    assert decision.expires_at == T0 + timedelta(minutes=1)


# -- evidence store --------------------------------------------------------


def test_findings_are_recorded_and_retrievable_by_id():
    store = EvidenceStore()
    f = finding()
    store.record(f)
    assert store.get(f.finding_id).finding == f
    assert len(store) == 1


def test_a_decision_can_be_attached_later():
    store = EvidenceStore()
    f = finding()
    store.record(f)
    decision = enforcing().decide(f, T0)
    record = store.attach_decision(f.finding_id, decision)
    assert record.decision.action is EnforcementAction.QUARANTINE
    assert store.get(f.finding_id).decision is not None


def test_attaching_to_an_unknown_finding_is_a_no_op():
    assert EvidenceStore().attach_decision("nope", enforcing().decide(finding(), T0)) is None


@pytest.mark.parametrize(
    "query,expected",
    [("by_kind", 1), ("by_verdict", 2), ("by_mac", 2), ("by_port", 2)],
)
def test_queries_filter_correctly(query, expected):
    store = EvidenceStore()
    store.record(finding(kind=FindingKind.HOST_LOCATION_HIJACK))
    store.record(finding(kind=FindingKind.LINK_FABRICATION))
    lookup = {
        "by_kind": lambda: store.by_kind(FindingKind.HOST_LOCATION_HIJACK),
        "by_verdict": lambda: store.by_verdict(Verdict.SUSPICIOUS),
        "by_mac": lambda: store.by_mac(IDENT.mac),
        "by_port": lambda: store.by_port(PORT),
    }
    assert len(lookup[query]()) == expected


def test_severity_query_is_inclusive_upward():
    store = EvidenceStore()
    for severity in Severity:
        store.record(finding(severity=severity))
    assert len(store.by_severity(Severity.INFO)) == 4
    assert len(store.by_severity(Severity.HIGH)) == 1


def test_time_range_query():
    store = EvidenceStore()
    store.record(finding())
    assert len(store.between(T0 - timedelta(seconds=1), T0 + timedelta(seconds=1))) == 1
    assert len(store.between(T0 + timedelta(hours=1), T0 + timedelta(hours=2))) == 0


def test_enforced_lists_only_actioned_records():
    store = EvidenceStore()
    f1, f2 = finding(), finding(severity=Severity.LOW)
    engine = enforcing()
    store.record(f1, engine.decide(f1, T0))
    store.record(f2, engine.decide(f2, T0))
    assert len(store.enforced()) == 1


def test_the_store_is_bounded_and_evicts_oldest():
    """Unlike the host table, an evidence ring may evict: losing the oldest
    finding does not let an attacker erase a live detection, and unbounded
    growth would be its own denial of service."""
    store = EvidenceStore(max_records=3)
    kept = [store.record(finding()) for _ in range(5)]
    assert len(store) == 3
    assert store.get(kept[0].finding.finding_id) is None
    assert store.get(kept[-1].finding.finding_id) is not None


def test_bundle_is_json_serialisable_and_self_describing():
    store = EvidenceStore()
    f = finding()
    store.record(f, enforcing().decide(f, T0))
    payload = json.loads(store.to_json(label="lab-run-1", extra={"topology": "t1"}))
    assert payload["schema"] == "sdnguard.evidence/1"
    assert payload["label"] == "lab-run-1"
    assert payload["record_count"] == 1
    assert payload["context"]["topology"] == "t1"
    assert payload["records"][0]["decision"]["enforcing"] is True


def test_the_bundle_contains_no_ground_truth():
    """Ground truth belongs to the harness. Keeping them apart is what makes
    a detection comparison meaningful rather than circular."""
    store = EvidenceStore()
    store.record(finding())
    text = store.to_json().lower()
    for forbidden in ("ground_truth", "expected", "is_attack", "label_true"):
        assert forbidden not in text


def test_counts_summarise_by_kind():
    store = EvidenceStore()
    store.record(finding(kind=FindingKind.HOST_LOCATION_HIJACK))
    store.record(finding(kind=FindingKind.HOST_LOCATION_HIJACK))
    store.record(finding(kind=FindingKind.LINK_FABRICATION))
    assert store.counts() == {"host_location_hijack": 2, "link_fabrication": 1}


def test_capacity_must_be_positive():
    with pytest.raises(ValueError):
        EvidenceStore(max_records=0)
