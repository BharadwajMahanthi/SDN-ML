"""Cross-domain fixtures: the evidence model must serve SDN, host and AI.

The AI fixture is explicitly synthetic. No AI gateway exists, and building a
finding shape is not a claim that one does.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from annulon.evidence import (
    Evidence,
    EvidenceGraph,
    EvidenceKind,
    MissingEvidence,
    MissingReason,
    Stance,
)
from annulon.finding import (
    Assessment,
    AssessmentOutcome,
    CollectionHealth,
    Confidence,
    ConfidenceBasis,
    Finding,
    FindingState,
    Severity,
    summarize_evidence,
)
from annulon.identity import EntityKind, EntityRef
from sdnguard.domain.host import HostIdentity, MacAddress
from sdnguard.domain.identity import PortIdentity
from sdnguard.v2.mapping import host_location_finding

T0 = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
IDENT = HostIdentity.of(MacAddress.parse("02:00:00:00:00:01"))
OLD, NEW = PortIdentity.of(0x0000AABBCCDDEEFF, 1), PortIdentity.of(0x0000AABBCCDDEEFF, 4)


def sdn_finding(**kw):
    base = dict(finding_id="FN-SDN-0001", identity=IDENT, previous_port=OLD,
                current_port=NEW, move_event_id="evt-move",
                probe_event_id="evt-probe", probe_replied=True,
                port_down_seen=False, port_status_available=True,
                detected_at=T0, network="lab")
    base.update(kw)
    return host_location_finding(**base)


# -- SDN vertical ----------------------------------------------------------


def test_a_probe_reply_supports_the_hijack_hypothesis():
    f, graph = sdn_finding(probe_replied=True)
    assert f.current.outcome is AssessmentOutcome.SUPPORTED
    assert f.current.confidence is Confidence.STRONG
    assert f.current.basis is ConfidenceBasis.DIRECT_OBSERVATION
    assert f.state is FindingState.CORROBORATED


def test_an_unanswered_probe_is_missing_evidence_not_departure():
    """The single most important mapping decision: silence is recorded as
    absence, so no downstream rule can read it as the host having left."""
    f, _ = sdn_finding(probe_replied=False)
    assert f.summarize().supporting >= 1
    assert any("liveness reply" in m.expected for m in f.missing)
    assert f.current.outcome is AssessmentOutcome.INCONCLUSIVE
    assert not any("departed" in e.summary or "gone" in e.summary
                   for e in f.evidence)


def test_a_port_down_is_recorded_as_contradictory_not_omitted():
    f, _ = sdn_finding(probe_replied=False, port_down_seen=True)
    contradicting = [e for e in f.evidence if e.stance is Stance.CONTRADICTS]
    assert len(contradicting) == 1
    assert "port-down" in contradicting[0].summary


def test_unavailable_port_status_forces_inconclusive():
    """An absent pre-condition must not look like a satisfied one."""
    f, _ = sdn_finding(probe_replied=False, port_status_available=False)
    assert f.current.collection_health is CollectionHealth.DEGRADED
    assert f.current.outcome is AssessmentOutcome.INCONCLUSIVE
    assert "incomplete" in f.current.rationale


def test_the_move_and_the_probe_are_two_real_observations():
    f, graph = sdn_finding(probe_replied=True)
    supporting = [e for e in f.evidence if e.stance is Stance.SUPPORTS
                  and e.kind is EvidenceKind.DIRECT_OBSERVATION]
    roots = {tuple(sorted(graph.root_event_ids(e.evidence_id))) for e in supporting}
    assert len(roots) == 2, "distinct source events, so genuinely two observations"
    assert not f.summarize(graph).shared_root_events


def test_the_sdn_finding_serializes_within_bounds():
    f, _ = sdn_finding()
    payload = json.loads(f.to_json())
    assert payload["kind"] == "sdn.host_location_conflict"
    assert len(f.to_json().encode()) < 8192


# -- host domain (synthetic; no sensor exists) ------------------------------


def test_a_host_finding_needs_no_sdn_field():
    graph = EvidenceGraph()
    f = Finding("FN-HOST-0001", "host.unexpected_outbound_connection",
                entity_refs=(EntityRef.of(EntityKind.PROCESS_INSTANCE,
                                          "1234@88231", "host=h1;boot=b7"),),
                created_at=T0)
    connect = Evidence("FN-HOST-0001-EV-CONN", EvidenceKind.DIRECT_OBSERVATION,
                       Stance.SUPPORTS, "host-kernel-sensor",
                       "process opened TCP connection to 203.0.113.8:443",
                       T0, T0, source_event_ids=("evt-conn",))
    intel = Evidence("FN-HOST-0001-EV-INTEL", EvidenceKind.EXTERNAL_ASSERTION,
                     Stance.SUPPORTS, "threat-intel-feed",
                     "destination appears in a reputation feed", T0, T0,
                     source_event_ids=("evt-conn",), parent_evidence_ids=(
                         "FN-HOST-0001-EV-CONN",))
    graph.add(connect); graph.add(intel)
    f.attach(connect); f.attach(intel)
    f.note_missing(MissingEvidence("application identity",
                                   MissingReason.NOT_CONFIGURED, "app-sdk"))

    payload = json.loads(f.to_json()).__str__().lower()
    for sdn_word in ("dpid", "datapath", "openflow", "ofport"):
        assert sdn_word not in payload


def test_threat_intel_derived_from_the_connection_is_not_a_second_observation():
    """The exact §8 case: a feed lookup on one connection is one observation
    seen twice, not two."""
    graph = EvidenceGraph()
    connect = Evidence("EV-HOST-CONN", EvidenceKind.DIRECT_OBSERVATION,
                       Stance.SUPPORTS, "host-kernel-sensor", "connection",
                       T0, T0, source_event_ids=("evt-conn",))
    intel = Evidence("EV-HOST-INTEL", EvidenceKind.EXTERNAL_ASSERTION,
                     Stance.SUPPORTS, "threat-intel-feed", "reputation hit",
                     T0, T0, parent_evidence_ids=("EV-HOST-CONN",))
    anomaly = Evidence("EV-HOST-ANOM", EvidenceKind.STATISTICAL_MODEL_RESULT,
                       Stance.SUPPORTS, "anomaly-model", "unusual destination",
                       T0, T0, parent_evidence_ids=("EV-HOST-CONN",),
                       model_score=0.77, model_id="iforest-v2")
    for e in (connect, intel, anomaly):
        graph.add(e)
    f = Finding("FN-HOST-0002", "host.unexpected_outbound_connection", created_at=T0)
    for e in (connect, intel, anomaly):
        f.attach(e)
    summary = f.summarize(graph)
    assert summary.supporting == 3
    assert summary.shared_root_events, "three detectors, one connection"
    assert summary.distinct_origins == 3, "distinct origins is not independence"


# -- AI domain (synthetic; no gateway exists) -------------------------------


def test_a_synthetic_ai_finding_fits_the_common_model():
    f = Finding("FN-AI-0001", "ai.unauthorized_tool_proposal",
                entity_refs=(EntityRef.of(EntityKind.AI_TASK, "task-9",
                                          "app=crm;tenant=t1"),
                             EntityRef.of(EntityKind.AI_TOOL, "DeleteCustomer")),
                created_at=T0)
    proposal = Evidence("FN-AI-0001-EV-PROP", EvidenceKind.DIRECT_OBSERVATION,
                        Stance.SUPPORTS, "ai-gateway",
                        "model proposed tool DeleteCustomer", T0, T0,
                        source_event_ids=("evt-prop",))
    authz = Evidence("FN-AI-0001-EV-AUTHZ", EvidenceKind.DETERMINISTIC_RULE_RESULT,
                     Stance.SUPPORTS, "application-auth-service",
                     "requesting principal lacks the required permission",
                     T0, T0, source_event_ids=("evt-authz",))
    f.attach(proposal); f.attach(authz)
    f.assess(Assessment("FN-AI-0001-AS-0001", AssessmentOutcome.SUPPORTED,
                        Severity.CRITICAL, Confidence.STRONG,
                        ConfidenceBasis.DETERMINISTIC_INVARIANT,
                        CollectionHealth.HEALTHY,
                        "the proposal is outside the principal's permissions",
                        T0, f.summarize()))
    assert f.current.severity is Severity.CRITICAL
    payload = json.loads(f.to_json())
    assert "pid" not in json.dumps(payload["entity_refs"])


def test_the_ai_fixture_is_not_a_claim_that_a_gateway_exists():
    """Guards against the fixture being cited later as capability."""
    import development  # noqa: F401  (namespace check only)
    from pathlib import Path

    src = Path(__file__).resolve().parents[2] / "src" / "annulon"
    assert not (src / "ai").exists(), "no AI package exists yet"


# -- domain neutrality -----------------------------------------------------


@pytest.mark.parametrize("kind", ["sdn.host_location_conflict",
                                  "host.unexpected_outbound_connection",
                                  "ai.unauthorized_tool_proposal",
                                  "cloud.iam_policy_change"])
def test_one_finding_type_serves_every_domain(kind):
    f = Finding(f"FN-{abs(hash(kind)) % 10000:04d}", kind, created_at=T0)
    f.attach(Evidence("EV-0001", EvidenceKind.DIRECT_OBSERVATION,
                      Stance.SUPPORTS, "origin-a", "s", T0, T0))
    assert json.loads(f.to_json())["kind"] == kind
