"""Findings and assessments: severity, confidence, contradiction, lifecycle."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

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
    FindingError,
    FindingState,
    ResponseClass,
    Severity,
    summarize_evidence,
)

T0 = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)


def ev(eid, *, stance=Stance.SUPPORTS, origin="host-sensor-a",
       kind=EvidenceKind.DIRECT_OBSERVATION, parents=(), events=()) -> Evidence:
    return Evidence(eid, kind, stance, origin, f"summary {eid}", T0, T0,
                    tuple(events), tuple(parents))


def assessment(aid="AS-0001", *, outcome=AssessmentOutcome.SUPPORTED,
               severity=Severity.HIGH, confidence=Confidence.MODERATE,
               basis=ConfidenceBasis.DIRECT_OBSERVATION,
               health=CollectionHealth.HEALTHY, supersedes=None,
               summary=None) -> Assessment:
    return Assessment(aid, outcome, severity, confidence, basis, health,
                      "because the evidence says so", T0,
                      summary or summarize_evidence((), ()), supersedes)


def finding(fid="FN-0001") -> Finding:
    return Finding(fid, "host_location_conflict", created_at=T0)


# -- severity and confidence are independent -------------------------------


def test_critical_severity_can_carry_weak_confidence():
    """The combination an operator most needs to see: it would be very bad
    if true, and we barely know."""
    a = assessment(severity=Severity.CRITICAL, confidence=Confidence.WEAK,
                   basis=ConfidenceBasis.HEURISTIC)
    assert a.severity is Severity.CRITICAL
    assert a.confidence is Confidence.WEAK


def test_low_severity_can_carry_strong_confidence():
    a = assessment(severity=Severity.LOW, confidence=Confidence.STRONG,
                   basis=ConfidenceBasis.DETERMINISTIC_INVARIANT)
    assert a.severity is Severity.LOW and a.confidence is Confidence.STRONG


@pytest.mark.parametrize("severity", list(Severity))
@pytest.mark.parametrize("confidence",
                         [c for c in Confidence if c is not Confidence.UNASSESSED])
def test_every_severity_confidence_combination_is_representable(severity, confidence):
    a = assessment(severity=severity, confidence=confidence)
    assert (a.severity, a.confidence) == (severity, confidence)


def test_neither_axis_is_derived_from_the_other():
    """No arithmetic relates them, so changing one cannot move the other."""
    import inspect

    import annulon.finding as module

    source = inspect.getsource(module)
    for forbidden in ("severity.value *", "confidence.value *",
                      "severity.value +", "risk_score", "* severity", "* confidence"):
        assert forbidden not in source


def test_there_is_no_universal_risk_score_field():
    payload = assessment().to_dict()
    for forbidden in ("risk_score", "score", "probability", "risk"):
        assert forbidden not in payload


def test_confidence_always_carries_a_basis():
    """A confidence level with no stated basis is not reviewable."""
    with pytest.raises(FindingError, match="basis"):
        assessment(confidence=Confidence.STRONG, basis=ConfidenceBasis.NONE)


def test_unassessed_confidence_must_have_no_basis():
    with pytest.raises(FindingError, match="no basis"):
        assessment(confidence=Confidence.UNASSESSED,
                   basis=ConfidenceBasis.DIRECT_OBSERVATION)


# -- corroboration, contradiction, absence ---------------------------------


def test_supporting_contradicting_and_missing_are_all_first_class():
    f = finding()
    f.attach(ev("EV-0001"))
    f.attach(ev("EV-0002", stance=Stance.CONTRADICTS, origin="cloud-audit-aws"))
    f.note_missing(MissingEvidence("port-status event",
                                   MissingReason.SENSOR_UNAVAILABLE, "sdn-a"))
    s = f.summarize()
    assert (s.supporting, s.contradicting, s.missing) == (1, 1, 1)


def test_a_contradicted_finding_does_not_look_like_an_unchallenged_one():
    clean, disputed = finding("FN-0001"), finding("FN-0002")
    clean.attach(ev("EV-0001"))
    disputed.attach(ev("EV-0002"))
    disputed.attach(ev("EV-0003", stance=Stance.CONTRADICTS,
                       origin="cloud-audit-aws"))
    assert clean.summarize().contradicting == 0
    assert disputed.summarize().contradicting == 1
    assert clean.summarize() != disputed.summarize()


def test_contradiction_is_not_arithmetic_on_a_score():
    """Three supporting and one contradicting must not silently become 75%."""
    f = finding()
    for i in range(3):
        f.attach(ev(f"EV-000{i+1}", origin=f"origin-{i}"))
    f.attach(ev("EV-0009", stance=Stance.CONTRADICTS, origin="cloud-audit-aws"))
    s = f.summarize()
    payload = s.to_dict()
    assert payload["supporting"] == 3 and payload["contradicting"] == 1
    assert not any(isinstance(v, float) for v in payload.values())


def test_a_single_contradiction_can_outweigh_many_weak_supports():
    """Expressed as policy input, not as a computation: the record makes the
    contradiction visible so a rule can decide it dominates."""
    f = finding()
    for i in range(5):
        f.attach(ev(f"EV-100{i}", kind=EvidenceKind.HEURISTIC_ASSESSMENT,
                    origin="heuristics"))
    f.attach(ev("EV-2000", stance=Stance.CONTRADICTS, origin="cloud-audit-aws"))
    a = assessment(outcome=AssessmentOutcome.CONTRADICTED,
                   confidence=Confidence.WEAK, basis=ConfidenceBasis.HEURISTIC,
                   summary=f.summarize())
    f.assess(a)
    assert f.state is FindingState.DISPUTED


# -- manufactured corroboration --------------------------------------------


def test_detectors_sharing_a_source_event_are_not_corroboration():
    graph = EvidenceGraph()
    graph.add(ev("EV-0001", events=("evt-100",)))
    f = finding()
    for eid in ("EV-0002", "EV-0003", "EV-0004"):
        e = ev(eid, kind=EvidenceKind.DETERMINISTIC_RULE_RESULT,
               parents=("EV-0001",), origin=f"detector-{eid}")
        graph.add(e)
        f.attach(e)
    s = f.summarize(graph)
    assert s.supporting == 3
    assert s.shared_root_events, "three views of one event is not three observations"


def test_genuinely_separate_origins_do_not_flag_shared_roots():
    graph = EvidenceGraph()
    a = ev("EV-0001", origin="host-sensor-a", events=("evt-100",))
    b = ev("EV-0002", origin="cloud-audit-aws", events=("evt-900",))
    graph.add(a); graph.add(b)
    f = finding(); f.attach(a); f.attach(b)
    s = f.summarize(graph)
    assert not s.shared_root_events
    assert s.distinct_origins == 2


def test_distinct_origin_is_not_a_claim_of_statistical_independence():
    """The field means different collection origin, nothing stronger."""
    from annulon.finding import EvidenceSummary
    import inspect

    doc = inspect.getdoc(EvidenceSummary.distinct_origins.fget)
    assert "independence" in doc.lower()


def test_a_model_only_finding_is_marked_as_such():
    f = finding()
    f.attach(Evidence("EV-0001", EvidenceKind.STATISTICAL_MODEL_RESULT,
                      Stance.SUPPORTS, "model-host", "score", T0, T0,
                      model_score=0.81, model_id="rf-v3"))
    assert f.summarize().statistical_only


# -- collection health -----------------------------------------------------


def test_a_collection_fault_is_counted_separately_from_a_configuration_choice():
    f = finding()
    f.note_missing(MissingEvidence("process events",
                                   MissingReason.SENSOR_UNAVAILABLE, "host-a"))
    f.note_missing(MissingEvidence("cloud audit",
                                   MissingReason.NOT_CONFIGURED, "aws"))
    s = f.summarize()
    assert s.missing == 2 and s.missing_from_fault == 1


def test_an_assessment_records_the_collection_context_it_was_made_in():
    a = assessment(outcome=AssessmentOutcome.INCONCLUSIVE,
                   confidence=Confidence.WEAK, basis=ConfidenceBasis.HEURISTIC,
                   health=CollectionHealth.DEGRADED)
    assert a.collection_health is CollectionHealth.DEGRADED
    assert a.to_dict()["collection_health"] == "degraded"


def test_inconclusive_is_a_legitimate_outcome():
    """Nothing is forced into attack-or-benign."""
    f = finding()
    f.assess(assessment(outcome=AssessmentOutcome.INCONCLUSIVE,
                        confidence=Confidence.WEAK,
                        basis=ConfidenceBasis.HEURISTIC))
    assert f.state is FindingState.INCONCLUSIVE


# -- lifecycle -------------------------------------------------------------


def test_assessments_are_append_only_and_history_is_kept():
    f = finding()
    first = assessment("AS-0001", confidence=Confidence.WEAK,
                       basis=ConfidenceBasis.HEURISTIC)
    f.assess(first)
    second = assessment("AS-0002", confidence=Confidence.STRONG,
                        basis=ConfidenceBasis.MULTI_ORIGIN_CORROBORATION,
                        supersedes="AS-0001")
    f.assess(second)
    assert len(f.history) == 2
    assert f.current is second
    assert f.history[0].confidence is Confidence.WEAK, "the past is preserved"


def test_a_new_assessment_must_name_what_it_supersedes():
    """So the history reads as a chain rather than a pile."""
    f = finding()
    f.assess(assessment("AS-0001"))
    with pytest.raises(FindingError, match="supersedes"):
        f.assess(assessment("AS-0002"))


def test_evidence_arriving_later_produces_a_new_assessment_not_an_edit():
    f = finding()
    f.attach(ev("EV-0001"))
    f.assess(assessment("AS-0001", outcome=AssessmentOutcome.INCONCLUSIVE,
                        confidence=Confidence.WEAK,
                        basis=ConfidenceBasis.HEURISTIC))
    f.attach(ev("EV-0002", stance=Stance.CONTRADICTS, origin="cloud-audit-aws"))
    f.assess(assessment("AS-0002", outcome=AssessmentOutcome.CONTRADICTED,
                        supersedes="AS-0001", summary=f.summarize()))
    assert f.history[0].outcome is AssessmentOutcome.INCONCLUSIVE
    assert f.current.outcome is AssessmentOutcome.CONTRADICTED
    assert f.state is FindingState.DISPUTED


def test_missing_evidence_can_later_arrive():
    f = finding()
    f.note_missing(MissingEvidence("port-status", MissingReason.NOT_YET_ARRIVED, "sdn"))
    assert f.summarize().missing == 1
    assert f.resolve_missing("port-status")
    assert f.summarize().missing == 0


def test_a_resolved_finding_is_not_reopened_by_a_new_assessment():
    """RESOLVED is a lifecycle state, not a claim that an attack was proven."""
    f = finding()
    f.assess(assessment("AS-0001"))
    f.state = FindingState.RESOLVED
    f.assess(assessment("AS-0002", outcome=AssessmentOutcome.SUPPORTED,
                        supersedes="AS-0001"))
    assert f.state is FindingState.RESOLVED


def test_one_finding_accumulates_evidence_rather_than_spawning_many():
    f = finding()
    for i in range(10):
        f.attach(ev(f"EV-{i:04d}"))
    assert len(f.evidence) == 10 and f.finding_id == "FN-0001"


# -- explanation -----------------------------------------------------------


def test_the_explanation_is_deterministic_and_built_from_the_record():
    graph = EvidenceGraph()
    f = finding()
    a = ev("EV-0001", events=("evt-1",)); graph.add(a); f.attach(a)
    b = ev("EV-0002", stance=Stance.CONTRADICTS, origin="cloud-audit-aws")
    graph.add(b); f.attach(b)
    f.note_missing(MissingEvidence("port lifecycle",
                                   MissingReason.SENSOR_UNAVAILABLE, "sdn-a"))
    f.assess(assessment(outcome=AssessmentOutcome.INCONCLUSIVE,
                        confidence=Confidence.WEAK,
                        basis=ConfidenceBasis.HEURISTIC,
                        summary=f.summarize(graph)))
    text = f.explain()
    assert f.explain() == text, "deterministic"
    for expected in ("Status: inconclusive", "Severity:", "Confidence:",
                     "Supporting:", "Contradictory:", "Missing:", "Collection:"):
        assert expected in text


def test_the_explanation_warns_when_corroboration_is_illusory():
    graph = EvidenceGraph()
    root = ev("EV-0001", events=("evt-100",)); graph.add(root)
    f = finding()
    for eid in ("EV-0002", "EV-0003"):
        e = ev(eid, kind=EvidenceKind.DETERMINISTIC_RULE_RESULT,
               parents=("EV-0001",), origin=f"d-{eid}")
        graph.add(e); f.attach(e)
    f.assess(assessment(summary=f.summarize(graph)))
    assert "not independent corroboration" in f.explain()


def test_an_unassessed_finding_explains_that_it_is_unassessed():
    assert "no assessment" in finding().explain()


# -- privacy and bounds ----------------------------------------------------


def test_a_finding_does_not_duplicate_raw_event_content():
    """One sensitive observation must not become ten sensitive findings."""
    e = Evidence("EV-0001", EvidenceKind.DIRECT_OBSERVATION, Stance.SUPPORTS,
                 "host-a", "process executed", T0, T0,
                 source_event_ids=("evt-100",), artifact_ref="local://spool/evt-100")
    f = finding(); f.attach(e)
    payload = json.loads(f.to_json())
    item = payload["evidence"][0]
    assert item["artifact_ref"] == "local://spool/evt-100"
    for forbidden in ("payload", "raw", "command_line", "prompt", "content"):
        assert forbidden not in item


def test_a_local_artifact_reference_survives_serialization():
    e = Evidence("EV-0001", EvidenceKind.DIRECT_OBSERVATION, Stance.SUPPORTS,
                 "host-a", "s", T0, T0, artifact_ref="local://spool/x")
    f = finding(); f.attach(e)
    assert "local://spool/x" in f.to_json()


def test_evidence_count_is_bounded():
    f = finding()
    for i in range(64):
        f.attach(ev(f"EV-{i:04d}"))
    with pytest.raises(FindingError, match="evidence items"):
        f.attach(ev("EV-9999"))


def test_assessment_count_is_bounded():
    f = finding()
    previous = None
    for i in range(32):
        aid = f"AS-{i:04d}"
        f.assess(assessment(aid, supersedes=previous))
        previous = aid
    with pytest.raises(FindingError, match="assessments"):
        f.assess(assessment("AS-9999", supersedes=previous))


def test_duplicate_evidence_is_refused():
    f = finding(); f.attach(ev("EV-0001"))
    with pytest.raises(FindingError, match="duplicate"):
        f.attach(ev("EV-0001"))


def test_serialized_finding_size_is_bounded():
    f = finding()
    for i in range(60):
        f.attach(ev(f"EV-{i:04d}"))
    with pytest.raises(FindingError, match="exceeds"):
        f.to_json(max_bytes=512)


def test_rationale_length_is_bounded():
    with pytest.raises(FindingError, match="rationale"):
        Assessment("AS-0001", AssessmentOutcome.SUPPORTED, Severity.HIGH,
                   Confidence.MODERATE, ConfidenceBasis.DIRECT_OBSERVATION,
                   CollectionHealth.HEALTHY, "x" * 9000, T0,
                   summarize_evidence((), ()))


# -- response metadata only ------------------------------------------------


def test_a_finding_expresses_response_classes_but_executes_nothing():
    a = assessment()
    assert ResponseClass.OBSERVE_ONLY in a.allowed_responses
    assert not hasattr(a, "execute")
    assert not hasattr(a, "apply")
