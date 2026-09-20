"""Evidence semantics: lineage, independence, contradiction and absence."""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

import pytest

from annulon.evidence import (
    MAX_LINEAGE_DEPTH,
    Evidence,
    EvidenceError,
    EvidenceGraph,
    EvidenceKind,
    LineageError,
    MissingEvidence,
    MissingReason,
    Stance,
)

T0 = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)


def ev(evidence_id: str, *, kind=EvidenceKind.DIRECT_OBSERVATION,
       stance=Stance.SUPPORTS, origin="host-sensor-a", parents=(),
       events=(), **kw) -> Evidence:
    return Evidence(evidence_id=evidence_id, kind=kind, stance=stance,
                    origin_group=origin, summary=f"summary for {evidence_id}",
                    observed_at=T0, produced_at=T0, source_event_ids=tuple(events),
                    parent_evidence_ids=tuple(parents), **kw)


# -- observation is not inference ------------------------------------------


def test_observation_and_inference_are_distinguishable():
    """Policy must be able to tell a kernel report from a model's opinion."""
    observed = ev("EV-0001", kind=EvidenceKind.DIRECT_OBSERVATION)
    modelled = ev("EV-0002", kind=EvidenceKind.STATISTICAL_MODEL_RESULT,
                  model_score=0.82, model_id="rf-v3")
    assert observed.kind.is_observation and not observed.kind.is_inference
    assert modelled.kind.is_inference and not modelled.kind.is_observation


def test_a_model_score_is_never_serialized_as_a_probability():
    e = ev("EV-0001", kind=EvidenceKind.STATISTICAL_MODEL_RESULT,
           model_score=0.82, model_id="rf-v3")
    payload = e.to_dict()
    assert payload["model_score_uncalibrated"] == 0.82
    assert "probability" not in str(payload).lower()
    assert "confidence" not in payload


def test_a_model_score_requires_a_model_identity():
    """A number without a model cannot be interpreted or reproduced."""
    with pytest.raises(EvidenceError, match="model identity"):
        ev("EV-0001", kind=EvidenceKind.STATISTICAL_MODEL_RESULT, model_score=0.82)


def test_a_model_score_is_refused_on_a_non_model_kind():
    with pytest.raises(EvidenceError, match="only meaningful"):
        ev("EV-0001", kind=EvidenceKind.DIRECT_OBSERVATION,
           model_score=0.9, model_id="rf-v3")


# -- lineage and manufactured corroboration --------------------------------


def test_three_detectors_on_one_event_share_a_root():
    """The central independence property: adding detectors must not create
    corroboration."""
    graph = EvidenceGraph()
    graph.add(ev("EV-0001", events=("evt-100",)))
    for child in ("EV-0002", "EV-0003", "EV-0004"):
        graph.add(ev(child, kind=EvidenceKind.DETERMINISTIC_RULE_RESULT,
                     parents=("EV-0001",)))
    roots = [graph.root_event_ids(c) for c in ("EV-0002", "EV-0003", "EV-0004")]
    assert all(r == frozenset({"evt-100"}) for r in roots)


def test_two_genuinely_separate_sensors_have_distinct_roots():
    graph = EvidenceGraph()
    graph.add(ev("EV-0001", origin="host-sensor-a", events=("evt-100",)))
    graph.add(ev("EV-0002", origin="cloud-audit-aws", events=("evt-900",)))
    assert graph.root_event_ids("EV-0001") != graph.root_event_ids("EV-0002")
    assert not (graph.root_event_ids("EV-0001") & graph.root_event_ids("EV-0002"))


def test_origin_group_is_required():
    """Evidence without a stated origin cannot be checked for corroboration."""
    with pytest.raises(EvidenceError, match="origin_group"):
        ev("EV-0001", origin="")


def test_an_unknown_parent_is_refused():
    graph = EvidenceGraph()
    with pytest.raises(LineageError, match="unknown parent"):
        graph.add(ev("EV-0002", parents=("EV-missing",)))


def test_self_reference_is_refused():
    with pytest.raises(LineageError, match="own parent"):
        ev("EV-0001", parents=("EV-0001",))


def test_duplicate_parents_are_refused():
    with pytest.raises(EvidenceError, match="duplicate parent"):
        ev("EV-0002", parents=("EV-0001", "EV-0001"))


def test_lineage_depth_is_bounded():
    """Evidence may derive from attacker-influenced input, so an unbounded
    walk is a denial-of-service primitive."""
    graph = EvidenceGraph(max_depth=4)
    graph.add(ev("EV-0000", events=("evt-1",)))
    previous = "EV-0000"
    for i in range(1, 5):
        graph.add(ev(f"EV-{i:04d}", parents=(previous,)))
        previous = f"EV-{i:04d}"
    with pytest.raises(LineageError, match="deeper than"):
        graph.add(ev("EV-0009", parents=(previous,)))


def test_graph_size_is_bounded():
    graph = EvidenceGraph(max_nodes=3)
    for i in range(3):
        graph.add(ev(f"EV-{i:04d}"))
    with pytest.raises(EvidenceError, match="limit"):
        graph.add(ev("EV-0099"))


def test_duplicate_evidence_ids_are_refused():
    graph = EvidenceGraph()
    graph.add(ev("EV-0001"))
    with pytest.raises(EvidenceError, match="duplicate"):
        graph.add(ev("EV-0001"))


def test_a_diamond_is_not_a_cycle():
    """KF-27: two derivations sharing an ancestor is the ordinary shape of
    correlated evidence, not a cycle."""
    graph = EvidenceGraph()
    graph.add(ev("EV-0001", events=("evt-100",)))
    graph.add(ev("EV-0002", parents=("EV-0001",)))
    graph.add(ev("EV-0003", parents=("EV-0001",)))
    graph.add(ev("EV-0004", parents=("EV-0002", "EV-0003")))
    assert len(graph) == 4


def test_a_diamond_ancestry_resolves_to_one_root():
    """Two derivation paths from one event are still one observation."""
    graph = EvidenceGraph()
    graph.add(ev("EV-0001", events=("evt-100",)))
    graph.add(ev("EV-0002", parents=("EV-0001",)))
    graph.add(ev("EV-0003", parents=("EV-0001",)))
    graph.add(ev("EV-0004", parents=("EV-0002", "EV-0003")))
    assert graph.root_event_ids("EV-0004") == frozenset({"evt-100"})
    assert set(graph.ancestry("EV-0004")) == {"EV-0001", "EV-0002", "EV-0003"}


# -- missing evidence is not negative evidence -----------------------------


def test_missing_evidence_is_a_separate_type_from_evidence():
    """If absence were evidence with a stance it would eventually be counted,
    and 'we did not see it' would become 'it did not happen'."""
    missing = MissingEvidence("port-status event", MissingReason.SENSOR_UNAVAILABLE,
                              "sdn-controller-a")
    assert not isinstance(missing, Evidence)
    assert not hasattr(missing, "stance")


@pytest.mark.parametrize(
    "reason,is_fault",
    [(MissingReason.SENSOR_UNAVAILABLE, True), (MissingReason.SEQUENCE_GAP, True),
     (MissingReason.QUEUE_OVERFLOW, True), (MissingReason.RETENTION_EXPIRED, True),
     (MissingReason.CAPABILITY_UNSUPPORTED, False),
     (MissingReason.NOT_CONFIGURED, False), (MissingReason.NOT_YET_ARRIVED, False)],
)
def test_a_collection_fault_is_distinguished_from_a_configuration_choice(reason, is_fault):
    assert MissingEvidence("x", reason, "origin").is_collection_fault is is_fault


def test_no_missing_reason_means_the_thing_did_not_happen():
    """Every reason describes a collection gap. None of them licenses the
    inference that the event did not occur."""
    for reason in MissingReason:
        assert "did_not" not in reason.value
        assert "absent" not in reason.value
        assert "none" not in reason.value


# -- validation and fuzzing ------------------------------------------------


@pytest.mark.parametrize("bad", ["", "ab", "x" * 80, "has space", "has/slash", "a"])
def test_malformed_ids_are_refused(bad):
    with pytest.raises(EvidenceError):
        ev(bad)


def test_summary_length_is_bounded():
    with pytest.raises(EvidenceError, match="summary exceeds"):
        Evidence("EV-0001", EvidenceKind.DIRECT_OBSERVATION, Stance.SUPPORTS,
                 "origin", "x" * 5000, T0, T0)


def test_naive_timestamps_are_refused():
    with pytest.raises(EvidenceError, match="timezone-aware"):
        Evidence("EV-0001", EvidenceKind.DIRECT_OBSERVATION, Stance.SUPPORTS,
                 "origin", "s", None, datetime(2026, 1, 1))


def test_fuzzing_the_graph_never_corrupts_it():
    """Random add attempts must leave the graph consistent and acyclic."""
    rng = random.Random(20260920)
    graph = EvidenceGraph(max_depth=5, max_nodes=60)
    added: list[str] = []
    for i in range(1500):
        eid = f"EV-{rng.randrange(0, 80):04d}"
        parents = tuple(rng.sample(added, min(len(added), rng.randrange(0, 3)))) \
            if added else ()
        try:
            graph.add(ev(eid, parents=parents, events=(f"evt-{i}",)))
            added.append(eid)
        except (EvidenceError, LineageError):
            continue
    for node in added:
        graph.ancestry(node)          # must terminate
        graph.root_event_ids(node)
    assert len(graph) <= 60
