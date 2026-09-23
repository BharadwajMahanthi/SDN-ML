"""The detector, attacked where it could manufacture a security claim.

Three refusals carry this module, and each is a way a detector's mistake
becomes a privileged action: it must not accuse a workload it cannot
identify, must not conclude anything while blind, and must never propose an
action itself.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from annulon.detect.attribution import WorkloadResolver
from annulon.detect.egress_policy import (
    EgressAllowlist, EgressPolicyDetector, WorkloadRule,
)
from annulon.finding import AssessmentOutcome, CollectionHealth, ResponseClass
from annulon.identity import EntityKind, EntityRef
from annulon.network.contract import (
    AddressFamily, AttributionConfidence, ConnectionOutcome, Direction,
    Endpoint, NetworkObservation, NetworkOperation, ProcessRef,
    SocketSemantic, Transport,
)
from annulon.response.from_finding import ContainmentPolicy, ProposalOutcome

NOW = datetime(2026, 9, 23, 12, tzinfo=timezone.utc)
UID = 1500


def _observation(*, address="203.0.113.9", port=443, uid=UID,
                 confidence=AttributionConfidence.CORRELATED,
                 operation=NetworkOperation.CONNECT_ATTEMPT,
                 self_test=False, namespace=None) -> NetworkObservation:
    entity = (EntityRef(EntityKind.WORKLOAD, "host=h;boot=b", str(uid))
              if uid is not None else None)
    outcome = (ConnectionOutcome.ESTABLISHED
               if operation is NetworkOperation.CONNECTION_ESTABLISHED
               else ConnectionOutcome.UNKNOWN)
    return NetworkObservation(
        observation_id="netobs-000000000001", operation=operation,
        transport=Transport.TCP, direction=Direction.OUTBOUND,
        process=ProcessRef(pid=4242, tgid=4242, comm="worker",
                           confidence=confidence, entity=entity),
        local=Endpoint("10.0.0.2", 51234, AddressFamily.IPV4),
        remote=Endpoint(address, port, AddressFamily.IPV4),
        observed_at=NOW, sensor_id="tracefs_network", outcome=outcome,
        socket_semantic=SocketSemantic.CONNECT_INITIATOR,
        is_self_test=self_test, network_namespace=namespace)


def _detector(**rule_kwargs) -> EgressPolicyDetector:
    base = dict(uid=UID, service_name="worker",
                permitted_destinations=("10.0.0.0/24",))
    base.update(rule_kwargs)
    return EgressPolicyDetector(EgressAllowlist((WorkloadRule(**base),)),
                                host_id="h", boot_id="b")


# --- the detector concludes only what it can ------------------------------

def test_a_permitted_destination_produces_no_finding():
    result = _detector().evaluate([_observation(address="10.0.0.5")],
                                  trustworthy_absence=True)
    assert result.findings == []


def test_a_forbidden_destination_produces_a_supported_finding():
    """The positive control. A detector that never fires is not safe."""
    result = _detector().evaluate([_observation()], trustworthy_absence=True)
    assert len(result.findings) == 1
    assessment = result.findings[0].assessments[-1]
    assert assessment.outcome is AssessmentOutcome.SUPPORTED
    assert ResponseClass.TEMPORARY_CONTAINMENT in assessment.allowed_responses


@pytest.mark.parametrize("confidence", [
    AttributionConfidence.PID_ONLY, AttributionConfidence.NONE])
def test_weak_attribution_never_reaches_a_supported_finding(confidence):
    """A pid that may have been reused is not an accusation."""
    result = _detector().evaluate(
        [_observation(confidence=confidence)], trustworthy_absence=True)
    for finding in result.findings:
        assessment = finding.assessments[-1]
        assert assessment.outcome is AssessmentOutcome.INCONCLUSIVE
        assert ResponseClass.TEMPORARY_CONTAINMENT not in assessment.allowed_responses


def test_degraded_collection_never_reaches_a_supported_finding():
    """Reporting a violation from a partial view invites containing the
    wrong workload; reporting *no* violation from one reports the sensor's
    silence as innocence."""
    result = _detector().evaluate([_observation()], trustworthy_absence=False,
                                  health_detail="sensor blind")
    assessment = result.findings[0].assessments[-1]
    assert assessment.outcome is AssessmentOutcome.INCONCLUSIVE
    assert assessment.collection_health is CollectionHealth.DEGRADED
    assert ResponseClass.TEMPORARY_CONTAINMENT not in assessment.allowed_responses


def test_an_unresolvable_workload_is_counted_not_accused():
    """No entity means the detector does not know whose connection this was.
    Silence about it is correct; naming somebody would not be."""
    result = _detector().evaluate([_observation(uid=None)],
                                  trustworthy_absence=True)
    assert result.findings == []
    assert result.skipped_uncovered_workload == 1


def test_a_workload_with_no_rule_is_not_assumed_forbidden():
    """"Not covered" is not "not permitted"."""
    result = _detector().evaluate([_observation(uid=9999)],
                                  trustworthy_absence=True)
    assert result.findings == []
    assert result.skipped_uncovered_workload == 1


def test_annulons_own_liveness_traffic_is_not_a_security_finding():
    result = _detector().evaluate([_observation(self_test=True)],
                                  trustworthy_absence=True)
    assert result.findings == []


@pytest.mark.parametrize("operation", [
    NetworkOperation.CONNECT_RESULT, NetworkOperation.CONNECTION_ESTABLISHED,
    NetworkOperation.CONNECTION_CLOSED])
def test_only_connection_attempts_are_evaluated(operation):
    """The attempt is what policy is about; the other operations would
    double-count one connection as several violations."""
    result = _detector().evaluate([_observation(operation=operation)],
                                  trustworthy_absence=True)
    assert result.findings == []


def test_the_missing_namespace_is_recorded_as_missing_evidence():
    """The tier cannot say which namespace a flow belongs to, and the finding
    says so instead of implying the destination was reachable host-wide."""
    result = _detector().evaluate([_observation()], trustworthy_absence=True)
    expected = [m.expected for m in result.findings[0].missing]
    assert any("namespace" in e for e in expected)


def test_a_port_outside_the_permitted_set_is_a_violation():
    detector = _detector(permitted_destinations=("203.0.113.0/24",),
                         permitted_ports=frozenset({8080}))
    allowed = detector.evaluate([_observation(port=8080)], trustworthy_absence=True)
    assert allowed.findings == []
    denied = detector.evaluate([_observation(port=443)], trustworthy_absence=True)
    assert len(denied.findings) == 1


def test_all_evidence_shares_one_origin_group():
    """Several findings from one sensor are not corroboration."""
    result = _detector().evaluate([_observation(), _observation()],
                                  trustworthy_absence=True)
    summaries = [f.assessments[-1].summary for f in result.findings]
    assert all(s.shared_root_events for s in summaries)
    assert all(len(s.origin_groups) == 1 for s in summaries)


def test_the_detector_has_no_way_to_act():
    """It emits findings. There is no request, no broker, no enforcer on it."""
    detector = _detector()
    for attribute in ("propose", "contain", "enforce", "broker", "client"):
        assert not hasattr(detector, attribute)


# --- the policy proposes, and refuses to over-propose ----------------------

def _policy() -> ContainmentPolicy:
    return ContainmentPolicy(host_id="h", boot_id="b",
                             duration=timedelta(minutes=5))


def test_a_supported_finding_becomes_a_scoped_proposal():
    finding = _detector().evaluate([_observation()],
                                   trustworthy_absence=True).findings[0]
    proposal = _policy().propose(finding)
    assert proposal.proposed
    assert proposal.request.destination_cidr == "203.0.113.9/32"
    assert proposal.request.destination_port == 443
    assert proposal.request.target.identifier == str(UID)


def test_an_inconclusive_finding_proposes_nothing():
    finding = _detector().evaluate([_observation()],
                                   trustworthy_absence=False).findings[0]
    proposal = _policy().propose(finding)
    assert not proposal.proposed
    assert proposal.outcome == ProposalOutcome.NOT_SUPPORTED


def test_a_finding_with_no_assessment_proposes_nothing():
    from annulon.finding import Finding
    proposal = _policy().propose(Finding(finding_id="fnd-1", kind="x"))
    assert proposal.outcome == ProposalOutcome.NO_ASSESSMENT


def test_the_proposal_duration_comes_from_configuration_not_the_finding():
    """A detector that could choose its own TTL could make a restriction
    permanent by being confident enough."""
    finding = _detector().evaluate([_observation()],
                                   trustworthy_absence=True).findings[0]
    policy = ContainmentPolicy(host_id="h", boot_id="b",
                               duration=timedelta(seconds=30))
    assert policy.propose(finding).request.duration == timedelta(seconds=30)


def test_the_reason_carried_into_the_audit_record_is_printable_and_bounded():
    finding = _detector().evaluate([_observation()],
                                   trustworthy_absence=True).findings[0]
    reason = _policy().propose(finding).request.reason
    assert 0 < len(reason) <= 250
    assert all(0x20 <= ord(c) != 0x7F for c in reason)


# --- the resolver refuses to attribute across a pid reuse ------------------

def test_the_resolver_declines_when_the_start_time_disagrees(tmp_path):
    """A reused pid must not lend its current occupant's identity to an
    earlier process's connection."""
    proc = tmp_path / "4242"
    proc.mkdir()
    (proc / "stat").write_text("4242 (worker) S " + " ".join(["0"] * 18)
                               + " 5550000 " + " ".join(["0"] * 30))
    (proc / "status").write_text("Name:\tworker\nUid:\t1500\t1500\t1500\t1500\n")
    resolver = WorkloadResolver(host_id="h", boot_id="b", proc_root=tmp_path)

    matched = resolver.resolve(_observation(
        confidence=AttributionConfidence.PID_ONLY, uid=None),
        expected_start_ticks=5550000)
    assert matched.process.entity is not None
    assert matched.process.confidence is AttributionConfidence.CORRELATED

    mismatched = resolver.resolve(_observation(
        confidence=AttributionConfidence.PID_ONLY, uid=None),
        expected_start_ticks=9999999)
    assert mismatched.process.entity is None
    assert resolver.stats.start_time_mismatch == 1


def test_the_resolver_does_not_touch_an_unattributable_observation(tmp_path):
    """Interrupt context already discarded the pid; re-deriving one would
    undo that decision."""
    resolver = WorkloadResolver(host_id="h", boot_id="b", proc_root=tmp_path)
    observation = _observation(confidence=AttributionConfidence.NONE, uid=None)
    assert resolver.resolve(observation) is observation
    assert resolver.stats.not_attempted == 1


def test_a_vanished_process_leaves_the_observation_unchanged(tmp_path):
    resolver = WorkloadResolver(host_id="h", boot_id="b", proc_root=tmp_path)
    observation = _observation(confidence=AttributionConfidence.PID_ONLY,
                               uid=None)
    assert resolver.resolve(observation).process.entity is None
    assert resolver.stats.process_gone == 1
