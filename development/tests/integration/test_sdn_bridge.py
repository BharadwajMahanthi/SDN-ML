"""SDN detections on the shared evidence boundary.

The bridge exists so a consumer sees one `Finding` type whatever produced it.
The risk it introduces is that an SDN finding arrives looking more certain
than it is — a fabricated link is `HIGH` severity, and severity is not
confidence.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from annulon.finding import (
    AssessmentOutcome, CollectionHealth, Confidence, FindingState,
    ResponseClass, Severity as AnnulonSeverity,
)
from annulon.identity import EntityKind
from sdnguard.domain.events import (
    FindingKind, SecurityFinding, Severity as SdnSeverity, Verdict,
)
from sdnguard.domain.host import HostIdentity, MacAddress
from sdnguard.domain.identity import DatapathId, PortIdentity, PortNumber
from sdnguard.v2.findings import ORIGIN_GROUP, map_finding, map_findings

PORT = PortIdentity(DatapathId(0xAABBCCDDEEFF), PortNumber(1))
IDENTITY = HostIdentity.of(MacAddress(0xAABBCCDDEE01))


def _sdn(verdict=Verdict.SUSPICIOUS, severity=SdnSeverity.HIGH,
         kind=FindingKind.LINK_FABRICATION, finding_id="f-1") -> SecurityFinding:
    return SecurityFinding(
        finding_id=finding_id, kind=kind, verdict=verdict, severity=severity,
        identity=IDENTITY, port=PORT,
        detected_at=datetime(2026, 9, 24, 12, tzinfo=timezone.utc),
        evidence=("probe-1", "probe-2"), summary="a fabricated link")


def test_a_suspicious_verdict_under_healthy_collection_is_supported():
    """The positive control."""
    mapped = map_finding(_sdn())
    assessment = mapped.assessments[-1]
    assert assessment.outcome is AssessmentOutcome.SUPPORTED
    assert mapped.state is FindingState.OPEN


def test_severity_is_not_confidence():
    """A HIGH-severity finding the detector could not resolve stays weak.

    This is the property most likely to be lost in a bridge: an alarming
    `kind` arriving as a confident conclusion.
    """
    mapped = map_finding(_sdn(verdict=Verdict.INCONCLUSIVE,
                              severity=SdnSeverity.HIGH))
    assessment = mapped.assessments[-1]
    assert assessment.severity is AnnulonSeverity.HIGH
    assert assessment.confidence is Confidence.WEAK
    assert assessment.outcome is AssessmentOutcome.INCONCLUSIVE


def test_a_benign_verdict_does_not_become_a_finding_against_anyone():
    mapped = map_finding(_sdn(verdict=Verdict.BENIGN))
    assert mapped.assessments[-1].outcome is AssessmentOutcome.NOT_SUPPORTED
    assert mapped.state is FindingState.RESOLVED


def test_degraded_controller_collection_blocks_a_supported_outcome():
    """Same rule as the host detector: a detector must not decide for itself
    that it can see."""
    mapped = map_finding(_sdn(), trustworthy_absence=False,
                         health_detail="controller lost the switch")
    assessment = mapped.assessments[-1]
    assert assessment.outcome is AssessmentOutcome.INCONCLUSIVE
    assert assessment.collection_health is CollectionHealth.DEGRADED
    assert "lost the switch" in assessment.rationale


@pytest.mark.parametrize("verdict", list(Verdict))
def test_no_sdn_finding_ever_offers_containment(verdict):
    """Fabric enforcement is NOT_RUN. Offering the response would invite a
    policy layer to propose an action nothing can carry out."""
    allowed = map_finding(_sdn(verdict=verdict)).assessments[-1].allowed_responses
    assert ResponseClass.TEMPORARY_CONTAINMENT not in allowed


def test_the_sdn_attachment_survives_as_an_entity_a_host_can_hold():
    """`(dpid, port)` means nothing on a plain host, so the network scope
    goes in the namespace and a correlator can join without knowing what a
    datapath id is."""
    reference = map_finding(_sdn()).entity_refs[0]
    assert reference.kind is EntityKind.SDN_ATTACHMENT
    assert "aa:bb:cc:dd:ee:ff" in reference.namespace
    assert reference.identifier == "1"


def test_the_detector_evidence_ids_are_carried_through():
    """Lineage has to survive the bridge or corroboration becomes unprovable."""
    evidence = map_finding(_sdn()).evidence[0]
    assert evidence.source_event_ids == ("probe-1", "probe-2")
    assert evidence.origin_group == ORIGIN_GROUP


def test_two_sdn_findings_are_not_independent_corroboration():
    """One controller is one witness however many detectors it runs."""
    mapped = map_findings([_sdn(finding_id="f-1"), _sdn(finding_id="f-2")])
    for finding in mapped:
        summary = finding.assessments[-1].summary
        assert summary.shared_root_events
        assert summary.origin_groups == (ORIGIN_GROUP,)


def test_the_sdn_origin_group_differs_from_the_host_sensor():
    """So a host observation and an SDN observation of one incident do count
    as two origins."""
    from annulon.detect.egress_policy import ORIGIN_GROUP as HOST_GROUP
    assert ORIGIN_GROUP != HOST_GROUP


@pytest.mark.parametrize("kind", list(FindingKind))
def test_every_detector_finding_kind_maps_without_raising(kind):
    """A bridge that crashes on an unfamiliar kind silently drops detections."""
    mapped = map_finding(_sdn(kind=kind))
    assert mapped.kind.startswith("sdn.")
    assert mapped.assessments


@pytest.mark.parametrize("severity", list(SdnSeverity))
def test_every_severity_maps_to_a_shared_severity(severity):
    mapped = map_finding(_sdn(severity=severity))
    assert isinstance(mapped.assessments[-1].severity, AnnulonSeverity)
