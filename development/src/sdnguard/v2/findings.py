"""Carry SDN detections onto the shared evidence boundary.

The SDN pack has its own `SecurityFinding`, produced by detectors that
understand datapath ids and ports. Nothing downstream of this module should
have to. A host-side consumer — the assessment layer, the response policy,
an operator reading a timeline — sees one `Finding` type whatever produced
it, and the SDN-specific identity survives as an `EntityRef` namespace rather
than as a special case (ADR-027 §8).

Two properties this module exists to preserve.

**An SDN finding is not privileged by being alarming.** A fabricated link is
`Severity.HIGH`, and severity is not confidence: the mapped assessment
reaches `SUPPORTED` only when the detector's own verdict is `SUSPICIOUS` and
collection was healthy. A `Verdict.INCONCLUSIVE` stays inconclusive no matter
how serious the finding kind sounds.

**The SDN pack still cannot act.** This mapper produces findings, exactly as
the host detector does, and the response decision remains the broker's. The
SDN controller has no import path to the response package, and
`test_pack_trust_boundaries.py` holds that open rather than leaving it to
happen to be true.
"""

from __future__ import annotations

from datetime import datetime, timezone

from annulon.evidence import Evidence, EvidenceKind, Stance
from annulon.finding import (
    Assessment, AssessmentOutcome, CollectionHealth, Confidence,
    ConfidenceBasis, EvidenceSummary, Finding, FindingState, ResponseClass,
    Severity as AnnulonSeverity,
)
from annulon.identity import EntityKind, EntityRef
from sdnguard.domain.events import SecurityFinding, Verdict

__all__ = ["ORIGIN_GROUP", "map_finding", "map_findings"]

#: Lineage tag for everything the SDN control plane observes. Distinct from
#: the host sensor's group, so a host observation and an SDN observation of
#: the same incident count as two origins — and two findings from this one
#: controller still count as one.
ORIGIN_GROUP = "sdn.controller"

_SEVERITY = {
    "INFO": AnnulonSeverity.INFO, "LOW": AnnulonSeverity.LOW,
    "MEDIUM": AnnulonSeverity.MEDIUM, "HIGH": AnnulonSeverity.HIGH,
    "CRITICAL": AnnulonSeverity.CRITICAL,
}


def _severity(finding: SecurityFinding) -> AnnulonSeverity:
    return _SEVERITY.get(finding.severity.name, AnnulonSeverity.MEDIUM)


def _attachment(finding: SecurityFinding) -> EntityRef:
    """The SDN attachment point, as an identity a host consumer can hold.

    `(datapath id, port)` means nothing on a plain Linux host, so the network
    scope goes in the namespace and the attachment in the identifier. A
    correlator can join on it without knowing what a DPID is.
    """
    return EntityRef(EntityKind.SDN_ATTACHMENT,
                     f"net={finding.port.datapath_id}",
                     str(finding.port.port))


def map_finding(finding: SecurityFinding, *,
                trustworthy_absence: bool = True,
                health_detail: str = "") -> Finding:
    """One SDN detection as a shared-model finding.

    ``trustworthy_absence`` comes from the controller's own collection
    health, for the same reason the host detector takes it as an argument: a
    detector must not be able to decide for itself that it can see.
    """
    health = (CollectionHealth.HEALTHY if trustworthy_absence
              else CollectionHealth.DEGRADED)
    now = datetime.now(timezone.utc)

    evidence = Evidence(
        evidence_id=f"ev-sdn-{finding.finding_id}",
        kind=EvidenceKind.DETERMINISTIC_RULE_RESULT,
        stance=Stance.SUPPORTS,
        origin_group=ORIGIN_GROUP,
        summary=finding.summary,
        observed_at=finding.detected_at,
        produced_at=now,
        source_event_ids=tuple(finding.evidence),
        attributes={
            "sdn_finding_kind": finding.kind.name,
            "sdn_verdict": finding.verdict.name,
            "dpid": str(finding.port.datapath_id),
            "port": str(finding.port.port),
            "host_identity": str(finding.identity),
        })

    summary = EvidenceSummary(
        supporting=1, contradicting=0, context=0, missing=0,
        missing_from_fault=0, origin_groups=(ORIGIN_GROUP,),
        # One controller observation. Several detectors agreeing about it
        # would still be one root event, and the record says so.
        shared_root_events=True, statistical_only=False)

    if finding.verdict is Verdict.SUSPICIOUS and health is CollectionHealth.HEALTHY:
        outcome = AssessmentOutcome.SUPPORTED
        confidence = Confidence.MODERATE
        responses = (ResponseClass.OBSERVE_ONLY, ResponseClass.INVESTIGATE,
                     ResponseClass.INCREASE_TELEMETRY)
        rationale = ("a deterministic SDN invariant was violated and the "
                     "controller's collection was healthy")
    elif finding.verdict is Verdict.BENIGN:
        outcome = AssessmentOutcome.NOT_SUPPORTED
        confidence = Confidence.MODERATE
        responses = (ResponseClass.OBSERVE_ONLY,)
        rationale = "the detector resolved this as ordinary behaviour"
    else:
        outcome = AssessmentOutcome.INCONCLUSIVE
        confidence = Confidence.WEAK
        responses = (ResponseClass.OBSERVE_ONLY, ResponseClass.INVESTIGATE)
        rationale = (
            "the detector could not resolve this"
            if finding.verdict is Verdict.INCONCLUSIVE
            else "the controller's collection was degraded")

    # Containment is deliberately absent from every branch. No SDN finding
    # currently authorises a response: the enforcement path for the fabric is
    # NOT_RUN, and offering TEMPORARY_CONTAINMENT would invite a policy layer
    # to propose an action nothing can carry out.
    assessment = Assessment(
        assessment_id=f"as-sdn-{finding.finding_id}",
        outcome=outcome, severity=_severity(finding), confidence=confidence,
        basis=ConfidenceBasis.DETERMINISTIC_INVARIANT,
        collection_health=health,
        rationale=rationale + (f"; {health_detail}" if health_detail else ""),
        assessed_at=now, summary=summary, allowed_responses=responses)

    state = {AssessmentOutcome.SUPPORTED: FindingState.OPEN,
             AssessmentOutcome.NOT_SUPPORTED: FindingState.RESOLVED,
             AssessmentOutcome.INCONCLUSIVE: FindingState.INCONCLUSIVE,
             }.get(outcome, FindingState.OPEN)

    return Finding(
        finding_id=f"fnd-sdn-{finding.finding_id}",
        kind=f"sdn.{finding.kind.name.lower()}",
        entity_refs=(_attachment(finding),),
        evidence=(evidence,), missing=(), assessments=(assessment,),
        state=state, created_at=now)


def map_findings(findings, *, trustworthy_absence: bool = True,
                 health_detail: str = "") -> list[Finding]:
    return [map_finding(f, trustworthy_absence=trustworthy_absence,
                        health_detail=health_detail) for f in findings]
