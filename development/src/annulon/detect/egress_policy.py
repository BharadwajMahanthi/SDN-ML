"""A deterministic egress-allowlist detector.

The simplest falsifiable rule the project can build a full chain on: a
declared workload is permitted to reach a declared set of destinations, and a
connection attempt to anything else is a policy violation. No model, no
threshold, no score — a reader can decide by hand whether any given finding
is correct, which is the property that makes the rest of the chain
auditable.

Three refusals carry the design, and each is a way the detector could
manufacture a security claim it cannot support:

**It refuses to attribute what the sensor could not.** A `CONNECT_ATTEMPT`
whose `AttributionConfidence` is `PID_ONLY` names a pid that may have been
reused, and `NONE` names nothing at all. Neither is enough to say *this
workload* violated policy. The observation still produces a finding, but the
assessment says `INCONCLUSIVE` and records what was missing.

**It refuses to speak while blind.** If collection health says absence is not
trustworthy, a detector that reports "no violations" is reporting the sensor's
silence as the workload's innocence. Every assessment made in a degraded
epoch carries `CollectionHealth.DEGRADED` and cannot reach `SUPPORTED`.

**It never proposes an action.** A detector that could contain would be a
detector whose bugs are privileged. It emits findings; policy proposes;
the broker decides (ADR-042).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone

from annulon.evidence import (
    Evidence, EvidenceKind, MissingEvidence, MissingReason, Stance,
)
from annulon.finding import (
    Assessment, AssessmentOutcome, CollectionHealth, Confidence,
    ConfidenceBasis, EvidenceSummary, Finding, FindingState, ResponseClass,
    Severity,
)
from annulon.identity import EntityKind, EntityRef
from annulon.network.contract import (
    AttributionConfidence, NetworkObservation, NetworkOperation,
)

__all__ = ["EgressAllowlist", "EgressPolicyDetector", "WorkloadRule",
           "DetectionResult", "ORIGIN_GROUP"]

#: Lineage tag. Every piece of evidence this detector makes comes from the
#: network sensor, so three detectors reading one observation are one
#: observation seen three ways, not three witnesses (ADR on corroboration).
ORIGIN_GROUP = "network.tracefs"


@dataclass(frozen=True)
class WorkloadRule:
    """What one declared workload may reach.

    Keyed by uid because that is the identity the tracefs tier can supply and
    the containment backend can act on. That is a deliberate narrowing, not
    an assumption that uid is a workload: a shared uid means this rule covers
    every process under it, which is stated rather than hidden.
    """

    uid: int
    service_name: str
    #: Destinations this workload is permitted to reach, as CIDRs.
    permitted_destinations: tuple[str, ...] = ()
    permitted_ports: frozenset[int] = frozenset()

    def permits(self, address: str, port: int) -> bool:
        if self.permitted_ports and port not in self.permitted_ports:
            return False
        try:
            target = ipaddress.ip_address(address)
        except ValueError:
            # An address the detector cannot parse is not one it can clear.
            return False
        for cidr in self.permitted_destinations:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if target.version == network.version and target in network:
                return True
        return False


@dataclass(frozen=True)
class EgressAllowlist:
    """The rules, and what to do about workloads that have none."""

    rules: tuple[WorkloadRule, ...] = ()

    def rule_for(self, uid: int | None) -> WorkloadRule | None:
        if uid is None:
            return None
        for rule in self.rules:
            if rule.uid == uid:
                return rule
        return None

    @property
    def covered_uids(self) -> frozenset[int]:
        return frozenset(rule.uid for rule in self.rules)


@dataclass
class DetectionResult:
    """What the detector concluded, and what it could not conclude."""

    findings: list[Finding] = field(default_factory=list)
    #: Observations that named a destination outside policy but could not be
    #: attributed firmly enough to accuse a workload. Counted so a consumer
    #: can tell "nothing happened" from "we could not tell who".
    unattributable_violations: int = 0
    observations_considered: int = 0
    skipped_uncovered_workload: int = 0

    def to_dict(self) -> dict:
        return {"findings": len(self.findings),
                "unattributable_violations": self.unattributable_violations,
                "observations_considered": self.observations_considered,
                "skipped_uncovered_workload": self.skipped_uncovered_workload}


class EgressPolicyDetector:
    """Turns connection attempts into findings, or into stated uncertainty."""

    kind = "network.egress_policy_violation"

    def __init__(self, allowlist: EgressAllowlist, *, host_id: str,
                 boot_id: str) -> None:
        self._allowlist = allowlist
        self._host_id = host_id
        self._boot_id = boot_id
        self._counter = 0

    def _next(self, prefix: str) -> str:
        self._counter += 1
        return f"{prefix}-{self._counter:012d}"

    def evaluate(self, observations, *,
                 trustworthy_absence: bool,
                 health_detail: str = "") -> DetectionResult:
        """Assess a batch of observations under a stated collection health.

        ``trustworthy_absence`` is passed in rather than read, because the
        detector must not be able to decide for itself that it can see. It
        comes from the sensor's own health, which the liveness monitor earns
        by proving the path works (ADR-054).
        """
        result = DetectionResult()
        health = (CollectionHealth.HEALTHY if trustworthy_absence
                  else CollectionHealth.DEGRADED)
        for observation in observations:
            if not isinstance(observation, NetworkObservation):
                continue
            if observation.operation is not NetworkOperation.CONNECT_ATTEMPT:
                continue
            if observation.is_self_test:
                # Annulon's own liveness traffic. Excluded from security
                # interpretation, and recognised from the observation's
                # trusted marking rather than from its destination.
                continue
            if observation.remote is None:
                continue
            result.observations_considered += 1

            rule = self._rule_for(observation)
            if rule is None:
                result.skipped_uncovered_workload += 1
                continue
            if rule.permits(observation.remote.address, observation.remote.port):
                continue

            finding = self._violation(observation, rule, health, health_detail)
            if finding is None:
                result.unattributable_violations += 1
                continue
            result.findings.append(finding)
        return result

    def _rule_for(self, observation: NetworkObservation) -> WorkloadRule | None:
        """Find the rule governing this observation's workload.

        The tracefs tier gives a pid, not a uid. Until a process table
        supplies the mapping, a rule is matched only when the caller has
        already resolved it — expressed here by the observation's process
        carrying a resolved entity. Returning ``None`` means "not covered",
        which is deliberately different from "permitted".
        """
        entity = observation.process.entity
        if entity is None or entity.kind is not EntityKind.WORKLOAD:
            return None
        try:
            uid = int(entity.identifier)
        except (TypeError, ValueError):
            return None
        return self._allowlist.rule_for(uid)

    def _violation(self, observation: NetworkObservation, rule: WorkloadRule,
                   health: CollectionHealth, health_detail: str) -> Finding | None:
        """Build the finding, or decline when attribution cannot carry it."""
        confidence_ok = observation.supports_workload_attribution
        evidence = Evidence(
            evidence_id=self._next("ev"),
            kind=EvidenceKind.DETERMINISTIC_RULE_RESULT,
            stance=Stance.SUPPORTS,
            origin_group=ORIGIN_GROUP,
            summary=(f"{rule.service_name} (uid {rule.uid}) attempted a "
                     f"connection to {observation.remote} which its egress "
                     f"policy does not permit"),
            observed_at=observation.observed_at,
            produced_at=datetime.now(timezone.utc),
            source_event_ids=(observation.observation_id,),
            attributes={
                "destination": str(observation.remote),
                "transport": observation.transport.value,
                "attribution_confidence": observation.process.confidence.value,
                "pid": observation.process.pid,
                "sensor_id": observation.sensor_id,
                "flow_key_namespace_qualified":
                    observation.flow_key_is_namespace_qualified,
            })

        missing: list[MissingEvidence] = []
        if not confidence_ok:
            missing.append(MissingEvidence(
                expected="process-instance identity for the connecting process",
                reason=MissingReason.CAPABILITY_UNSUPPORTED,
                origin_group=ORIGIN_GROUP,
                detail=("the tracefs tier supplies a pid without a start "
                        "time, so the observation cannot be bound to one "
                        "process instance")))
        if health is CollectionHealth.DEGRADED:
            missing.append(MissingEvidence(
                expected="a complete view of this workload's egress",
                reason=MissingReason.SENSOR_UNAVAILABLE,
                origin_group=ORIGIN_GROUP,
                detail=health_detail or "collection was degraded"))
        if not observation.flow_key_is_namespace_qualified:
            missing.append(MissingEvidence(
                expected="the network namespace of the observed socket",
                reason=MissingReason.CAPABILITY_UNSUPPORTED,
                origin_group=ORIGIN_GROUP,
                detail=("this tier cannot say which namespace a flow "
                        "belongs to, so the destination is not proven to be "
                        "reachable from the host's own routing view")))

        summary = EvidenceSummary(
            supporting=1, contradicting=0, context=0, missing=len(missing),
            missing_from_fault=sum(1 for m in missing if m.is_collection_fault),
            # One origin group, because every piece of this finding comes
            # from the same sensor reading. `shared_root_events` is true for
            # the same reason: this is one observation, not corroboration.
            origin_groups=(ORIGIN_GROUP,),
            shared_root_events=True,
            # No model contributed to this. The rule is deterministic, and
            # saying otherwise would misrepresent what the confidence rests
            # on.
            statistical_only=False)

        # Outcome and confidence are decided by what is actually known, not
        # by how alarming the destination is.
        if health is CollectionHealth.DEGRADED or not confidence_ok:
            outcome = AssessmentOutcome.INCONCLUSIVE
            confidence = Confidence.WEAK
            responses = (ResponseClass.OBSERVE_ONLY, ResponseClass.INVESTIGATE)
            rationale = (
                "a connection outside policy was observed, but "
                + ("collection was degraded; " if health is CollectionHealth.DEGRADED
                   else "")
                + ("the observation cannot be bound to a process instance; "
                   if not confidence_ok else "")
                + "so this does not support acting against a specific workload")
        else:
            outcome = AssessmentOutcome.SUPPORTED
            confidence = Confidence.MODERATE
            responses = (ResponseClass.OBSERVE_ONLY, ResponseClass.INVESTIGATE,
                         ResponseClass.TEMPORARY_CONTAINMENT)
            rationale = (
                "a deterministic egress rule was violated by an observation "
                "bound to a known workload, under healthy collection")

        assessment = Assessment(
            assessment_id=self._next("as"),
            outcome=outcome, severity=Severity.MEDIUM, confidence=confidence,
            basis=ConfidenceBasis.DETERMINISTIC_INVARIANT,
            collection_health=health, rationale=rationale,
            assessed_at=datetime.now(timezone.utc), summary=summary,
            allowed_responses=responses)

        state = (FindingState.INCONCLUSIVE
                 if outcome is AssessmentOutcome.INCONCLUSIVE
                 else FindingState.OPEN)
        return Finding(
            finding_id=self._next("fnd"), kind=self.kind,
            entity_refs=(EntityRef(EntityKind.WORKLOAD,
                                   f"host={self._host_id};boot={self._boot_id}",
                                   str(rule.uid)),),
            evidence=(evidence,), missing=tuple(missing),
            assessments=(assessment,), state=state,
            created_at=datetime.now(timezone.utc))
