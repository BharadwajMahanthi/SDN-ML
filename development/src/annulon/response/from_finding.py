"""Turn a finding into a *proposal*. Nothing here authorizes anything.

This is the narrowest layer in the chain and the one most likely to be
misread, so its limits are worth stating plainly. It reads an assessment and,
when that assessment says containment is among the permitted responses,
constructs an :class:`ActionRequest`. It then hands that request to the
broker, which evaluates it against policy the core cannot read and which will
refuse it for its own reasons (ADR-042).

The request is a question. This module cannot make it an answer.

Three refusals, each of which would otherwise let a detector's mistake become
a privileged action:

* **An assessment that does not permit containment never produces a
  request.** `ResponseClass.TEMPORARY_CONTAINMENT` has to be present, which
  means the detector reached `SUPPORTED` under healthy collection with an
  attributable workload. An `INCONCLUSIVE` finding proposes nothing.
* **A finding whose entity is not a workload never produces a request.** The
  containment backend scopes by uid; a finding about something else has no
  target it could act on, and inventing one would aim a privileged action at
  a guess.
* **The proposed duration and scope come from configuration, not from the
  finding.** A detector that could choose its own TTL would be a detector
  that could make a restriction permanent by being confident enough.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from annulon.finding import (
    AssessmentOutcome, CollectionHealth, Finding, ResponseClass,
)
from annulon.identity import EntityKind
from annulon.response.client import new_request_id
from annulon.response.contract import (
    ActionRequest, ActionType, ContractError, Target, TargetKind,
)

__all__ = ["ContainmentProposal", "ProposalOutcome", "ContainmentPolicy"]


class ProposalOutcome:
    """Why a finding did or did not become a request. Strings, not an enum,
    because these are diagnostic text rather than a decision surface."""

    PROPOSED = "proposed"
    NOT_PERMITTED_BY_ASSESSMENT = "assessment does not permit containment"
    NOT_SUPPORTED = "the assessment outcome is not SUPPORTED"
    COLLECTION_DEGRADED = "collection health is degraded"
    NO_WORKLOAD_TARGET = "the finding names no workload to act on"
    NO_ASSESSMENT = "the finding carries no assessment"
    MALFORMED = "a request could not be represented safely"


@dataclass(frozen=True)
class ContainmentProposal:
    """A request the core would like to make, and why."""

    finding_id: str
    outcome: str
    request: ActionRequest | None = None
    detail: str = ""

    @property
    def proposed(self) -> bool:
        return self.request is not None

    def to_dict(self) -> dict:
        return {"finding_id": self.finding_id, "outcome": self.outcome,
                "proposed": self.proposed, "detail": self.detail,
                "request_id": self.request.request_id if self.request else None}


@dataclass
class ContainmentPolicy:
    """Configuration that decides what may be proposed, and for how long.

    Lives with the core rather than the broker because it is a *proposal*
    policy — the broker has its own, stricter, and will cut anything this one
    gets wrong. Two independent limits is the point: a bug here is bounded by
    the broker, and a bug there is bounded by this never asking for more.
    """

    host_id: str
    boot_id: str
    duration: timedelta = timedelta(minutes=5)
    requesting_component: str = "annulon-core"
    #: When set, the proposal is scoped to the destination the finding is
    #: about rather than all egress. Narrower is always preferred: an
    #: unscoped restriction takes out the workload's legitimate traffic too.
    scope_to_observed_destination: bool = True

    def propose(self, finding: Finding) -> ContainmentProposal:
        if not finding.assessments:
            return ContainmentProposal(finding.finding_id,
                                       ProposalOutcome.NO_ASSESSMENT)
        assessment = finding.assessments[-1]

        if assessment.outcome is not AssessmentOutcome.SUPPORTED:
            return ContainmentProposal(
                finding.finding_id, ProposalOutcome.NOT_SUPPORTED,
                detail=f"outcome is {assessment.outcome.value}")
        if assessment.collection_health is not CollectionHealth.HEALTHY:
            # Redundant with the check above for this detector, and kept
            # anyway: a future detector could reach SUPPORTED while degraded,
            # and containment on a partial view is how the wrong workload
            # gets cut off.
            return ContainmentProposal(
                finding.finding_id, ProposalOutcome.COLLECTION_DEGRADED,
                detail=f"collection is {assessment.collection_health.value}")
        if ResponseClass.TEMPORARY_CONTAINMENT not in assessment.allowed_responses:
            return ContainmentProposal(
                finding.finding_id, ProposalOutcome.NOT_PERMITTED_BY_ASSESSMENT,
                detail="permitted: " + ", ".join(
                    r.value for r in assessment.allowed_responses))

        workload = next((ref for ref in finding.entity_refs
                         if ref.kind is EntityKind.WORKLOAD), None)
        if workload is None:
            return ContainmentProposal(finding.finding_id,
                                       ProposalOutcome.NO_WORKLOAD_TARGET)

        destination, destination_port = self._destination(finding)
        try:
            request = ActionRequest(
                request_id=new_request_id(),
                action_type=ActionType.TEMPORARY_EGRESS_RESTRICTION,
                target=Target(TargetKind.SERVICE_UID, self.host_id,
                              self.boot_id, workload.identifier,
                              self._service_name(finding)),
                duration=self.duration,
                reason=self._reason(finding),
                finding_id=finding.finding_id,
                requested_at=datetime.now(timezone.utc),
                requesting_component=self.requesting_component,
                destination_cidr=destination,
                destination_port=destination_port)
        except ContractError as exc:
            return ContainmentProposal(finding.finding_id,
                                       ProposalOutcome.MALFORMED,
                                       detail=str(exc)[:200])
        return ContainmentProposal(finding.finding_id, ProposalOutcome.PROPOSED,
                                   request=request)

    def _destination(self, finding: Finding) -> tuple[str | None, int | None]:
        """The single destination the finding is about, as a host CIDR.

        Returns ``None`` — meaning all egress — only when the finding does
        not name one. Preferring the narrow scope matters: the broker's
        protected-destination check will refuse an unscoped request that
        would cover the management path, so a detector that always asked for
        everything would simply never be granted anything.
        """
        if not self.scope_to_observed_destination:
            return None, None
        for evidence in finding.evidence:
            raw = (evidence.attributes or {}).get("destination")
            if not isinstance(raw, str):
                continue
            address, _, port_text = raw.rpartition(":")
            address = address.strip("[]")
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError:
                continue
            try:
                port = int(port_text)
            except ValueError:
                port = None
            if port is not None and not 0 <= port <= 65535:
                port = None
            return f"{parsed}/{parsed.max_prefixlen}", port
        return None, None

    @staticmethod
    def _service_name(finding: Finding) -> str:
        for evidence in finding.evidence:
            name = (evidence.attributes or {}).get("service_name")
            if isinstance(name, str) and name:
                return name
        return ""

    @staticmethod
    def _reason(finding: Finding) -> str:
        """A bounded, printable justification carried into the audit record."""
        if finding.evidence:
            summary = finding.evidence[0].summary
        else:
            summary = finding.kind
        cleaned = "".join(c for c in summary if 0x20 <= ord(c) != 0x7F)
        return cleaned[:250] or finding.kind
