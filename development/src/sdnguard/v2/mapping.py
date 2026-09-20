"""Map existing SDN observations onto the shared V2 event envelope.

Deliberately the smallest possible adapter. `HostObservation`, `HostTable`,
the topology registries and the detectors are untouched: V2 §16 asks for a
mapper, not a rewrite, and the SDN regression tests must stay green.

The interesting part is the identity mapping. SDN identity is
``(datapath id, port)``, which has no meaning on a plain Linux host, so it
becomes an `EntityRef` whose *namespace* carries the network scope:

    sdn_port[net=lab]:00:00:aa:bb:cc:dd:ee:ff/1

A host-side consumer can correlate on the attachment without knowing what a
DPID is, which is exactly the property V2 §8 asks for.
"""

from __future__ import annotations

from datetime import datetime

from annulon.events import (
    CollectionQuality,
    DataClassification,
    Event,
    QualityFlag,
)
from annulon.identity import EntityKind, EntityRef
from sdnguard.domain.host import HostObservation
from sdnguard.domain.identity import DatapathId, PortIdentity

__all__ = ["SDN_SENSOR", "port_ref", "switch_ref", "attachment_ref",
           "observation_to_event"]

SDN_SENSOR = "sdnguard.openflow"


def switch_ref(dpid: DatapathId, network: str = "") -> EntityRef:
    return EntityRef(EntityKind.SDN_SWITCH, f"net={network}" if network else "",
                     str(dpid))


def port_ref(port: PortIdentity, network: str = "") -> EntityRef:
    return EntityRef(EntityKind.SDN_PORT, f"net={network}" if network else "",
                     str(port))


def attachment_ref(observation: HostObservation, network: str = "") -> EntityRef:
    """A MAC observed at a port. Named an *attachment* rather than a host,
    because that is all the network layer actually witnessed -- the MAC is an
    observation, not an identity (ADR-007)."""
    return EntityRef(EntityKind.SDN_ATTACHMENT,
                     f"net={network}" if network else "",
                     f"{observation.mac}@{observation.port}")


def observation_to_event(observation: HostObservation, *, event_id: str,
                         sequence: int, received_time: datetime,
                         sensor_version: str = "0.1",
                         network: str = "",
                         generation: int | None = None,
                         quality: CollectionQuality | None = None) -> Event:
    """One SDN observation as a common event.

    Addresses are ``INTERNAL`` rather than ``SENSITIVE``: a lab MAC and IP are
    topology metadata. No frame payload is carried -- the envelope references
    what was seen, never the bytes.
    """
    attributes: dict = {
        "mac": str(observation.mac),
        "ingress_port": str(observation.port),
        "datapath_id": observation.port.datapath_id.hex,
        "source": observation.source,
        "broadcast": observation.is_broadcast,
    }
    if observation.ip is not None:
        attributes["ip"] = str(observation.ip)
    if generation is not None:
        # The connection generation travels with the event so a consumer can
        # reject evidence from a superseded switch session (ADR-011).
        attributes["connection_generation"] = generation

    return Event(
        event_id=event_id,
        event_type="sdn.host.observation",
        sensor=SDN_SENSOR,
        sensor_version=sensor_version,
        sequence=sequence,
        observed_time=observation.observed_at,
        received_time=received_time,
        entity_refs=(
            attachment_ref(observation, network),
            port_ref(observation.port, network),
            switch_ref(observation.port.datapath_id, network),
        ),
        attributes=attributes,
        data_classification=DataClassification.INTERNAL,
        quality=quality or CollectionQuality(flags=(QualityFlag.OK,)),
    )


# -- host-location conflict as a shared finding -----------------------------
#
# One vertical proof that the shared model can carry a real SDN detection.
# The existing detector, state machine and tests are untouched: this maps
# their output, it does not replace them.

from annulon.evidence import (  # noqa: E402
    Evidence,
    EvidenceGraph,
    EvidenceKind,
    MissingEvidence,
    MissingReason,
    Stance,
)
from annulon.finding import (  # noqa: E402
    Assessment,
    AssessmentOutcome,
    CollectionHealth,
    Confidence,
    ConfidenceBasis,
    Finding,
    Severity,
    summarize_evidence,
)

SDN_ORIGIN = "sdn-controller"


def host_location_finding(
    *,
    finding_id: str,
    identity,
    previous_port: PortIdentity,
    current_port: PortIdentity,
    move_event_id: str,
    probe_event_id: str | None,
    probe_replied: bool | None,
    port_down_seen: bool,
    port_status_available: bool,
    detected_at: datetime,
    network: str = "",
) -> tuple[Finding, EvidenceGraph]:
    """Build a shared finding for a host-location conflict.

    The mapping is where the SDN reasoning becomes legible to the rest of the
    platform. Three things are deliberate:

    * The move observation and the probe reply are separate evidence with
      separate source events, because they genuinely are two observations.
    * An unanswered probe is **not** recorded as evidence that the host left.
      It is ``MissingEvidence`` with ``NOT_YET_ARRIVED``, so no downstream
      rule can read silence as departure.
    * A missing port-status feed is recorded as a collection fault, which
      forces the assessment to ``INCONCLUSIVE`` rather than letting an absent
      pre-condition look like a satisfied one.
    """
    graph = EvidenceGraph()
    finding = Finding(finding_id, "sdn.host_location_conflict",
                      entity_refs=(port_ref(current_port, network),
                                   port_ref(previous_port, network)),
                      created_at=detected_at)

    move = Evidence(
        evidence_id=f"{finding_id}-EV-MOVE",
        kind=EvidenceKind.DIRECT_OBSERVATION, stance=Stance.SUPPORTS,
        origin_group=SDN_ORIGIN,
        summary=f"{identity.mac} observed at {current_port} after {previous_port}",
        observed_at=detected_at, produced_at=detected_at,
        source_event_ids=(move_event_id,))
    graph.add(move)
    finding.attach(move)

    if probe_replied is True and probe_event_id:
        reply = Evidence(
            evidence_id=f"{finding_id}-EV-PROBE",
            kind=EvidenceKind.DIRECT_OBSERVATION, stance=Stance.SUPPORTS,
            origin_group=SDN_ORIGIN,
            summary=f"{identity.mac} answered a liveness probe at {previous_port}",
            observed_at=detected_at, produced_at=detected_at,
            source_event_ids=(probe_event_id,))
        graph.add(reply)
        finding.attach(reply)
    elif probe_replied is False:
        # Silence. Recorded as absence, never as departure.
        finding.note_missing(MissingEvidence(
            f"liveness reply at {previous_port}", MissingReason.NOT_YET_ARRIVED,
            SDN_ORIGIN,
            "no reply within the probe deadline; this does not establish that "
            "the host left, only that nothing answered"))

    if port_down_seen:
        finding.attach(_port_down_evidence(finding_id, previous_port,
                                           detected_at, graph))
    elif port_status_available:
        pre = Evidence(
            evidence_id=f"{finding_id}-EV-NOPORTDOWN",
            kind=EvidenceKind.DETERMINISTIC_RULE_RESULT, stance=Stance.SUPPORTS,
            origin_group=SDN_ORIGIN,
            summary=f"no port-down observed at {previous_port} before the move",
            observed_at=detected_at, produced_at=detected_at,
            source_event_ids=(move_event_id,))
        graph.add(pre)
        finding.attach(pre)
    else:
        finding.note_missing(MissingEvidence(
            f"port lifecycle events for {previous_port}",
            MissingReason.SENSOR_UNAVAILABLE, SDN_ORIGIN,
            "port-status collection unavailable, so the migration "
            "pre-condition could not be evaluated either way"))

    summary = summarize_evidence(finding.evidence, finding.missing, graph)
    health = (CollectionHealth.DEGRADED if summary.missing_from_fault
              else CollectionHealth.HEALTHY)

    if probe_replied is True:
        outcome = AssessmentOutcome.SUPPORTED
        confidence = Confidence.STRONG
        basis = ConfidenceBasis.DIRECT_OBSERVATION
        rationale = ("the host answered at its previous location after "
                     "appearing elsewhere, so the move is not consistent with "
                     "the host having left")
    elif summary.missing_from_fault:
        outcome = AssessmentOutcome.INCONCLUSIVE
        confidence = Confidence.WEAK
        basis = ConfidenceBasis.HEURISTIC
        rationale = ("evidence is incomplete: required collection was "
                     "unavailable, so neither conclusion is supported")
    else:
        outcome = AssessmentOutcome.INCONCLUSIVE
        confidence = Confidence.WEAK
        basis = ConfidenceBasis.HEURISTIC
        rationale = ("a relocation was observed and nothing answered at the "
                     "old location; silence is not evidence of departure")

    finding.assess(Assessment(
        assessment_id=f"{finding_id}-AS-0001", outcome=outcome,
        severity=Severity.HIGH, confidence=confidence, basis=basis,
        collection_health=health, rationale=rationale, assessed_at=detected_at,
        summary=summary))
    return finding, graph


def _port_down_evidence(finding_id: str, port: PortIdentity,
                        moment: datetime, graph: EvidenceGraph) -> Evidence:
    """A port-down before the move weakens the hypothesis, so it is recorded
    as contradictory rather than quietly omitted."""
    evidence = Evidence(
        evidence_id=f"{finding_id}-EV-PORTDOWN",
        kind=EvidenceKind.DIRECT_OBSERVATION, stance=Stance.CONTRADICTS,
        origin_group=SDN_ORIGIN,
        summary=f"port-down observed at {port} before the relocation",
        observed_at=moment, produced_at=moment,
        source_event_ids=(f"{finding_id}-portstatus",))
    graph.add(evidence)
    return evidence
