"""Deterministic detectors: turn state-machine actions into findings.

Deliberately dull. Every rule here is a stated condition over observed
evidence, with no scoring, no threshold tuning and no model. That is the
point: the project must be able to say what the system detects and why,
before any question of whether machine learning adds measurable value.

Two detectors, matching the two TopoGuard attacks:

* :class:`HostHijackDetector` consumes the movement machine's resolution and
  emits a finding with the evidence that produced it.
* :class:`LinkFabricationDetector` consumes port-classification conflicts and
  topology inconsistencies.

Neither detector decides what to *do*; that is the policy engine's job.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sdnguard.domain.events import (
    FindingKind,
    SecurityFinding,
    Severity,
    Verdict,
)
from sdnguard.domain.host import HostIdentity
from sdnguard.domain.identity import PortIdentity
from sdnguard.hosts.movement import ActionKind, HostMovementState, MovementState
from sdnguard.topology.links import Link, LinkRegistry
from sdnguard.topology.ports import ClassificationConflict, PortRegistry

__all__ = ["HostHijackDetector", "LinkFabricationDetector", "DetectionPolicy"]


@dataclass(frozen=True)
class DetectionPolicy:
    """Severity assignment, in one place so it can be argued about.

    These are *labels*, not probabilities. A hijack confirmed by a probe
    reply is HIGH because two independent conditions agree; a missing
    port-down alone is LOW because the pre-condition is attacker-influenceable
    and benign wireless roaming routinely omits it.
    """

    hijack_severity: Severity = Severity.HIGH
    missing_port_down_severity: Severity = Severity.LOW
    multi_location_severity: Severity = Severity.MEDIUM
    link_fabrication_severity: Severity = Severity.HIGH
    host_on_switch_port_severity: Severity = Severity.LOW
    unresolved_probe_severity: Severity = Severity.INFO


class HostHijackDetector:
    """Emits findings from resolved movement state."""

    def __init__(self, policy: DetectionPolicy | None = None) -> None:
        self.policy = policy or DetectionPolicy()

    def from_resolution(self, state: HostMovementState, actions: list,
                        detected_at: datetime,
                        concurrent_locations: int = 1) -> list[SecurityFinding]:
        """Translate the movement machine's output into findings.

        The mapping is total: every EMIT_FINDING action produces exactly one
        finding, and no finding is produced without one. That keeps the
        detector auditable -- a finding can always be traced to the
        transition that caused it.
        """
        findings: list[SecurityFinding] = []
        port = state.current.port if state.current else None
        if port is None:
            return findings

        for action in actions:
            if action.kind is not ActionKind.EMIT_FINDING:
                continue
            findings.append(self._build(action.detail, state, port, detected_at))

        # Multi-location is reported when validation did NOT establish that
        # the host left. If the probe expired, the old location was silent,
        # so a lingering table entry inside its TTL is bookkeeping rather
        # than evidence of concurrent presence -- reporting it would make
        # every ordinary relocation look multi-homed (KF-16). When the probe
        # replied, or could not be resolved, concurrency is a real question
        # and the legacy code skipped exactly that case.
        if concurrent_locations > 1 and state.state is not MovementState.MOVE_ACCEPTED:
            findings.append(SecurityFinding.create(
                FindingKind.HOST_MULTI_LOCATION,
                Verdict.SUSPICIOUS,
                self.policy.multi_location_severity,
                state.identity, port, detected_at,
                tuple(state.evidence) + (
                    f"observed at {concurrent_locations} ports concurrently",),
                f"{state.identity.mac} is present at {concurrent_locations} "
                "ports at once"))
        return findings

    def _build(self, detail: str, state: HostMovementState,
               port: PortIdentity, detected_at: datetime) -> SecurityFinding:
        evidence = tuple(state.evidence) or ("no evidence recorded",)
        if detail == "host_location_hijack":
            return SecurityFinding.create(
                FindingKind.HOST_LOCATION_HIJACK, Verdict.SUSPICIOUS,
                self.policy.hijack_severity, state.identity, port, detected_at,
                evidence,
                f"{state.identity.mac} answered at its previous location after "
                f"appearing at {port}; the move is not consistent with the host "
                "having left")
        if detail == "host_moved_without_port_down":
            return SecurityFinding.create(
                FindingKind.HOST_MOVED_WITHOUT_PORT_DOWN, Verdict.SUSPICIOUS,
                self.policy.missing_port_down_severity, state.identity, port,
                detected_at, evidence,
                f"{state.identity.mac} moved to {port} with no port-down "
                "observed at its previous port")
        if detail == "probe_unresolved":
            return SecurityFinding.create(
                FindingKind.PROBE_UNRESOLVED, Verdict.INCONCLUSIVE,
                self.policy.unresolved_probe_severity, state.identity, port,
                detected_at, evidence,
                f"validation of {state.identity.mac}'s move to {port} could "
                "not complete; neither accused nor cleared")
        raise ValueError(f"unmapped finding detail {detail!r}")

    def verdict_for(self, state: HostMovementState) -> Verdict:
        """The overall verdict for a host's current movement state."""
        if state.state is MovementState.SUSPICIOUS_MOVE:
            return Verdict.SUSPICIOUS
        if state.state is MovementState.MOVE_ACCEPTED:
            return Verdict.BENIGN
        return Verdict.INCONCLUSIVE


class LinkFabricationDetector:
    """Emits findings from port-classification conflicts and link topology."""

    def __init__(self, policy: DetectionPolicy | None = None) -> None:
        self.policy = policy or DetectionPolicy()

    def from_conflict(self, conflict: ClassificationConflict,
                      identity: HostIdentity, port: PortIdentity,
                      detected_at: datetime) -> SecurityFinding | None:
        """A per-packet classification conflict."""
        if conflict is ClassificationConflict.NONE:
            return None
        if conflict is ClassificationConflict.LLDP_ON_HOST_PORT:
            return SecurityFinding.create(
                FindingKind.LINK_FABRICATION, Verdict.SUSPICIOUS,
                self.policy.link_fabrication_severity, identity, port,
                detected_at,
                (f"LLDP observed on {port}, which is classified as a host port",
                 "a host port cannot legitimately originate link discovery"),
                f"possible link fabrication: LLDP from host port {port}")
        return SecurityFinding.create(
            FindingKind.HOST_TRAFFIC_FROM_SWITCH_PORT, Verdict.INCONCLUSIVE,
            self.policy.host_on_switch_port_severity, identity, port,
            detected_at,
            (f"host traffic observed on {port}, classified as a switch port",
             "intended response is unrecoverable from the legacy source (B-3)"),
            f"host traffic from switch port {port}")

    def from_topology(self, links: LinkRegistry, ports: PortRegistry,
                      identity: HostIdentity,
                      detected_at: datetime) -> list[SecurityFinding]:
        """Links whose endpoint is a known host port.

        Catches a link accepted *before* its endpoint was known to be a host
        port -- something a per-packet check alone cannot do.
        """
        findings = []
        for link, endpoint in links.inconsistent_endpoints(ports):
            findings.append(SecurityFinding.create(
                FindingKind.LINK_FABRICATION, Verdict.SUSPICIOUS,
                self.policy.link_fabrication_severity, identity, endpoint,
                detected_at,
                (f"link {link} terminates on {endpoint}",
                 f"{endpoint} is classified as a host port"),
                f"inconsistent link topology at {endpoint}"))
        return findings
