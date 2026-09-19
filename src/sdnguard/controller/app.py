"""The security controller: the one place the P4 components are wired together.

It implements :class:`SecurityCore`, so it can be driven by the fake adapter,
by a replay harness, or by a real OS-Ken adapter without changing a line. It
imports no framework (ADR-005) and holds no eventlet (ADR-017).

Design rules it enforces, each recovered from a specific legacy defect:

* A probe that cannot be sent is resolved immediately as UNDELIVERABLE rather
  than left outstanding forever.
* A switch disconnect cancels its probes, drops its ports and links, and
  invalidates movement state anchored to it.
* A stale connection generation cannot resolve a probe issued before a
  reconnect.
* Every detection produces a finding and a policy decision, both recorded.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sdnguard.adapter.contract import (
    LinkObserved,
    PortChanged,
    PortStatus,
    SendOutcome,
    SwitchCommands,
    SwitchConnected,
    SwitchDisconnected,
)
from sdnguard.clock import Clock, SystemClock
from sdnguard.detection.deterministic import (
    DetectionPolicy,
    HostHijackDetector,
    LinkFabricationDetector,
)
from sdnguard.domain.events import ProbeOutcome, ProbeResult, SecurityFinding
from sdnguard.domain.host import HostObservation
from sdnguard.domain.identity import DatapathId, PortIdentity
from sdnguard.hosts.movement import ActionKind, MovementStateMachine
from sdnguard.hosts.table import HostTable
from sdnguard.observability.evidence import EvidenceStore
from sdnguard.policy.engine import PolicyEngine
from sdnguard.probes.manager import ProbeManager, ProbeManagerFull, ProbeRejected
from sdnguard.topology.links import LinkRegistry
from sdnguard.topology.ports import ClassificationConflict, PortRegistry
from sdnguard.topology.switches import SwitchRegistry

__all__ = ["SecurityController", "ControllerStats"]


@dataclass
class ControllerStats:
    observations: int = 0
    movements: int = 0
    probes_issued: int = 0
    probes_undeliverable: int = 0
    findings: int = 0
    enforcements: int = 0
    dropped_events: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "observations": self.observations,
            "movements": self.movements,
            "probes_issued": self.probes_issued,
            "probes_undeliverable": self.probes_undeliverable,
            "findings": self.findings,
            "enforcements": self.enforcements,
            "dropped_events": self.dropped_events,
        }


@dataclass
class SecurityController:
    commands: SwitchCommands
    clock: Clock = field(default_factory=SystemClock)
    policy: PolicyEngine = field(default_factory=PolicyEngine)
    detection_policy: DetectionPolicy = field(default_factory=DetectionPolicy)
    probe_timeout: timedelta = timedelta(seconds=3)

    ports: PortRegistry = field(default_factory=PortRegistry)
    switches: SwitchRegistry = field(default_factory=SwitchRegistry)
    links: LinkRegistry = field(default_factory=LinkRegistry)
    hosts: HostTable = field(default_factory=HostTable)
    movement: MovementStateMachine = field(default_factory=MovementStateMachine)
    evidence: EvidenceStore = field(default_factory=EvidenceStore)
    stats: ControllerStats = field(default_factory=ControllerStats)

    def __post_init__(self) -> None:
        self.probes = ProbeManager(clock=self.clock, timeout=self.probe_timeout)
        self.hijack = HostHijackDetector(self.detection_policy)
        self.fabrication = LinkFabricationDetector(self.detection_policy)

    # -- inbound: SecurityCore ------------------------------------------

    def on_switch_connected(self, event: SwitchConnected) -> None:
        self.switches.connect(event.dpid, event.at)
        for port in event.ports:
            self.ports.register(port)
        # A reconnect makes any probe issued under the old generation
        # unanswerable: the port may now be a different physical link.
        for result in self.probes.cancel_stale_generations(
                event.dpid, event.generation):
            self._resolve_probe(result)

    def on_switch_disconnected(self, event: SwitchDisconnected) -> None:
        self.switches.disconnect(event.dpid, event.at)
        for result in self.probes.cancel_switch(event.dpid):
            self._resolve_probe(result, suppress_missing=True)
        # Capture the port list BEFORE clearing the registry: reading it
        # afterwards finds nothing and silently leaks every host that was
        # attached to the departed switch -- the same class of leak as KF-12.
        departed_ports = self._ports_of(event.dpid)
        self.ports.remove_switch(event.dpid)
        self.links.remove_switch(event.dpid)
        self.movement.on_switch_lost(event.dpid)
        for port in departed_ports:
            self.hosts.forget_port(port)

    def on_port_changed(self, event: PortChanged) -> None:
        if event.status is PortStatus.ADDED:
            self.ports.register(event.port)
            return
        if event.status is PortStatus.UP:
            self.ports.observe_port_up(event.port)
            return
        # DOWN or REMOVED: record the migration pre-condition for every host
        # currently attached here, before any of them appears elsewhere.
        record = self.ports.observe_port_down(event.port)
        for mac in sorted(record.host_macs):
            self.movement.on_port_down(mac, event.port)
        if event.status is PortStatus.REMOVED:
            self.links.remove_port(event.port)

    def on_host_observation(self, observation: HostObservation,
                            generation: int) -> None:
        self.stats.observations += 1
        conflict = self.ports.observe_host(observation.port, observation.mac)
        if conflict is not ClassificationConflict.NONE:
            self._record(self.fabrication.from_conflict(
                conflict, observation.identity, observation.port,
                observation.observed_at))

        self.hosts.observe(observation)
        state, actions = self.movement.on_observation(
            observation.identity, observation.to_location(), generation)
        self._perform(actions, observation, generation)

    def on_link_observed(self, event: LinkObserved) -> None:
        conflict = self.ports.observe_lldp(event.receiving_port)
        if conflict is not ClassificationConflict.NONE:
            record = self.hosts.hosts_on(event.receiving_port)
            identity = record[0].identity if record else None
            if identity is not None:
                self._record(self.fabrication.from_conflict(
                    conflict, identity, event.receiving_port, event.at))
            return
        if event.claimed_source is not None:
            self.links.observe(event.receiving_port, event.claimed_source, event.at)

    # -- outbound and resolution ----------------------------------------

    def _perform(self, actions: list, observation: HostObservation,
                 generation: int) -> None:
        for action in actions:
            if action.kind is ActionKind.ISSUE_PROBE and action.port is not None:
                self.stats.movements += 1
                self._issue_probe(observation, action.port, generation)
            elif action.kind is ActionKind.CANCEL_PROBE:
                result = self.probes.cancel(observation.mac,
                                            "host re-observed at current port")
                if result is not None:
                    # The host is demonstrably where we thought; there is
                    # nothing left to validate, so no finding is produced.
                    pass

    def _issue_probe(self, observation: HostObservation,
                     target: PortIdentity, generation: int) -> None:
        try:
            probe = self.probes.issue(observation.identity, target,
                                      generation=generation,
                                      timeout=self.probe_timeout)
        except (ProbeRejected, ProbeManagerFull):
            self.stats.dropped_events += 1
            return
        self.movement.on_probe_issued(observation.mac, probe)
        self.stats.probes_issued += 1

        result = self.commands.send_probe(probe, generation=generation)
        if not result.sent:
            # Never leave an unsendable probe outstanding: that is exactly how
            # the legacy probedPorts map grew without bound.
            self.stats.probes_undeliverable += 1
            undeliverable = self.probes.mark_undeliverable(
                probe.correlation_id, f"{result.outcome.value}: {result.detail}")
            if undeliverable is not None:
                self._resolve_probe(undeliverable)

    def tick(self) -> list[ProbeResult]:
        """Advance expiry. Called by the adapter's timer or by a test."""
        results = self.probes.expire()
        for result in results:
            self._resolve_probe(result)
        return results

    def _resolve_probe(self, result: ProbeResult, *,
                       suppress_missing: bool = False) -> None:
        mac = self._mac_for(result.correlation_id)
        if mac is None:
            return
        try:
            state, actions = self.movement.on_probe_result(mac, result)
        except Exception:
            if suppress_missing:
                return
            raise
        record = self.hosts.get(mac)
        findings = self.hijack.from_resolution(
            state, actions, self.clock.now(),
            concurrent_locations=record.concurrent_locations if record else 1)
        for finding in findings:
            self._record(finding)

    def _mac_for(self, correlation_id: str):
        for probe_id, mac in self.movement.outstanding_probes().items():
            if probe_id == correlation_id:
                return mac
        return None

    def observe_probe_reply(self, correlation_id: str, *,
                            source_port: PortIdentity, mac) -> bool:
        """An observed frame that may be a probe reply. Returns whether it
        correlated -- an unmatched reply is not an error, just not evidence."""
        result = self.probes.correlate(correlation_id, source_port=source_port,
                                       mac=mac)
        if result is None:
            return False
        self._resolve_probe(result)
        return True

    def _record(self, finding: SecurityFinding | None) -> None:
        if finding is None:
            return
        self.stats.findings += 1
        decision = self.policy.decide(finding, self.clock.now())
        if decision.is_enforcing:
            self.stats.enforcements += 1
        self.evidence.record(finding, decision)

    def _ports_of(self, dpid: DatapathId) -> list[PortIdentity]:
        return [r.port for r in self.ports if r.port.datapath_id == dpid]

    # -- introspection ---------------------------------------------------

    def health(self) -> dict:
        return {
            "switches_connected": len(self.switches.connected()),
            "ports_tracked": len(self.ports),
            "hosts_tracked": len(self.hosts),
            "probes_outstanding": len(self.probes),
            "findings_recorded": len(self.evidence),
            "enforcement_disabled": self.policy.enforcement_disabled,
            **self.stats.as_dict(),
        }
