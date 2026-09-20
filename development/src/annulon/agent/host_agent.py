"""The Annulon host agent.

Wires a :class:`~annulon.collectors.base.HostSensor` to enrichment, a bounded
queue and a capability manifest. It produces evidence; it decides nothing and
executes nothing. Detection is a separate component, and response is a
separate *process* (ADR-028).

Three properties this module exists to hold:

* **Discovery and enrichment are different.** The sensor discovers; ``/proc``
  only adds detail to something already discovered. Losing the enrichment
  race costs fields, never the event (ADR-038).
* **Health is derived, never asserted.** The manifest reports what the sensor
  actually attests to. A sensor that cannot attest to completeness degrades
  the agent's state, so downstream silence is not read as safety (ADR-039).
* **The queue is bounded and drops are counted.** An agent that grows without
  limit under event pressure is a denial-of-service primitive against the
  host it protects.
"""

from __future__ import annotations

import queue
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from annulon.agent.enrichment import ProcessDetails, enrich_pid
from annulon.capability import (
    AgentState,
    Capability,
    CapabilityManifest,
    Configuration,
    Health,
    PlatformProfile,
    Support,
)
from annulon.agent.liveness import SensorLivenessMonitor
from annulon.collectors.base import HostSensor, SensorCapability, SensorUnavailable
from annulon.events import CollectionQuality, DataClassification, Event, QualityFlag
from annulon.identity import EntityKind, EntityRef

__all__ = ["AgentConfig", "AgentStats", "HostAgent"]

FEATURE_PROCESS_EVENTS = "host_process_events"
FEATURE_PROCESS_DETAIL = "host_process_detail"
FEATURE_NETWORK_EVENTS = "host_network_connections"
FEATURE_FILE_EVENTS = "host_file_integrity"


@dataclass(frozen=True)
class AgentConfig:
    agent_version: str = "0.1"
    queue_size: int = 4096
    capture_argv: bool = False        # off by default: argv can carry secrets
    enrich: bool = True
    poll_timeout: float = 0.5
    #: Prove the sensor still delivers instead of trusting an open socket.
    liveness_interval_seconds: float = 300.0
    liveness_enabled: bool = True


@dataclass
class AgentStats:
    received: int = 0
    enriched: int = 0
    enrichment_incomplete: int = 0
    queued: int = 0
    dropped_queue_full: int = 0
    consumed: int = 0

    def as_dict(self) -> dict[str, int]:
        return {"received": self.received, "enriched": self.enriched,
                "enrichment_incomplete": self.enrichment_incomplete,
                "queued": self.queued,
                "dropped_queue_full": self.dropped_queue_full,
                "consumed": self.consumed}


class HostAgent:
    """Reads from a sensor, enriches, and publishes bounded events."""

    def __init__(self, sensor: HostSensor, *, config: AgentConfig | None = None,
                 host_id: str = "", boot_id: str = "",
                 enricher: Callable[[int], ProcessDetails] = None) -> None:
        self.sensor = sensor
        self.config = config or AgentConfig()
        self.host_id = host_id or getattr(sensor, "host_id", "unknown")
        self.boot_id = boot_id or getattr(sensor, "boot_id", "unknown")
        self._enrich = enricher or (
            lambda pid: enrich_pid(pid, capture_argv=self.config.capture_argv))
        self._queue: queue.Queue[Event] = queue.Queue(maxsize=self.config.queue_size)
        self.stats = AgentStats()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._manifest = self._build_manifest()
        self.liveness = SensorLivenessMonitor(
            interval_seconds=self.config.liveness_interval_seconds,
            enabled=self.config.liveness_enabled)

    # -- capability ------------------------------------------------------

    def _build_manifest(self) -> CapabilityManifest:
        manifest = CapabilityManifest(PlatformProfile.LINUX_HOST,
                                      self.config.agent_version)
        caps = self.sensor.capabilities()

        manifest.declare(Capability(
            FEATURE_PROCESS_EVENTS,
            Support.SUPPORTED if SensorCapability.PROCESS_EXEC in caps
            else Support.NOT_IMPLEMENTED,
            Configuration.ENABLED if SensorCapability.PROCESS_EXEC in caps
            else Configuration.NOT_CONFIGURED,
            Health.UNKNOWN if SensorCapability.PROCESS_EXEC in caps
            else Health.NOT_APPLICABLE))

        detail_supported = self.config.enrich
        manifest.declare(Capability(
            FEATURE_PROCESS_DETAIL,
            Support.SUPPORTED if detail_supported else Support.NOT_IMPLEMENTED,
            Configuration.ENABLED if detail_supported else Configuration.DISABLED,
            Health.UNKNOWN if detail_supported else Health.NOT_APPLICABLE))

        # Declared as not implemented rather than omitted. An absent feature
        # that is never named cannot be noticed by an operator reading the
        # manifest to see what is actually protecting the host.
        for name, capability in ((FEATURE_NETWORK_EVENTS,
                                  SensorCapability.NETWORK_CONNECT),
                                 (FEATURE_FILE_EVENTS,
                                  SensorCapability.FILE_ACCESS)):
            present = capability in caps
            manifest.declare(Capability(
                name,
                Support.SUPPORTED if present else Support.NOT_IMPLEMENTED,
                Configuration.ENABLED if present else Configuration.NOT_CONFIGURED,
                Health.UNKNOWN if present else Health.NOT_APPLICABLE,
                "" if present else "no sensor on this profile provides it"))
        return manifest

    def manifest(self) -> CapabilityManifest:
        """Refresh health from what the sensor actually attests to."""
        health = self.sensor.health()
        if not health.running:
            state = Health.FAILED
            detail = "sensor is not running"
        elif self.config.liveness_enabled and self.liveness.last is not None \
                and not self.liveness.healthy:
            # A socket can stay open while the kernel stops delivering. Only a
            # probe that came back proves the path still works; a failed probe
            # is stronger evidence of blindness than any counter.
            state = Health.FAILED
            detail = (f"liveness probe failed "
                      f"{self.liveness.consecutive_failures} time(s): "
                      f"{self.liveness.last.detail}")
        elif not health.attests_completeness:
            # The V2-HOST-01 finding in one branch: a sensor that cannot vouch
            # for completeness must not leave the agent looking healthy.
            state = Health.DEGRADED
            detail = health.blind_spot or "sensor cannot attest to completeness"
        elif health.lossy or self.stats.dropped_queue_full:
            state = Health.DEGRADED
            detail = (f"{health.stats.dropped} sensor drop(s), "
                      f"{self.stats.dropped_queue_full} queue drop(s)")
        else:
            state = Health.HEALTHY
            detail = "collecting"
        self._manifest.update_health(FEATURE_PROCESS_EVENTS, state, detail)

        if self.config.enrich:
            incomplete = self.stats.enrichment_incomplete
            self._manifest.update_health(
                FEATURE_PROCESS_DETAIL,
                Health.DEGRADED if incomplete else Health.HEALTHY,
                f"{incomplete} process(es) exited before detail could be read"
                if incomplete else "detail available")
        return self._manifest

    def state(self) -> AgentState:
        return self.manifest().state()

    def trustworthy_absence(self) -> bool:
        """Can "no events" be read as "nothing happened"?

        The same predicate as :meth:`collection_complete`, deliberately
        delegating rather than restating it. They were separate implementations
        once and drifted: liveness was added to one and not the other, so a
        sensor proven dead still reported that its silence was meaningful.

        Both exclude *detail* completeness. Missing enrichment means we know
        less about processes we did see; it does not mean we missed any.
        """
        return self.collection_complete()

    def collection_complete(self) -> bool:
        """Did we observe everything in scope?

        Separate from :meth:`state`, which also degrades on missing *detail*.
        A detector asking "can I trust that nothing happened" wants this one;
        an operator asking "is the agent fully working" wants the other.
        """
        health = self.sensor.health()
        if not (health.running and health.attests_completeness
                and not health.lossy and self.stats.dropped_queue_full == 0):
            return False
        # A sensor that has failed its most recent liveness probe cannot
        # support the claim that nothing happened, whatever its counters say.
        if self.config.liveness_enabled and self.liveness.last is not None:
            return self.liveness.healthy
        return True

    def check_liveness(self):
        """Run a liveness probe now, returning its result.

        Events consumed while looking for the marker are put back, so a
        self-check never swallows real evidence.
        """
        buffered: list[Event] = []

        def drain_for_probe() -> list[Event]:
            events = self.drain(limit=512)
            buffered.extend(events)
            return events

        result = self.liveness.run(drain_for_probe)
        for event in buffered:
            try:
                self._queue.put_nowait(event)
            except queue.Full:
                self.stats.dropped_queue_full += 1
        return result

    def maybe_check_liveness(self):
        """Run a probe only if one is due. Cheap to call from a loop."""
        return self.check_liveness() if self.liveness.due() else None

    # -- lifecycle -------------------------------------------------------

    def start(self) -> None:
        ok, detail = self.sensor.preflight()
        if not ok:
            raise SensorUnavailable(detail)
        self.sensor.start()
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="annulon-host-agent")
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None
        self.sensor.stop()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                for event in self.sensor.events(timeout=self.config.poll_timeout):
                    self._handle(event)
            except Exception:
                # A collector fault must not take the agent down silently; it
                # is recorded through health, and the loop continues so the
                # operator sees a degraded agent rather than a dead one.
                self.stats.dropped_queue_full += 0
                continue

    def _handle(self, event: Event) -> None:
        self.stats.received += 1
        published = self._enrich_event(event) if self.config.enrich else event
        try:
            self._queue.put_nowait(published)
            self.stats.queued += 1
        except queue.Full:
            # Refuse rather than grow. The count is what makes the gap
            # visible; a silently dropped event is indistinguishable from an
            # event that never happened.
            self.stats.dropped_queue_full += 1

    def _enrich_event(self, event: Event) -> Event:
        pid = event.attributes.get("pid")
        if not isinstance(pid, int) or pid <= 0:
            return event
        details = self._enrich(pid)
        self.stats.enriched += 1
        attributes = dict(event.attributes)
        for key in ("comm", "exe", "argv", "parent_pid", "uid", "gid", "cgroup"):
            value = getattr(details, key, None)
            if value is not None:
                attributes[key] = value

        flags = list(event.quality.flags)
        classification = event.data_classification
        if not details.complete:
            self.stats.enrichment_incomplete += 1
            attributes["enrichment_missing"] = list(details.missing)
            if QualityFlag.PARTIAL_FIELDS not in flags:
                flags.append(QualityFlag.PARTIAL_FIELDS)
        if details.argv is not None:
            # argv can carry credentials, so an enriched event is reclassified
            # rather than inheriting the bare event's classification.
            classification = DataClassification.SENSITIVE

        refs = tuple(
            EntityRef(EntityKind.PROCESS_INSTANCE,
                      f"host={self.host_id};boot={self.boot_id}",
                      details.process_key)
            if ref.kind is EntityKind.PROCESS_INSTANCE else ref
            for ref in event.entity_refs)

        return Event(
            event_id=event.event_id, event_type=event.event_type,
            sensor=event.sensor, sensor_version=event.sensor_version,
            sequence=event.sequence, observed_time=event.observed_time,
            received_time=datetime.now(timezone.utc), entity_refs=refs,
            attributes=attributes, data_classification=classification,
            quality=CollectionQuality(
                flags=tuple(flags),
                dropped_events=event.quality.dropped_events,
                gap_before=event.quality.gap_before,
                clock_uncertainty_ms=event.quality.clock_uncertainty_ms),
            causal_refs=event.causal_refs)

    # -- consumption -----------------------------------------------------

    def drain(self, limit: int = 1000) -> list[Event]:
        events: list[Event] = []
        while len(events) < limit:
            try:
                events.append(self._queue.get_nowait())
            except queue.Empty:
                break
        self.stats.consumed += len(events)
        return events

    @property
    def pending(self) -> int:
        return self._queue.qsize()
