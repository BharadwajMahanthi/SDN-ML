"""Host agent: enrichment, bounded queue, and health that tells the truth."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterator

import pytest

from annulon.agent.enrichment import ProcessDetails, enrich_pid
from annulon.agent.host_agent import AgentConfig, HostAgent
from annulon.capability import AgentState, Health
from annulon.collectors.base import (
    SensorCapability,
    SensorHealth,
    SensorStats,
    SensorUnavailable,
)
from annulon.events import CollectionQuality, DataClassification, Event, QualityFlag
from annulon.identity import EntityKind, EntityRef

T0 = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)


class FakeSensor:
    """A sensor whose health and output the test controls exactly."""

    name = "fake"
    host_id = "h1"
    boot_id = "b7"

    def __init__(self, *, events=(), attests=True, running=True,
                 dropped=0, available=True,
                 caps=frozenset({SensorCapability.PROCESS_EXEC,
                                 SensorCapability.PROCESS_EXIT})) -> None:
        self._events = list(events)
        self._attests = attests
        self._running = running
        self._dropped = dropped
        self._available = available
        self._caps = caps
        self.started = False

    def capabilities(self): return self._caps
    def requires_root(self): return True
    def preflight(self):
        return (self._available, "ok" if self._available else "not here")
    def start(self):
        if not self._available:
            raise SensorUnavailable("not here")
        self.started = True
    def stop(self): self.started = False
    def health(self) -> SensorHealth:
        return SensorHealth(running=self._running, detail="",
                            stats=SensorStats(dropped=self._dropped),
                            attests_completeness=self._attests,
                            blind_spot="" if self._attests else "cannot see short-lived")
    def events(self, timeout: float = 1.0) -> Iterator[Event]:
        while self._events:
            yield self._events.pop(0)


def exec_event(pid: int = 1234, sequence: int = 1) -> Event:
    return Event(
        event_id=f"fake-{sequence:016d}", event_type="host.process.exec",
        sensor="fake", sensor_version="0.1", sequence=sequence,
        observed_time=T0, received_time=T0,
        entity_refs=(EntityRef(EntityKind.PROCESS_INSTANCE,
                               "host=h1;boot=b7", str(pid)),),
        attributes={"pid": pid},
        quality=CollectionQuality(flags=(QualityFlag.OK,)))


def agent(sensor: FakeSensor, **kw) -> HostAgent:
    config = AgentConfig(**{"enrich": False, **kw})
    return HostAgent(sensor, config=config, host_id="h1", boot_id="b7")


# -- enrichment is not discovery -------------------------------------------


def test_a_process_that_exited_yields_a_partial_event_not_a_lost_one():
    """The whole point of demoting /proc to enrichment (ADR-038): losing the
    race costs detail, never the observation."""
    sensor = FakeSensor(events=[exec_event(pid=4242)])
    a = HostAgent(sensor, config=AgentConfig(enrich=True), host_id="h1",
                  boot_id="b7",
                  enricher=lambda pid: ProcessDetails(pid, complete=False,
                                                      missing=("comm", "exe")))
    a._handle(sensor._events.pop(0))
    event = a.drain()[0]
    assert event.attributes["pid"] == 4242, "the event survives"
    assert QualityFlag.PARTIAL_FIELDS in event.quality.flags
    assert event.attributes["enrichment_missing"] == ["comm", "exe"]
    assert a.stats.enrichment_incomplete == 1


def test_a_fully_enriched_event_is_not_flagged_partial():
    sensor = FakeSensor(events=[exec_event()])
    a = HostAgent(sensor, config=AgentConfig(enrich=True), host_id="h1",
                  boot_id="b7",
                  enricher=lambda pid: ProcessDetails(
                      pid, complete=True, comm="curl", exe="/usr/bin/curl",
                      parent_pid=1, uid=0, start_ticks="88231"))
    a._handle(sensor._events.pop(0))
    event = a.drain()[0]
    assert QualityFlag.PARTIAL_FIELDS not in event.quality.flags
    assert event.attributes["comm"] == "curl"
    assert event.attributes["exe"] == "/usr/bin/curl"


def test_enrichment_qualifies_the_process_reference_with_its_start_time():
    """A bare PID is reused; pid@start_ticks survives reuse."""
    sensor = FakeSensor(events=[exec_event(pid=1234)])
    a = HostAgent(sensor, config=AgentConfig(enrich=True), host_id="h1",
                  boot_id="b7",
                  enricher=lambda pid: ProcessDetails(pid, complete=True,
                                                      start_ticks="88231"))
    a._handle(sensor._events.pop(0))
    ref = next(r for r in a.drain()[0].entity_refs
               if r.kind is EntityKind.PROCESS_INSTANCE)
    assert ref.identifier == "1234@88231"
    assert "boot=b7" in ref.namespace


def test_argv_reclassifies_the_event_as_sensitive():
    """argv can carry credentials, so it must not inherit the bare event's
    classification."""
    sensor = FakeSensor(events=[exec_event()])
    a = HostAgent(sensor, config=AgentConfig(enrich=True, capture_argv=True),
                  host_id="h1", boot_id="b7",
                  enricher=lambda pid: ProcessDetails(
                      pid, complete=True, argv="mysql -pSECRET", start_ticks="1"))
    a._handle(sensor._events.pop(0))
    assert a.drain()[0].data_classification is DataClassification.SENSITIVE


def test_argv_capture_is_off_by_default():
    assert AgentConfig().capture_argv is False


def test_enrichment_of_a_departed_pid_never_raises():
    details = enrich_pid(999_999)
    assert details.complete is False and details.missing


# -- bounded queue ---------------------------------------------------------


def test_the_queue_is_bounded_and_drops_are_counted():
    """An agent that grows without limit under event pressure is a
    denial-of-service primitive against the host it protects."""
    sensor = FakeSensor()
    a = agent(sensor, queue_size=4)
    for i in range(10):
        a._handle(exec_event(pid=i + 1, sequence=i + 1))
    assert a.pending == 4
    assert a.stats.queued == 4
    assert a.stats.dropped_queue_full == 6
    assert a.stats.received == 10, "received is counted even when dropped"


def test_draining_frees_capacity():
    sensor = FakeSensor()
    a = agent(sensor, queue_size=4)
    for i in range(4):
        a._handle(exec_event(pid=i + 1, sequence=i + 1))
    assert len(a.drain()) == 4
    a._handle(exec_event(pid=99, sequence=99))
    assert a.stats.dropped_queue_full == 0


# -- health tells the truth ------------------------------------------------


def test_a_sensor_that_cannot_attest_degrades_the_agent():
    """The V2-HOST-01 finding carried into the agent: a blind sensor must not
    leave the agent looking healthy."""
    a = agent(FakeSensor(attests=False))
    manifest = a.manifest()
    assert manifest.capabilities["host_process_events"].health is Health.DEGRADED
    assert a.state() is AgentState.DEGRADED_COLLECTION
    assert not a.trustworthy_absence()


def test_a_healthy_attesting_sensor_yields_a_healthy_agent():
    a = agent(FakeSensor(attests=True))
    assert a.manifest().capabilities["host_process_events"].health is Health.HEALTHY
    assert a.state() is AgentState.HEALTHY
    assert a.trustworthy_absence()


def test_sensor_loss_degrades_the_agent():
    a = agent(FakeSensor(dropped=3))
    assert a.manifest().capabilities["host_process_events"].health is Health.DEGRADED
    assert not a.trustworthy_absence()


def test_queue_loss_degrades_the_agent():
    a = agent(FakeSensor(), queue_size=1)
    for i in range(5):
        a._handle(exec_event(pid=i + 1, sequence=i + 1))
    assert a.manifest().capabilities["host_process_events"].health is Health.DEGRADED


def test_a_stopped_sensor_is_failed_not_merely_quiet():
    a = agent(FakeSensor(running=False))
    assert a.manifest().capabilities["host_process_events"].health is Health.FAILED
    assert not a.trustworthy_absence()


# -- honest capability reporting -------------------------------------------


def test_absent_capabilities_are_named_not_omitted():
    """An absent feature that is never named cannot be noticed by an operator
    reading the manifest to see what is actually protecting the host."""
    manifest = agent(FakeSensor()).manifest()
    for feature in ("host_network_connections", "host_file_integrity"):
        assert feature in manifest.capabilities
        assert not manifest.covers(feature)


def test_the_agent_never_claims_a_capability_its_sensor_lacks():
    a = agent(FakeSensor(caps=frozenset({SensorCapability.PROCESS_EXEC})))
    manifest = a.manifest()
    assert manifest.covers("host_process_events")
    assert not manifest.covers("host_network_connections")


def test_an_unavailable_sensor_refuses_to_start():
    a = agent(FakeSensor(available=False))
    with pytest.raises(SensorUnavailable):
        a.start()


# -- the agent decides nothing ---------------------------------------------


def test_the_agent_produces_evidence_and_decides_nothing():
    a = agent(FakeSensor())
    for forbidden in ("assess", "detect", "decide", "enforce", "respond",
                      "quarantine", "kill"):
        assert not hasattr(a, forbidden)


def test_missing_detail_does_not_make_absence_untrustworthy():
    """A detail gap must not suppress a genuine negative result: we still saw
    every process, we just know less about some of them."""
    sensor = FakeSensor(attests=True)
    a = HostAgent(sensor, config=AgentConfig(enrich=True), host_id="h1",
                  boot_id="b7",
                  enricher=lambda pid: ProcessDetails(pid, complete=False,
                                                      missing=("exe",)))
    for i in range(5):
        a._handle(exec_event(pid=i + 1, sequence=i + 1))
    assert a.stats.enrichment_incomplete == 5
    assert a.trustworthy_absence(), "discovery was complete"
    assert a.collection_complete()
    assert a.manifest().capabilities["host_process_detail"].health is Health.DEGRADED


def test_missed_events_do_make_absence_untrustworthy():
    a = agent(FakeSensor(attests=False))
    assert not a.collection_complete()
    assert not a.trustworthy_absence()


def test_queue_drops_break_collection_completeness():
    a = agent(FakeSensor(attests=True), queue_size=1)
    for i in range(5):
        a._handle(exec_event(pid=i + 1, sequence=i + 1))
    assert not a.collection_complete()


# -- active liveness: never trust an open socket ---------------------------


def test_an_unprobed_sensor_is_not_assumed_live():
    """Before any probe there is no evidence either way, and reporting
    healthy on no evidence is the habit this mechanism exists to break."""
    a = agent(FakeSensor(attests=True))
    assert a.liveness.last is None
    assert not a.liveness.healthy


def test_a_failed_liveness_probe_marks_the_sensor_failed():
    """A socket can stay open while the kernel stops delivering. That is
    silence that looks like safety, and no counter can catch it."""
    from annulon.agent.liveness import LivenessResult

    a = agent(FakeSensor(attests=True, dropped=0))
    a.liveness.record_external(LivenessResult(
        "abc123", observed=False, latency_seconds=None,
        checked_at=T0, detail="marker not observed within 5.0s"))
    manifest = a.manifest()
    assert manifest.capabilities["host_process_events"].health is Health.FAILED
    assert not a.collection_complete()
    assert not a.trustworthy_absence()


def test_a_passing_liveness_probe_leaves_the_agent_healthy():
    from annulon.agent.liveness import LivenessResult

    a = agent(FakeSensor(attests=True))
    a.liveness.record_external(LivenessResult(
        "abc123", observed=True, latency_seconds=0.02, checked_at=T0))
    assert a.manifest().capabilities["host_process_events"].health is Health.HEALTHY
    assert a.collection_complete() and a.trustworthy_absence()


def test_consecutive_failures_are_counted():
    from annulon.agent.liveness import LivenessResult

    a = agent(FakeSensor())
    for observed in (True, False, False, False):
        a.liveness.record_external(LivenessResult(
            "x", observed=observed, latency_seconds=None, checked_at=T0))
    assert a.liveness.consecutive_failures == 3


def test_a_liveness_check_does_not_swallow_real_events():
    """The probe drains the queue looking for its marker; anything else it
    finds must go back, or self-checking would destroy evidence."""
    sensor = FakeSensor(attests=True)
    a = agent(sensor, queue_size=64, liveness_enabled=True)
    for i in range(5):
        a._handle(exec_event(pid=i + 1, sequence=i + 1))
    assert a.pending == 5
    a.check_liveness()
    assert a.pending == 5, "real events were preserved across the self-check"


def test_a_probe_only_matches_its_own_marker():
    """A stale event from an earlier probe must not satisfy the current one:
    'I saw a process' is much weaker than 'I saw this process'."""
    from annulon.agent.liveness import LivenessProbe

    probe = LivenessProbe()
    probe_id = probe.fire()
    try:
        assert probe.matches({"exe": f"/tmp/annulon-live-{probe_id}"})
        assert not probe.matches({"exe": "/tmp/annulon-live-0000000000000000"})
        assert not probe.matches({"exe": "/usr/bin/curl"})
        assert not probe.matches({})
    finally:
        probe.cleanup()


def test_liveness_can_be_disabled_explicitly_for_locked_down_hosts():
    """A deployment that genuinely cannot exec should disable the check
    explicitly rather than silently always failing it."""
    a = agent(FakeSensor(attests=True), liveness_enabled=False)
    assert not a.liveness.due()
    assert a.collection_complete(), "not penalised for a check it never runs"
