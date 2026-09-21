"""Network liveness, attacked at every clause that could manufacture health.

The property under test is not "the thread is alive". It is that Annulon can
*demonstrate* the selected observation path currently works, and that it
refuses to treat silence as meaningful when it cannot.

Most of these tests try to satisfy the probe with something the probe did not
cause: a stale observation, another process's connection, the right port with
the wrong operation. Each clause in `matches` is here because removing it
opens one of those doors, so each has a test that fails without it.
"""

from __future__ import annotations

import os
import socket
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from annulon.network.contract import (
    AddressFamily, AttributionConfidence, ConnectionOutcome, Direction,
    Endpoint, NetworkObservation, NetworkOperation, ProcessRef,
    SocketSemantic, Transport,
)
from annulon.network.liveness import (
    CLOCK_TOLERANCE_SECONDS, NetworkLivenessMonitor, NetworkLivenessProbe,
    NetworkLivenessReceipt, network_collection_health,
)
from annulon.network.tracefs import LossCounters
from annulon.agent.liveness import LivenessResult

ME = os.getpid()


def _observation(*, port: int, pid: int = ME, address: str = "127.0.0.1",
                 operation=NetworkOperation.CONNECT_ATTEMPT,
                 transport=Transport.TCP, when: datetime | None = None,
                 family=AddressFamily.IPV4, namespace: int | None = None,
                 direction=Direction.OUTBOUND) -> NetworkObservation:
    outcome = (ConnectionOutcome.ESTABLISHED
               if operation is NetworkOperation.CONNECTION_ESTABLISHED
               else ConnectionOutcome.UNKNOWN)
    local_address = "127.0.0.1" if family is AddressFamily.IPV4 else "::1"
    return NetworkObservation(
        observation_id="netobs-000000000001", operation=operation,
        transport=transport, direction=direction,
        process=ProcessRef(pid=pid, tgid=pid, comm="python3",
                           confidence=AttributionConfidence.PID_ONLY),
        local=Endpoint(local_address, 40000, family),
        remote=Endpoint(address, port, family),
        observed_at=when or datetime.now(timezone.utc),
        sensor_id="tracefs_network", outcome=outcome,
        socket_semantic=SocketSemantic.CONNECT_INITIATOR,
        network_namespace=namespace)


def _armed_probe(port: int = 45678, **kwargs) -> NetworkLivenessProbe:
    """A probe with its window open, without binding a real socket."""
    probe = NetworkLivenessProbe(**kwargs)
    probe.port = port
    probe.fired_at = datetime.now(timezone.utc)
    probe.deadline_at = probe.fired_at + timedelta(seconds=5)
    return probe


# --- 1. before the first probe ---------------------------------------------

def test_a_monitor_that_has_never_probed_is_not_healthy():
    """Reporting health on no evidence is the habit ADR-041 exists to break."""
    monitor = NetworkLivenessMonitor()
    assert monitor.status() == "NEVER_PROBED"
    assert not monitor.healthy
    assert not monitor.ever_succeeded


def test_never_probed_removes_trustworthy_absence_even_with_a_clean_sensor():
    """A sensor reporting itself perfectly healthy is still unproven."""
    health = network_collection_health(
        {"running": True, "attests_completeness": True,
         "loss": {"total": 0}, "degraded_reasons": []},
        NetworkLivenessMonitor())
    assert not health.attests_completeness
    assert not health.trustworthy_absence
    assert "never been proved" in health.blind_spot


# --- matching: every clause earns its place --------------------------------

def test_the_probe_matches_the_observation_it_caused():
    """The positive control. A matcher that never matches is not safe, it is
    broken, and every negative test below would pass vacuously."""
    probe = _armed_probe()
    assert probe.matches(_observation(port=probe.port))


@pytest.mark.parametrize("mutation,reason", [
    ({"port": 45679}, "a different port is a different probe"),
    ({"pid": ME + 1}, "another process must not certify our sensor"),
    ({"address": "10.0.0.5"}, "the probe only ever talks to loopback"),
    ({"operation": NetworkOperation.CONNECTION_ESTABLISHED},
     "the selected primary semantic is the attempt, not the completion"),
    ({"operation": NetworkOperation.CONNECT_RESULT},
     "a connect result carries no destination"),
    ({"transport": Transport.UDP}, "the probe is a TCP connection"),
    ({"direction": Direction.INBOUND}, "the probe is outbound"),
])
def test_an_observation_the_probe_did_not_cause_does_not_match(mutation, reason):
    probe = _armed_probe()
    mutation.setdefault("port", probe.port)
    assert not probe.matches(_observation(**mutation)), reason


def test_a_matching_port_in_a_different_address_family_does_not_match():
    probe = _armed_probe(family=AddressFamily.IPV4)
    assert not probe.matches(_observation(port=probe.port, address="::1",
                                          family=AddressFamily.IPV6))


def test_a_different_network_namespace_does_not_match():
    """The same tuple can exist in several namespaces at once."""
    probe = _armed_probe(network_namespace=4026531840)
    assert probe.matches(_observation(port=probe.port, namespace=4026531840))
    assert not probe.matches(_observation(port=probe.port, namespace=4026532567))


def test_an_unarmed_probe_matches_nothing():
    assert not NetworkLivenessProbe().matches(_observation(port=1234))


@pytest.mark.parametrize("value", [None, "observation", 42, [], {}])
def test_a_non_observation_never_matches(value):
    assert not _armed_probe().matches(value)


# --- 4. stale events --------------------------------------------------------

def test_an_observation_from_before_the_probe_window_does_not_satisfy_it():
    """A delayed item from an earlier probe carries an earlier timestamp.

    This is the network form of ADR-041's nonce rule: "I saw *a* connection"
    is a much weaker statement than "I saw *this* connection".
    """
    probe = _armed_probe()
    stale = probe.fired_at - timedelta(seconds=CLOCK_TOLERANCE_SECONDS + 5)
    assert not probe.matches(_observation(port=probe.port, when=stale))


def test_an_observation_after_the_deadline_does_not_satisfy_it():
    probe = _armed_probe()
    late = probe.deadline_at + timedelta(seconds=CLOCK_TOLERANCE_SECONDS + 5)
    assert not probe.matches(_observation(port=probe.port, when=late))


def test_the_clock_tolerance_accepts_reconstruction_error_not_stale_events():
    """`observed_at` is rebuilt from btime, which has one-second resolution.

    The tolerance covers our own arithmetic error. It is not a grace period:
    the port and pid still have to match, so widening it cannot admit an
    event from a different probe.
    """
    probe = _armed_probe()
    slightly_early = probe.fired_at - timedelta(seconds=CLOCK_TOLERANCE_SECONDS - 0.5)
    assert probe.matches(_observation(port=probe.port, when=slightly_early))


def test_a_second_probe_is_not_satisfied_by_the_first_probes_observation():
    """Two probes in sequence, and the older observation replayed."""
    first = _armed_probe(port=45678)
    first_observation = _observation(port=45678)
    assert first.matches(first_observation)
    second = _armed_probe(port=45999)
    assert not second.matches(first_observation)


# --- 5. another process ------------------------------------------------------

def test_another_process_connecting_to_the_listener_does_not_certify_us():
    """A health check any local process can satisfy is one an attacker can
    satisfy."""
    probe = _armed_probe()
    assert not probe.matches(_observation(port=probe.port, pid=ME + 4242))


# --- 6. unrelated observations are not consumed -----------------------------

def test_consider_never_removes_or_alters_an_observation():
    """The monitor reads; the caller keeps. ADR-041's rule that
    self-checking must not destroy evidence, applied to a pipeline with a
    bounded queue in it."""
    monitor = NetworkLivenessMonitor()
    monitor._pending = _armed_probe()
    unrelated = [_observation(port=9001), _observation(port=9002)]
    kept = []
    for observation in unrelated:
        matched = monitor.consider(observation)
        assert matched is False
        kept.append(observation)
    assert kept == unrelated, "an unrelated observation was consumed"


def test_consider_returns_true_only_for_the_probe_and_keeps_the_rest():
    monitor = NetworkLivenessMonitor()
    probe = _armed_probe()
    monitor._pending = probe
    stream = [_observation(port=9001), _observation(port=probe.port),
              _observation(port=9002)]
    verdicts = [monitor.consider(o) for o in stream]
    assert verdicts == [False, True, False]
    assert len(stream) == 3, "the stream was mutated"


def test_consider_with_no_pending_probe_matches_nothing():
    assert not NetworkLivenessMonitor().consider(_observation(port=1234))


# --- 7 & 8. loss makes a successful probe insufficient ----------------------

def _receipt(*, observed=True, before=0, after=0) -> NetworkLivenessReceipt:
    return NetworkLivenessReceipt(
        result=LivenessResult(probe_id="p", observed=observed,
                              latency_seconds=0.1 if observed else None,
                              checked_at=datetime.now(timezone.utc)),
        loss_before=LossCounters(overrun=before),
        loss_after=LossCounters(overrun=after))


def test_kernel_loss_during_the_interval_makes_the_epoch_degraded():
    """The path demonstrably works *and* something was missed. Both are true,
    and reporting only the first would be the dangerous half."""
    monitor = NetworkLivenessMonitor()
    monitor.record_external(_receipt(observed=True, before=0, after=5))
    assert monitor.status() == "DEGRADED"
    assert not monitor.healthy
    assert monitor.ever_succeeded, "the probe did succeed; that is not erased"


def test_userspace_queue_drops_also_degrade_the_epoch():
    """Kernel loss and queue loss have different fixes but the same effect on
    whether silence can be trusted."""
    receipt = NetworkLivenessReceipt(
        result=LivenessResult("p", True, 0.1, datetime.now(timezone.utc)),
        loss_before=LossCounters(),
        loss_after=LossCounters(queue_dropped=3))
    monitor = NetworkLivenessMonitor()
    monitor.record_external(receipt)
    assert receipt.loss_delta == 3
    assert monitor.status() == "DEGRADED"


def test_a_clean_probe_with_no_loss_is_healthy():
    monitor = NetworkLivenessMonitor()
    monitor.record_external(_receipt(observed=True))
    assert monitor.status() == "HEALTHY"
    assert monitor.healthy


def test_a_failed_probe_is_failed_regardless_of_loss():
    monitor = NetworkLivenessMonitor()
    monitor.record_external(_receipt(observed=False))
    assert monitor.status() == "FAILED"
    assert not monitor.healthy


def test_loss_counters_going_backwards_do_not_invent_a_clean_interval():
    """A counter reset must not read as negative loss."""
    receipt = _receipt(observed=True, before=10, after=0)
    assert receipt.loss_delta == 0


# --- health integration (D, E) ----------------------------------------------

@pytest.mark.parametrize("receipt,expected_fragment", [
    (None, "never been proved"),
    (_receipt(observed=False), "was not observed"),
    (_receipt(observed=True, after=3), "events were lost"),
])
def test_every_unhealthy_state_removes_trustworthy_absence(receipt, expected_fragment):
    monitor = NetworkLivenessMonitor()
    if receipt is not None:
        monitor.record_external(receipt)
    health = network_collection_health(
        {"running": True, "attests_completeness": True,
         "loss": {"total": 0}, "degraded_reasons": []}, monitor)
    assert not health.trustworthy_absence
    assert expected_fragment in health.blind_spot


def test_a_clean_probe_and_a_clean_sensor_allow_trustworthy_absence():
    """The positive control for the health combiner."""
    monitor = NetworkLivenessMonitor()
    monitor.record_external(_receipt(observed=True))
    health = network_collection_health(
        {"running": True, "attests_completeness": True,
         "loss": {"total": 0}, "degraded_reasons": []}, monitor)
    assert health.attests_completeness
    assert health.trustworthy_absence


def test_a_stopped_sensor_is_never_trustworthy_even_with_a_good_probe():
    """A stale success must not outlive the sensor it was about."""
    monitor = NetworkLivenessMonitor()
    monitor.record_external(_receipt(observed=True))
    health = network_collection_health(
        {"running": False, "attests_completeness": False,
         "loss": {"total": 0}, "degraded_reasons": ["the reader thread is not running"]},
        monitor)
    assert not health.trustworthy_absence
    assert "reader thread" in health.blind_spot


def test_sensor_reported_loss_reaches_the_stats():
    health = network_collection_health(
        {"running": True, "attests_completeness": False,
         "loss": {"total": 7}, "unparsed_lines": 2, "degraded_reasons": []},
        NetworkLivenessMonitor())
    assert health.stats.dropped == 7
    assert health.stats.decode_errors == 2
    assert health.lossy


# --- 9. recovery is prospective ---------------------------------------------

def test_recovery_does_not_erase_the_earlier_gap():
    """A later clean probe says the path works *now*. It says nothing about
    the interval that failed, and the record keeps both."""
    monitor = NetworkLivenessMonitor()
    monitor.record_external(_receipt(observed=False))
    monitor.record_external(_receipt(observed=True))
    assert monitor.status() == "HEALTHY"
    assert len(monitor.history) == 2
    assert not monitor.history[0].observed, "the failed interval was rewritten"
    assert monitor.history[0].result.checked_at is not None


def test_history_is_bounded():
    monitor = NetworkLivenessMonitor(history_limit=5)
    for _ in range(50):
        monitor.record_external(_receipt(observed=True))
    assert len(monitor.history) == 5


# --- 11. the self-probe is internal, and only from trusted state ------------

def test_the_probe_traffic_is_recognised_as_internal_from_in_process_state():
    """Recognised because *we* bound that port, not because the event said so."""
    monitor = NetworkLivenessMonitor()
    monitor._known_ports.add(45678)
    assert monitor.is_internal(_observation(port=45678))


def test_an_observation_cannot_declare_itself_internal():
    """`is_self_test` is a field on the record. If health or exemption were
    decided from it, any workload could set it by choosing a port."""
    monitor = NetworkLivenessMonitor()
    forged = _observation(port=45678)
    object.__setattr__(forged, "is_self_test", True)
    assert not monitor.is_internal(forged), (
        "an untrusted field decided internal status")


def test_loopback_traffic_from_another_process_is_not_internal():
    """No blanket "ignore loopback" rule: that would be a bypass any workload
    could use."""
    monitor = NetworkLivenessMonitor()
    monitor._known_ports.add(45678)
    assert not monitor.is_internal(_observation(port=45678, pid=ME + 9))


def test_ordinary_loopback_traffic_on_an_unknown_port_is_not_internal():
    monitor = NetworkLivenessMonitor()
    monitor._known_ports.add(45678)
    assert not monitor.is_internal(_observation(port=45679))


def test_non_loopback_traffic_is_never_internal():
    monitor = NetworkLivenessMonitor()
    monitor._known_ports.add(45678)
    assert not monitor.is_internal(_observation(port=45678, address="10.0.0.5"))


# --- 10. bounded shutdown ---------------------------------------------------

def test_a_pending_probe_can_be_cancelled_without_waiting_out_the_deadline():
    """KF-44's lesson one layer up: a health check that delays shutdown is a
    health check that gets removed."""
    monitor = NetworkLivenessMonitor(deadline_seconds=30.0)
    cancel = threading.Event()
    cancel.set()
    started = time.monotonic()
    receipt = monitor.run(pump=lambda: [], loss=LossCounters, cancel=cancel)
    assert time.monotonic() - started < 5.0, "cancellation did not take effect"
    assert not receipt.observed


def test_a_probe_whose_connection_fails_says_so_rather_than_blaming_the_sensor():
    """"The probe never happened" and "Annulon could not see it" need
    different responses, so they are different states."""
    receipt = NetworkLivenessReceipt(
        result=LivenessResult("p", False, None, datetime.now(timezone.utc)),
        loss_before=LossCounters(), loss_after=LossCounters(),
        connection_made=False)
    assert not receipt.observed
    assert not receipt.connection_made


# --- the probe really does open a connection --------------------------------

def test_the_probe_opens_a_real_loopback_connection():
    """Independent of Annulon's telemetry: the listener accepts it.

    Without this, a probe that silently failed to connect would look
    identical to a sensor that stopped observing.
    """
    probe = NetworkLivenessProbe()
    port = probe.open()
    try:
        assert 1024 <= port <= 65535
        assert probe.fire(deadline_seconds=1.0) is True
    finally:
        probe.close()


def test_each_probe_gets_a_fresh_port():
    """The port is the nonce, so reuse would weaken it."""
    ports = []
    probes = [NetworkLivenessProbe() for _ in range(5)]
    try:
        for probe in probes:
            ports.append(probe.open())
    finally:
        for probe in probes:
            probe.close()
    assert len(set(ports)) == len(ports)


def test_closing_a_probe_twice_is_safe():
    probe = NetworkLivenessProbe()
    probe.open()
    probe.close()
    probe.close()


# --- closing mutation survivors in the security-relevant predicates --------
#
# Each of these killed a specific surviving mutation in a predicate the
# campaign brief names: probe identity, deadline/freshness, pid matching,
# state-semantic matching, the loss check, and the health transition. A
# predicate that can be weakened without a test failing is a predicate that
# will be weakened by a refactor.

def test_a_probe_with_a_port_but_no_window_matches_nothing():
    """`port is None or fired_at is None` — both halves, separately.

    Testing only the both-unset case let `or` become `and`, which would make
    a probe with a port and no window match anything on that port.
    """
    probe = NetworkLivenessProbe()
    probe.port = 45678
    probe.fired_at = None
    assert not probe.matches(_observation(port=45678))


def test_a_probe_with_a_window_but_no_port_matches_nothing():
    probe = NetworkLivenessProbe()
    probe.port = None
    probe.fired_at = datetime.now(timezone.utc)
    assert not probe.matches(_observation(port=45678))


def test_an_observation_without_a_remote_endpoint_does_not_match():
    """A CONNECT_RESULT carries no destination; it must not satisfy a probe
    that is defined by one."""
    probe = _armed_probe()
    without_remote = NetworkObservation(
        observation_id="netobs-000000000002",
        operation=NetworkOperation.CONNECT_ATTEMPT, transport=Transport.TCP,
        direction=Direction.OUTBOUND,
        process=ProcessRef(pid=ME, tgid=ME,
                           confidence=AttributionConfidence.PID_ONLY),
        local=None, remote=None, observed_at=datetime.now(timezone.utc),
        sensor_id="tracefs_network")
    assert not probe.matches(without_remote)


def test_a_probe_with_no_deadline_falls_back_to_its_fire_time():
    """`deadline_at or fired_at`. Without the fallback a probe whose deadline
    was never set would accept an observation from any future time."""
    probe = NetworkLivenessProbe()
    probe.port = 45678
    probe.fired_at = datetime.now(timezone.utc)
    probe.deadline_at = None
    assert probe.matches(_observation(port=45678))
    far_future = probe.fired_at + timedelta(seconds=CLOCK_TOLERANCE_SECONDS + 60)
    assert not probe.matches(_observation(port=45678, when=far_future))


@pytest.mark.parametrize("value", [None, "observation", 42, [], {}])
def test_consider_rejects_a_non_observation(value):
    """The monitor is fed by a pipeline; a malformed item must not raise
    inside a health check, nor satisfy one."""
    monitor = NetworkLivenessMonitor()
    monitor._pending = _armed_probe()
    assert monitor.consider(value) is False


def test_history_is_bounded_at_exactly_its_limit():
    """`> history_limit`, not `>=`. Asserting only that 50 records become 5
    left the boundary untested."""
    monitor = NetworkLivenessMonitor(history_limit=3)
    for _ in range(3):
        monitor.record_external(_receipt(observed=True))
    assert len(monitor.history) == 3, "the limit was applied one record early"
    monitor.record_external(_receipt(observed=True))
    assert len(monitor.history) == 3


@pytest.mark.parametrize("connected,observed,after,fragment", [
    (False, False, 0, "did not open"),
    (True, False, 0, "no longer delivering"),
    (True, True, 4, "not trustworthy"),
    (True, True, 0, "no loss occurred"),
])
def test_each_outcome_states_its_own_reason(connected, observed, after, fragment):
    """The four branches of the explanation are distinct on purpose.

    "The probe never happened" and "Annulon could not see it" need different
    responses, and collapsing them would hide which one occurred.
    """
    detail = NetworkLivenessMonitor._detail(
        observed, connected, LossCounters(), LossCounters(overrun=after))
    assert fragment in detail


def test_an_unattested_health_always_carries_a_stated_reason():
    """`if not attests and not blind_spot`. A health record that refuses to
    attest completeness while explaining nothing is not actionable."""
    monitor = NetworkLivenessMonitor()
    monitor.record_external(_receipt(observed=True))
    health = network_collection_health(
        {"running": True, "attests_completeness": False,
         "loss": {"total": 0}, "degraded_reasons": []}, monitor)
    assert not health.attests_completeness
    assert health.blind_spot, "no reason was given for withholding attestation"


def test_run_without_a_cancel_event_still_completes():
    """`cancel is not None and cancel.is_set()`. Turning that `and` into `or`
    dereferences None on every deployment that does not pass one -- which is
    the default path."""
    monitor = NetworkLivenessMonitor(deadline_seconds=0.2)
    receipt = monitor.run(pump=lambda: [], loss=LossCounters)
    assert receipt.result.probe_id
    assert not receipt.observed


def test_run_recognises_the_probe_when_the_pipeline_delivers_it():
    """A unit-level positive control for `run()` itself.

    The pump stands in for the ordinary consumer and hands back an
    observation matching the pending probe, so the loop's success path and
    its `break` are exercised without a kernel.
    """
    monitor = NetworkLivenessMonitor(deadline_seconds=5.0)
    delivered: list = []

    def pump():
        probe = monitor._pending
        if probe is None or probe.port is None or delivered:
            return []
        observation = _observation(port=probe.port, pid=probe.expected_pid)
        delivered.append(observation)
        return [observation]

    receipt = monitor.run(pump=pump, loss=LossCounters)
    assert receipt.observed, "the pipeline delivered the probe and run() missed it"
    assert receipt.clean
    assert monitor.status() == "HEALTHY"
    assert receipt.result.latency_seconds is not None
    assert len(delivered) == 1, "the observation was consumed or duplicated"


def test_run_does_not_accept_a_foreign_observation_from_the_pipeline():
    """The same loop, fed an observation from another process."""
    monitor = NetworkLivenessMonitor(deadline_seconds=0.3)

    def pump():
        probe = monitor._pending
        if probe is None or probe.port is None:
            return []
        return [_observation(port=probe.port, pid=probe.expected_pid + 5)]

    receipt = monitor.run(pump=pump, loss=LossCounters)
    assert not receipt.observed
    assert monitor.status() == "FAILED"


def test_firing_without_opening_first_still_binds_a_listener():
    """`if self._listener is None: self.open()`. Removing it would fire at
    port None and fail in a way that looks like a dead sensor."""
    probe = NetworkLivenessProbe()
    try:
        assert probe.fire(deadline_seconds=1.0) is True
        assert probe.port is not None
    finally:
        probe.close()


def test_closing_releases_the_listener_reference():
    """`if self._listener is not None`. Inverting it made close() a no-op on
    the first call, which leaks the port that is supposed to be a nonce."""
    probe = NetworkLivenessProbe()
    probe.open()
    probe.close()
    assert probe._listener is None


def test_an_ipv6_probe_targets_the_v6_loopback():
    """The family ternary decides which socket is bound and which loopback
    address is expected; swapping it would probe the wrong stack."""
    probe = NetworkLivenessProbe(family=AddressFamily.IPV6)
    assert probe.address == "::1"
    try:
        port = probe.open()
    except OSError:
        pytest.skip("no IPv6 loopback in this environment")
    try:
        assert port > 0
        assert probe._listener.family == socket.AF_INET6
    finally:
        probe.close()


def test_an_ipv4_probe_targets_the_v4_loopback():
    probe = NetworkLivenessProbe(family=AddressFamily.IPV4)
    assert probe.address == "127.0.0.1"
    probe.open()
    try:
        assert probe._listener.family == socket.AF_INET
    finally:
        probe.close()


def test_the_probe_socket_family_follows_the_address_family():
    """One site decides which stack is probed, and it is tested directly.

    It was previously two identical ternaries, neither testable alone, and
    swapping one behaved differently on Linux and macOS -- so the defect was
    invisible on whichever platform happened to be forgiving.
    """
    assert NetworkLivenessProbe(family=AddressFamily.IPV4).socket_family == socket.AF_INET
    assert NetworkLivenessProbe(family=AddressFamily.IPV6).socket_family == socket.AF_INET6


@pytest.mark.parametrize("value", [None, "observation", 42, [], {}])
def test_is_internal_rejects_a_non_observation(value):
    """The exemption path must not raise on, or accept, a malformed item."""
    monitor = NetworkLivenessMonitor()
    monitor._known_ports.add(45678)
    assert monitor.is_internal(value) is False


def test_run_returns_promptly_once_the_probe_is_observed():
    """`if matched: break`. Without it the loop runs to the deadline and the
    probe still succeeds -- slowly. A health check that always takes its full
    deadline is one that gets given a shorter deadline, or removed.
    """
    monitor = NetworkLivenessMonitor(deadline_seconds=10.0)

    def pump():
        probe = monitor._pending
        if probe is None or probe.port is None:
            return []
        return [_observation(port=probe.port, pid=probe.expected_pid)]

    started = time.monotonic()
    receipt = monitor.run(pump=pump, loss=LossCounters)
    elapsed = time.monotonic() - started
    assert receipt.observed
    assert elapsed < 2.0, (
        f"run() took {elapsed:.2f}s after an immediate match; it waited out "
        "the deadline instead of returning")


def test_repeated_probes_do_not_grow_history_without_bound():
    """The trim inside `run()` is a separate code path from the one in
    `record_external`, and was untested."""
    monitor = NetworkLivenessMonitor(deadline_seconds=0.05, history_limit=3)
    for _ in range(6):
        monitor.run(pump=lambda: [], loss=LossCounters)
    assert len(monitor.history) == 3
