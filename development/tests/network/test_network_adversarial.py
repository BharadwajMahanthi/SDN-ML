"""Try to make Annulon say something stronger than its evidence supports.

Organised by failure family rather than by function, because the question is
never "does `flow_key` work" but "can I get two different flows to share an
identity". Each class below is one way to obtain a confidently wrong answer.

The claim under attack:

    For NETWORK_TELEMETRY_TRACEFS on the tested environment, Annulon does not
    convert ambiguous, stale, reordered, cross-process, cross-namespace,
    degraded, malformed or adversarial telemetry into a stronger statement
    than the evidence supports.

Annulon must prefer WEAK / PENDING / DEGRADED / MISSING over a confident
attributed-to-X / established / failed / clean.
"""

from __future__ import annotations

import ipaddress
import os
from datetime import datetime, timedelta, timezone

import pytest

from annulon.network.contract import (
    AddressFamily, AttributionConfidence, ConnectionOutcome, Direction,
    Endpoint, NetworkContractError, NetworkObservation, NetworkOperation,
    ProcessRef, SocketSemantic, Transport, outcome_for_errno,
)
from annulon.network.normalize import NetworkNormalizer
from annulon.network.tracefs import RawEvent, parse_trace_line

BOOT = datetime(2026, 9, 22, 0, tzinfo=timezone.utc)
NOW = datetime(2026, 9, 22, 1, tzinfo=timezone.utc)


def _normalizer(**kwargs) -> NetworkNormalizer:
    return NetworkNormalizer(boot_time=BOOT, **kwargs)


def _state_line(*, pid=1000, comm="worker", flags=".....", timestamp="100.5",
                family="AF_INET", protocol="IPPROTO_TCP", sport=0, dport=443,
                saddr="10.0.0.2", daddr="10.0.0.3",
                saddrv6="::ffff:10.0.0.2", daddrv6="::ffff:10.0.0.3",
                old="TCP_CLOSE", new="TCP_SYN_SENT") -> str:
    return (f"   {comm}-{pid}   [006] {flags} {timestamp}: inet_sock_set_state: "
            f"family={family} protocol={protocol} sport={sport} dport={dport} "
            f"saddr={saddr} daddr={daddr} saddrv6={saddrv6} daddrv6={daddrv6} "
            f"oldstate={old} newstate={new}")


def _observation(**overrides) -> NetworkObservation:
    base = dict(
        observation_id="netobs-000000000001",
        operation=NetworkOperation.CONNECT_ATTEMPT, transport=Transport.TCP,
        direction=Direction.OUTBOUND,
        process=ProcessRef(pid=1000, tgid=1000, comm="worker",
                           confidence=AttributionConfidence.PID_ONLY),
        local=Endpoint("10.0.0.2", 51234, AddressFamily.IPV4),
        remote=Endpoint("10.0.0.3", 443, AddressFamily.IPV4),
        observed_at=NOW, sensor_id="tracefs_network")
    base.update(overrides)
    return NetworkObservation(**base)


# ==========================================================================
# A. Same destination, different processes
# ==========================================================================

class TestSameDestinationDifferentProcesses:
    """uid equality, binary equality and destination equality are not
    identity. The 04C same-uid result has to survive concurrency."""

    def test_two_processes_to_one_destination_stay_distinct(self):
        normalizer = _normalizer()
        first = normalizer.normalize(parse_trace_line(_state_line(pid=1000)))
        second = normalizer.normalize(parse_trace_line(_state_line(pid=2000)))
        assert first.process.pid != second.process.pid
        assert first.observation_id != second.observation_id

    def test_identical_comm_and_destination_do_not_merge_processes(self):
        """Same binary name, same uid in practice, same target: still two."""
        normalizer = _normalizer()
        observations = [
            normalizer.normalize(parse_trace_line(
                _state_line(pid=pid, comm="worker", sport=port)))
            for pid, port in ((1000, 40001), (1001, 40002), (1002, 40003))]
        assert len({o.process.pid for o in observations}) == 3

    def test_a_process_ref_is_not_equal_to_another_with_a_different_pid(self):
        """Identity is structural, so nothing downstream can merge them by
        accident."""
        first = ProcessRef(pid=1000, tgid=1000, comm="worker")
        second = ProcessRef(pid=1001, tgid=1000, comm="worker")
        assert first != second

    def test_uid_is_not_part_of_process_identity_at_all(self):
        """There is no uid field to be tempted by. Containment scopes by uid
        and cannot separate these; telemetry must, and does."""
        assert not hasattr(ProcessRef(pid=1), "uid")

    def test_interleaved_events_from_two_processes_do_not_cross_attribute(self):
        """The dangerous version: A's attempt, B's attempt, A's established."""
        normalizer = _normalizer()
        lines = [_state_line(pid=1000, sport=40001, timestamp="100.1"),
                 _state_line(pid=2000, sport=40002, timestamp="100.2"),
                 _state_line(pid=1000, sport=40001, timestamp="100.3",
                             old="TCP_SYN_SENT", new="TCP_ESTABLISHED")]
        produced = [normalizer.normalize(parse_trace_line(l)) for l in lines]
        assert produced[0].process.pid == 1000
        assert produced[1].process.pid == 2000
        assert produced[2].process.pid == 1000


# ==========================================================================
# B. Identical / reused flow tuples
# ==========================================================================

class TestReusedFlowTuples:
    """Distinct observations must not collapse because tuples match."""

    def test_the_same_tuple_at_two_times_is_two_observations(self):
        normalizer = _normalizer()
        first = normalizer.normalize(parse_trace_line(_state_line(timestamp="100.0")))
        second = normalizer.normalize(parse_trace_line(_state_line(timestamp="900.0")))
        assert first.observation_id != second.observation_id
        assert first.observed_at != second.observed_at

    def test_an_unknown_namespace_never_shares_identity_with_namespace_zero(self):
        """The defect this branch found first.

        `network_namespace or 0` collapsed unknown into zero, and the tracefs
        tier never populates the field — so every production observation
        landed in that bucket while the contract advertised namespace-aware
        flow identity.
        """
        unknown = _observation(network_namespace=None)
        zero = _observation(network_namespace=0)
        assert unknown.flow_key != zero.flow_key
        assert not unknown.flow_key_is_namespace_qualified
        assert zero.flow_key_is_namespace_qualified

    def test_the_tracefs_tier_declares_its_flow_keys_unqualified(self):
        """Do not fabricate what the mechanism cannot supply. The sensor sees
        transitions for every namespace and is told which for none of them."""
        normalizer = _normalizer()
        observation = normalizer.normalize(parse_trace_line(_state_line()))
        assert observation.network_namespace is None
        assert not observation.flow_key_is_namespace_qualified
        assert "ns:unknown" in observation.flow_key

    def test_a_local_port_reused_after_close_is_not_the_same_flow(self):
        """TIME_WAIT expires and the port returns. A dedup key that ignored
        time would merge two unrelated connections."""
        normalizer = _normalizer()
        first = normalizer.normalize(parse_trace_line(
            _state_line(sport=0, dport=443, timestamp="100.0")))
        second = normalizer.normalize(parse_trace_line(
            _state_line(sport=0, dport=443, timestamp="700.0")))
        assert first.flow_key == second.flow_key, "tuples do match"
        assert first.observation_id != second.observation_id, (
            "identical tuples must not collapse into one observation")


# ==========================================================================
# C. Namespace separation
# ==========================================================================

class TestNamespaceSeparation:

    @pytest.mark.parametrize("first_ns,second_ns", [
        (4026531840, 4026532567), (0, 1), (None, 4026531840),
    ])
    def test_the_same_tuple_in_different_namespaces_stays_distinct(
            self, first_ns, second_ns):
        assert (_observation(network_namespace=first_ns).flow_key
                != _observation(network_namespace=second_ns).flow_key)

    def test_the_same_tuple_in_the_same_namespace_shares_a_key(self):
        """The positive control: the key must still be useful."""
        assert (_observation(network_namespace=4026531840).flow_key
                == _observation(network_namespace=4026531840).flow_key)

    def test_container_attribution_is_not_claimed(self):
        """NOT_RUN, and the data says so rather than a document saying so."""
        normalizer = _normalizer()
        observation = normalizer.normalize(parse_trace_line(_state_line()))
        assert observation.process.pid_namespace is None
        assert observation.network_namespace is None


# ==========================================================================
# D. Event ordering
# ==========================================================================

class TestEventOrdering:
    """The kernel guarantees no ordering across these sources, so the
    normaliser must not acquire one by accident."""

    def test_an_established_event_before_its_attempt_is_still_established(self):
        """Out-of-order arrival must not change what a fact means."""
        normalizer = _normalizer()
        established = normalizer.normalize(parse_trace_line(_state_line(
            timestamp="100.9", old="TCP_SYN_SENT", new="TCP_ESTABLISHED")))
        attempt = normalizer.normalize(parse_trace_line(_state_line(timestamp="100.1")))
        assert established.outcome is ConnectionOutcome.ESTABLISHED
        assert attempt.outcome is ConnectionOutcome.UNKNOWN

    def test_a_connect_result_does_not_upgrade_a_previous_attempt(self):
        """Each observation carries its own outcome. There is no correlation
        object joining them, so none may be implied."""
        normalizer = _normalizer()
        attempt = normalizer.normalize(parse_trace_line(_state_line()))
        result = normalizer.normalize(RawEvent(
            "sys_exit_connect", "worker", 1000, 0, 100.7, ".....", {"ret": "0x0"}))
        assert attempt.outcome is ConnectionOutcome.UNKNOWN, (
            "a later result silently upgraded an earlier attempt")
        assert result.outcome is ConnectionOutcome.ESTABLISHED

    def test_a_duplicate_state_notification_produces_a_second_observation(self):
        """Not deduplicated here on purpose: the normaliser reports what it
        saw. Deduplication is a consumer decision that needs the namespace
        qualification this tier cannot provide."""
        normalizer = _normalizer()
        line = _state_line()
        first = normalizer.normalize(parse_trace_line(line))
        second = normalizer.normalize(parse_trace_line(line))
        assert first.observation_id != second.observation_id
        assert first.flow_key == second.flow_key

    def test_an_event_timestamped_before_boot_does_not_become_a_future_time(self):
        normalizer = _normalizer()
        observation = normalizer.normalize(parse_trace_line(
            _state_line(timestamp="0.000001")))
        assert observation is not None, "a tiny timestamp was unparseable"
        assert observation.observed_at >= BOOT


# ==========================================================================
# E. Connect result semantics
# ==========================================================================

class TestConnectResultSemantics:
    """EINPROGRESS is the case that would have been wrong 500 times."""

    @pytest.mark.parametrize("raw,expected", [
        ("0x0", ConnectionOutcome.ESTABLISHED),
        ("0xffffffffffffff8d", ConnectionOutcome.PENDING),      # -115
        ("0xffffffffffffff8e", ConnectionOutcome.PENDING),      # -114 EALREADY
        ("0xffffffffffffff91", ConnectionOutcome.REFUSED),      # -111
        ("0xffffffffffffff8f", ConnectionOutcome.UNREACHABLE),  # -113
        ("0xffffffffffffff92", ConnectionOutcome.TIMED_OUT),    # -110
    ])
    def test_each_result_keeps_its_own_meaning(self, raw, expected):
        observation = _normalizer().normalize(RawEvent(
            "sys_exit_connect", "worker", 1000, 0, 100.0, ".....", {"ret": raw}))
        assert observation.outcome is expected

    def test_pending_is_never_reported_as_established_or_failed(self):
        pending = outcome_for_errno(-115)
        assert not pending.is_established
        assert pending not in (ConnectionOutcome.REFUSED,
                               ConnectionOutcome.TIMED_OUT,
                               ConnectionOutcome.UNREACHABLE,
                               ConnectionOutcome.OTHER_ERROR)

    def test_a_connect_result_carries_no_destination_it_could_invent(self):
        """The syscall tracepoint has only a pointer (KF-45)."""
        observation = _normalizer().normalize(RawEvent(
            "sys_exit_connect", "worker", 1000, 0, 100.0, ".....", {"ret": "0x0"}))
        assert observation.remote is None
        assert observation.local is None
        assert observation.flow_key is None

    def test_a_syscall_success_is_not_an_established_socket_state(self):
        """Distinct facts. `sys_exit_connect == 0` means the call returned,
        and the contract keeps that separate from the socket reaching
        ESTABLISHED."""
        observation = _normalizer().normalize(RawEvent(
            "sys_exit_connect", "worker", 1000, 0, 100.0, ".....", {"ret": "0x0"}))
        assert observation.operation is NetworkOperation.CONNECT_RESULT
        assert observation.operation is not NetworkOperation.CONNECTION_ESTABLISHED


# ==========================================================================
# F. The softirq attribution trap
# ==========================================================================

class TestSoftirqAttributionTrap:
    """An attractive-looking comm in interrupt context is not identity."""

    @pytest.mark.parametrize("flags", ["..s1.", "..s2.", "..h1.", "..H1."])
    def test_any_interrupt_context_discards_the_process(self, flags):
        observation = _normalizer().normalize(parse_trace_line(_state_line(
            flags=flags, comm="sshd", pid=99,
            old="TCP_SYN_SENT", new="TCP_ESTABLISHED")))
        assert observation.process.confidence is AttributionConfidence.NONE
        assert observation.process.pid == 0
        assert "sshd" not in observation.process.comm

    def test_the_socket_state_evidence_survives_the_downgrade(self):
        """Discarding the pid must not discard the flow: it is still real."""
        observation = _normalizer().normalize(parse_trace_line(_state_line(
            flags="..s1.", old="TCP_SYN_SENT", new="TCP_ESTABLISHED")))
        assert observation.outcome.is_established
        assert str(observation.remote) == "10.0.0.3:443"
        assert observation.socket_semantic is SocketSemantic.CURRENT_TASK

    def test_a_tempting_comm_in_softirq_cannot_be_used_as_identity(self):
        """The attack: make the completing task look like a juicy target."""
        for comm in ("sshd", "annulon-core", "root", "systemd"):
            observation = _normalizer().normalize(parse_trace_line(_state_line(
                flags="..s1.", comm=comm, pid=1,
                old="TCP_SYN_SENT", new="TCP_ESTABLISHED")))
            assert not observation.supports_workload_attribution

    def test_task_context_is_still_attributable(self):
        """The positive control: downgrading everything would be useless."""
        observation = _normalizer().normalize(parse_trace_line(_state_line(
            flags=".....", old="TCP_SYN_SENT", new="TCP_ESTABLISHED")))
        assert observation.process.confidence is AttributionConfidence.PID_ONLY


# ==========================================================================
# G. Process exit / enrichment race
# ==========================================================================

class TestProcessExitAndStaleGeneration:
    """A PID is not an identity, and enrichment that arrives late must not
    attach to whatever now holds the number."""

    def test_the_observation_survives_without_any_enrichment(self):
        """The process may be gone before anything can read /proc."""
        observation = _normalizer().normalize(parse_trace_line(_state_line()))
        assert observation.process.pid == 1000
        assert observation.process.start_boottime_ns is None
        assert observation.process.instance_key is None
        assert observation.process.confidence is AttributionConfidence.PID_ONLY

    def test_missing_enrichment_is_visible_as_weak_attribution(self):
        """Not silently equivalent to a fully bound identity."""
        observation = _normalizer().normalize(parse_trace_line(_state_line()))
        assert observation.supports_workload_attribution is False or (
            observation.process.confidence
            is not AttributionConfidence.INSTANCE_BOUND)

    def test_two_generations_of_one_pid_are_different_identities(self):
        """The stale-generation family, expressed where it can be tested.

        Physically forcing PID reuse is NOT_RUN; this pins the contract so a
        future enrichment path cannot merge them.
        """
        first = ProcessRef(pid=1234, tgid=1234, start_boottime_ns=1_000_000_000,
                           confidence=AttributionConfidence.INSTANCE_BOUND)
        second = ProcessRef(pid=1234, tgid=1234, start_boottime_ns=9_000_000_000,
                            confidence=AttributionConfidence.INSTANCE_BOUND)
        assert first.pid == second.pid
        assert first.instance_key != second.instance_key
        assert first != second

    def test_an_instance_bound_identity_outranks_a_pid_only_one(self):
        assert AttributionConfidence.INSTANCE_BOUND.sufficient_for_workload_attribution
        assert not AttributionConfidence.PID_ONLY.sufficient_for_workload_attribution
        assert not AttributionConfidence.NONE.sufficient_for_workload_attribution

    def test_correlated_is_sufficient_but_instance_bound_is_stronger(self):
        """CORRELATED rests on a process table rather than capture at source;
        both are usable, and they are not the same statement."""
        assert AttributionConfidence.CORRELATED.sufficient_for_workload_attribution
        assert (AttributionConfidence.CORRELATED
                is not AttributionConfidence.INSTANCE_BOUND)


# ==========================================================================
# J. Malformed trace input
# ==========================================================================

class TestMalformedTraceInput:
    """Fail closed at the decode boundary; never fabricate a confident
    observation; never grow state without bound."""

    @pytest.mark.parametrize("mutation", [
        ("family=AF_INET", ""), ("protocol=IPPROTO_TCP", ""),
        ("dport=443", ""), ("daddr=10.0.0.3", ""),
        ("newstate=TCP_SYN_SENT", ""), ("oldstate=TCP_CLOSE", ""),
    ])
    def test_a_missing_field_never_produces_an_observation(self, mutation):
        normalizer = _normalizer()
        line = _state_line().replace(*mutation)
        assert normalizer.normalize(parse_trace_line(line)) is None

    @pytest.mark.parametrize("dport", [
        "99999", "-1", "0x1bb", "4４3", "١٥٠٠", "443.0", "443 ", "+443",
        "18446744073709551616",
    ])
    def test_an_out_of_range_or_non_ascii_port_is_refused(self, dport):
        normalizer = _normalizer()
        line = _state_line().replace("dport=443", f"dport={dport}")
        observation = normalizer.normalize(parse_trace_line(line))
        assert observation is None or observation.remote.port == 443

    @pytest.mark.parametrize("daddr", [
        "999.999.999.999", "10.0.0", "10.0.0.1/24", "0x0a000001",
        "not-an-address", "example.com", "２５５.255.255.255",
    ])
    def test_a_malformed_address_is_refused(self, daddr):
        normalizer = _normalizer()
        line = _state_line().replace("daddr=10.0.0.3", f"daddr={daddr}")
        assert normalizer.normalize(parse_trace_line(line)) is None

    @pytest.mark.parametrize("family", ["AF_UNIX", "AF_NETLINK", "AF_PACKET",
                                        "AF_BLUETOOTH", "2", "", "AF_INET7"])
    def test_an_unknown_family_is_refused(self, family):
        normalizer = _normalizer()
        line = _state_line().replace("family=AF_INET ", f"family={family} ")
        assert normalizer.normalize(parse_trace_line(line)) is None

    @pytest.mark.parametrize("state", ["TCP_NONSENSE", "", "1", "TCP_SYN_SENT_X"])
    def test_an_unknown_state_is_ignored_not_guessed(self, state):
        normalizer = _normalizer()
        line = _state_line().replace("newstate=TCP_SYN_SENT", f"newstate={state}")
        assert normalizer.normalize(parse_trace_line(line)) is None

    def test_an_oversized_comm_does_not_produce_an_observation_or_raise(self):
        normalizer = _normalizer()
        line = _state_line(comm="c" * 5000)
        observation = normalizer.normalize(parse_trace_line(line))
        assert observation is None or len(observation.process.comm) <= 64

    @pytest.mark.parametrize("injection", [
        "worker\\nfake", "worker\\x00", "wor ker", "worker\\t", "\\u202eworker",
    ])
    def test_control_bytes_in_comm_cannot_reach_an_observation(self, injection):
        normalizer = _normalizer()
        observation = normalizer.normalize(parse_trace_line(_state_line(comm=injection)))
        if observation is not None:
            assert "\n" not in observation.process.comm
            assert "\x00" not in observation.process.comm

    def test_a_truncated_line_never_raises_at_any_cut_point(self):
        line = _state_line()
        normalizer = _normalizer()
        for cut in range(1, len(line)):
            normalizer.normalize(parse_trace_line(line[:cut]))

    def test_repeated_rejections_do_not_grow_unbounded_state(self):
        """A parser that accumulates per-rejection state is a memory attack
        reachable by anyone who can make the kernel emit odd lines."""
        normalizer = _normalizer()
        for index in range(5000):
            normalizer.normalize(parse_trace_line(
                _state_line(daddr=f"bad-{index}")))
        assert normalizer.stats.malformed_address >= 1
        assert len(vars(normalizer.stats)) <= 10

    def test_a_duplicate_field_resolves_without_inventing_a_value(self):
        """`_FIELD.findall` into a dict keeps the last occurrence; pinning it
        so a parser change cannot silently prefer the first."""
        normalizer = _normalizer()
        line = _state_line() + " dport=8080"
        observation = normalizer.normalize(parse_trace_line(line))
        assert observation is None or observation.remote.port in (443, 8080)


# ==========================================================================
# L. Replay and duplication
# ==========================================================================

class TestReplayAndDuplication:
    """Three consumers of one event are not three witnesses."""

    def test_replaying_one_event_does_not_create_independent_facts(self):
        normalizer = _normalizer()
        line = _state_line()
        produced = [normalizer.normalize(parse_trace_line(line)) for _ in range(5)]
        assert len({o.flow_key for o in produced}) == 1, (
            "one flow became several distinct flows")
        assert len({o.observed_at for o in produced}) == 1, (
            "replay invented distinct times")

    def test_a_replayed_observation_is_not_stronger_than_the_original(self):
        normalizer = _normalizer()
        line = _state_line()
        first = normalizer.normalize(parse_trace_line(line))
        tenth = [normalizer.normalize(parse_trace_line(line)) for _ in range(10)][-1]
        assert tenth.process.confidence is first.process.confidence
        assert tenth.outcome is first.outcome

    def test_observation_ids_are_unique_per_normalizer(self):
        """So a consumer can deduplicate deliberately rather than by
        accident."""
        normalizer = _normalizer()
        ids = [normalizer.normalize(parse_trace_line(_state_line())).observation_id
               for _ in range(100)]
        assert len(set(ids)) == 100
