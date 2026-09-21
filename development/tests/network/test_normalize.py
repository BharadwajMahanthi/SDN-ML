"""The normaliser, attacked with the events a kernel actually emits.

The mapping here is not the obvious one, and the tests exist mostly to hold
that shape in place. `sys_enter_connect` looks like the natural source for a
connection observation and is not: tracefs renders its argument as a pointer,
and it fires for AF_UNIX too, so a sensor built on it reports local socket
activity as network activity (KF-45).
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from annulon.network.contract import (
    AddressFamily, AttributionConfidence, ConnectionOutcome, NetworkOperation,
    SocketSemantic, Transport,
)
from annulon.network.normalize import NetworkNormalizer
from annulon.network.tracefs import RawEvent, parse_trace_line

BOOT = datetime(2026, 9, 21, 0, tzinfo=timezone.utc)

SYN_SENT = ("   python3-84870   [006] ..... 100.5: inet_sock_set_state: "
            "family=AF_INET protocol=IPPROTO_TCP sport=0 dport=44579 "
            "saddr=10.0.0.2 daddr=10.0.0.3 saddrv6=::ffff:10.0.0.2 "
            "daddrv6=::ffff:10.0.0.3 oldstate=TCP_CLOSE newstate=TCP_SYN_SENT")
ESTABLISHED_SOFTIRQ = (
    "   swapper/0-0   [002] ..s1. 100.6: inet_sock_set_state: "
    "family=AF_INET protocol=IPPROTO_TCP sport=51234 dport=44579 "
    "saddr=10.0.0.2 daddr=10.0.0.3 saddrv6=::ffff:10.0.0.2 "
    "daddrv6=::ffff:10.0.0.3 oldstate=TCP_SYN_SENT newstate=TCP_ESTABLISHED")
SYN_SENT_V6 = ("   curl-99   [001] ..... 200.0: inet_sock_set_state: "
               "family=AF_INET6 protocol=IPPROTO_TCP sport=0 dport=443 "
               "saddr= daddr= saddrv6=2001:db8::5 daddrv6=2001:db8::1 "
               "oldstate=TCP_CLOSE newstate=TCP_SYN_SENT")
CONNECT_RET = "   python3-84870   [006] ..... 100.7: sys_connect -> 0xffffffffffffff8d"


def _normalizer(**kwargs) -> NetworkNormalizer:
    return NetworkNormalizer(boot_time=BOOT, **kwargs)


def _one(line: str, **kwargs):
    return _normalizer(**kwargs).normalize(parse_trace_line(line))


# --- the primary event ------------------------------------------------------

def test_syn_sent_becomes_an_attributed_connect_attempt():
    """The measured design decision: this is the only source carrying both a
    destination and trustworthy process context."""
    observation = _one(SYN_SENT)
    assert observation.operation is NetworkOperation.CONNECT_ATTEMPT
    assert observation.process.pid == 84870
    assert observation.process.confidence is AttributionConfidence.PID_ONLY
    assert str(observation.remote) == "10.0.0.3:44579"
    assert observation.socket_semantic is SocketSemantic.CONNECT_INITIATOR


def test_an_attempt_does_not_claim_an_outcome():
    """SYN_SENT means it started, not that it worked."""
    assert _one(SYN_SENT).outcome is ConnectionOutcome.UNKNOWN


def test_ipv6_reads_the_v6_address_not_the_empty_v4_field():
    """tracefs emits both forms on every transition. Reading the wrong one
    yields an address that parses but is not what the socket used."""
    observation = _one(SYN_SENT_V6)
    assert observation.remote.family is AddressFamily.IPV6
    assert observation.remote.address == "2001:db8::1"
    assert str(observation.remote) == "[2001:db8::1]:443"


def test_ipv4_reads_the_v4_field_not_the_mapped_v6_form():
    observation = _one(SYN_SENT)
    assert observation.remote.family is AddressFamily.IPV4
    assert observation.remote.address == "10.0.0.3"


# --- softirq attribution ----------------------------------------------------

def test_a_softirq_transition_never_names_a_process():
    """The central safety property of this module.

    The completing ACK is processed while an unrelated task is current, so
    `swapper/0` would otherwise be recorded as having made the connection.
    A confidently wrong attribution is worse than none.
    """
    observation = _one(ESTABLISHED_SOFTIRQ)
    assert observation.operation is NetworkOperation.CONNECTION_ESTABLISHED
    assert observation.process.confidence is AttributionConfidence.NONE
    assert observation.process.pid == 0
    assert observation.socket_semantic is SocketSemantic.CURRENT_TASK
    assert "swapper" not in observation.process.comm


def test_a_softirq_transition_still_carries_its_flow():
    """Discarding the PID must not discard the observation: the flow is
    still real and can be correlated to an attempt."""
    observation = _one(ESTABLISHED_SOFTIRQ)
    assert str(observation.remote) == "10.0.0.3:44579"
    assert observation.outcome.is_established


def test_the_discarded_pid_is_counted():
    """A normaliser quietly dropping context is indistinguishable from a
    quiet network unless someone keeps score."""
    normalizer = _normalizer()
    normalizer.normalize(parse_trace_line(ESTABLISHED_SOFTIRQ))
    assert normalizer.stats.unattributable_discarded_pid == 1


def test_an_established_observation_in_task_context_keeps_its_process():
    """On loopback the client transition completes inline, and roughly half
    of the measured ones did. Discarding those would lose real attribution."""
    line = ESTABLISHED_SOFTIRQ.replace("..s1.", ".....").replace("swapper/0-0", "python3-84870")
    observation = _one(line)
    assert observation.process.pid == 84870
    assert observation.process.confidence is AttributionConfidence.PID_ONLY


# --- connect results --------------------------------------------------------

def test_einprogress_becomes_pending_not_failure():
    observation = _one(CONNECT_RET)
    assert observation.operation is NetworkOperation.CONNECT_RESULT
    assert observation.outcome is ConnectionOutcome.PENDING
    assert observation.errno == -115
    assert observation.remote is None, (
        "the syscall tracepoint cannot supply an address; claiming one would "
        "invent it")


@pytest.mark.parametrize("raw,expected", [
    ("0x0", ConnectionOutcome.ESTABLISHED),
    ("0xffffffffffffff8d", ConnectionOutcome.PENDING),      # -115
    ("0xffffffffffffff91", ConnectionOutcome.REFUSED),      # -111
    ("0xffffffffffffff92", ConnectionOutcome.TIMED_OUT),    # -110
])
def test_unsigned_kernel_returns_fold_to_signed_errnos(raw, expected):
    """tracefs prints returns unsigned. Reading 0xffffffffffffff8d as a
    positive number would make every error look like success."""
    event = RawEvent("sys_exit_connect", "python3", 1, 0, 1.0, ".....",
                     {"ret": raw})
    assert _normalizer().normalize(event).outcome is expected


# --- what must not become an observation ------------------------------------

def test_an_unrelated_state_transition_is_ignored_and_counted():
    line = SYN_SENT.replace("newstate=TCP_SYN_SENT", "newstate=TCP_TIME_WAIT") \
                   .replace("oldstate=TCP_CLOSE", "oldstate=TCP_FIN_WAIT2")
    normalizer = _normalizer()
    assert normalizer.normalize(parse_trace_line(line)) is None
    assert normalizer.stats.ignored_other_states == 1


@pytest.mark.parametrize("substitution", [
    ("family=AF_INET", "family=AF_UNIX"),
    ("family=AF_INET", "family=AF_NETLINK"),
    ("protocol=IPPROTO_TCP", "protocol=IPPROTO_ICMP"),
])
def test_a_non_ip_transition_is_ignored(substitution):
    """Local socket activity is not network activity (KF-45)."""
    normalizer = _normalizer()
    line = SYN_SENT.replace(*substitution)
    assert normalizer.normalize(parse_trace_line(line)) is None
    assert normalizer.stats.ignored_non_ip == 1


@pytest.mark.parametrize("substitution", [
    ("daddr=10.0.0.3", "daddr=999.999.999.999"),
    ("daddr=10.0.0.3", "daddr=not-an-address"),
    ("daddr=10.0.0.3", "daddr="),
    ("dport=44579", "dport=99999"),
    ("dport=44579", "dport=notaport"),
    ("dport=44579", "dport=-1"),
])
def test_a_malformed_address_or_port_produces_nothing(substitution):
    """Dropped and counted, never guessed at."""
    normalizer = _normalizer()
    assert normalizer.normalize(parse_trace_line(SYN_SENT.replace(*substitution))) is None
    assert normalizer.stats.dropped >= 1 or normalizer.stats.malformed_address >= 1


def test_a_v4_mapped_address_on_a_dual_stack_socket_is_reported_as_ipv4():
    """The packet on the wire is IPv4, so the observation says IPv4.

    A dual-stack socket reports AF_INET6 while carrying `::ffff:10.0.0.3`.
    Recording that as IPv6 would let an IPv4 policy miss it and an IPv6
    policy match traffic that is not IPv6 -- the same class of mistake as
    KF-38, one layer up.
    """
    line = SYN_SENT.replace("family=AF_INET ", "family=AF_INET6 ")
    observation = _normalizer().normalize(parse_trace_line(line))
    assert observation is not None
    assert observation.remote.family is AddressFamily.IPV4
    assert observation.remote.address == "10.0.0.3"
    assert observation.local.family is AddressFamily.IPV4


def test_a_genuine_ipv6_address_is_not_unmapped():
    """The positive control: unmapping must not eat real IPv6 traffic."""
    observation = _one(SYN_SENT_V6)
    assert observation.remote.family is AddressFamily.IPV6
    assert observation.remote.address == "2001:db8::1"


@pytest.mark.parametrize("event", [None, "a string", 42, [], {},
                                   RawEvent("unknown_kind", "x", 1, 0, 1.0, ".....")])
def test_anything_unrecognised_normalises_to_nothing(event):
    assert _normalizer().normalize(event) is None


# --- self-test marking ------------------------------------------------------

def test_a_liveness_probe_observation_is_marked_not_discarded():
    """Excluded from security interpretation, retained for health accounting:
    proving the sensor saw the probe is the entire point of the probe."""
    line = SYN_SENT.replace("dport=44579", "dport=19999") \
                   .replace("daddr=10.0.0.3", "daddr=127.0.0.1")
    observation = _one(line, self_test_port=19999)
    assert observation.is_self_test
    assert observation.remote.port == 19999


def test_ordinary_traffic_is_not_marked_as_a_self_test():
    """The reverse error would let an attacker's connection be ignored by
    claiming the probe's port."""
    assert not _one(SYN_SENT, self_test_port=19999).is_self_test


def test_a_remote_address_on_the_probe_port_is_not_a_self_test():
    """The probe only ever talks to loopback, so a non-loopback destination
    on the same port is somebody else."""
    line = SYN_SENT.replace("dport=44579", "dport=19999")
    assert not _one(line, self_test_port=19999).is_self_test


# --- timestamps -------------------------------------------------------------

def test_trace_timestamps_are_placed_on_a_wall_clock():
    """Seconds since boot cannot be correlated with any other sensor."""
    observation = _one(SYN_SENT)
    assert observation.observed_at.tzinfo is not None
    assert observation.observed_at > BOOT
    assert (observation.observed_at - BOOT).total_seconds() == pytest.approx(100.5)
