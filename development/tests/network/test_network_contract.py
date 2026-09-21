"""The network observation contract, attacked rather than demonstrated.

KF-36 was four ALLOW-producing defects in the privileged decoder, every one
caused by `str()` or `int()` being helpful with the wrong type. This contract
is written after that lesson, so the tests are written to find the same
family here before it ships rather than after.

The other theme is honesty about uncertainty: an observation that cannot say
which process instance it belongs to must say so, and a record must never
contradict itself.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

import pytest

from annulon.network.contract import (
    AddressFamily, AttributionConfidence, ConnectionOutcome, Direction,
    Endpoint, NetworkContractError, NetworkObservation, NetworkOperation,
    ProcessRef, SocketSemantic, Transport, outcome_for_errno,
)

NOW = datetime(2026, 9, 21, 12, tzinfo=timezone.utc)

HOSTILE = [
    None, True, False, -1, 0, 2 ** 63, -(2 ** 63), 1.5, float("inf"),
    float("nan"), "", " ", "\x00", "\n", "../../etc/passwd", "; rm -rf /",
    "$(id)", "`id`", "‮", "﻿", "A" * 10_000, [], {}, [1, 2],
    {"a": {"b": {}}},
]


def _process(**overrides) -> ProcessRef:
    base = dict(pid=1234, tgid=1234, comm="worker",
                start_boottime_ns=53304640255814, pid_namespace=4026531836,
                confidence=AttributionConfidence.INSTANCE_BOUND)
    base.update(overrides)
    return ProcessRef(**base)


def _observation(**overrides) -> NetworkObservation:
    base = dict(
        observation_id="obs-000001", operation=NetworkOperation.CONNECT_ATTEMPT,
        transport=Transport.TCP, direction=Direction.OUTBOUND,
        process=_process(),
        local=Endpoint("10.0.0.2", 51234, AddressFamily.IPV4),
        remote=Endpoint("10.0.0.3", 443, AddressFamily.IPV4),
        observed_at=NOW, sensor_id="tracefs")
    base.update(overrides)
    return NetworkObservation(**base)


# --- EINPROGRESS is not a failure ------------------------------------------

def test_einprogress_is_pending_not_failure_and_not_success():
    """The measurement that shaped this contract.

    All 500 successful connections in the sensor evaluation returned -115,
    because `settimeout()` makes the socket non-blocking. A contract that
    could only say "succeeded" or "failed" would have been wrong 500 times.
    """
    outcome = outcome_for_errno(-115)
    assert outcome is ConnectionOutcome.PENDING
    assert not outcome.is_established


@pytest.mark.parametrize("errno,expected", [
    (0, ConnectionOutcome.ESTABLISHED),
    (-115, ConnectionOutcome.PENDING),
    (-114, ConnectionOutcome.PENDING),
    (-111, ConnectionOutcome.REFUSED),
    (-113, ConnectionOutcome.UNREACHABLE),
    (-101, ConnectionOutcome.UNREACHABLE),
    (-110, ConnectionOutcome.TIMED_OUT),
    (-13, ConnectionOutcome.PERMISSION_DENIED),
])
def test_each_errno_maps_to_its_own_outcome(errno, expected):
    """Distinct failures stay distinct. Collapsing them all into one
    'connection failed' would make a refused port indistinguishable from an
    unreachable network, which are different security stories."""
    assert outcome_for_errno(errno) is expected


def test_an_unmapped_errno_is_other_error_not_a_guess():
    assert outcome_for_errno(-9999) is ConnectionOutcome.OTHER_ERROR


@pytest.mark.parametrize("value", [None, "0", True, 1.0, [0]])
def test_a_non_integer_errno_is_refused(value):
    with pytest.raises(NetworkContractError):
        outcome_for_errno(value)


def test_an_established_observation_cannot_carry_a_contradictory_outcome():
    """A record that contradicts itself is worse than a missing one."""
    with pytest.raises(NetworkContractError, match="must carry an ESTABLISHED"):
        _observation(operation=NetworkOperation.CONNECTION_ESTABLISHED,
                     outcome=ConnectionOutcome.PENDING)


def test_an_established_observation_with_a_matching_outcome_is_fine():
    observation = _observation(
        operation=NetworkOperation.CONNECTION_ESTABLISHED,
        outcome=ConnectionOutcome.ESTABLISHED)
    assert observation.outcome.is_established


# --- endpoints --------------------------------------------------------------

@pytest.mark.parametrize("address", [
    "not-an-address", "999.999.999.999", "10.0.0", "10.0.0.1/24", "",
    "10.0.0.1:443", " 10.0.0.1", "10.0.0.1 ", "0x0a000001",
    "２５５.255.255.255",          # fullwidth digits
    "localhost", "example.com",   # a name is not a socket destination
])
def test_a_malformed_address_is_refused(address):
    """Addresses are parsed, never trusted as text.

    `example.com` is refused deliberately: a DNS name is not a socket
    destination, and an observation must not imply a correlation that has
    not been established.
    """
    with pytest.raises(NetworkContractError):
        Endpoint(address, 443, AddressFamily.IPV4)


@pytest.mark.parametrize("port", [-1, 65536, 2 ** 31, "443", None, True, 443.0])
def test_a_malformed_port_is_refused(port):
    with pytest.raises(NetworkContractError):
        Endpoint("10.0.0.1", port, AddressFamily.IPV4)


@pytest.mark.parametrize("port", [0, 1, 80, 65535])
def test_valid_ports_are_accepted(port):
    """The positive control: strictness must not refuse real ports."""
    assert Endpoint("10.0.0.1", port, AddressFamily.IPV4).port == port


def test_an_address_family_mismatch_is_refused():
    """A v4 address labelled v6 would make every family-based rule wrong."""
    with pytest.raises(NetworkContractError, match="IPv4 but family says IPv6"):
        Endpoint("10.0.0.1", 443, AddressFamily.IPV6)
    with pytest.raises(NetworkContractError, match="IPv6 but family says IPv4"):
        Endpoint("2001:db8::1", 443, AddressFamily.IPV4)


@pytest.mark.parametrize("address", [
    "::1", "2001:db8::1", "fe80::1", "::", "::ffff:10.0.0.1",
    "2001:0db8:0000:0000:0000:0000:0000:0001",
])
def test_ipv6_addresses_are_supported_from_the_start(address):
    """IPv6 is in scope here, unlike containment where it is a stated gap."""
    endpoint = Endpoint(address, 443, AddressFamily.IPV6)
    assert endpoint.family is AddressFamily.IPV6
    assert str(endpoint).startswith("[")


def test_endpoints_disagreeing_about_family_are_refused():
    with pytest.raises(NetworkContractError, match="disagree about address family"):
        _observation(local=Endpoint("10.0.0.2", 51234, AddressFamily.IPV4),
                     remote=Endpoint("2001:db8::1", 443, AddressFamily.IPV6))


# --- process attribution ----------------------------------------------------

def test_a_pid_alone_is_marked_as_such():
    """The enum exists so that a weak attribution cannot pass for a strong
    one without the consumer ignoring a field."""
    reference = ProcessRef(pid=1234, confidence=AttributionConfidence.PID_ONLY)
    assert reference.instance_key is None
    assert not reference.confidence.sufficient_for_workload_attribution


def test_an_instance_key_survives_pid_reuse():
    """Two processes, same PID, different start times: different identities.

    This is the synthetic half of the PID-reuse property. Forcing real reuse
    is a separate, physical test.
    """
    first = _process(pid=1234, start_boottime_ns=1_000_000_000)
    second = _process(pid=1234, start_boottime_ns=9_000_000_000)
    assert first.pid == second.pid
    assert first.instance_key != second.instance_key
    assert first != second


def test_a_start_time_in_ticks_also_forms_an_instance_key():
    """Not every sensor can supply nanoseconds; ticks still disambiguate."""
    reference = ProcessRef(pid=7, tgid=7, start_ticks=5338115,
                           confidence=AttributionConfidence.CORRELATED)
    assert reference.instance_key == "7@5338115"


@pytest.mark.parametrize("value", HOSTILE)
def test_no_hostile_value_is_accepted_as_a_pid(value):
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return                       # a real pid; not a hostile case
    with pytest.raises(NetworkContractError):
        ProcessRef(pid=value)


@pytest.mark.parametrize("field", ["tgid", "start_boottime_ns", "start_ticks",
                                   "pid_namespace"])
@pytest.mark.parametrize("value", [-1, "1", True, 1.5, [], {}])
def test_no_hostile_value_is_accepted_in_an_identity_field(field, value):
    with pytest.raises(NetworkContractError):
        _process(**{field: value})


@pytest.mark.parametrize("comm", ["a" * 65, "worker\n", "worker\x00",
                                  "‮worker", "wörker", 1234, None, b"x"])
def test_a_malformed_comm_is_refused(comm):
    """`comm` is decorative, but a control character in it reaches logs."""
    with pytest.raises(NetworkContractError):
        _process(comm=comm)


def test_attribution_confidence_must_be_the_enum():
    with pytest.raises(NetworkContractError):
        _process(confidence="instance_bound")


# --- namespace and flow identity -------------------------------------------

def test_the_flow_key_includes_the_network_namespace():
    """The same address pair can exist in several namespaces at once, so a
    tuple alone does not identify a flow on a host running containers."""
    host = _observation(network_namespace=4026531840)
    container = _observation(network_namespace=4026532567)
    assert host.flow_key != container.flow_key
    assert "4026531840" in host.flow_key


def test_a_flow_key_is_absent_when_endpoints_are():
    assert _observation(local=None, remote=None).flow_key is None


def test_socket_semantic_is_explicit():
    """"Owner" is never used unqualified: the process that created a socket,
    the one that connected it and the one that writes to it can all differ."""
    observation = _observation()
    assert observation.socket_semantic is SocketSemantic.CONNECT_INITIATOR
    assert SocketSemantic.CURRENT_TASK is not SocketSemantic.CONNECT_INITIATOR


def test_the_destination_semantic_is_recorded():
    """Pre-NAT and wire destinations must never be silently merged."""
    assert _observation().destination_semantic == "application_requested_pre_nat"


# --- self-test marking ------------------------------------------------------

def test_a_self_test_observation_is_identifiable():
    """Liveness traffic must be excludable from security interpretation --
    and must still exist, so health accounting can prove the sensor saw it."""
    probe = _observation(is_self_test=True)
    assert probe.is_self_test
    assert not _observation().is_self_test
    assert probe.to_dict()["is_self_test"] is True


# --- structural -------------------------------------------------------------

@pytest.mark.parametrize("field,expected", [
    ("operation", NetworkOperation), ("transport", Transport),
    ("direction", Direction), ("outcome", ConnectionOutcome),
    ("socket_semantic", SocketSemantic),
])
def test_every_enum_field_rejects_a_bare_string(field, expected):
    """The KF-36 family: a string that looks like an enum value is not one."""
    with pytest.raises(NetworkContractError):
        _observation(**{field: "connect_attempt"})


@pytest.mark.parametrize("identifier", ["", " ", "obs 1", "../obs", "obs\n",
                                        "a" * 200, None, 1])
def test_a_malformed_observation_id_is_refused(identifier):
    with pytest.raises(NetworkContractError):
        _observation(observation_id=identifier)


def test_a_naive_timestamp_is_refused():
    with pytest.raises(NetworkContractError, match="timezone-aware"):
        _observation(observed_at=datetime(2026, 9, 21, 12))


def test_the_observation_serialises_completely():
    body = _observation().to_dict()
    for key in ("operation", "transport", "direction", "process", "local",
                "remote", "observed_at", "sensor_id", "outcome",
                "socket_semantic", "destination_semantic",
                "network_namespace", "is_self_test", "flow_key"):
        assert key in body, f"{key} missing from the serialised form"
    assert body["process"]["instance_key"] == "1234@53304640255814"
