"""The network contract's defensive guards, exercised directly.

Mutation testing left 29 survivors across `contract.py` and `normalize.py`,
and almost every one was a type or range guard that the tracefs decode path
cannot reach — they exist for *programmatic* misuse, and nothing constructed
these objects wrongly on purpose. That is the second pattern KF-42 named: a
guard no test can reach is a guard a refactor can delete silently.

The boundary values are the other half. Every range check was exercised well
inside and well outside its limit and never *at* it, so `<` and `<=` were
indistinguishable.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from annulon.network.contract import (
    AddressFamily, AttributionConfidence, ConnectionOutcome, Direction,
    Endpoint, NetworkContractError, NetworkObservation, NetworkOperation,
    ProcessRef, SocketSemantic, Transport,
)
from annulon.network.normalize import NetworkNormalizer
from annulon.network.tracefs import RawEvent, parse_trace_line

NOW = datetime(2026, 9, 22, 12, tzinfo=timezone.utc)
BOOT = datetime(2026, 9, 22, 0, tzinfo=timezone.utc)


def _observation(**overrides) -> NetworkObservation:
    base = dict(
        observation_id="netobs-000000000001",
        operation=NetworkOperation.CONNECT_ATTEMPT, transport=Transport.TCP,
        direction=Direction.OUTBOUND,
        process=ProcessRef(pid=1000, tgid=1000, comm="worker"),
        local=Endpoint("10.0.0.2", 51234, AddressFamily.IPV4),
        remote=Endpoint("10.0.0.3", 443, AddressFamily.IPV4),
        observed_at=NOW, sensor_id="tracefs_network")
    base.update(overrides)
    return NetworkObservation(**base)


# --- ProcessRef range boundaries -------------------------------------------

def test_a_tgid_of_zero_is_accepted_and_minus_one_is_not():
    """`tgid < 0`, at the boundary. Zero is a real tgid."""
    assert ProcessRef(pid=0, tgid=0).tgid == 0
    with pytest.raises(NetworkContractError, match="must not be negative"):
        ProcessRef(pid=1, tgid=-1)


@pytest.mark.parametrize("field", ["start_boottime_ns", "start_ticks",
                                   "pid_namespace"])
def test_an_identity_field_of_zero_is_accepted_and_minus_one_is_not(field):
    """`value < 0`, at the boundary, for every field sharing the check."""
    assert getattr(ProcessRef(pid=1, **{field: 0}), field) == 0
    with pytest.raises(NetworkContractError, match="must not be negative"):
        ProcessRef(pid=1, **{field: -1})


def test_the_instance_key_falls_back_to_pid_when_there_is_no_tgid():
    """`tgid or pid`. Turning that into `and` yields `None@...`, an identity
    that silently matches every other process without a tgid."""
    reference = ProcessRef(pid=77, tgid=None, start_boottime_ns=5)
    assert reference.instance_key == "77@5"


def test_the_instance_key_prefers_the_tgid_when_present():
    """A thread's pid is not the process identity."""
    reference = ProcessRef(pid=99, tgid=77, start_boottime_ns=5)
    assert reference.instance_key == "77@5"


def test_the_tick_based_instance_key_has_the_same_fallback():
    assert ProcessRef(pid=77, tgid=None, start_ticks=9).instance_key == "77@9"


# --- Endpoint guards --------------------------------------------------------

def test_an_empty_address_and_a_non_string_address_are_both_refused():
    """`not isinstance(address, str) or not address`. As `and`, an empty
    string reaches `ip_address("")` and the error changes shape."""
    with pytest.raises(NetworkContractError):
        Endpoint("", 443, AddressFamily.IPV4)
    with pytest.raises(NetworkContractError):
        Endpoint(None, 443, AddressFamily.IPV4)
    with pytest.raises(NetworkContractError):
        Endpoint(167772161, 443, AddressFamily.IPV4)


@pytest.mark.parametrize("family", ["ipv4", "IPV4", 4, None, True, object()])
def test_the_address_family_must_be_the_enum(family):
    with pytest.raises(NetworkContractError, match="family must be"):
        Endpoint("10.0.0.1", 443, family)


# --- NetworkObservation guards ----------------------------------------------

@pytest.mark.parametrize("value", [None, "worker", 1000,
                                   {"pid": 1000}, ["worker"]])
def test_the_process_must_be_a_process_ref(value):
    with pytest.raises(NetworkContractError, match="process must be"):
        _observation(process=value)


@pytest.mark.parametrize("field", ["local", "remote"])
@pytest.mark.parametrize("value", ["10.0.0.3:443", 443,
                                   {"address": "10.0.0.3"}, []])
def test_an_endpoint_field_must_be_an_endpoint(field, value):
    with pytest.raises(NetworkContractError, match="must be an Endpoint"):
        _observation(**{field: value})


@pytest.mark.parametrize("sensor_id", ["", " ", "sensor id", "../sensor",
                                       "sensor\n", None, 42, "a" * 200])
def test_the_sensor_id_must_be_a_simple_identifier(sensor_id):
    """Both halves: the type check and the pattern. As `and`, a non-string
    reaches `_ID.match` and raises `TypeError` instead of the contract's own
    error — which the decoder above does not catch."""
    with pytest.raises(NetworkContractError, match="sensor_id"):
        _observation(sensor_id=sensor_id)


@pytest.mark.parametrize("errno", ["-115", 1.5, [], {}, True])
def test_the_errno_must_be_an_integer_when_present(errno):
    with pytest.raises(NetworkContractError, match="errno must be"):
        _observation(errno=errno)


def test_an_absent_errno_is_allowed():
    """The positive control for an optional field."""
    assert _observation(errno=None).errno is None


@pytest.mark.parametrize("namespace", ["4026531840", 1.5, [], {}, True])
def test_the_network_namespace_must_be_an_integer_when_present(namespace):
    with pytest.raises(NetworkContractError, match="network_namespace"):
        _observation(network_namespace=namespace)


def test_family_agreement_is_only_checked_when_both_endpoints_exist():
    """`local is not None and remote is not None`. As `or`, one endpoint
    being absent dereferences the other's `.family` on `None`."""
    assert _observation(local=None).local is None
    assert _observation(remote=None).remote is None
    with pytest.raises(NetworkContractError, match="disagree about"):
        _observation(local=Endpoint("10.0.0.2", 1, AddressFamily.IPV4),
                     remote=Endpoint("2001:db8::1", 2, AddressFamily.IPV6))


@pytest.mark.parametrize("missing", ["local", "remote"])
def test_a_flow_key_needs_both_endpoints(missing):
    """`local is None or remote is None`. As `and`, a half-formed flow gets
    a key containing the string `None` and can collide with another."""
    assert _observation(**{missing: None}).flow_key is None


def test_a_complete_observation_has_a_flow_key():
    assert _observation().flow_key is not None


# --- normalize: address-family handling -------------------------------------

def _state_line(**kwargs) -> str:
    fields = dict(family="AF_INET", protocol="IPPROTO_TCP", sport="0",
                  dport="443", saddr="10.0.0.2", daddr="10.0.0.3",
                  saddrv6="::ffff:10.0.0.2", daddrv6="::ffff:10.0.0.3",
                  old="TCP_CLOSE", new="TCP_SYN_SENT")
    fields.update(kwargs)
    return ("   worker-1000   [006] ..... 100.5: inet_sock_set_state: "
            f"family={fields['family']} protocol={fields['protocol']} "
            f"sport={fields['sport']} dport={fields['dport']} "
            f"saddr={fields['saddr']} daddr={fields['daddr']} "
            f"saddrv6={fields['saddrv6']} daddrv6={fields['daddrv6']} "
            f"oldstate={fields['old']} newstate={fields['new']}")


def test_unmapping_requires_both_endpoints_to_be_v6():
    """`local.family is IPV6 and remote.family is IPV6`. As `or`, a genuinely
    mixed pair would be half-unmapped into an inconsistent record."""
    normalizer = NetworkNormalizer(boot_time=BOOT)
    observation = normalizer.normalize(parse_trace_line(_state_line(
        family="AF_INET6", saddrv6="2001:db8::5", daddrv6="2001:db8::1")))
    assert observation.local.family is AddressFamily.IPV6
    assert observation.remote.family is AddressFamily.IPV6


def test_unmapping_happens_only_when_both_sides_unmap():
    """`unmapped_local is not None and unmapped_remote is not None`. As `or`,
    one side becomes IPv4 while the other stays IPv6 -- a record the contract
    would then reject, losing a real observation."""
    normalizer = NetworkNormalizer(boot_time=BOOT)
    observation = normalizer.normalize(parse_trace_line(_state_line(
        family="AF_INET6", saddrv6="::ffff:10.0.0.2", daddrv6="::ffff:10.0.0.3")))
    assert observation is not None
    assert observation.local.family is observation.remote.family is AddressFamily.IPV4


@pytest.mark.parametrize("unset", ["::", "::ffff:0.0.0.0", ""])
def test_an_unset_v6_address_yields_no_observation(unset):
    """tracefs emits a placeholder rather than omitting the field."""
    normalizer = NetworkNormalizer(boot_time=BOOT)
    assert normalizer.normalize(parse_trace_line(_state_line(
        family="AF_INET6", saddrv6="2001:db8::5", daddrv6=unset))) is None


def test_a_v4_address_under_a_v6_family_is_refused():
    """`parsed.version != family.version`. Without it an address that parses
    as IPv4 would be labelled IPv6."""
    normalizer = NetworkNormalizer(boot_time=BOOT)
    assert normalizer.normalize(parse_trace_line(_state_line(
        family="AF_INET6", saddrv6="10.0.0.2", daddrv6="10.0.0.3"))) is None


def test_a_non_mapped_v6_address_is_not_unmapped():
    """`mapped is None`. The positive control for `_unmap`: real IPv6 must
    survive."""
    normalizer = NetworkNormalizer(boot_time=BOOT)
    observation = normalizer.normalize(parse_trace_line(_state_line(
        family="AF_INET6", saddrv6="2001:db8::5", daddrv6="2001:db8::1")))
    assert observation.remote.address == "2001:db8::1"


# --- normalize: return-value folding ----------------------------------------

def _result(raw: str):
    return NetworkNormalizer(boot_time=BOOT).normalize(
        RawEvent("sys_exit_connect", "worker", 1000, 0, 100.0, ".....",
                 {"ret": raw}))


def test_the_unsigned_fold_boundary_is_exact():
    """`value >= 1 << 63`. At exactly 2**63 the value is the most negative
    signed integer, not a huge positive success."""
    observation = _result(hex(1 << 63))
    assert observation.errno == -(1 << 63)
    assert observation.outcome is ConnectionOutcome.OTHER_ERROR


def test_one_below_the_fold_boundary_stays_positive_and_is_unexplained():
    observation = _result(hex((1 << 63) - 1))
    assert observation.errno == (1 << 63) - 1
    assert observation.outcome is ConnectionOutcome.OTHER_ERROR


def test_an_anomalous_positive_return_is_not_upgraded_to_established():
    """`connect()` returns 0 or a negative errno, never a positive value.

    Coercing an anomalous positive to zero turned it into ESTABLISHED -- an
    upgrade of evidence from something the kernel is not supposed to
    produce. Found by mutation testing in 04E.
    """
    observation = _result("0x5")
    assert observation.errno == 5
    assert observation.outcome is ConnectionOutcome.OTHER_ERROR
    assert not observation.outcome.is_established


def test_a_zero_return_is_still_established():
    """The positive control: the honest success case must survive."""
    assert _result("0x0").outcome is ConnectionOutcome.ESTABLISHED


# --- normalize_all filtering ------------------------------------------------

def test_normalize_all_drops_unusable_events_rather_than_emitting_none():
    """`if observation is not None`. Inverting it fills the stream with
    `None`, and every consumer then has to guess."""
    normalizer = NetworkNormalizer(boot_time=BOOT)
    events = [parse_trace_line(_state_line()),
              parse_trace_line(_state_line(new="TCP_TIME_WAIT", old="TCP_FIN_WAIT2")),
              parse_trace_line(_state_line(daddr="not-an-address"))]
    produced = normalizer.normalize_all(events)
    assert len(produced) == 1
    assert all(o is not None for o in produced)


def test_normalize_all_on_an_empty_stream_produces_nothing():
    assert NetworkNormalizer(boot_time=BOOT).normalize_all([]) == []


# --- boot time reconstruction ----------------------------------------------

def test_the_boot_time_is_read_from_proc_stat_when_available(tmp_path, monkeypatch):
    """Trace timestamps are seconds since boot; without a boot wall-clock
    they cannot be placed on a timeline shared with any other sensor."""
    stat = tmp_path / "stat"
    stat.write_text("cpu  1 2 3\nbtime 1758499200\nprocesses 42\n")
    import builtins
    real_open = builtins.open

    def fake_open(path, *args, **kwargs):
        if path == "/proc/stat":
            return real_open(stat, *args, **kwargs)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", fake_open)
    normalizer = NetworkNormalizer()
    assert normalizer._boot_time == datetime.fromtimestamp(
        1758499200, tz=timezone.utc)


def test_an_unreadable_proc_stat_falls_back_to_now_rather_than_raising(monkeypatch):
    """A sensor that cannot start because /proc/stat is odd is worse than one
    whose timestamps are slightly less well anchored."""
    import builtins
    real_open = builtins.open

    def fake_open(path, *args, **kwargs):
        if path == "/proc/stat":
            raise OSError("unavailable")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", fake_open)
    normalizer = NetworkNormalizer()
    assert normalizer._boot_time.tzinfo is not None


def test_a_proc_stat_without_btime_falls_back(monkeypatch, tmp_path):
    stat = tmp_path / "stat"
    stat.write_text("cpu  1 2 3\nprocesses 42\n")
    import builtins
    real_open = builtins.open

    def fake_open(path, *args, **kwargs):
        if path == "/proc/stat":
            return real_open(stat, *args, **kwargs)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", fake_open)
    assert NetworkNormalizer()._boot_time.tzinfo is not None


# --- partial v4-mapping -----------------------------------------------------

def test_a_pair_where_only_one_side_is_v4_mapped_stays_ipv6():
    """Both endpoints unmap together or not at all.

    A dual-stack socket talking to a genuine IPv6 peer has a v4-mapped local
    address and a real v6 remote. Unmapping only the half that can be
    unmapped produces a mixed-family record the contract then rejects -- so
    a real observation would be silently lost rather than reported.
    """
    normalizer = NetworkNormalizer(boot_time=BOOT)
    observation = normalizer.normalize(parse_trace_line(_state_line(
        family="AF_INET6", saddrv6="::ffff:10.0.0.2", daddrv6="2001:db8::1")))
    assert observation is not None, "a valid observation was dropped"
    assert observation.local.family is AddressFamily.IPV6
    assert observation.remote.family is AddressFamily.IPV6
    assert observation.remote.address == "2001:db8::1"
