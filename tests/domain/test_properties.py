"""Property-based tests for domain invariants.

Uses a seeded stdlib generator rather than ``hypothesis``. That is a
deliberate, reversible choice: adding a dependency is governed by P8-SEC-04
and the isolated dependency-acquisition workflow does not exist yet. The
generators below are explicit about their domains, and every failure is
reproducible from the printed seed.

The properties asserted here are the ones whose violation in the legacy
implementation caused real defects:

  P1  value equality implies hash equality, across the full identifier space
  P2  round-tripping through any serialisation preserves the value
  P3  no constructor accepts a value outside its stated domain
  P4  no "update" method mutates its receiver
  P5  ordering is total and consistent with equality
  P6  a deadline's expiry depends only on monotonic time
"""

from __future__ import annotations

import pickle
import random
from datetime import datetime, timedelta, timezone

import pytest

from sdnguard.clock import Deadline, ManualClock
from sdnguard.domain.events import (
    EnforcementAction,
    EnforcementDecision,
    FindingKind,
    MovementEvent,
    ProbeMethod,
    ProbeOutcome,
    ProbeRequest,
    ProbeResult,
    SecurityFinding,
    Severity,
    Verdict,
)
from sdnguard.domain.host import (
    HostIdentity,
    HostLocation,
    IPAddress,
    MacAddress,
)
from sdnguard.domain.identity import (
    DPID_MAX,
    OFPP_MAX,
    DatapathId,
    InvalidIdentity,
    PortIdentity,
    PortNumber,
)

SEED = 20260920
ITERATIONS = 400
T0 = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)


# -- generators ------------------------------------------------------------


def _rng(tag: str) -> random.Random:
    """A separate deterministic stream per property, so one test's draw count
    cannot shift another's."""
    return random.Random(f"{SEED}:{tag}")


def gen_dpid(rng: random.Random) -> DatapathId:
    return DatapathId(rng.randrange(0, DPID_MAX + 1))


def gen_port_number(rng: random.Random) -> PortNumber:
    return PortNumber(rng.randrange(1, OFPP_MAX + 1))


def gen_port(rng: random.Random) -> PortIdentity:
    return PortIdentity(gen_dpid(rng), gen_port_number(rng))


def gen_mac(rng: random.Random) -> MacAddress:
    """Unicast only: multicast cannot identify a host."""
    while True:
        mac = MacAddress(rng.randrange(0, 2**48))
        if mac.is_unicast_routable:
            return mac


def gen_ip(rng: random.Random) -> IPAddress:
    if rng.random() < 0.5:
        return IPAddress.from_int(rng.randrange(0, 2**32), 4)
    return IPAddress.from_int(rng.randrange(0, 2**128), 6)


def gen_identity(rng: random.Random) -> HostIdentity:
    return HostIdentity.of(gen_mac(rng), gen_ip(rng) if rng.random() < 0.5 else None)


def gen_moment(rng: random.Random) -> datetime:
    return T0 + timedelta(seconds=rng.randrange(0, 10_000_000))


# -- P1: equality implies hash equality ------------------------------------


@pytest.mark.parametrize(
    "tag,build",
    [
        ("dpid", gen_dpid),
        ("portnum", gen_port_number),
        ("port", gen_port),
        ("mac", gen_mac),
        ("ip", gen_ip),
        ("identity", gen_identity),
    ],
)
def test_property_equality_implies_equal_hash(tag, build):
    rng = _rng(tag)
    for i in range(ITERATIONS):
        a = build(rng)
        b = pickle.loads(pickle.dumps(a))       # an independently built equal value
        assert a == b, f"{tag} iteration {i} seed {SEED}"
        assert hash(a) == hash(b), f"{tag} iteration {i} seed {SEED}"
        assert len({a, b}) == 1
        assert {a: i}[b] == i


def test_property_distinct_values_are_not_equal():
    rng = _rng("distinct")
    seen: dict[PortIdentity, tuple[int, int]] = {}
    for _ in range(ITERATIONS * 4):
        port = gen_port(rng)
        key = (port.datapath_id.value, port.port.value)
        if port in seen:
            assert seen[port] == key, "a hash collision returned the wrong entry"
        seen[port] = key


# -- P2: serialisation round-trips -----------------------------------------


@pytest.mark.parametrize("tag,build", [("dpid", gen_dpid), ("mac", gen_mac), ("ip", gen_ip)])
def test_property_text_round_trip(tag, build):
    rng = _rng(f"text:{tag}")
    parsers = {"dpid": DatapathId.from_hex, "mac": MacAddress.parse, "ip": IPAddress.parse}
    for i in range(ITERATIONS):
        value = build(rng)
        assert parsers[tag](str(value)) == value, f"{tag} iteration {i} seed {SEED}"


def test_property_pickle_round_trip_over_composite_values():
    rng = _rng("pickle")
    for _ in range(ITERATIONS):
        loc = HostLocation.at(gen_port(rng), gen_moment(rng))
        assert pickle.loads(pickle.dumps(loc)) == loc


def test_property_finding_serialisation_is_json_safe():
    import json

    rng = _rng("finding")
    for _ in range(ITERATIONS):
        finding = SecurityFinding.create(
            rng.choice(list(FindingKind)), rng.choice(list(Verdict)),
            rng.choice(list(Severity)), gen_identity(rng), gen_port(rng),
            gen_moment(rng), ("evidence",), "summary")
        payload = finding.to_dict()
        assert json.loads(json.dumps(payload)) == payload


# -- P3: constructors reject out-of-domain values --------------------------


def test_property_dpid_rejects_everything_outside_the_range():
    rng = _rng("dpid-bad")
    for _ in range(ITERATIONS):
        for bad in (-rng.randrange(1, 2**64), DPID_MAX + rng.randrange(1, 2**32)):
            with pytest.raises(InvalidIdentity):
                DatapathId(bad)


def test_property_port_rejects_the_unassigned_gap():
    """Values between OFPP_MAX and OFPP_IN_PORT are unassigned in OpenFlow 1.3;
    accepting them would turn an adapter bug into a silent lookup miss."""
    rng = _rng("port-gap")
    for _ in range(ITERATIONS):
        bad = rng.randrange(OFPP_MAX + 1, 0xFFFFFFF8)
        with pytest.raises(InvalidIdentity):
            PortNumber(bad)


def test_property_mac_rejects_out_of_range():
    rng = _rng("mac-bad")
    for _ in range(ITERATIONS):
        with pytest.raises(InvalidIdentity):
            MacAddress(2**48 + rng.randrange(0, 2**32))


def test_property_multicast_mac_never_identifies_a_host():
    rng = _rng("mcast")
    for _ in range(ITERATIONS):
        value = rng.randrange(0, 2**48) | (1 << 40)      # set the group bit
        mac = MacAddress(value)
        assert mac.is_multicast
        with pytest.raises(InvalidIdentity):
            HostIdentity.of(mac)


def test_property_probe_always_requires_a_future_deadline():
    rng = _rng("probe-deadline")
    for _ in range(ITERATIONS):
        issued = gen_moment(rng)
        with pytest.raises(InvalidIdentity):
            ProbeRequest.create(gen_identity(rng), gen_port(rng), issued,
                                timedelta(seconds=-rng.randrange(0, 1000)))


def test_property_enforcement_always_requires_scope_and_expiry():
    rng = _rng("enforce")
    enforcing = [a for a in EnforcementAction
                 if a not in {EnforcementAction.OBSERVE, EnforcementAction.ALERT}]
    for _ in range(ITERATIONS):
        action = rng.choice(enforcing)
        with pytest.raises(InvalidIdentity):
            EnforcementDecision.create("f" * 32, action, gen_moment(rng), "reason")


# -- P4: updates never mutate the receiver ---------------------------------


def test_property_with_ip_does_not_mutate():
    rng = _rng("with-ip")
    for _ in range(ITERATIONS):
        before = HostIdentity.of(gen_mac(rng))
        snapshot = (before.mac, before.ip)
        after = before.with_ip(gen_ip(rng))
        assert (before.mac, before.ip) == snapshot
        assert after is not before


def test_property_refreshed_does_not_mutate():
    rng = _rng("refresh")
    for _ in range(ITERATIONS):
        moment = gen_moment(rng)
        loc = HostLocation.at(gen_port(rng), moment)
        later = loc.refreshed(moment + timedelta(seconds=rng.randrange(1, 1000)))
        assert loc.last_seen == moment
        assert later.first_seen == moment
        assert later.last_seen >= later.first_seen


def test_property_refresh_never_accepts_a_backwards_moment():
    rng = _rng("refresh-back")
    for _ in range(ITERATIONS):
        moment = gen_moment(rng)
        loc = HostLocation.at(gen_port(rng), moment)
        with pytest.raises(InvalidIdentity):
            loc.refreshed(moment - timedelta(seconds=rng.randrange(1, 1000)))


# -- P5: ordering is total and consistent with equality --------------------


@pytest.mark.parametrize("tag,build", [("dpid", gen_dpid), ("port", gen_port), ("mac", gen_mac)])
def test_property_ordering_is_total_and_consistent(tag, build):
    rng = _rng(f"order:{tag}")
    for _ in range(ITERATIONS):
        a, b = build(rng), build(rng)
        assert (a < b) + (a > b) + (a == b) == 1, "exactly one relation must hold"
        if a == b:
            assert not (a < b or b < a)
        else:
            assert (a < b) != (b < a)


def test_property_sorting_is_stable_and_deterministic():
    rng = _rng("sort")
    for _ in range(50):
        ports = [gen_port(rng) for _ in range(20)]
        assert sorted(ports) == sorted(list(ports))
        assert [str(p) for p in sorted(ports)] == [str(p) for p in sorted(reversed(ports))]


# -- P6: deadlines depend only on monotonic time ---------------------------


def test_property_deadline_ignores_arbitrary_wall_clock_steps():
    rng = _rng("deadline")
    for _ in range(ITERATIONS):
        clock = ManualClock(T0)
        timeout = rng.randrange(1, 600)
        deadline = Deadline.after(clock, timeout)
        clock.advance(rng.randrange(0, timeout))
        assert not deadline.expired(clock)
        clock.set_wall(T0 + timedelta(days=rng.randrange(-3650, 3650)))
        assert not deadline.expired(clock), "a wall step must not expire a live deadline"
        clock.advance_monotonic(timeout)
        assert deadline.expired(clock)
        clock.set_wall(T0 - timedelta(days=rng.randrange(1, 3650)))
        assert deadline.expired(clock), "a wall step must not un-expire a deadline"


def test_property_probe_expiry_is_monotonic_in_time():
    rng = _rng("probe-expiry")
    for _ in range(ITERATIONS):
        issued = gen_moment(rng)
        timeout = timedelta(seconds=rng.randrange(1, 600))
        probe = ProbeRequest.create(gen_identity(rng), gen_port(rng), issued, timeout)
        assert not probe.is_expired_at(issued)
        assert probe.is_expired_at(issued + timeout)
        assert probe.is_expired_at(issued + timeout * 2)


# -- cross-cutting: a movement event always describes two ports ------------


def test_property_movement_requires_two_distinct_ports():
    rng = _rng("movement")
    for _ in range(ITERATIONS):
        port = gen_port(rng)
        loc = HostLocation.at(port, gen_moment(rng))
        with pytest.raises(InvalidIdentity):
            MovementEvent.of(gen_identity(rng), loc,
                             HostLocation.at(port, gen_moment(rng)), gen_moment(rng))


def test_property_probe_result_presence_is_exactly_replied():
    rng = _rng("outcome")
    for _ in range(ITERATIONS):
        outcome = rng.choice(list(ProbeOutcome))
        result = ProbeResult.of("c" * 32, outcome, gen_moment(rng))
        assert result.host_was_still_present == (outcome is ProbeOutcome.REPLIED)
