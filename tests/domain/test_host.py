"""Host addressing, identity, location and observation."""

from __future__ import annotations

import dataclasses
import pickle
import random
from datetime import datetime, timedelta, timezone

import pytest

from sdnguard.domain.host import (
    BROADCAST_MAC,
    NULL_MAC,
    HostIdentity,
    HostLocation,
    HostObservation,
    IPAddress,
    MacAddress,
)
from sdnguard.domain.identity import InvalidIdentity, PortIdentity

T0 = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
PORT_A = PortIdentity.of(0x0000AABBCCDDEEFF, 3)
PORT_B = PortIdentity.of(0x0000AABBCCDDEEFF, 4)
MAC_A = MacAddress.parse("aa:bb:cc:dd:ee:01")


# -- MacAddress ------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    ["aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff",
     "aabb.ccdd.eeff", "aabbccddeeff", "  aa:bb:cc:dd:ee:ff  "],
)
def test_all_mac_notations_normalise_to_one_value(text):
    """Equality must not depend on which adapter produced the string."""
    assert MacAddress.parse(text) == MacAddress(0xAABBCCDDEEFF)
    assert hash(MacAddress.parse(text)) == hash(MacAddress(0xAABBCCDDEEFF))


def test_mac_canonical_string_and_bytes_round_trip():
    m = MacAddress(0xAABBCCDDEEFF)
    assert str(m) == "aa:bb:cc:dd:ee:ff"
    assert MacAddress.from_bytes(m.to_bytes()) == m
    assert m.to_bytes() == b"\xaa\xbb\xcc\xdd\xee\xff"


@pytest.mark.parametrize("bad", ["", "zz:zz:zz:zz:zz:zz", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:ff:00", 42, None])
def test_mac_parse_rejects_malformed(bad):
    with pytest.raises(InvalidIdentity):
        MacAddress.parse(bad)


@pytest.mark.parametrize("bad", [-1, 2**48, True, "x"])
def test_mac_rejects_out_of_range(bad):
    with pytest.raises(InvalidIdentity):
        MacAddress(bad)


@pytest.mark.parametrize("raw", [b"", b"\x01" * 5, b"\x01" * 7, "abcdef"])
def test_mac_from_bytes_requires_six_bytes(raw):
    with pytest.raises(InvalidIdentity):
        MacAddress.from_bytes(raw)


def test_mac_classification_flags():
    assert BROADCAST_MAC.is_broadcast and BROADCAST_MAC.is_multicast
    assert NULL_MAC.is_null and not NULL_MAC.is_unicast_routable
    assert MacAddress.parse("01:80:c2:00:00:0e").is_multicast          # LLDP
    assert MacAddress.parse("02:00:00:00:00:01").is_locally_administered
    assert not MacAddress.parse("aa:bb:cc:dd:ee:01").is_multicast
    assert MacAddress.parse("aa:bb:cc:dd:ee:01").is_unicast_routable


def test_mac_property_round_trip_over_random_48bit_values():
    rng = random.Random(4242)
    for _ in range(2000):
        v = rng.randrange(0, 2**48)
        m = MacAddress(v)
        assert MacAddress.parse(str(m)) == m
        assert MacAddress.from_bytes(m.to_bytes()) == m
        assert hash(MacAddress(v)) == hash(m)


# -- IPAddress -------------------------------------------------------------


@pytest.mark.parametrize(
    "text,version",
    [("10.0.0.1", 4), ("0.0.0.0", 4), ("255.255.255.255", 4),
     ("172.20.20.10", 4), ("2001:db8::1", 6), ("::1", 6)],
)
def test_ip_parse_round_trip(text, version):
    ip = IPAddress.parse(text)
    assert ip.version == version
    assert str(ip) == text
    assert IPAddress.parse(str(ip)) == ip
    assert hash(IPAddress.parse(text)) == hash(ip)


@pytest.mark.parametrize("value", [0x0A000001, 0xAC14140A, 0x00FF0001, 0, 0xFFFFFFFF])
def test_ip_from_int_handles_values_that_broke_the_legacy_conversion(value):
    """Legacy used BigInteger.valueOf(int).toByteArray(), which drops leading
    zero bytes and mishandles the sign bit. 0x00FF0001 and 0xAC14140A are the
    cases that exposed it."""
    ip = IPAddress.from_int(value)
    assert ip.version == 4
    assert len(ip.packed) == 4
    assert int.from_bytes(ip.packed, "big") == value


@pytest.mark.parametrize("bad", ["", "999.1.1.1", "not-an-ip", None, "10.0.0.1/24"])
def test_ip_parse_rejects_malformed(bad):
    with pytest.raises(InvalidIdentity, match="malformed"):
        IPAddress.parse(bad)


@pytest.mark.parametrize("bad", [-1, 2**32, True])
def test_ip_from_int_rejects_out_of_range(bad):
    with pytest.raises(InvalidIdentity):
        IPAddress.from_int(bad)


def test_ip_rejects_wrong_packed_width():
    with pytest.raises(InvalidIdentity):
        IPAddress(b"\x01\x02", 4)
    with pytest.raises(InvalidIdentity):
        IPAddress(b"\x00" * 4, 6)
    with pytest.raises(InvalidIdentity, match="version"):
        IPAddress(b"\x00" * 4, 5)


# -- HostIdentity ----------------------------------------------------------


def test_identity_is_a_value_and_ip_is_optional():
    a = HostIdentity.of(MAC_A)
    b = HostIdentity.of(MacAddress.parse("aa:bb:cc:dd:ee:01"))
    assert a == b and hash(a) == hash(b)
    assert a.ip is None and a.confidence == "mac-observed"


def test_with_ip_returns_a_new_value_and_does_not_mutate():
    a = HostIdentity.of(MAC_A)
    b = a.with_ip(IPAddress.parse("10.0.0.1"))
    assert a.ip is None, "original must be untouched"
    assert b.ip == IPAddress.parse("10.0.0.1")
    assert b.confidence == "mac+ip-observed"
    assert a != b


def test_confidence_is_a_label_not_a_number():
    """Refusing unearned precision: the legacy Zeek stub emitted a hardcoded
    0.93 'confidence' for a forgeable L2 signal."""
    label = HostIdentity.of(MAC_A).confidence
    assert isinstance(label, str)
    with pytest.raises(ValueError):
        float(label)


@pytest.mark.parametrize("mac", [BROADCAST_MAC, MacAddress.parse("01:80:c2:00:00:0e")])
def test_multicast_cannot_identify_a_host(mac):
    with pytest.raises(InvalidIdentity, match="cannot"):
        HostIdentity.of(mac)


@pytest.mark.parametrize("bad", [("x", None), (MAC_A, "10.0.0.1")])
def test_identity_rejects_untyped_components(bad):
    with pytest.raises(InvalidIdentity):
        HostIdentity(*bad)


def test_same_mac_at_two_ports_stays_distinguishable():
    """The core modelling requirement: a hijack presents one MAC at two
    locations. If the model collapsed them, the attack would be invisible."""
    ident = HostIdentity.of(MAC_A)
    one = HostObservation.of(ident, PORT_A, T0, "arp")
    two = HostObservation.of(ident, PORT_B, T0, "arp")
    assert one != two
    assert one.mac == two.mac
    assert len({one, two}) == 2


# -- HostLocation ----------------------------------------------------------


def test_location_at_and_refresh_are_immutable_updates():
    loc = HostLocation.at(PORT_A, T0)
    assert loc.first_seen == loc.last_seen == T0 and loc.dwell_seconds == 0
    later = loc.refreshed(T0 + timedelta(seconds=30))
    assert loc.last_seen == T0, "original untouched"
    assert later.first_seen == T0 and later.dwell_seconds == 30


def test_location_rejects_naive_datetimes():
    """Naive datetimes compare incorrectly and make evidence ambiguous."""
    with pytest.raises(InvalidIdentity, match="timezone-aware"):
        HostLocation.at(PORT_A, datetime(2026, 9, 20, 12, 0, 0))


def test_location_rejects_inverted_interval():
    with pytest.raises(InvalidIdentity, match="precedes"):
        HostLocation(PORT_A, T0, T0 - timedelta(seconds=1))


def test_refresh_refuses_to_silently_reorder():
    """Out-of-order observations are a real condition; the caller must decide,
    the value type must not quietly rewrite history."""
    loc = HostLocation.at(PORT_A, T0)
    with pytest.raises(InvalidIdentity, match="out-of-order"):
        loc.refreshed(T0 - timedelta(seconds=1))


def test_location_equality_covers_port_and_times():
    assert HostLocation.at(PORT_A, T0) == HostLocation.at(PORT_A, T0)
    assert HostLocation.at(PORT_A, T0) != HostLocation.at(PORT_B, T0)
    assert HostLocation.at(PORT_A, T0) != HostLocation.at(PORT_A, T0 + timedelta(seconds=1))


# -- HostObservation -------------------------------------------------------


@pytest.mark.parametrize("source", ["arp", "ipv4", "ipv6", "icmp", "probe_reply", "dhcp", "lldp", "unknown"])
def test_known_sources_are_accepted(source):
    obs = HostObservation.of(HostIdentity.of(MAC_A), PORT_A, T0, source)
    assert obs.source == source


def test_unknown_source_is_rejected():
    with pytest.raises(InvalidIdentity, match="unknown observation source"):
        HostObservation.of(HostIdentity.of(MAC_A), PORT_A, T0, "telepathy")


def test_observation_rejects_naive_time():
    with pytest.raises(InvalidIdentity, match="timezone-aware"):
        HostObservation.of(HostIdentity.of(MAC_A), PORT_A, datetime(2026, 9, 20))


def test_observation_exposes_mac_ip_and_location():
    ident = HostIdentity.of(MAC_A, IPAddress.parse("10.0.0.1"))
    obs = HostObservation.of(ident, PORT_A, T0, "arp", is_broadcast=True)
    assert obs.mac == MAC_A
    assert obs.ip == IPAddress.parse("10.0.0.1")
    assert obs.to_location() == HostLocation.at(PORT_A, T0)
    assert obs.is_broadcast is True


def test_broadcast_arp_is_a_valid_observation():
    """Legacy returned early on broadcast frames, so ARP -- the main host
    announcement -- never populated the host table (KF-09)."""
    obs = HostObservation.of(HostIdentity.of(MAC_A), PORT_A, T0, "arp", is_broadcast=True)
    assert obs.is_broadcast and obs.mac == MAC_A


# -- immutability and serialisation ---------------------------------------


@pytest.mark.parametrize(
    "obj",
    [
        MacAddress(1),
        IPAddress.parse("10.0.0.1"),
        HostIdentity.of(MAC_A),
        HostLocation.at(PORT_A, T0),
        HostObservation.of(HostIdentity.of(MAC_A), PORT_A, T0, "arp"),
    ],
)
def test_values_are_frozen_and_pickle(obj):
    with pytest.raises(dataclasses.FrozenInstanceError):
        obj.injected = "x"
    restored = pickle.loads(pickle.dumps(obj))
    assert restored == obj and hash(restored) == hash(obj)
