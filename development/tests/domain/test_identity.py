"""Value-semantics tests for switch/port identity.

The central regression is KF-07: the legacy implementation compared boxed
integers by reference, which is correct only inside Java's -128..127 cache.
A lab using datapath ids 1, 2 and 3 could never have revealed it. Every
equality test here therefore runs across the full unsigned 64-bit space.
"""

from __future__ import annotations

import dataclasses
import pickle
import random

import pytest

from sdnguard.domain.identity import (
    DPID_MAX,
    DPID_MIN,
    OFPP_ANY,
    OFPP_CONTROLLER,
    OFPP_LOCAL,
    OFPP_MAX,
    DatapathId,
    InvalidIdentity,
    PortIdentity,
    PortNumber,
)

# Values deliberately spread across the whole domain, including several far
# outside the range where the legacy defect was invisible.
DPID_VALUES = [
    0,
    1,
    3,
    127,                      # last value inside Java's boxed-integer cache
    128,                      # first value outside it
    255,
    0xFFFF,
    0x0000AABBCCDDEEFF,       # a realistic OVS datapath id
    2**31,
    2**32 - 1,
    2**32,
    2**63 - 1,
    2**63,                    # sign bit set: negative as a signed Java long
    2**64 - 2,
    DPID_MAX,
]

PORT_VALUES = [1, 2, 3, 127, 128, 65535, 65536, OFPP_MAX,
               OFPP_CONTROLLER, OFPP_LOCAL, OFPP_ANY]


# -- DatapathId: value semantics ------------------------------------------


@pytest.mark.parametrize("value", DPID_VALUES)
def test_independently_constructed_dpids_are_equal_and_hash_alike(value):
    """KF-07 regression: this is exactly what the legacy Port.equals failed."""
    a = DatapathId(value)
    b = DatapathId(int(str(value)))          # forced through a separate object
    assert a is not b
    assert a == b
    assert hash(a) == hash(b)
    assert len({a, b}) == 1
    assert {a: "x"}[b] == "x"


@pytest.mark.parametrize("value", DPID_VALUES)
def test_dpid_round_trips_through_hex(value):
    d = DatapathId(value)
    assert DatapathId.from_hex(str(d)) == d
    assert DatapathId.from_hex(d.hex) == d
    assert DatapathId.from_hex("0x" + d.hex) == d


@pytest.mark.parametrize("value", DPID_VALUES)
def test_dpid_signed_round_trip(value):
    """Java-derived adapters hand out signed longs; 2**64-1 arrives as -1."""
    d = DatapathId(value)
    assert DatapathId.from_signed(d.to_signed()) == d


def test_dpid_from_signed_negative_one_is_all_ones():
    assert DatapathId.from_signed(-1).value == DPID_MAX
    assert str(DatapathId.from_signed(-1)) == "ff:ff:ff:ff:ff:ff:ff:ff"


def test_dpid_string_is_deterministic_and_canonical():
    d = DatapathId(0x0000AABBCCDDEEFF)
    assert str(d) == "00:00:aa:bb:cc:dd:ee:ff"
    assert d.hex == "0000aabbccddeeff"
    assert str(d) == str(DatapathId(0x0000AABBCCDDEEFF))
    assert repr(d) == "DatapathId(00:00:aa:bb:cc:dd:ee:ff)"


def test_distinct_dpids_are_not_equal():
    assert DatapathId(0x0000AABBCCDDEEFF) != DatapathId(0x0000AABBCCDDEEFE)
    assert DatapathId(2**63) != DatapathId(2**63 - 1)


def test_dpid_ordering_is_by_value():
    values = [0x0000AABBCCDDEEFF, 1, DPID_MAX, 128, 127]
    assert [d.value for d in sorted(DatapathId(v) for v in values)] == sorted(values)


# -- DatapathId: validation ------------------------------------------------


@pytest.mark.parametrize("bad", [-1, -(2**63), DPID_MAX + 1, 2**64, 2**128])
def test_dpid_rejects_out_of_range(bad):
    with pytest.raises(InvalidIdentity, match="unsigned 64-bit"):
        DatapathId(bad)


@pytest.mark.parametrize("bad", ["1", 1.0, None, b"\x01", True])
def test_dpid_rejects_non_int(bad):
    with pytest.raises(InvalidIdentity):
        DatapathId(bad)


@pytest.mark.parametrize("bad", ["", "zz", "00:00:aa:bb:cc:dd:ee:ff:00", "0x" + "f" * 17])
def test_dpid_from_hex_rejects_malformed(bad):
    with pytest.raises(InvalidIdentity, match="malformed"):
        DatapathId.from_hex(bad)


@pytest.mark.parametrize("bad", [2**63, -(2**63) - 1])
def test_dpid_from_signed_rejects_out_of_signed_range(bad):
    with pytest.raises(InvalidIdentity, match="signed 64-bit"):
        DatapathId.from_signed(bad)


# -- PortNumber ------------------------------------------------------------


@pytest.mark.parametrize("value", PORT_VALUES)
def test_independently_constructed_ports_are_equal_and_hash_alike(value):
    a, b = PortNumber(value), PortNumber(int(str(value)))
    assert a is not b and a == b and hash(a) == hash(b)
    assert len({a, b}) == 1


@pytest.mark.parametrize("value", [1, 2, 65535, OFPP_MAX])
def test_physical_ports(value):
    p = PortNumber(value)
    assert p.is_physical and not p.is_reserved
    assert p.name is None
    assert str(p) == str(value)


@pytest.mark.parametrize(
    "value,name",
    [(OFPP_CONTROLLER, "CONTROLLER"), (OFPP_LOCAL, "LOCAL"), (OFPP_ANY, "ANY")],
)
def test_reserved_ports_are_named(value, name):
    p = PortNumber(value)
    assert p.is_reserved and not p.is_physical
    assert p.name == name and str(p) == name


@pytest.mark.parametrize(
    "bad",
    [
        0,                 # not a valid OF 1.3 port
        -1,
        OFPP_MAX + 1,      # start of the unassigned gap
        0xFFFFFFF7,        # last value in the unassigned gap
        2**32,             # beyond uint32
    ],
)
def test_port_rejects_invalid(bad):
    with pytest.raises(InvalidIdentity):
        PortNumber(bad)


@pytest.mark.parametrize("bad", ["3", 3.0, None, True])
def test_port_rejects_non_int(bad):
    with pytest.raises(InvalidIdentity):
        PortNumber(bad)


# -- PortIdentity ----------------------------------------------------------


@pytest.mark.parametrize("dpid", DPID_VALUES)
@pytest.mark.parametrize("port", [1, 3, OFPP_MAX])
def test_independently_constructed_port_identities_match(dpid, port):
    a = PortIdentity(DatapathId(dpid), PortNumber(port))
    b = PortIdentity.of(dpid, port)
    assert a is not b
    assert a == b
    assert hash(a) == hash(b)
    assert {a: "state"}[b] == "state"


def test_port_identity_distinguishes_switch_and_port():
    base = PortIdentity.of(0x0000AABBCCDDEEFF, 3)
    assert base != PortIdentity.of(0x0000AABBCCDDEEFE, 3)
    assert base != PortIdentity.of(0x0000AABBCCDDEEFF, 4)


def test_port_identity_string_is_deterministic():
    assert str(PortIdentity.of(0x0000AABBCCDDEEFF, 3)) == "00:00:aa:bb:cc:dd:ee:ff/3"
    assert str(PortIdentity.of(1, OFPP_CONTROLLER)) == \
        "00:00:00:00:00:00:00:01/CONTROLLER"


def test_port_identity_sorts_deterministically():
    ports = [PortIdentity.of(2, 1), PortIdentity.of(1, 9), PortIdentity.of(1, 2)]
    assert [str(p) for p in sorted(ports)] == [str(p) for p in sorted(ports)]
    assert sorted(ports)[0] == PortIdentity.of(1, 2)


@pytest.mark.parametrize(
    "dpid,port", [(1, PortNumber(1)), (DatapathId(1), 1), ("x", PortNumber(1))]
)
def test_port_identity_rejects_untyped_components(dpid, port):
    with pytest.raises(InvalidIdentity):
        PortIdentity(dpid, port)


# -- immutability ----------------------------------------------------------


@pytest.mark.parametrize(
    "obj,field",
    [
        (DatapathId(1), "value"),
        (PortNumber(1), "value"),
        (PortIdentity.of(1, 1), "port"),
    ],
)
def test_values_are_immutable(obj, field):
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(obj, field, 2)


@pytest.mark.parametrize("obj", [DatapathId(1), PortNumber(1), PortIdentity.of(1, 1)])
def test_slots_prevent_attribute_injection(obj):
    """KF-08: with dataclass(slots=True) this raised a confusing TypeError
    because the option rebuilds the class and the frozen __setattr__ keeps a
    stale class reference. Manual __slots__ gives a consistent error."""
    with pytest.raises(dataclasses.FrozenInstanceError):
        obj.injected = "x"


@pytest.mark.parametrize(
    "obj", [DatapathId(DPID_MAX), PortNumber(OFPP_CONTROLLER), PortIdentity.of(2**63, 7)]
)
def test_survives_a_pickle_round_trip(obj):
    restored = pickle.loads(pickle.dumps(obj))
    assert restored == obj and hash(restored) == hash(obj)


# -- properties (seeded; stdlib only, no new dependency) -------------------


def test_property_dpid_equality_and_hash_over_random_64bit_values():
    rng = random.Random(20260920)
    for _ in range(2000):
        v = rng.randrange(DPID_MIN, DPID_MAX + 1)
        a, b = DatapathId(v), DatapathId(v)
        assert a == b and hash(a) == hash(b)
        assert DatapathId.from_hex(str(a)) == a
        assert DatapathId.from_signed(a.to_signed()) == a


def test_property_distinct_values_stay_distinct():
    rng = random.Random(7)
    seen: dict[DatapathId, int] = {}
    for _ in range(2000):
        v = rng.randrange(DPID_MIN, DPID_MAX + 1)
        d = DatapathId(v)
        if d in seen:
            assert seen[d] == v, "hash collision returned the wrong entry"
        seen[d] = v
    assert len(seen) == len({v for v in seen.values()})


def test_property_port_identity_dict_behaves_as_a_value_key():
    rng = random.Random(99)
    table: dict[PortIdentity, str] = {}
    pairs = []
    for i in range(1000):
        dpid = rng.randrange(DPID_MIN, DPID_MAX + 1)
        port = rng.randrange(1, OFPP_MAX + 1)
        pairs.append((dpid, port))
        table[PortIdentity.of(dpid, port)] = f"state-{i}"
    for i, (dpid, port) in enumerate(pairs):
        assert table[PortIdentity.of(dpid, port)] == f"state-{i}"
