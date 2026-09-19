"""Frame parsing: fixtures, the legacy ICMP defect, and hostile input."""

from __future__ import annotations

import random
import struct
from datetime import datetime, timezone

import pytest

from sdnguard.adapter.normalize import (
    LLDP_MULTICAST,
    EtherType,
    MalformedFrame,
    parse_ethernet,
    to_observation,
)
from sdnguard.domain.host import IPAddress, MacAddress
from sdnguard.domain.identity import PortIdentity

T0 = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
PORT = PortIdentity.of(0x0000AABBCCDDEEFF, 1)
SRC = "aabbccddee01"
DST = "aabbccddee02"
BCAST = "ffffffffffff"


def eth(dst: str, src: str, ethertype: int, body: bytes = b"") -> bytes:
    return bytes.fromhex(dst) + bytes.fromhex(src) + struct.pack("!H", ethertype) + body


def arp_frame(dst=BCAST, src=SRC, opcode=1, sender_ip=(10, 0, 0, 1),
              target_ip=(10, 0, 0, 2), htype=1, ptype=EtherType.IPV4):
    body = (struct.pack("!HHBBH", htype, ptype, 6, 4, opcode)
            + bytes.fromhex(src) + bytes(sender_ip)
            + b"\x00" * 6 + bytes(target_ip))
    return eth(dst, src, EtherType.ARP, body)


def ipv4_frame(protocol=1, payload=b"\x00\x00\x00\x00", src=(10, 0, 0, 1),
               dst=(10, 0, 0, 2), ihl=5):
    header = struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, 0, 20 + len(payload),
                         0, 0, 64, protocol, 0, bytes(src), bytes(dst))
    return eth(DST, SRC, EtherType.IPV4, header + payload)


# -- ARP -------------------------------------------------------------------


def test_arp_request_yields_mac_and_ip():
    frame = parse_ethernet(arp_frame())
    assert frame.source_mac == MacAddress.parse("aa:bb:cc:dd:ee:01")
    assert frame.source_ip == IPAddress.parse("10.0.0.1")
    assert frame.destination_ip == IPAddress.parse("10.0.0.2")
    assert frame.arp_opcode == 1
    assert frame.is_arp and frame.is_broadcast
    assert frame.observation_source == "arp"


def test_arp_reply_is_parsed_the_same_way():
    frame = parse_ethernet(arp_frame(dst=DST, opcode=2))
    assert frame.arp_opcode == 2 and not frame.is_broadcast


@pytest.mark.parametrize("octets", [(0, 0, 0, 0), (10, 0, 0, 1), (172, 20, 20, 10),
                                    (192, 168, 1, 1), (255, 255, 255, 255)])
def test_addresses_with_leading_zero_and_high_bits_round_trip(octets):
    """Legacy used BigInteger.valueOf(int).toByteArray(), which drops leading
    zero bytes and mishandles the sign bit."""
    frame = parse_ethernet(arp_frame(sender_ip=octets))
    assert frame.source_ip == IPAddress.parse(".".join(map(str, octets)))


def test_unexpected_arp_hardware_type_is_not_guessed_at():
    """Guessing at the layout of an unexpected hardware type is how parsers
    get exploited."""
    frame = parse_ethernet(arp_frame(htype=99))
    assert frame.arp_opcode == 1
    assert frame.source_ip is None


def test_truncated_arp_is_parsed_only_as_far_as_it_is_valid():
    full = arp_frame()
    frame = parse_ethernet(full[:20])
    assert frame is not None and frame.source_ip is None


# -- IPv4 and ICMP ---------------------------------------------------------


def test_icmp_echo_reply_is_recognised_by_type():
    frame = parse_ethernet(ipv4_frame(payload=b"\x00\x00\x00\x00"))
    assert frame.icmp_type == 0 and frame.icmp_code == 0
    assert frame.is_icmp_echo_reply


@pytest.mark.parametrize(
    "icmp_type,name",
    [(8, "echo request"), (11, "TTL exceeded"), (3, "destination unreachable")],
)
def test_the_legacy_icmp_confusion_cannot_recur(icmp_type, name):
    """Legacy compared getIcmpCode() against ICMP.ECHO_REPLY, a *type*
    constant equal to zero, so every one of these matched as a reply."""
    frame = parse_ethernet(ipv4_frame(payload=bytes([icmp_type, 0, 0, 0])))
    assert frame.icmp_code == 0, "these all carry code 0"
    assert not frame.is_icmp_echo_reply, f"{name} must not read as a reply"


def test_non_icmp_ipv4_is_parsed_without_icmp_fields():
    frame = parse_ethernet(ipv4_frame(protocol=6, payload=b"\x00" * 20))
    assert frame.ip_protocol == 6
    assert frame.icmp_type is None
    assert frame.observation_source == "ipv4"


def test_ipv4_options_are_skipped_correctly():
    frame = parse_ethernet(ipv4_frame(ihl=6, payload=b"\x04\x00" + b"\x00" * 6))
    assert frame.ip_protocol == 1


@pytest.mark.parametrize("bad_ihl", [0, 1, 4])
def test_an_impossible_header_length_is_not_trusted(bad_ihl):
    frame = parse_ethernet(ipv4_frame(ihl=bad_ihl))
    assert frame.source_ip is None


# -- VLAN ------------------------------------------------------------------


def test_a_vlan_tag_is_unwrapped():
    inner = arp_frame()[12:]
    frame = parse_ethernet(eth(BCAST, SRC, EtherType.VLAN,
                               struct.pack("!H", 100) + inner))
    assert frame.vlan_ids == (100,)
    assert frame.is_arp and frame.source_ip == IPAddress.parse("10.0.0.1")


def test_a_stack_of_vlan_tags_is_bounded():
    """An attacker can supply an arbitrary tag stack; the walk must terminate."""
    body = b""
    for _ in range(50):
        body += struct.pack("!HH", 0, EtherType.VLAN)[2:] + struct.pack("!H", EtherType.VLAN)
    frame = parse_ethernet(eth(BCAST, SRC, EtherType.VLAN, body))
    assert frame is None or len(frame.vlan_ids) <= 4


# -- LLDP ------------------------------------------------------------------


def test_lldp_is_identified_and_is_not_broadcast():
    frame = parse_ethernet(eth("0180c200000e", SRC, EtherType.LLDP, b"\x02\x07"))
    assert frame.is_lldp and not frame.is_broadcast
    assert frame.destination_mac == LLDP_MULTICAST
    assert frame.observation_source == "lldp"


# -- observation conversion ------------------------------------------------


def test_a_broadcast_arp_becomes_an_observation():
    """KF-09: discarding broadcast is exactly what stopped the legacy table
    ever learning a host."""
    frame = parse_ethernet(arp_frame())
    observation = to_observation(frame, PORT, T0)
    assert observation is not None
    assert observation.is_broadcast and observation.source == "arp"
    assert observation.ip == IPAddress.parse("10.0.0.1")


@pytest.mark.parametrize("src", ["ffffffffffff", "0180c200000e", "010000000001"])
def test_a_multicast_or_broadcast_source_cannot_identify_a_host(src):
    frame = parse_ethernet(eth(DST, src, EtherType.IPV4))
    assert to_observation(frame, PORT, T0) is None


def test_a_null_source_cannot_identify_a_host():
    frame = parse_ethernet(eth(DST, "000000000000", EtherType.IPV4))
    assert to_observation(frame, PORT, T0) is None


# -- hostile input ---------------------------------------------------------


@pytest.mark.parametrize("data", [b"", b"\x00", b"\x00" * 13])
def test_frames_too_short_return_none_rather_than_raising(data):
    assert parse_ethernet(data) is None


@pytest.mark.parametrize("bad", [None, 42, "a string", 3.5])
def test_non_bytes_input_is_rejected_loudly(bad):
    with pytest.raises(MalformedFrame):
        parse_ethernet(bad)


def test_random_bytes_never_crash_the_parser():
    """Truncated and nonsensical frames are ordinary on a real network; they
    must not be able to stop the controller."""
    rng = random.Random(20260920)
    for _ in range(3000):
        length = rng.randrange(0, 200)
        data = bytes(rng.randrange(0, 256) for _ in range(length))
        frame = parse_ethernet(data)
        if frame is not None:
            to_observation(frame, PORT, T0)


def test_structured_fuzzing_of_each_ethertype_never_crashes():
    rng = random.Random(7)
    for ethertype in (EtherType.ARP, EtherType.IPV4, EtherType.VLAN,
                      EtherType.LLDP, EtherType.IPV6, 0x1234):
        for _ in range(500):
            body = bytes(rng.randrange(0, 256) for _ in range(rng.randrange(0, 60)))
            frame = parse_ethernet(eth(DST, SRC, int(ethertype), body))
            if frame is not None:
                to_observation(frame, PORT, T0)


def test_a_giant_frame_is_handled():
    frame = parse_ethernet(ipv4_frame(payload=b"\x00" * 60000))
    assert frame is not None and frame.ip_protocol == 1


def test_the_parser_imports_no_packet_library():
    import ast
    from pathlib import Path

    path = (Path(__file__).resolve().parents[2] / "src" / "sdnguard"
            / "adapter" / "normalize.py")
    tree = ast.parse(path.read_text())
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            roots.add(node.module.split(".")[0])
    assert not (roots & {"scapy", "dpkt", "ryu", "os_ken", "pypacker"})
