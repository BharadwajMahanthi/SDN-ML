"""Raw frame bytes -> domain events. No packet library, no framework.

Written with :mod:`struct` and :mod:`ipaddress` from the standard library
rather than scapy or dpkt, for three reasons:

1. Parsing hostile input is the most exposed surface in the whole system.
   A small, explicit parser that validates every length before reading is
   easier to reason about than a general-purpose dissector.
2. It keeps ADR-005 intact: normalisation lives in the adapter layer and
   still imports nothing outside the standard library.
3. The legacy implementation converted addresses with
   ``BigInteger.valueOf(int).toByteArray()``, which silently drops leading
   zero bytes. That whole class of bug disappears with explicit slicing.

Every parser returns ``None`` for input it does not understand and raises
:class:`MalformedFrame` only for input that is structurally impossible.
Truncated and unknown frames are ordinary on a real network; they must not
be able to stop the controller.
"""

from __future__ import annotations

import enum
import struct
from dataclasses import dataclass
from datetime import datetime

from sdnguard.domain.host import (
    HostIdentity,
    HostObservation,
    IPAddress,
    MacAddress,
)
from sdnguard.domain.identity import InvalidIdentity, PortIdentity

__all__ = [
    "EtherType",
    "MalformedFrame",
    "ParsedFrame",
    "parse_ethernet",
    "to_observation",
    "LLDP_MULTICAST",
]

LLDP_MULTICAST = MacAddress.parse("01:80:c2:00:00:0e")

_ETH_HEADER = struct.Struct("!6s6sH")
_ARP_FIXED = struct.Struct("!HHBBH")
_IPV4_FIXED = struct.Struct("!BBHHHBBH4s4s")
_VLAN_TAG = struct.Struct("!HH")

MIN_ETHERNET = 14
IPV4_MIN_IHL = 5


class EtherType(enum.IntEnum):
    IPV4 = 0x0800
    ARP = 0x0806
    VLAN = 0x8100
    QINQ = 0x88A8
    IPV6 = 0x86DD
    LLDP = 0x88CC


class MalformedFrame(ValueError):
    """Structurally impossible input. Truncation alone is not malformed."""


@dataclass(frozen=True)
class ParsedFrame:
    """What we could extract, with everything optional that may be absent."""

    source_mac: MacAddress
    destination_mac: MacAddress
    ethertype: int
    source_ip: IPAddress | None = None
    destination_ip: IPAddress | None = None
    ip_protocol: int | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None
    arp_opcode: int | None = None
    payload: bytes = b""
    vlan_ids: tuple[int, ...] = ()

    @property
    def is_lldp(self) -> bool:
        return self.ethertype == EtherType.LLDP

    @property
    def is_arp(self) -> bool:
        return self.ethertype == EtherType.ARP

    @property
    def is_broadcast(self) -> bool:
        return self.destination_mac.is_broadcast

    @property
    def is_icmp_echo_reply(self) -> bool:
        """ICMP *type* 0, not code 0.

        The legacy implementation compared ``getIcmpCode()`` against
        ``ICMP.ECHO_REPLY``, which is a type constant equal to zero. That
        matched an echo *request*, a TTL-exceeded and a destination-unreachable
        as readily as a reply.
        """
        return self.ip_protocol == 1 and self.icmp_type == 0

    @property
    def observation_source(self) -> str:
        if self.is_arp:
            return "arp"
        if self.is_lldp:
            return "lldp"
        if self.ip_protocol == 1:
            return "icmp"
        if self.ethertype == EtherType.IPV4:
            return "ipv4"
        if self.ethertype == EtherType.IPV6:
            return "ipv6"
        return "unknown"


def parse_ethernet(data: bytes) -> ParsedFrame | None:
    """Parse a frame. Returns ``None`` when it is too short to be one."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise MalformedFrame(f"expected bytes, got {type(data).__name__}")
    data = bytes(data)
    if len(data) < MIN_ETHERNET:
        return None

    dst_raw, src_raw, ethertype = _ETH_HEADER.unpack_from(data, 0)
    offset = _ETH_HEADER.size
    vlan_ids: list[int] = []

    # Walk any stack of VLAN tags. A frame can legitimately carry more than
    # one; an attacker can supply many, so the walk is bounded.
    while ethertype in (EtherType.VLAN, EtherType.QINQ) and len(vlan_ids) < 4:
        if len(data) < offset + _VLAN_TAG.size:
            return None
        tci, ethertype = _VLAN_TAG.unpack_from(data, offset)
        vlan_ids.append(tci & 0x0FFF)
        offset += _VLAN_TAG.size

    try:
        source_mac = MacAddress.from_bytes(src_raw)
        destination_mac = MacAddress.from_bytes(dst_raw)
    except InvalidIdentity as exc:  # pragma: no cover - 6 bytes always valid
        raise MalformedFrame(str(exc)) from exc

    body = data[offset:]
    common = dict(source_mac=source_mac, destination_mac=destination_mac,
                  ethertype=ethertype, vlan_ids=tuple(vlan_ids))

    if ethertype == EtherType.ARP:
        return _parse_arp(body, common)
    if ethertype == EtherType.IPV4:
        return _parse_ipv4(body, common)
    return ParsedFrame(payload=body, **common)


def _parse_arp(body: bytes, common: dict) -> ParsedFrame:
    if len(body) < _ARP_FIXED.size:
        return ParsedFrame(payload=body, **common)
    htype, ptype, hlen, plen, opcode = _ARP_FIXED.unpack_from(body, 0)
    # Only Ethernet/IPv4 ARP carries addresses we can use. Anything else is
    # parsed as far as the opcode and no further -- guessing at the layout of
    # an unexpected hardware type is how parsers get exploited.
    if htype != 1 or ptype != EtherType.IPV4 or hlen != 6 or plen != 4:
        return ParsedFrame(arp_opcode=opcode, payload=body, **common)
    needed = _ARP_FIXED.size + 2 * (hlen + plen)
    if len(body) < needed:
        return ParsedFrame(arp_opcode=opcode, payload=body, **common)

    base = _ARP_FIXED.size
    sender_ip = body[base + hlen: base + hlen + plen]
    target_ip = body[base + 2 * hlen + plen: base + 2 * hlen + 2 * plen]
    return ParsedFrame(
        source_ip=IPAddress(sender_ip, 4),
        destination_ip=IPAddress(target_ip, 4),
        arp_opcode=opcode,
        payload=body,
        **common,
    )


def _parse_ipv4(body: bytes, common: dict) -> ParsedFrame:
    if len(body) < _IPV4_FIXED.size:
        return ParsedFrame(payload=body, **common)
    (version_ihl, _tos, total_length, _ident, _flags, _ttl, protocol,
     _checksum, src_raw, dst_raw) = _IPV4_FIXED.unpack_from(body, 0)

    version, ihl = version_ihl >> 4, version_ihl & 0x0F
    if version != 4 or ihl < IPV4_MIN_IHL:
        return ParsedFrame(payload=body, **common)
    header_length = ihl * 4
    if len(body) < header_length:
        return ParsedFrame(payload=body, **common)

    frame = dict(source_ip=IPAddress(src_raw, 4),
                 destination_ip=IPAddress(dst_raw, 4),
                 ip_protocol=protocol, **common)
    payload = body[header_length:]

    if protocol == 1 and len(payload) >= 2:
        return ParsedFrame(icmp_type=payload[0], icmp_code=payload[1],
                           payload=payload, **frame)
    return ParsedFrame(payload=payload, **frame)


def to_observation(frame: ParsedFrame, port: PortIdentity,
                   observed_at: datetime) -> HostObservation | None:
    """Turn a parsed frame into a host observation, or ``None``.

    Returns ``None`` when the source cannot identify a host -- a multicast or
    null source address. Note that a *broadcast destination* is fine: ARP is
    the main way a host announces itself, and discarding it is exactly the
    legacy defect KF-09.
    """
    if not frame.source_mac.is_unicast_routable:
        return None
    identity = HostIdentity.of(frame.source_mac, frame.source_ip)
    return HostObservation.of(identity, port, observed_at,
                              frame.observation_source, frame.is_broadcast)
