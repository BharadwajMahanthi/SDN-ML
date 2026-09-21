"""Host addressing, identity, location and observation.

Design point that shapes every type here: **a MAC address is an observation,
not an authenticated identity.** The attack this project defends against
consists precisely of one machine presenting another's MAC. If the domain
model collapses "same MAC" into "same host", the hijack becomes invisible to
every layer above -- which is exactly what the legacy implementation did by
keying its host table on MAC alone.

So ``HostIdentity`` carries the MAC *and* the location at which it was
observed, and two observations of one MAC at different ports remain
distinguishable values.

Standard library only (ADR-005).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Final

from sdnguard.domain.identity import InvalidIdentity, PortIdentity, _ValueObject

__all__ = [
    "MacAddress",
    "IPAddress",
    "HostIdentity",
    "HostLocation",
    "HostObservation",
    "BROADCAST_MAC",
    "NULL_MAC",
]

_MAC_SEPARATORS: Final = re.compile(r"[:\-.\s]")
_MAC_HEX: Final = re.compile(r"\A[0-9a-f]{12}\Z")
_MAC_MAX: Final = 2**48 - 1


@dataclass(frozen=True, order=True)
class MacAddress(_ValueObject):
    """An IEEE 802 MAC address, stored as an unsigned 48-bit integer.

    Normalising to an int means ``aa:bb:cc:dd:ee:ff``, ``AA-BB-CC-DD-EE-FF``
    and ``aabb.ccdd.eeff`` are the same value, so equality cannot depend on
    which adapter produced the string.
    """

    __slots__ = ("value",)
    value: int

    def __post_init__(self) -> None:
        if isinstance(self.value, bool) or not isinstance(self.value, int):
            raise InvalidIdentity(
                f"MAC must be an int, got {type(self.value).__name__}")
        if not 0 <= self.value <= _MAC_MAX:
            raise InvalidIdentity(
                f"MAC {self.value} outside unsigned 48-bit range")

    @classmethod
    def parse(cls, text: str) -> "MacAddress":
        if not isinstance(text, str):
            raise InvalidIdentity(f"MAC text must be a str, got {type(text).__name__}")
        cleaned = _MAC_SEPARATORS.sub("", text.strip()).lower()
        if not _MAC_HEX.match(cleaned):
            raise InvalidIdentity(f"malformed MAC {text!r}")
        return cls(int(cleaned, 16))

    @classmethod
    def from_bytes(cls, raw: bytes) -> "MacAddress":
        if not isinstance(raw, (bytes, bytearray)) or len(raw) != 6:
            raise InvalidIdentity("MAC bytes must be exactly 6 bytes")
        return cls(int.from_bytes(raw, "big"))

    def to_bytes(self) -> bytes:
        return self.value.to_bytes(6, "big")

    @property
    def is_broadcast(self) -> bool:
        return self.value == _MAC_MAX

    @property
    def is_multicast(self) -> bool:
        """Group bit set. Broadcast is a special case of multicast."""
        return bool(self.to_bytes()[0] & 0x01)

    @property
    def is_locally_administered(self) -> bool:
        """Locally administered addresses are trivially forged, so this is a
        signal a detector may weigh -- never a verdict on its own."""
        return bool(self.to_bytes()[0] & 0x02)

    @property
    def is_null(self) -> bool:
        return self.value == 0

    @property
    def is_unicast_routable(self) -> bool:
        """A plausible host source address: not null, not multicast."""
        return not self.is_null and not self.is_multicast

    def __str__(self) -> str:
        h = f"{self.value:012x}"
        return ":".join(h[i: i + 2] for i in range(0, 12, 2))

    def __repr__(self) -> str:
        return f"MacAddress({self})"


BROADCAST_MAC: Final = MacAddress(_MAC_MAX)
NULL_MAC: Final = MacAddress(0)


@dataclass(frozen=True, order=True)
class IPAddress(_ValueObject):
    """An IPv4 or IPv6 address. Wraps :mod:`ipaddress` so the security core
    has one comparable, hashable value type rather than two stdlib classes.

    The legacy implementation converted addresses with
    ``BigInteger.valueOf(int).toByteArray()``, which silently drops leading
    zero bytes; ``ipaddress`` removes that whole class of defect.
    """

    __slots__ = ("packed", "version")
    packed: bytes
    version: int

    def __post_init__(self) -> None:
        if self.version not in (4, 6):
            raise InvalidIdentity(f"IP version must be 4 or 6, got {self.version}")
        expected = 4 if self.version == 4 else 16
        if not isinstance(self.packed, bytes) or len(self.packed) != expected:
            raise InvalidIdentity(
                f"IPv{self.version} needs {expected} packed bytes, "
                f"got {len(self.packed) if isinstance(self.packed, bytes) else '?'}")

    @classmethod
    def parse(cls, text: str) -> "IPAddress":
        try:
            addr = ipaddress.ip_address(text)
        except (ValueError, TypeError) as exc:
            raise InvalidIdentity(f"malformed IP address {text!r}") from exc
        return cls(addr.packed, addr.version)

    @classmethod
    def from_int(cls, value: int, version: int = 4) -> "IPAddress":
        """Build from a host-order integer, e.g. an OpenFlow match field."""
        if isinstance(value, bool) or not isinstance(value, int):
            raise InvalidIdentity("IP integer must be an int")
        width = 4 if version == 4 else 16
        if not 0 <= value < 2 ** (width * 8):
            raise InvalidIdentity(f"IP integer {value} outside IPv{version} range")
        return cls(value.to_bytes(width, "big"), version)

    @property
    def address(self) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        return ipaddress.ip_address(self.packed)

    @property
    def is_unspecified(self) -> bool:
        return self.address.is_unspecified

    def __str__(self) -> str:
        return str(self.address)

    def __repr__(self) -> str:
        return f"IPAddress({self})"


@dataclass(frozen=True, order=True)
class HostIdentity(_ValueObject):
    """What we believe identifies a host, and how strongly.

    ``mac`` is the only field the network guarantees is present. ``ip`` is
    optional because a host is frequently observed before any L3 traffic.
    Neither field is authenticated; see ``confidence``.
    """

    # Both fields are required rather than defaulted: manual __slots__ (KF-08)
    # cannot coexist with class-level defaults. Use HostIdentity.of() when the
    # IP is not yet known.
    __slots__ = ("mac", "ip")
    mac: MacAddress
    ip: IPAddress | None

    def __post_init__(self) -> None:
        if not isinstance(self.mac, MacAddress):
            raise InvalidIdentity(
                f"mac must be a MacAddress, got {type(self.mac).__name__}")
        if self.ip is not None and not isinstance(self.ip, IPAddress):
            raise InvalidIdentity(
                f"ip must be an IPAddress or None, got {type(self.ip).__name__}")
        if self.mac.is_multicast:
            raise InvalidIdentity(
                f"{self.mac} is a multicast/broadcast address and cannot "
                "identify a host")

    @classmethod
    def of(cls, mac: MacAddress, ip: IPAddress | None = None) -> "HostIdentity":
        return cls(mac, ip)

    def with_ip(self, ip: IPAddress) -> "HostIdentity":
        """Return a new identity; values are never mutated in place."""
        return HostIdentity(self.mac, ip)

    @property
    def confidence(self) -> str:
        """Deliberately coarse and non-numeric.

        This is a *label*, not a probability. Calling a forgeable L2 address
        "0.93 confident" is exactly the kind of unearned precision this
        project refuses to produce.
        """
        return "mac+ip-observed" if self.ip is not None else "mac-observed"

    def __str__(self) -> str:
        return f"{self.mac}" + (f"({self.ip})" if self.ip else "")

    def __repr__(self) -> str:
        return f"HostIdentity({self})"


@dataclass(frozen=True, order=True)
class HostLocation(_ValueObject):
    """Where a host was seen: a switch port plus when it was first and last
    observed there."""

    __slots__ = ("port", "first_seen", "last_seen")
    port: PortIdentity
    first_seen: datetime
    last_seen: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.port, PortIdentity):
            raise InvalidIdentity(
                f"port must be a PortIdentity, got {type(self.port).__name__}")
        for name in ("first_seen", "last_seen"):
            moment = getattr(self, name)
            if not isinstance(moment, datetime):
                raise InvalidIdentity(f"{name} must be a datetime")
            if moment.tzinfo is None:
                raise InvalidIdentity(
                    f"{name} must be timezone-aware; naive datetimes compare "
                    "incorrectly across hosts and make evidence ambiguous")
        if self.last_seen < self.first_seen:
            raise InvalidIdentity("last_seen precedes first_seen")

    @classmethod
    def at(cls, port: PortIdentity, moment: datetime) -> "HostLocation":
        return cls(port, moment, moment)

    def refreshed(self, moment: datetime) -> "HostLocation":
        """Same port, later sighting. Returns a new value."""
        if moment < self.last_seen:
            raise InvalidIdentity(
                "refresh moment precedes last_seen; out-of-order observations "
                "must be handled by the caller, not silently reordered")
        return HostLocation(self.port, self.first_seen, moment)

    @property
    def dwell_seconds(self) -> float:
        return (self.last_seen - self.first_seen).total_seconds()

    def __str__(self) -> str:
        return f"{self.port}@{self.last_seen.astimezone(timezone.utc).isoformat()}"

    def __repr__(self) -> str:
        return f"HostLocation({self})"


@dataclass(frozen=True)
class HostObservation(_ValueObject):
    """A normalised sighting of a host: the single event type that crosses
    the adapter boundary into the security core.

    Nothing below this type may import an OpenFlow library, which is what
    makes the whole movement engine unit-testable without OVS.
    """

    __slots__ = ("identity", "port", "observed_at", "source", "is_broadcast")
    identity: HostIdentity
    port: PortIdentity
    observed_at: datetime
    source: str
    is_broadcast: bool

    def __post_init__(self) -> None:
        if not isinstance(self.identity, HostIdentity):
            raise InvalidIdentity("identity must be a HostIdentity")
        if not isinstance(self.port, PortIdentity):
            raise InvalidIdentity("port must be a PortIdentity")
        if not isinstance(self.observed_at, datetime):
            raise InvalidIdentity("observed_at must be a datetime")
        if self.observed_at.tzinfo is None:
            raise InvalidIdentity("observed_at must be timezone-aware")
        if self.source not in {"arp", "ipv4", "ipv6", "icmp", "probe_reply",
                               "dhcp", "lldp", "unknown"}:
            raise InvalidIdentity(f"unknown observation source {self.source!r}")

    @classmethod
    def of(
        cls,
        identity: HostIdentity,
        port: PortIdentity,
        observed_at: datetime,
        source: str = "unknown",
        is_broadcast: bool = False,
    ) -> "HostObservation":
        return cls(identity, port, observed_at, source, is_broadcast)

    @property
    def mac(self) -> MacAddress:
        return self.identity.mac

    @property
    def ip(self) -> IPAddress | None:
        return self.identity.ip

    def to_location(self) -> HostLocation:
        return HostLocation.at(self.port, self.observed_at)

    def __str__(self) -> str:
        return f"{self.identity}@{self.port} via {self.source}"

    def __repr__(self) -> str:
        return f"HostObservation({self})"
