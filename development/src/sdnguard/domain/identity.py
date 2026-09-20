"""Switch and port identity as immutable value types.

Why this module exists in this shape
------------------------------------
The legacy Java implementation keyed all per-port security state on a class
whose ``equals`` compared boxed ``Long``/``Short`` by **reference**. That is
correct only for values inside Java's integer cache (-128..127), so a lab
using datapath ids 1, 2 and 3 concealed the defect entirely while any real
64-bit datapath id would have broken every map lookup silently.

The requirement that follows is not "translate the Java class" but: switch
and port identity must have value semantics across the **full** identifier
space, and the tests must exercise that space rather than toy values.

This module imports nothing outside the standard library, and in particular
no OpenFlow framework (ADR-005).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

__all__ = [
    "DatapathId",
    "PortNumber",
    "PortIdentity",
    "InvalidIdentity",
    "DPID_MIN",
    "DPID_MAX",
    "OFPP_MAX",
    "OFPP_IN_PORT",
    "OFPP_TABLE",
    "OFPP_NORMAL",
    "OFPP_FLOOD",
    "OFPP_ALL",
    "OFPP_CONTROLLER",
    "OFPP_LOCAL",
    "OFPP_ANY",
]


class InvalidIdentity(ValueError):
    """An identity was constructed from a value outside its defined domain."""


class _ValueObject:
    """Pickling support for frozen dataclasses that declare ``__slots__``.

    ``dataclass(slots=True)`` generates these methods, but it also rebuilds the
    class and leaves the frozen ``__setattr__`` holding a stale class
    reference (KF-08). Declaring ``__slots__`` manually avoids that, at the
    cost of having to restore state through ``object.__setattr__`` -- the
    default unpickling path uses ``setattr`` and would hit the frozen guard.

    This matters beyond tidiness: domain values cross process boundaries in
    evidence bundles and in the out-of-band inference worker planned for P9.
    """

    __slots__ = ()

    def __getstate__(self) -> dict[str, object]:
        return {name: getattr(self, name) for name in self.__slots__}

    def __setstate__(self, state: dict[str, object]) -> None:
        for name, value in state.items():
            object.__setattr__(self, name, value)


# -- datapath id -----------------------------------------------------------

DPID_MIN: Final[int] = 0
DPID_MAX: Final[int] = 2**64 - 1
_UINT64_SPAN: Final[int] = 2**64


@dataclass(frozen=True, order=True)
class DatapathId(_ValueObject):
    # Manual __slots__ rather than dataclass(slots=True): the latter rebuilds
    # the class, leaving the generated frozen __setattr__ holding a stale class
    # reference, so setting an UNKNOWN attribute raises a confusing TypeError
    # instead of FrozenInstanceError (KF-08).
    __slots__ = ("value",)

    """An OpenFlow datapath identifier: unsigned 64-bit.

    Frozen and slotted, so it is hashable, comparable by value, and cannot be
    mutated after construction. Two independently constructed instances with
    the same value are equal and hash identically -- the property the legacy
    implementation failed to provide.
    """

    value: int

    def __post_init__(self) -> None:
        if isinstance(self.value, bool) or not isinstance(self.value, int):
            raise InvalidIdentity(
                f"datapath id must be an int, got {type(self.value).__name__}")
        if not DPID_MIN <= self.value <= DPID_MAX:
            raise InvalidIdentity(
                f"datapath id {self.value} outside unsigned 64-bit range "
                f"[{DPID_MIN}, {DPID_MAX}]")

    @classmethod
    def from_signed(cls, signed: int) -> "DatapathId":
        """Build from a signed 64-bit integer.

        OpenFlow libraries with Java heritage hand out datapath ids as signed
        longs, so ``0xFFFFFFFFFFFFFFFF`` arrives as ``-1``. Reinterpreting the
        two's-complement bit pattern here keeps that conversion in one tested
        place instead of scattered through adapter code.
        """
        if isinstance(signed, bool) or not isinstance(signed, int):
            raise InvalidIdentity(
                f"signed datapath id must be an int, got {type(signed).__name__}")
        if not -(2**63) <= signed <= 2**63 - 1:
            raise InvalidIdentity(
                f"signed datapath id {signed} outside signed 64-bit range")
        return cls(signed & (_UINT64_SPAN - 1))

    def to_signed(self) -> int:
        """Inverse of :meth:`from_signed`."""
        return self.value - _UINT64_SPAN if self.value >= 2**63 else self.value

    @classmethod
    def from_hex(cls, text: str) -> "DatapathId":
        """Parse ``00:00:aa:bb:cc:dd:ee:ff``, ``0000aabbccddeeff`` or ``0x...``."""
        if not isinstance(text, str):
            raise InvalidIdentity(
                f"datapath id text must be a str, got {type(text).__name__}")
        cleaned = text.strip().replace(":", "").replace("-", "")
        if cleaned.lower().startswith("0x"):
            cleaned = cleaned[2:]
        if not cleaned or len(cleaned) > 16:
            raise InvalidIdentity(f"malformed datapath id {text!r}")
        try:
            return cls(int(cleaned, 16))
        except ValueError as exc:
            raise InvalidIdentity(f"malformed datapath id {text!r}") from exc

    @property
    def hex(self) -> str:
        """16 lowercase hex digits, zero padded."""
        return f"{self.value:016x}"

    def __str__(self) -> str:
        """Deterministic canonical form: eight colon-separated octets."""
        h = self.hex
        return ":".join(h[i: i + 2] for i in range(0, 16, 2))

    def __repr__(self) -> str:
        return f"DatapathId({self})"


# -- port number -----------------------------------------------------------

OFPP_MAX: Final[int] = 0xFFFFFF00
OFPP_IN_PORT: Final[int] = 0xFFFFFFF8
OFPP_TABLE: Final[int] = 0xFFFFFFF9
OFPP_NORMAL: Final[int] = 0xFFFFFFFA
OFPP_FLOOD: Final[int] = 0xFFFFFFFB
OFPP_ALL: Final[int] = 0xFFFFFFFC
OFPP_CONTROLLER: Final[int] = 0xFFFFFFFD
OFPP_LOCAL: Final[int] = 0xFFFFFFFE
OFPP_ANY: Final[int] = 0xFFFFFFFF

_RESERVED_NAMES: Final[dict[int, str]] = {
    OFPP_IN_PORT: "IN_PORT",
    OFPP_TABLE: "TABLE",
    OFPP_NORMAL: "NORMAL",
    OFPP_FLOOD: "FLOOD",
    OFPP_ALL: "ALL",
    OFPP_CONTROLLER: "CONTROLLER",
    OFPP_LOCAL: "LOCAL",
    OFPP_ANY: "ANY",
}


@dataclass(frozen=True, order=True)
class PortNumber(_ValueObject):
    __slots__ = ("value",)  # see KF-08

    """An OpenFlow 1.3 port number: unsigned 32-bit.

    Valid values are a physical/logical port in ``[1, OFPP_MAX]`` or one of
    the reserved ports. Zero is not a valid port in OpenFlow 1.3, and the gap
    between ``OFPP_MAX`` and ``OFPP_IN_PORT`` is unassigned; both are rejected
    so that an adapter bug surfaces at the boundary rather than as a silent
    lookup miss deep in the security logic.
    """

    value: int

    def __post_init__(self) -> None:
        if isinstance(self.value, bool) or not isinstance(self.value, int):
            raise InvalidIdentity(
                f"port number must be an int, got {type(self.value).__name__}")
        if self.value in _RESERVED_NAMES:
            return
        if not 1 <= self.value <= OFPP_MAX:
            raise InvalidIdentity(
                f"port number {self.value} is neither a physical port in "
                f"[1, {OFPP_MAX}] nor a reserved OpenFlow port")

    @property
    def is_reserved(self) -> bool:
        return self.value in _RESERVED_NAMES

    @property
    def is_physical(self) -> bool:
        return not self.is_reserved

    @property
    def name(self) -> str | None:
        """Reserved-port name, or ``None`` for a physical port."""
        return _RESERVED_NAMES.get(self.value)

    def __str__(self) -> str:
        return self.name or str(self.value)

    def __repr__(self) -> str:
        return f"PortNumber({self})"


# -- port identity ---------------------------------------------------------

@dataclass(frozen=True, order=True)
class PortIdentity(_ValueObject):
    __slots__ = ("datapath_id", "port")  # see KF-08

    """A switch port: the anchor of "where a host is".

    Ordering is ``(datapath_id, port)``, which makes collections of ports
    deterministically sortable for evidence bundles and test fixtures.
    """

    datapath_id: DatapathId
    port: PortNumber

    def __post_init__(self) -> None:
        if not isinstance(self.datapath_id, DatapathId):
            raise InvalidIdentity(
                "datapath_id must be a DatapathId, got "
                f"{type(self.datapath_id).__name__}")
        if not isinstance(self.port, PortNumber):
            raise InvalidIdentity(
                f"port must be a PortNumber, got {type(self.port).__name__}")

    @classmethod
    def of(cls, datapath_id: int | DatapathId, port: int | PortNumber) -> "PortIdentity":
        """Convenience constructor accepting raw ints."""
        dpid = datapath_id if isinstance(datapath_id, DatapathId) else DatapathId(datapath_id)
        pnum = port if isinstance(port, PortNumber) else PortNumber(port)
        return cls(dpid, pnum)

    def __str__(self) -> str:
        return f"{self.datapath_id}/{self.port}"

    def __repr__(self) -> str:
        return f"PortIdentity({self})"
