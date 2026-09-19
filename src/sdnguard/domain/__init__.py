"""Framework-independent domain model for the sdnguard security core."""

from sdnguard.domain.host import (  # noqa: F401
    BROADCAST_MAC,
    NULL_MAC,
    HostIdentity,
    HostLocation,
    HostObservation,
    IPAddress,
    MacAddress,
)
from sdnguard.domain.identity import (  # noqa: F401
    DatapathId,
    InvalidIdentity,
    PortIdentity,
    PortNumber,
)

__all__ = [
    "DatapathId", "PortNumber", "PortIdentity", "InvalidIdentity",
    "MacAddress", "IPAddress", "HostIdentity", "HostLocation",
    "HostObservation", "BROADCAST_MAC", "NULL_MAC",
]
