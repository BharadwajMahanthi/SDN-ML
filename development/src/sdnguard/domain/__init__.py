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
from sdnguard.domain.events import (  # noqa: F401
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
    new_correlation_id,
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
    "MovementEvent", "ProbeMethod", "ProbeRequest", "ProbeOutcome",
    "ProbeResult", "Verdict", "Severity", "FindingKind", "SecurityFinding",
    "EnforcementAction", "EnforcementDecision", "new_correlation_id",
]
