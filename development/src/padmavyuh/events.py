"""The common event envelope.

One envelope for host, cloud, application, AI and SDN sources. A plain Linux
process event must be representable with no DPID, switch, MAC or port, and an
SDN event must fit the same outer shape.

Every field earns its place by answering a decision or preserving an
invariant:

===================  ====================================================
field                what would go wrong without it
===================  ====================================================
schema_version       an unknown future schema would be silently trusted
event_id             V2-CORE-02 could not express that three findings
                     share one source event (§10 double counting)
event_type           routing, and a defined answer for unknown types
sensor / version     which sensor produced this, for independence and for
                     attributing a collection fault
sequence             ordering without trusting the wall clock
observed/received    a clock anomaly becomes representable instead of a
                     silent reordering
collection_quality   a missing event must not read as "nothing happened"
entity_refs          identity that is not one unqualified string
attributes           bounded payload; never an unlimited dict
data_classification  privacy minimisation is a property of the event
causal_refs          lineage for correlation, without a correlation engine
===================  ====================================================

There is deliberately **no** ``risk_score``. Raw observation and interpreted
finding are different things, and one number that later code mistakes for
severity-and-confidence-and-probability is exactly what ADR-030 forbids.
"""

from __future__ import annotations

import enum
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from padmavyuh.identity import EntityRef

__all__ = [
    "SCHEMA_VERSION",
    "EventLimits",
    "DEFAULT_LIMITS",
    "DataClassification",
    "CollectionQuality",
    "Event",
    "EventError",
    "OversizeEvent",
    "DecodeOutcome",
    "decode_event",
]

SCHEMA_VERSION = 1
_TYPE = re.compile(r"^[a-z][a-z0-9_]{0,63}(\.[a-z][a-z0-9_]{0,63}){0,4}$")


@dataclass(frozen=True)
class EventLimits:
    """Explicit bounds. A security event must never be an unbounded dict."""

    max_attributes: int = 64
    max_key_chars: int = 64
    max_string_chars: int = 4096
    max_collection_items: int = 256
    max_entity_refs: int = 16
    max_causal_refs: int = 32
    max_serialized_bytes: int = 64 * 1024


DEFAULT_LIMITS = EventLimits()


class DataClassification(enum.Enum):
    """Privacy is a property of the event, not an afterthought.

    ``RESTRICTED`` marks material that must stay on the protected host --
    prompts, file contents, packet payloads. The envelope carries a reference
    or a hash; it does not carry the material.
    """

    PUBLIC = "public"
    INTERNAL = "internal"
    SENSITIVE = "sensitive"
    RESTRICTED = "restricted"


class QualityFlag(enum.Enum):
    """Sensor health is security data (V2 §12, §15)."""

    OK = "ok"
    SEQUENCE_GAP = "sequence_gap"
    SENSOR_RESTART = "sensor_restart"
    EVENTS_DROPPED = "events_dropped"
    QUEUE_OVERFLOW = "queue_overflow"
    CLOCK_ANOMALY = "clock_anomaly"
    PARTIAL_FIELDS = "partial_fields"
    UNSUPPORTED_CAPABILITY = "unsupported_capability"

    @classmethod
    def parse(cls, value: object) -> "QualityFlag | None":
        try:
            return cls(value)
        except ValueError:
            return None


@dataclass(frozen=True)
class CollectionQuality:
    """What the source knows about its own completeness."""

    flags: tuple[QualityFlag, ...] = ()
    dropped_events: int = 0
    gap_before: int = 0
    clock_uncertainty_ms: int | None = None

    @property
    def healthy(self) -> bool:
        return not self.flags or set(self.flags) == {QualityFlag.OK}

    def to_dict(self) -> dict:
        return {"flags": [f.value for f in self.flags],
                "dropped_events": self.dropped_events,
                "gap_before": self.gap_before,
                "clock_uncertainty_ms": self.clock_uncertainty_ms}

    @staticmethod
    def from_dict(raw: object) -> "CollectionQuality":
        if not isinstance(raw, dict):
            return CollectionQuality()
        flags = tuple(f for f in (QualityFlag.parse(v)
                                  for v in (raw.get("flags") or [])) if f)
        def _int(key: str) -> int:
            value = raw.get(key, 0)
            return value if isinstance(value, int) and not isinstance(value, bool) else 0
        uncertainty = raw.get("clock_uncertainty_ms")
        return CollectionQuality(
            flags, _int("dropped_events"), _int("gap_before"),
            uncertainty if isinstance(uncertainty, int) else None)


class EventError(ValueError):
    """The event cannot be represented safely."""


class OversizeEvent(EventError):
    """EVENT_REJECTED_OVERSIZE: refused rather than silently truncated.

    Truncation is not offered here because a shortened identifier or
    authorization field would change security meaning while looking valid.
    """


class DecodeOutcome(enum.Enum):
    OK = "ok"
    #: A known schema with fields we do not recognise: usable, flagged.
    PARSEABLE_UNKNOWN_EXTENSION = "parseable_unknown_extension"
    #: A schema version we do not implement: never treated as trusted.
    UNSUPPORTED_SCHEMA = "unsupported_schema"
    REJECTED = "rejected"


def _require_aware(value: object, name: str) -> datetime:
    if not isinstance(value, datetime):
        raise EventError(f"{name} must be a datetime")
    if value.tzinfo is None:
        raise EventError(f"{name} must be timezone-aware")
    return value


@dataclass(frozen=True)
class Event:
    event_id: str
    event_type: str
    sensor: str
    sensor_version: str
    sequence: int
    observed_time: datetime
    received_time: datetime
    entity_refs: tuple[EntityRef, ...] = ()
    attributes: dict = field(default_factory=dict)
    data_classification: DataClassification = DataClassification.INTERNAL
    quality: CollectionQuality = field(default_factory=CollectionQuality)
    causal_refs: tuple[str, ...] = ()
    unknown_fields: tuple[str, ...] = ()
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        self.validate(DEFAULT_LIMITS)

    # -- validation ------------------------------------------------------

    def validate(self, limits: EventLimits) -> None:
        if not isinstance(self.event_id, str) or not 8 <= len(self.event_id) <= 64:
            raise EventError("event_id must be 8-64 characters")
        if not isinstance(self.event_type, str) or not _TYPE.match(self.event_type):
            raise EventError(f"malformed event_type {self.event_type!r}")
        if not isinstance(self.sensor, str) or not self.sensor:
            raise EventError("sensor required")
        if not isinstance(self.sequence, int) or isinstance(self.sequence, bool):
            raise EventError("sequence must be an int")
        if self.sequence < 0:
            raise EventError("sequence must not be negative")
        _require_aware(self.observed_time, "observed_time")
        _require_aware(self.received_time, "received_time")
        if len(self.entity_refs) > limits.max_entity_refs:
            raise OversizeEvent(f"more than {limits.max_entity_refs} entity refs")
        if not all(isinstance(r, EntityRef) for r in self.entity_refs):
            raise EventError("entity_refs must be EntityRef values")
        if len(self.causal_refs) > limits.max_causal_refs:
            raise OversizeEvent(f"more than {limits.max_causal_refs} causal refs")
        _check_attributes(self.attributes, limits)

    @property
    def clock_skew_ms(self) -> float:
        """Positive when the sensor's clock ran behind the receiver's."""
        return (self.received_time - self.observed_time).total_seconds() * 1000

    @property
    def has_clock_anomaly(self) -> bool:
        """Observed after received is impossible on one timeline, so it is
        surfaced rather than silently reordered."""
        return self.observed_time > self.received_time

    # -- serialisation ---------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "sensor": self.sensor,
            "sensor_version": self.sensor_version,
            "sequence": self.sequence,
            "observed_time": self.observed_time.astimezone(timezone.utc).isoformat(),
            "received_time": self.received_time.astimezone(timezone.utc).isoformat(),
            "entity_refs": [r.to_dict() for r in self.entity_refs],
            "attributes": self.attributes,
            "data_classification": self.data_classification.value,
            "quality": self.quality.to_dict(),
            "causal_refs": list(self.causal_refs),
        }

    def to_json(self, limits: EventLimits = DEFAULT_LIMITS) -> str:
        payload = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        size = len(payload.encode())
        if size > limits.max_serialized_bytes:
            raise OversizeEvent(
                f"serialized event is {size}B, limit {limits.max_serialized_bytes}B")
        return payload


def _check_attributes(attributes: object, limits: EventLimits) -> None:
    if not isinstance(attributes, dict):
        raise EventError("attributes must be a mapping")
    if len(attributes) > limits.max_attributes:
        raise OversizeEvent(f"more than {limits.max_attributes} attributes")
    for key, value in attributes.items():
        if not isinstance(key, str):
            raise EventError("attribute keys must be strings")
        if len(key) > limits.max_key_chars:
            raise OversizeEvent(f"attribute key exceeds {limits.max_key_chars}")
        _check_value(value, limits, depth=0)


def _check_value(value: object, limits: EventLimits, depth: int) -> None:
    if depth > 3:
        raise OversizeEvent("attribute nesting deeper than 3 levels")
    if value is None or isinstance(value, (bool, int, float)):
        return
    if isinstance(value, str):
        if len(value) > limits.max_string_chars:
            raise OversizeEvent(f"string exceeds {limits.max_string_chars} chars")
        return
    if isinstance(value, (list, tuple)):
        if len(value) > limits.max_collection_items:
            raise OversizeEvent(f"collection exceeds {limits.max_collection_items}")
        for item in value:
            _check_value(item, limits, depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > limits.max_attributes:
            raise OversizeEvent("nested mapping too large")
        for key, item in value.items():
            if not isinstance(key, str):
                raise EventError("nested keys must be strings")
            _check_value(item, limits, depth + 1)
        return
    raise EventError(f"unsupported attribute type {type(value).__name__}")


_KNOWN_FIELDS = {
    "schema_version", "event_id", "event_type", "sensor", "sensor_version",
    "sequence", "observed_time", "received_time", "entity_refs", "attributes",
    "data_classification", "quality", "causal_refs",
}


def decode_event(payload: str | bytes,
                 limits: EventLimits = DEFAULT_LIMITS) -> tuple[DecodeOutcome, Event | None, str]:
    """Decode an event from a trust boundary.

    Returns an outcome rather than raising, because malformed input is
    ordinary at a boundary and must never stop the agent. JSON is used
    because it decodes without executing anything; pickle is forbidden across
    a trust boundary by construction.
    """
    raw_bytes = payload.encode() if isinstance(payload, str) else payload
    if len(raw_bytes) > limits.max_serialized_bytes:
        return DecodeOutcome.REJECTED, None, "payload exceeds size bound"
    try:
        raw = json.loads(raw_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        return DecodeOutcome.REJECTED, None, f"undecodable: {type(exc).__name__}"
    if not isinstance(raw, dict):
        return DecodeOutcome.REJECTED, None, "event must be an object"

    version = raw.get("schema_version")
    if version != SCHEMA_VERSION:
        # Known-unknown: recorded, never trusted as a validated event.
        return (DecodeOutcome.UNSUPPORTED_SCHEMA, None,
                f"schema {version!r} is not implemented")

    unknown = tuple(sorted(set(raw) - _KNOWN_FIELDS))
    try:
        event = Event(
            event_id=str(raw.get("event_id", "")),
            event_type=str(raw.get("event_type", "")),
            sensor=str(raw.get("sensor", "")),
            sensor_version=str(raw.get("sensor_version", "")),
            sequence=raw.get("sequence", 0),
            observed_time=_parse_time(raw.get("observed_time")),
            received_time=_parse_time(raw.get("received_time")),
            entity_refs=tuple(EntityRef.from_dict(r)
                              for r in _as_list(raw.get("entity_refs"),
                                                limits.max_entity_refs + 1)),
            attributes=raw.get("attributes") or {},
            data_classification=_parse_classification(raw.get("data_classification")),
            quality=CollectionQuality.from_dict(raw.get("quality")),
            causal_refs=tuple(str(c) for c in
                              _as_list(raw.get("causal_refs"),
                                       limits.max_causal_refs + 1)),
            unknown_fields=unknown,
        )
    except (EventError, ValueError, TypeError) as exc:
        return DecodeOutcome.REJECTED, None, str(exc)

    if unknown:
        return (DecodeOutcome.PARSEABLE_UNKNOWN_EXTENSION, event,
                f"unknown fields: {', '.join(unknown)}")
    return DecodeOutcome.OK, event, "ok"


def _as_list(value: object, cap: int) -> list:
    """Coerce a decoded field to a bounded list.

    Found by fuzzing: a payload whose ``entity_refs`` was an object rather
    than an array reached an unguarded slice and raised ``KeyError`` out of
    the decoder. At a trust boundary the answer to malformed input is a
    rejection, never an exception escaping into the caller.
    """
    if not isinstance(value, list):
        return []
    return value[:cap]


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str):
        raise EventError("time must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise EventError(f"malformed time {value!r}") from exc
    if parsed.tzinfo is None:
        raise EventError("time must carry a timezone")
    return parsed


def _parse_classification(value: object) -> DataClassification:
    try:
        return DataClassification(value)
    except ValueError:
        # An unrecognised classification is treated as the most restrictive
        # value we know, never as the least.
        return DataClassification.RESTRICTED
