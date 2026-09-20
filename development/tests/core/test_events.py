"""Common event envelope: bounds, forward compatibility, and the boundary."""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone

import pytest

from padmavyuh.events import (
    DEFAULT_LIMITS,
    CollectionQuality,
    DataClassification,
    DecodeOutcome,
    Event,
    EventError,
    EventLimits,
    OversizeEvent,
    QualityFlag,
    decode_event,
)
from padmavyuh.identity import EntityKind, EntityRef, InvalidEntityRef

T0 = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)


def event(**kw) -> Event:
    base = dict(event_id="evt-00000001", event_type="host.process.exec",
                sensor="linux_sensor", sensor_version="0.1", sequence=1,
                observed_time=T0, received_time=T0)
    base.update(kw)
    return Event(**base)


# -- the defining property: no SDN dependency ------------------------------


def test_a_plain_host_event_needs_no_sdn_concept():
    """A Linux process event must be representable with no DPID, switch,
    MAC or port anywhere in it."""
    e = event(entity_refs=(EntityRef.of(EntityKind.PROCESS_INSTANCE,
                                        "1234@88231", "host=h1;boot=b7"),),
              attributes={"exe": "/usr/bin/curl", "uid": 1000})
    payload = e.to_json().lower()
    for sdn_word in ("dpid", "datapath", "openflow", "switch", "ofport"):
        assert sdn_word not in payload


def test_process_identity_is_qualified_not_a_bare_pid():
    """PIDs are reused, so a bare pid could never be correct later."""
    ref = EntityRef.of(EntityKind.PROCESS_INSTANCE, "1234@88231", "host=h1;boot=b7")
    assert "host=h1" in ref.namespace and "boot=b7" in ref.namespace
    other_boot = EntityRef.of(EntityKind.PROCESS_INSTANCE, "1234@88231", "host=h1;boot=b8")
    assert ref != other_boot, "same pid in a different boot is a different process"


# -- round trip ------------------------------------------------------------


def test_round_trip_preserves_the_event():
    original = event(entity_refs=(EntityRef.of(EntityKind.HOST, "h1"),),
                     attributes={"a": 1, "b": "two", "c": [1, 2], "d": {"e": True}},
                     causal_refs=("evt-00000000",))
    outcome, decoded, _ = decode_event(original.to_json())
    assert outcome is DecodeOutcome.OK
    assert decoded.to_dict() == original.to_dict()


def test_serialization_is_deterministic():
    assert event().to_json() == event().to_json()


# -- bounds ----------------------------------------------------------------


def test_an_event_at_the_limit_is_accepted():
    e = event(attributes={f"k{i}": "v" for i in range(DEFAULT_LIMITS.max_attributes)})
    assert len(e.attributes) == DEFAULT_LIMITS.max_attributes


@pytest.mark.parametrize(
    "attributes,match",
    [
        ({f"k{i}": 1 for i in range(DEFAULT_LIMITS.max_attributes + 1)}, "attributes"),
        ({"k" * (DEFAULT_LIMITS.max_key_chars + 1): 1}, "key exceeds"),
        ({"k": "x" * (DEFAULT_LIMITS.max_string_chars + 1)}, "string exceeds"),
        ({"k": list(range(DEFAULT_LIMITS.max_collection_items + 1))}, "collection"),
        ({"k": {"a": {"b": {"c": {"d": 1}}}}}, "nesting"),
    ],
)
def test_oversized_events_are_rejected_not_truncated(attributes, match):
    """Truncation is not offered: a shortened identifier or authorization
    field would change security meaning while still looking valid."""
    with pytest.raises(OversizeEvent, match=match):
        event(attributes=attributes)


def test_too_many_entity_refs_is_rejected():
    refs = tuple(EntityRef.of(EntityKind.HOST, f"h{i}")
                 for i in range(DEFAULT_LIMITS.max_entity_refs + 1))
    with pytest.raises(OversizeEvent):
        event(entity_refs=refs)


def test_an_oversized_serialized_event_is_refused():
    tiny = EventLimits(max_serialized_bytes=200)
    with pytest.raises(OversizeEvent, match="serialized"):
        event(attributes={"k": "x" * 500}).to_json(tiny)


@pytest.mark.parametrize("value", [object(), {1, 2}, b"bytes"])
def test_unsupported_attribute_types_are_rejected(value):
    with pytest.raises(EventError):
        event(attributes={"k": value})


# -- validation ------------------------------------------------------------


@pytest.mark.parametrize(
    "kw",
    [{"event_id": "short"}, {"event_id": "x" * 65}, {"event_type": "Bad Type"},
     {"event_type": ""}, {"sensor": ""}, {"sequence": -1}, {"sequence": "1"},
     {"sequence": True}, {"observed_time": "2026-01-01"},
     {"observed_time": datetime(2026, 1, 1)}],
)
def test_malformed_fields_are_rejected(kw):
    with pytest.raises(EventError):
        event(**kw)


@pytest.mark.parametrize("bad", ["", "x" * 300, "has\x00null", "héllo"])
def test_entity_identifiers_must_be_printable_ascii(bad):
    with pytest.raises(InvalidEntityRef):
        EntityRef.of(EntityKind.HOST, bad)


# -- clock semantics -------------------------------------------------------


def test_clock_skew_is_measured_not_hidden():
    e = event(observed_time=T0, received_time=T0 + timedelta(milliseconds=250))
    assert e.clock_skew_ms == pytest.approx(250)
    assert not e.has_clock_anomaly


def test_observed_after_received_is_surfaced_as_an_anomaly():
    """Impossible on one timeline, so it is reported rather than silently
    reordered."""
    e = event(observed_time=T0 + timedelta(seconds=5), received_time=T0)
    assert e.has_clock_anomaly
    assert e.clock_skew_ms < 0


def test_sequence_allows_ordering_without_the_wall_clock():
    events = [event(event_id=f"evt-{i:08d}", sequence=i,
                    observed_time=T0 - timedelta(seconds=i)) for i in range(5)]
    assert [e.sequence for e in sorted(events, key=lambda e: e.sequence)] == [0, 1, 2, 3, 4]


# -- collection quality ----------------------------------------------------


def test_a_healthy_source_reports_healthy():
    assert event(quality=CollectionQuality(flags=(QualityFlag.OK,))).quality.healthy


@pytest.mark.parametrize(
    "flag", [QualityFlag.SEQUENCE_GAP, QualityFlag.SENSOR_RESTART,
             QualityFlag.EVENTS_DROPPED, QualityFlag.QUEUE_OVERFLOW,
             QualityFlag.CLOCK_ANOMALY, QualityFlag.PARTIAL_FIELDS,
             QualityFlag.UNSUPPORTED_CAPABILITY])
def test_every_collection_fault_is_representable(flag):
    e = event(quality=CollectionQuality(flags=(flag,), dropped_events=3, gap_before=2))
    assert not e.quality.healthy
    _, decoded, _ = decode_event(e.to_json())
    assert flag in decoded.quality.flags
    assert decoded.quality.dropped_events == 3


def test_quality_survives_the_round_trip():
    q = CollectionQuality(flags=(QualityFlag.SEQUENCE_GAP,), dropped_events=7,
                          gap_before=4, clock_uncertainty_ms=120)
    _, decoded, _ = decode_event(event(quality=q).to_json())
    assert decoded.quality.dropped_events == 7
    assert decoded.quality.clock_uncertainty_ms == 120


# -- forward compatibility -------------------------------------------------


def test_an_unknown_schema_version_is_never_trusted():
    raw = json.loads(event().to_json())
    raw["schema_version"] = 99
    outcome, decoded, reason = decode_event(json.dumps(raw))
    assert outcome is DecodeOutcome.UNSUPPORTED_SCHEMA
    assert decoded is None, "an unsupported schema must not yield a usable event"


def test_unknown_fields_are_usable_but_flagged():
    raw = json.loads(event().to_json())
    raw["future_field"] = {"anything": 1}
    outcome, decoded, reason = decode_event(json.dumps(raw))
    assert outcome is DecodeOutcome.PARSEABLE_UNKNOWN_EXTENSION
    assert decoded is not None
    assert "future_field" in decoded.unknown_fields


def test_an_unknown_entity_kind_decodes_to_unknown():
    raw = json.loads(event(entity_refs=(EntityRef.of(EntityKind.HOST, "h1"),)).to_json())
    raw["entity_refs"][0]["kind"] = "quantum_widget"
    _, decoded, _ = decode_event(json.dumps(raw))
    assert decoded.entity_refs[0].kind is EntityKind.UNKNOWN
    assert decoded.entity_refs[0].identifier == "h1"


def test_an_unknown_classification_defaults_to_the_most_restrictive():
    raw = json.loads(event().to_json())
    raw["data_classification"] = "brand_new_level"
    _, decoded, _ = decode_event(json.dumps(raw))
    assert decoded.data_classification is DataClassification.RESTRICTED


def test_an_unknown_event_type_is_carried_not_rejected():
    _, decoded, _ = decode_event(event(event_type="future.sensor.thing").to_json())
    assert decoded.event_type == "future.sensor.thing"


# -- the decoder is a trust boundary ---------------------------------------


@pytest.mark.parametrize(
    "payload",
    ["", "{", "null", "[]", '"a string"', "123", "[1,2,3]", b"\xff\xfe\x00",
     '{"schema_version":1}', '{"schema_version":1,"event_id":null}'],
)
def test_malformed_payloads_are_rejected_without_crashing(payload):
    outcome, decoded, _ = decode_event(payload)
    assert outcome in (DecodeOutcome.REJECTED, DecodeOutcome.UNSUPPORTED_SCHEMA)
    assert decoded is None


def test_deeply_nested_json_does_not_blow_the_stack():
    payload = '{"schema_version":1,"attributes":' + "[" * 2000 + "]" * 2000 + "}"
    outcome, decoded, _ = decode_event(payload)
    assert outcome is DecodeOutcome.REJECTED
    assert decoded is None


def test_a_huge_payload_is_refused_before_parsing():
    outcome, _, reason = decode_event('{"x":"' + "a" * 200_000 + '"}')
    assert outcome is DecodeOutcome.REJECTED and "size bound" in reason


def test_the_decoder_never_executes_anything():
    """JSON is used precisely because decoding cannot run code. There is no
    pickle path across this boundary."""
    import ast
    import pathlib

    import padmavyuh.events as module

    tree = ast.parse(pathlib.Path(module.__file__).read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in {"eval", "exec", "compile"}
    assert "pickle" not in imported and "marshal" not in imported


def test_a_non_list_entity_refs_field_is_rejected_not_a_crash():
    """Regression for KF-26, found by fuzzing: an object where an array was
    expected reached an unguarded slice and raised out of the decoder."""
    raw = json.loads(event().to_json())
    for bad in ({"a": 1}, "string", 42, True):
        raw["entity_refs"] = bad
        outcome, decoded, _ = decode_event(json.dumps(raw))
        assert isinstance(outcome, DecodeOutcome)
        if decoded is not None:
            assert decoded.entity_refs == ()


def test_fuzzing_the_decoder_never_raises():
    rng = random.Random(20260920)
    alphabet = '{}[]",:0123456789abcdefghijklmnopqrstuvwxyz_-. \\\n\t'
    for _ in range(4000):
        payload = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 300)))
        outcome, decoded, _ = decode_event(payload)
        assert isinstance(outcome, DecodeOutcome)
        if decoded is not None:
            decoded.to_dict()


def test_fuzzing_structurally_valid_events_never_raises():
    """Mutate a valid event field by field; the decoder must always answer."""
    rng = random.Random(7)
    base = json.loads(event().to_json())
    junk = [None, 0, -1, 2**70, "", "x" * 5000, [], {}, [1, 2, 3],
            {"a": {"b": {"c": {"d": {"e": 1}}}}}, True,
            {"not": "a list"}, [{"kind": None}], [[]], {"0": "dict not list"}]
    for _ in range(2000):
        raw = dict(base)
        raw[rng.choice(list(base))] = rng.choice(junk)
        outcome, decoded, _ = decode_event(json.dumps(raw))
        assert isinstance(outcome, DecodeOutcome)


# -- privacy ---------------------------------------------------------------


def test_classification_travels_with_the_event():
    e = event(data_classification=DataClassification.RESTRICTED)
    assert json.loads(e.to_json())["data_classification"] == "restricted"


def test_the_envelope_has_no_field_for_raw_material():
    """Prompts, file contents and packet payloads are referenced, never
    carried, so minimisation is structural rather than a convention."""
    fields = set(json.loads(event().to_json()))
    for forbidden in ("payload", "raw", "body", "prompt", "content", "stdout"):
        assert forbidden not in fields
