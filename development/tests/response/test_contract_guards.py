"""The contract's defensive guards, exercised directly.

Mutation testing found fourteen changes to `contract.py` that no test
detected. Almost all were type guards that the JSON path can never reach,
because `_require_str`/`_require_int` reject a wrong type first — so the
guards existed only for *programmatic* misuse, and nothing constructed these
objects wrongly on purpose.

That is a real gap rather than dead code. These types are constructed
directly by the broker, by the backend and by future callers, and a guard
that no test covers is a guard that can be deleted by a refactor without
anything noticing. The length boundaries were a second gap: every field was
tested well inside its limit and never at it.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from annulon.response.contract import (
    ActionRequest, ActionType, ContractError, MAX_POLICY_VERSION_CHARS,
    MAX_REASON_CHARS, Target, TargetKind,
)

NOW = datetime(2026, 9, 21, 12, tzinfo=timezone.utc)


def _request(**overrides):
    base = dict(
        request_id="req-abcdef012345",
        action_type=ActionType.TEMPORARY_EGRESS_RESTRICTION,
        target=Target(TargetKind.SERVICE_UID, "h", "b", "1500", "worker"),
        duration=timedelta(minutes=5), reason="ok",
        finding_id="finding-00000001", requested_at=NOW,
        requesting_component="annulon-core")
    base.update(overrides)
    return ActionRequest(**base)


# --- Target: direct construction -------------------------------------------

@pytest.mark.parametrize("kind", ["service_uid", 0, None, True, object()])
def test_target_kind_must_be_the_enum_not_something_that_looks_like_it(kind):
    with pytest.raises(ContractError, match="kind must be a TargetKind"):
        Target(kind, "h", "b", "1500")


@pytest.mark.parametrize("field", ["host_id", "boot_id", "identifier"])
def test_a_required_identity_field_cannot_be_empty(field):
    """`not isinstance(value, str) or not value`.

    Mutating that `or` to `and` let an empty string through, and an empty
    host_id compares equal to nothing, so `same_boot` would never match and
    every action would be denied as TARGET_NOT_CURRENT — a containment
    outage rather than an escalation, but a silent one.
    """
    values = {"host_id": "h", "boot_id": "b", "identifier": "1500"}
    values[field] = ""
    with pytest.raises(ContractError, match="is required"):
        Target(TargetKind.SERVICE_UID, **values)


@pytest.mark.parametrize("field", ["host_id", "boot_id", "identifier"])
@pytest.mark.parametrize("value", [None, 1500, b"1500", ["1500"], {"a": 1}])
def test_a_required_identity_field_must_be_a_string(field, value):
    values = {"host_id": "h", "boot_id": "b", "identifier": "1500"}
    values[field] = value
    with pytest.raises(ContractError):
        Target(TargetKind.SERVICE_UID, **values)


def test_identity_field_length_boundary():
    """Exactly 128 characters is accepted; 129 is not."""
    Target(TargetKind.SERVICE_UID, "h" * 128, "b", "1500")
    with pytest.raises(ContractError, match="exceeds 128"):
        Target(TargetKind.SERVICE_UID, "h" * 129, "b", "1500")


def test_an_unknown_target_field_is_refused_not_ignored():
    """A caller that believes it sent something meaningful must not be
    silently misunderstood by a privileged component."""
    with pytest.raises(ContractError, match="unknown target field"):
        Target.from_dict({"kind": "service_uid", "host_id": "h", "boot_id": "b",
                          "identifier": "1500", "authorized": True})


def test_target_from_dict_rejects_a_non_object():
    for raw in [None, [], "x", 1, True]:
        with pytest.raises(ContractError):
            Target.from_dict(raw)


def test_target_str_prefers_the_service_name_but_falls_back():
    named = Target(TargetKind.SERVICE_UID, "h", "b", "1500", "worker")
    unnamed = Target(TargetKind.SERVICE_UID, "h", "b", "1500")
    assert "worker" in str(named)
    assert "1500" in str(unnamed), "an unnamed target must still identify itself"


# --- ActionRequest: direct construction ------------------------------------

@pytest.mark.parametrize("value", ["temporary_egress_restriction", None, 1, True])
def test_action_type_must_be_the_enum(value):
    with pytest.raises(ContractError, match="action_type must be an ActionType"):
        _request(action_type=value)


@pytest.mark.parametrize("value", [None, "target", {"kind": "service_uid"}, 1])
def test_target_must_be_a_target(value):
    with pytest.raises(ContractError, match="target must be a Target"):
        _request(target=value)


@pytest.mark.parametrize("value", [300, "300", None, 300.0, True])
def test_duration_must_be_a_timedelta(value):
    with pytest.raises(ContractError, match="duration must be a timedelta"):
        _request(duration=value)


def test_reason_length_boundary():
    """Exactly MAX_REASON_CHARS is accepted; one more is not."""
    _request(reason="r" * MAX_REASON_CHARS)
    with pytest.raises(ContractError, match="bounded"):
        _request(reason="r" * (MAX_REASON_CHARS + 1))


def test_policy_version_length_boundary():
    _request(policy_version="v" * MAX_POLICY_VERSION_CHARS)
    with pytest.raises(ContractError, match="exceeds"):
        _request(policy_version="v" * (MAX_POLICY_VERSION_CHARS + 1))


def test_a_naive_timestamp_is_refused():
    """A timestamp without a timezone cannot be compared to the broker's
    clock without inventing an offset."""
    with pytest.raises(ContractError, match="timezone-aware"):
        _request(requested_at=datetime(2026, 9, 21, 12))


def test_request_from_dict_rejects_a_non_object():
    for raw in [None, [], "x", 1, True]:
        with pytest.raises(ContractError):
            ActionRequest.from_dict(raw)


@pytest.mark.parametrize("field", [
    "request_id", "action_type", "target", "duration_seconds", "reason",
    "finding_id", "requested_at", "requesting_component"])
def test_a_missing_required_field_raises_the_contract_error(field):
    """Specifically ContractError, not KeyError.

    Deleting the presence check in `_require_str` survived because the
    resulting KeyError still failed the broker's decode — but it escaped as
    a different exception type, and the broker only catches ContractError,
    TypeError and ValueError. A KeyError would have propagated out of the
    decode path.
    """
    payload = _request().to_dict()
    payload.pop(field)
    with pytest.raises(ContractError):
        ActionRequest.from_dict(payload)


def test_a_keyerror_never_escapes_the_decoder():
    """The broker's decode must produce a denial, never an unhandled error."""
    payload = _request().to_dict()
    del payload["reason"]
    try:
        ActionRequest.from_dict(payload)
    except ContractError:
        pass
    except KeyError as exc:                 # pragma: no cover - the defect
        pytest.fail(f"KeyError escaped the decoder: {exc}")
