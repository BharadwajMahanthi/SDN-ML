"""The action contract: a component may request, it may not authorize."""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timedelta, timezone

import pytest

from annulon.response.contract import (
    MAX_TTL,
    ActionRequest,
    ActionState,
    ActionType,
    AuthorizationDecision,
    ContractError,
    Decision,
    DenyReason,
    Target,
    TargetKind,
)

T0 = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
TARGET = Target(TargetKind.SERVICE_UID, "h1", "b7", "1500", "annulon-lab-service")


def request(**kw) -> ActionRequest:
    base = dict(request_id="REQ-00000001", action_type=ActionType.TEMPORARY_EGRESS_RESTRICTION,
                target=TARGET, duration=timedelta(minutes=5),
                reason="finding indicates unexpected egress",
                finding_id="FN-HOST-0001", requested_at=T0,
                requesting_component="annulon-core")
    base.update(kw)
    return ActionRequest(**base)


# -- the structural property -----------------------------------------------


def test_a_request_has_no_field_in_which_to_claim_authorization():
    """Making the field absent is cheaper to defend than making it ignored."""
    fields = {f.name for f in dataclasses.fields(ActionRequest)}
    for forbidden in ("authorized", "allow", "allowed", "approved", "permitted",
                      "override", "force", "privileged", "sudo"):
        assert forbidden not in fields


def test_a_request_carries_no_command_of_any_kind():
    """A broker that accepts a command string is an RPC wrapper around root."""
    payload = json.dumps(request().to_dict()).lower()
    for forbidden in ("command", "cmd", "argv", "shell", "script", "exec",
                      "iptables", "nft", "systemctl"):
        assert forbidden not in payload


def test_an_extra_field_in_a_serialized_request_is_refused_not_ignored():
    """A caller that believes it sent something meaningful must not be
    silently misunderstood by a privileged component."""
    raw = request().to_dict()
    raw["authorized"] = True
    with pytest.raises(ContractError, match="unknown request field"):
        ActionRequest.from_dict(raw)


def test_an_allow_cannot_be_deserialized_from_untrusted_data():
    """There is no from_dict that yields an ALLOW: an authorization can only
    be constructed by broker-side code."""
    assert not hasattr(AuthorizationDecision, "from_dict")


def test_a_denial_must_state_a_reason():
    with pytest.raises(ContractError, match="at least one reason"):
        AuthorizationDecision("REQ-00000001", Decision.DENY, (), "p", T0)


def test_an_allow_cannot_carry_denial_reasons():
    with pytest.raises(ContractError):
        AuthorizationDecision("REQ-00000001", Decision.ALLOW,
                              (DenyReason.TARGET_PROTECTED,), "p", T0,
                              granted_duration=timedelta(minutes=1))


def test_an_allow_must_state_the_duration_granted():
    with pytest.raises(ContractError, match="duration granted"):
        AuthorizationDecision("REQ-00000001", Decision.ALLOW, (), "p", T0)


# -- action surface --------------------------------------------------------


def test_the_action_surface_is_small_and_contains_no_execution_primitive():
    values = {a.value for a in ActionType}
    assert values == {"temporary_egress_restriction", "release_restriction"}
    for forbidden in ("run", "exec", "shell", "command", "script"):
        assert not any(forbidden in v for v in values)


def test_pid_is_not_an_available_target_kind():
    """A PID authorized now may be a different process by apply time."""
    assert {k.value for k in TargetKind} == {"service_uid"}


def test_unimplemented_target_kinds_are_not_declared():
    """Declaring a kind we cannot enforce invites a policy that appears to
    cover something it does not."""
    for absent in ("cgroup", "container", "systemd_unit", "workload"):
        assert absent not in {k.value for k in TargetKind}


# -- target identity -------------------------------------------------------


@pytest.mark.parametrize("bad", ["15/00", "15;00", "15 00", "15$x", "15`x",
                                 "15|x", "15&x", "15\nx", "15'x", '15"x'])
def test_identities_reject_path_and_shell_metacharacters(bad):
    """These identities are compared against OS state; metacharacters have no
    legitimate place in them."""
    with pytest.raises(ContractError, match="forbidden character"):
        Target(TargetKind.SERVICE_UID, "h1", "b7", bad)


@pytest.mark.parametrize("identifier", [
    "not-a-uid", "", "-1", "+1500", "01500", "1500.0", "1_500", "1e3",
    " 1500", "1500 ", "0x5dc",
    "\u06f1\u06f5\u06f0\u06f0",   # Arabic-Indic digits: isdigit() is True
    "\uff11\uff15\uff10\uff10",   # fullwidth digits: int() converts these
    "\u0967\u096b\u0966\u0966",   # Devanagari digits
])
def test_a_service_uid_target_must_be_a_canonical_decimal_uid(identifier):
    """Stricter than "numeric", because "numeric" was not enough.

    `str.isdigit()` is true for several non-ASCII digit families and `int()`
    converts them, so `\u0661\u0665\u0660\u0660` resolved to uid 1500 and was
    authorized. Leading zeros gave one uid a second spelling. Neither was an
    escalation by itself -- policy and enforcement both go through `int()` --
    but one identity with several representations is how a future check that
    compares strings disagrees with one that compares numbers (KF-40).
    """
    with pytest.raises(ContractError):
        Target(TargetKind.SERVICE_UID, "h1", "b7", identifier)


def test_a_canonical_uid_is_accepted():
    """The positive control: the strictness must not refuse real uids."""
    for identifier in ["0", "1", "1500", "65534", "4294967294"]:
        target = Target(TargetKind.SERVICE_UID, "h1", "b7", identifier)
        assert target.uid == int(identifier)


def test_a_uid_beyond_the_kernel_range_is_refused():
    with pytest.raises(ContractError, match="out of range"):
        Target(TargetKind.SERVICE_UID, "h1", "b7", "4294967295")


def test_a_target_from_another_boot_is_not_this_target():
    """A UID means something different after a rebuild."""
    assert TARGET.same_boot("h1", "b7")
    assert not TARGET.same_boot("h1", "b8")
    assert not TARGET.same_boot("h2", "b7")


# -- request validation ----------------------------------------------------


@pytest.mark.parametrize(
    "kw",
    [{"request_id": "short"}, {"request_id": "has space!"},
     {"duration": timedelta(0)}, {"duration": timedelta(seconds=-1)},
     {"reason": ""}, {"reason": "x" * 300}, {"finding_id": "no"},
     {"requesting_component": "Annulon Core"},
     {"requested_at": datetime(2026, 1, 1)},
     {"destination_cidr": "not-a-cidr"}, {"destination_cidr": "10.0.0.0/99"}],
)
def test_malformed_requests_are_refused(kw):
    with pytest.raises(ContractError):
        request(**kw)


def test_round_trip_preserves_the_request():
    original = request(destination_cidr="203.0.113.0/24")
    assert ActionRequest.from_dict(original.to_dict()).to_dict() == original.to_dict()


@pytest.mark.parametrize(
    "mutation",
    [{"schema_version": 99}, {"action_type": "run_shell"},
     {"duration_seconds": -1}, {"duration_seconds": 10**9},
     {"duration_seconds": "600"}, {"duration_seconds": True},
     {"requested_at": "not a time"}, {"target": "a string"},
     {"target": {"kind": "pid", "host_id": "h", "boot_id": "b",
                 "identifier": "1"}}],
)
def test_hostile_serialized_requests_are_refused(mutation):
    raw = request().to_dict()
    raw.update(mutation)
    with pytest.raises(ContractError):
        ActionRequest.from_dict(raw)


def test_expiry_is_derived_not_supplied():
    """A caller cannot state an expiry inconsistent with its own duration."""
    assert request(duration=timedelta(minutes=5)).expires_at == T0 + timedelta(minutes=5)
    assert "expires_at" not in request().to_dict()


# -- lifecycle -------------------------------------------------------------


def test_applied_and_effect_verified_are_distinct_states():
    """The broker saying a rule was installed is one piece of evidence; a
    measurement that traffic stopped is another."""
    assert ActionState.APPLIED is not ActionState.EFFECT_VERIFIED
    assert not ActionState.APPLIED.is_terminal


@pytest.mark.parametrize(
    "state,holds",
    [(ActionState.REQUESTED, False), (ActionState.DENIED, False),
     (ActionState.AUTHORIZED, False), (ActionState.APPLYING, True),
     (ActionState.APPLIED, True), (ActionState.EFFECT_VERIFIED, True),
     (ActionState.EFFECT_NOT_VERIFIED, True), (ActionState.EXPIRING, True),
     (ActionState.ROLLBACK_REQUIRED, True), (ActionState.RELEASED, False),
     (ActionState.FAILED, False)],
)
def test_states_that_may_hold_os_state_are_identified(state, holds):
    """Drives reconciliation: any such state means look for an owned rule."""
    assert state.holds_os_state is holds
