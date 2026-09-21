"""The exact boundaries of every authorization limit.

Written because mutation testing found six changes to the policy that no
existing test detected. Five were genuine gaps: every limit was tested well
inside its range and never *at* it, so flipping `>` to `>=` — the classic
off-by-one that turns "exceeds the limit" into "is at the limit" — changed
authorization semantics silently.

Doctrine §17: a deadline needs before, exact, and after. Doctrine §5: for
security code, explore denial harder than permission.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from annulon.response.contract import (
    ActionRequest, ActionType, DenyReason, MAX_TTL, Target, TargetKind,
)
from annulon.response.policy import BrokerPolicy, PolicyError, ProtectedScopes

NOW = datetime(2026, 9, 21, 12, tzinfo=timezone.utc)
UID = 1500


def _target(uid=UID):
    return Target(TargetKind.SERVICE_UID, "h", "b", str(uid), "worker")


def _request(*, requested_at=NOW, duration=timedelta(minutes=5),
             request_id="req-abcdef012345", destination=None):
    return ActionRequest(
        request_id=request_id,
        action_type=ActionType.TEMPORARY_EGRESS_RESTRICTION,
        target=_target(), duration=duration, reason="boundary",
        finding_id="finding-00000001", requested_at=requested_at,
        requesting_component="annulon-core", destination_cidr=destination)


def _policy(**overrides) -> BrokerPolicy:
    base = dict(permitted_uids=frozenset({UID}),
                authorized_callers=frozenset({"annulon-core"}))
    base.update(overrides)
    return BrokerPolicy(**base)


def _evaluate(policy, request, *, rate=0, active=0, seen=frozenset(), now=NOW):
    return policy.evaluate(request, caller="annulon-core", now=now,
                           host_id="h", boot_id="b", active_actions=active,
                           recent_request_rate=rate, seen_request_ids=seen)


# --- request freshness: before / exact / after -----------------------------

@pytest.mark.parametrize("offset,expected_denial", [
    (timedelta(seconds=29), False),
    (timedelta(seconds=30), False),      # exactly at the limit is still fresh
    (timedelta(seconds=31), True),
])
def test_request_age_boundary(offset, expected_denial):
    """`age > max_request_age`. A request exactly at the limit is accepted;
    one microsecond past it is not."""
    policy = _policy(max_request_age=timedelta(seconds=30))
    decision = _evaluate(policy, _request(requested_at=NOW - offset))
    denied = DenyReason.REQUEST_EXPIRED in decision.reasons
    assert denied is expected_denial, f"age {offset}"


@pytest.mark.parametrize("skew,expected_denial", [
    (timedelta(seconds=4), False),
    (timedelta(seconds=5), False),       # exactly at the tolerance
    (timedelta(seconds=6), True),
])
def test_clock_skew_boundary(skew, expected_denial):
    """`age < -max_clock_skew`, for a future-dated request."""
    policy = _policy(max_clock_skew=timedelta(seconds=5))
    decision = _evaluate(policy, _request(requested_at=NOW + skew))
    denied = DenyReason.REQUEST_FROM_THE_FUTURE in decision.reasons
    assert denied is expected_denial, f"skew {skew}"


# --- rate limit ------------------------------------------------------------

@pytest.mark.parametrize("rate,expected_denial", [
    (29, False), (30, False),            # at the limit is permitted
    (31, True),
])
def test_rate_limit_boundary(rate, expected_denial):
    policy = _policy(max_requests_per_minute=30)
    decision = _evaluate(policy, _request(), rate=rate)
    denied = DenyReason.RATE_LIMIT_EXCEEDED in decision.reasons
    assert denied is expected_denial, f"rate {rate}"


# --- active action ceiling -------------------------------------------------

@pytest.mark.parametrize("active,expected_denial", [
    (3, False), (4, True), (5, True),    # `>=`: the 5th concurrent is refused
])
def test_active_action_ceiling_boundary(active, expected_denial):
    policy = _policy(max_active_actions=4)
    decision = _evaluate(policy, _request(), active=active)
    denied = DenyReason.TOO_MANY_ACTIVE_ACTIONS in decision.reasons
    assert denied is expected_denial, f"active {active}"


# --- TTL -------------------------------------------------------------------

@pytest.mark.parametrize("duration,expected_denial", [
    (timedelta(minutes=9, seconds=59), False),
    (timedelta(minutes=10), False),      # exactly the maximum is allowed
    (timedelta(minutes=10, seconds=1), True),
])
def test_ttl_boundary(duration, expected_denial):
    policy = _policy(max_ttl=timedelta(minutes=10))
    decision = _evaluate(policy, _request(duration=duration))
    denied = DenyReason.DURATION_EXCEEDS_POLICY in decision.reasons
    assert denied is expected_denial, f"duration {duration}"


# --- policy loading --------------------------------------------------------

def test_a_policy_at_exactly_the_contract_ceiling_loads(tmp_path):
    """`ttl > MAX_TTL` rejects only what is *over* the ceiling.

    Mutating this to `>=` made a policy at exactly the contract maximum
    unloadable, and — because an unloadable policy denies everything — would
    have been a silent containment outage. No test noticed.
    """
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({
        "max_ttl_seconds": int(MAX_TTL.total_seconds()),
        "permitted_uids": [UID]}))
    policy = BrokerPolicy.load(path)
    assert policy.max_ttl == MAX_TTL


def test_a_policy_one_second_over_the_ceiling_is_refused(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({
        "max_ttl_seconds": int(MAX_TTL.total_seconds()) + 1,
        "permitted_uids": [UID]}))
    with pytest.raises(PolicyError, match="exceeds the contract ceiling"):
        BrokerPolicy.load(path)


# --- target kind -----------------------------------------------------------

def test_a_target_kind_outside_policy_is_refused():
    """Deleting this check survived because every declared TargetKind is
    permitted by default, so the guard never fired in any test."""
    policy = _policy(permitted_target_kinds=frozenset())
    decision = _evaluate(policy, _request())
    assert DenyReason.UNKNOWN_TARGET_KIND in decision.reasons
    assert not decision.allowed


def test_a_target_kind_inside_policy_is_not_refused():
    policy = _policy(permitted_target_kinds=frozenset({TargetKind.SERVICE_UID}))
    decision = _evaluate(policy, _request())
    assert DenyReason.UNKNOWN_TARGET_KIND not in decision.reasons


def test_an_action_type_outside_policy_is_refused():
    policy = _policy(permitted_actions=frozenset({ActionType.RELEASE_RESTRICTION}))
    decision = _evaluate(policy, _request())
    assert DenyReason.UNKNOWN_ACTION_TYPE in decision.reasons


# --- protected destinations ------------------------------------------------

def test_an_unscoped_destination_counts_as_covering_protected_space():
    """No destination means all egress, which necessarily includes the
    management path."""
    scopes = ProtectedScopes()
    assert scopes.covers_destination(None) is True


@pytest.mark.parametrize("cidr", ["not-a-cidr", "", "999.999.999.999/32",
                                  "10.0.0.0/99"])
def test_an_unparseable_destination_is_treated_as_protected(cidr):
    """The safe direction: refuse, rather than assume it is harmless."""
    assert ProtectedScopes().covers_destination(cidr) is True


@pytest.mark.parametrize("cidr,covered", [
    ("169.254.169.254/32", True), ("169.254.169.0/24", True),
    ("127.0.0.1/32", True), ("127.0.0.0/8", True),
    ("10.0.0.5/32", False), ("8.8.8.8/32", False),
])
def test_protected_destination_membership(cidr, covered):
    assert ProtectedScopes().covers_destination(cidr) is covered


# --- every denial reason is reachable --------------------------------------

def test_all_reasons_are_reported_not_just_the_first():
    """An operator reading a denial wants every reason.

    Also guards against a future short-circuit: if evaluation started
    returning early, this collapses to one reason.
    """
    policy = _policy(max_ttl=timedelta(minutes=1),
                     permitted_uids=frozenset())
    decision = _evaluate(
        policy, _request(duration=timedelta(minutes=30),
                         requested_at=NOW - timedelta(minutes=5)),
        rate=10_000, active=10_000, seen=frozenset({"req-abcdef012345"}))
    assert len(decision.reasons) >= 5, decision.reasons
    assert len(set(decision.reasons)) == len(decision.reasons), "duplicates"
