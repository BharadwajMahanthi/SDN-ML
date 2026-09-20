"""Broker authorization: default deny, and independent of core honesty.

The scenario these tests exist for is a compromised or simply buggy core
constructing syntactically valid requests. Every one below is well-formed;
policy refuses them anyway.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from annulon.response.contract import (
    ActionRequest,
    ActionType,
    Decision,
    DenyReason,
    Target,
    TargetKind,
)
from annulon.response.policy import BrokerPolicy, PolicyError, ProtectedScopes

T0 = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
HOST, BOOT = "h1", "b7"
LAB_UID = 1500


def target(uid: int = LAB_UID, *, host=HOST, boot=BOOT, service="annulon-lab-service"):
    return Target(TargetKind.SERVICE_UID, host, boot, str(uid), service)


def request(**kw) -> ActionRequest:
    base = dict(request_id="REQ-00000001",
                action_type=ActionType.TEMPORARY_EGRESS_RESTRICTION,
                target=target(), duration=timedelta(minutes=5),
                reason="unexpected egress observed", finding_id="FN-HOST-0001",
                requested_at=T0, requesting_component="annulon-core")
    base.update(kw)
    return ActionRequest(**base)


def policy(**kw) -> BrokerPolicy:
    base = dict(permitted_uids=frozenset({LAB_UID}))
    base.update(kw)
    return BrokerPolicy(**base)


def evaluate(req=None, pol=None, *, caller="annulon-core", now=None,
             host=HOST, boot=BOOT, active=0, rate=0, seen=frozenset()):
    return (pol or policy()).evaluate(
        req or request(), caller=caller, now=now or T0, host_id=host,
        boot_id=boot, active_actions=active, recent_request_rate=rate,
        seen_request_ids=seen)


# -- the baseline ----------------------------------------------------------


def test_a_fully_compliant_request_is_allowed():
    decision = evaluate()
    assert decision.allowed
    assert decision.granted_duration == timedelta(minutes=5)
    assert decision.reasons == ()


def test_an_empty_policy_denies_everything():
    """Default deny is the starting point, not a fallback."""
    decision = evaluate(pol=BrokerPolicy())
    assert not decision.allowed
    assert DenyReason.TARGET_NOT_PERMITTED in decision.reasons


# -- compromised-core simulation: valid requests, refused anyway -----------


def test_an_unpermitted_uid_is_refused():
    """Permitted UIDs are an allowlist: a new service is not containable
    until someone decides it should be."""
    decision = evaluate(request(target=target(uid=2000)))
    assert not decision.allowed
    assert DenyReason.TARGET_NOT_PERMITTED in decision.reasons


def test_a_protected_uid_is_refused_even_if_also_requested():
    decision = evaluate(request(target=target(uid=0, service="root-thing")))
    assert not decision.allowed
    assert DenyReason.TARGET_PROTECTED in decision.reasons


@pytest.mark.parametrize(
    "service", ["annulon-broker", "annulon-core", "sshd", "amazon-ssm-agent",
                "systemd", "snapd"])
def test_protected_services_cannot_be_contained(service):
    """Containing these either removes the operator's ability to intervene or
    Annulon's ability to recover."""
    decision = evaluate(request(target=target(uid=LAB_UID, service=service)))
    assert not decision.allowed
    assert DenyReason.TARGET_PROTECTED in decision.reasons


def test_a_target_from_another_boot_is_refused():
    decision = evaluate(request(target=target(boot="b-old")))
    assert not decision.allowed
    assert DenyReason.TARGET_NOT_CURRENT in decision.reasons


def test_a_target_on_another_host_is_refused():
    decision = evaluate(request(target=target(host="h-other")))
    assert not decision.allowed
    assert DenyReason.TARGET_NOT_CURRENT in decision.reasons


def test_an_unauthorized_caller_is_refused():
    """Caller identity comes from the transport's peer credentials, not from
    anything in the request body."""
    decision = evaluate(caller="some-other-process")
    assert not decision.allowed
    assert DenyReason.CALLER_NOT_AUTHORIZED in decision.reasons


def test_an_oversized_ttl_is_denied_not_silently_shortened():
    """Quietly granting less than was asked for makes the caller's record
    disagree with the broker's about what is in force."""
    decision = evaluate(request(duration=timedelta(hours=2)))
    assert not decision.allowed
    assert DenyReason.DURATION_EXCEEDS_POLICY in decision.reasons
    assert decision.granted_duration is None


def test_a_replayed_request_id_is_refused():
    decision = evaluate(seen=frozenset({"REQ-00000001"}))
    assert not decision.allowed
    assert DenyReason.REPLAYED_REQUEST in decision.reasons


def test_a_stale_request_is_refused():
    decision = evaluate(now=T0 + timedelta(minutes=5))
    assert not decision.allowed
    assert DenyReason.REQUEST_EXPIRED in decision.reasons


def test_a_future_dated_request_is_refused():
    """Either a clock problem or an attempt to widen the replay window."""
    decision = evaluate(now=T0 - timedelta(minutes=5))
    assert not decision.allowed
    assert DenyReason.REQUEST_FROM_THE_FUTURE in decision.reasons


def test_small_clock_skew_is_tolerated():
    assert evaluate(now=T0 - timedelta(seconds=2)).allowed


@pytest.mark.parametrize("destination", ["169.254.169.254/32", "127.0.0.1/32",
                                         "127.0.0.0/8", "169.254.0.0/16"])
def test_protected_destinations_cannot_be_restricted(destination):
    """Cutting the management path leaves the host unrecoverable except by
    rebuild."""
    decision = evaluate(request(destination_cidr=destination))
    assert not decision.allowed
    assert DenyReason.DESTINATION_PROTECTED in decision.reasons


def test_an_unparseable_destination_is_treated_as_protected():
    scopes = ProtectedScopes()
    assert scopes.covers_destination("garbage")
    assert scopes.covers_destination(None), "unscoped egress includes protected space"


def test_too_many_active_actions_is_refused():
    decision = evaluate(active=4)
    assert not decision.allowed
    assert DenyReason.TOO_MANY_ACTIVE_ACTIONS in decision.reasons


def test_rate_limiting_refuses_a_flood():
    """A compromised core must not exhaust the broker with valid requests."""
    decision = evaluate(rate=100)
    assert not decision.allowed
    assert DenyReason.RATE_LIMIT_EXCEEDED in decision.reasons


def test_an_unpermitted_action_type_is_refused():
    pol = policy(permitted_actions=frozenset({ActionType.RELEASE_RESTRICTION}))
    decision = evaluate(pol=pol)
    assert not decision.allowed
    assert DenyReason.UNKNOWN_ACTION_TYPE in decision.reasons


def test_scope_can_be_required_by_policy():
    pol = policy(require_destination_scope=True)
    assert not evaluate(pol=pol).allowed
    assert evaluate(request(destination_cidr="203.0.113.0/24"), pol).allowed


# -- all reasons are reported ----------------------------------------------


def test_every_failing_check_is_reported_not_just_the_first():
    """An operator reading a denial wants all the reasons; short-circuiting
    would make the audit record depend on check order."""
    decision = evaluate(request(target=target(uid=0, service="sshd"),
                                duration=timedelta(hours=3)),
                        caller="impostor", seen=frozenset({"REQ-00000001"}))
    assert not decision.allowed
    assert len(decision.reasons) >= 4
    for expected in (DenyReason.CALLER_NOT_AUTHORIZED, DenyReason.TARGET_PROTECTED,
                     DenyReason.DURATION_EXCEEDS_POLICY,
                     DenyReason.REPLAYED_REQUEST):
        assert expected in decision.reasons


def test_reasons_are_deduplicated_and_ordered_deterministically():
    first = evaluate(caller="impostor")
    second = evaluate(caller="impostor")
    assert first.reasons == second.reasons
    assert len(set(first.reasons)) == len(first.reasons)


# -- policy loading --------------------------------------------------------


def test_policy_loads_from_a_broker_owned_file(tmp_path: Path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({
        "version": "test/1", "permitted_uids": [LAB_UID],
        "max_ttl_seconds": 300, "authorized_callers": ["annulon-core"]}))
    loaded = BrokerPolicy.load(path)
    assert loaded.version == "test/1"
    assert loaded.max_ttl == timedelta(minutes=5)
    assert evaluate(pol=loaded).allowed


@pytest.mark.parametrize(
    "content",
    ["", "{", "[]", '"a string"', '{"permitted_actions": ["run_shell"]}',
     '{"permitted_target_kinds": ["pid"]}', '{"max_ttl_seconds": 999999}'],
)
def test_an_unusable_policy_is_fatal_rather_than_permissive(tmp_path, content):
    """An unreadable policy must yield a broker that denies, never one that
    allows by default."""
    path = tmp_path / "policy.json"
    path.write_text(content)
    with pytest.raises(PolicyError):
        BrokerPolicy.load(path)


def test_a_missing_policy_file_is_fatal(tmp_path):
    with pytest.raises(PolicyError, match="unreadable"):
        BrokerPolicy.load(tmp_path / "absent.json")


def test_a_uid_cannot_be_both_permitted_and_protected(tmp_path):
    """Resolving the contradiction silently either way would be a guess."""
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"permitted_uids": [1500],
                                "protected_uids": [0, 1500]}))
    with pytest.raises(PolicyError, match="both permitted and protected"):
        BrokerPolicy.load(path)


def test_policy_cannot_exceed_the_contract_ceiling(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"max_ttl_seconds": 7200}))
    with pytest.raises(PolicyError, match="contract ceiling"):
        BrokerPolicy.load(path)


# -- protections are not requestable --------------------------------------


def test_a_request_cannot_express_an_exemption():
    """Protections are properties of the broker's configuration; there is no
    field through which a caller can ask for one."""
    import dataclasses

    fields = {f.name for f in dataclasses.fields(ActionRequest)}
    for forbidden in ("exempt", "bypass", "ignore_protected", "protected",
                      "emergency", "priority"):
        assert forbidden not in fields
