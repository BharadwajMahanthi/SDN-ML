"""Assume the core is hostile and has full knowledge of the protocol.

Every request here is *syntactically valid*. None is a parser fuzz case —
that is `test_broker_fuzz.py`. These are the requests an attacker who has
read this repository would send: well-formed, plausible, and each one an
attempt to obtain slightly more authority than policy grants.

The property under test is that the core cannot expand its own authority by
anything it puts in a message. There is no field for permission, no field for
urgency, no field naming the sender, and no combination of values that adds a
target, an action type, a TTL or a capability that broker policy does not
already contain.
"""

from __future__ import annotations

import json
import unicodedata
from datetime import datetime, timedelta, timezone

import pytest

from annulon.response.broker import Broker, BrokerConfig, UNKNOWN_CALLER
from annulon.response.contract import (
    ActionType, ContractError, DenyReason, SCHEMA_VERSION, Target, TargetKind,
)
from annulon.response.enforcement import RecordingEnforcer
from annulon.response.policy import BrokerPolicy

NOW = datetime(2026, 9, 21, 12, tzinfo=timezone.utc)
PERMITTED_UID = 1500
BROKER_UID, CORE_UID, ROOT_UID = 998, 999, 0


@pytest.fixture
def broker(tmp_path):
    config = BrokerConfig(
        host_id="host-alpha", boot_id="boot-7",
        socket_path=str(tmp_path / "s.sock"),
        journal_path=tmp_path / "actions.jsonl",
        caller_uids={CORE_UID: "annulon-core"})
    policy = BrokerPolicy(
        permitted_uids=frozenset({PERMITTED_UID}),
        authorized_callers=frozenset({"annulon-core"}),
        max_ttl=timedelta(minutes=10), max_active_actions=4,
        max_requests_per_minute=1000)
    return Broker(config, policy, enforcer=RecordingEnforcer(), clock=lambda: NOW)


_counter = iter(range(1, 10 ** 6))


def _payload(**overrides) -> dict:
    payload = {
        "schema_version": SCHEMA_VERSION,
        "request_id": f"req-{next(_counter):012d}",
        "action_type": ActionType.TEMPORARY_EGRESS_RESTRICTION.value,
        "target": {"kind": TargetKind.SERVICE_UID.value, "host_id": "host-alpha",
                   "boot_id": "boot-7", "identifier": str(PERMITTED_UID),
                   "service_name": "batch-worker"},
        "duration_seconds": 300, "reason": "plausible-looking justification",
        "finding_id": "finding-00000001", "requested_at": NOW.isoformat(),
        "requesting_component": "annulon-core", "policy_version": "",
        "destination_cidr": None}
    target_overrides = overrides.pop("target", None)
    payload.update(overrides)
    if target_overrides:
        payload["target"] = {**payload["target"], **target_overrides}
    return payload


def _send(broker, payload, caller="annulon-core") -> dict:
    return broker.handle({"schema_version": SCHEMA_VERSION,
                          "type": "action_request", "request": payload},
                         caller=caller)


def _assert_denied(response, *, expected: DenyReason | None = None):
    assert response["decision"] == "deny", response
    if expected is not None:
        assert expected.value in response["reasons"], response["reasons"]


# --- the attacker aims at something it should not reach --------------------

@pytest.mark.parametrize("uid,label", [
    (ROOT_UID, "root"), (BROKER_UID, "the broker's own uid"),
    (CORE_UID, "the core's own uid"), (4242, "a uid outside the allowlist"),
    (65534, "nobody"), (1, "daemon"),
])
def test_the_core_cannot_contain_a_uid_policy_does_not_permit(broker, uid, label):
    response = _send(broker, _payload(target={"identifier": str(uid)}))
    _assert_denied(response)
    assert broker._enforcer.applied == [], f"{label} reached the backend"


@pytest.mark.parametrize("service", [
    "sshd", "amazon-ssm-agent", "annulon-broker", "annulon-core", "systemd",
    "snapd"])
def test_the_core_cannot_contain_a_management_identity(broker, service):
    """Containing these is how the tool becomes the incident."""
    response = _send(broker, _payload(
        target={"identifier": str(PERMITTED_UID), "service_name": service}))
    _assert_denied(response, expected=DenyReason.TARGET_PROTECTED)


@pytest.mark.parametrize("destination", [
    "169.254.169.254/32", "169.254.0.0/16", "127.0.0.1/32", "127.0.0.0/8",
    "0.0.0.0/0",
])
def test_the_core_cannot_cut_the_management_path(broker, destination):
    """`0.0.0.0/0` is the interesting one: a syntactically narrow-looking
    destination that is in fact every address, including the recovery path."""
    _assert_denied(_send(broker, _payload(destination_cidr=destination)),
                   expected=DenyReason.DESTINATION_PROTECTED)


def test_a_whole_host_restriction_is_not_expressible_as_a_privilege_grab(broker):
    """An unscoped request is permitted only because policy allows it here;
    it still cannot exceed the uid allowlist."""
    response = _send(broker, _payload(destination_cidr=None,
                                      target={"identifier": "4242"}))
    _assert_denied(response, expected=DenyReason.TARGET_NOT_PERMITTED)


# --- the attacker asks for more time ---------------------------------------

@pytest.mark.parametrize("seconds", [601, 3600, 86_400])
def test_the_core_cannot_exceed_the_ttl_policy_allows(broker, seconds):
    _assert_denied(_send(broker, _payload(duration_seconds=seconds)),
                   expected=DenyReason.DURATION_EXCEEDS_POLICY)


@pytest.mark.parametrize("seconds", [0, -1, -300, -86_400, 86_401, 2 ** 31])
def test_a_nonsensical_ttl_is_refused(broker, seconds):
    _assert_denied(_send(broker, _payload(duration_seconds=seconds)),
                   expected=DenyReason.MALFORMED_REQUEST)


# --- the attacker tries to name a capability that does not exist -----------

@pytest.mark.parametrize("action", [
    "run_shell", "execute_command", "execute_python", "run_aws_cli",
    "raw_nftables", "raw_iptables", "raw_systemd", "flush_ruleset",
    "temporary_egress_restriction_v2", "TEMPORARY_EGRESS_RESTRICTION",
    "permanent_egress_restriction",
])
def test_the_core_cannot_invent_an_action_type(broker, action):
    """There is no action that means "run this"; asking is a decode failure."""
    _assert_denied(_send(broker, _payload(action_type=action)),
                   expected=DenyReason.MALFORMED_REQUEST)


@pytest.mark.parametrize("kind", ["pid", "process", "host", "cgroup",
                                  "container", "service_uid_v2", "SERVICE_UID"])
def test_the_core_cannot_invent_a_target_kind(broker, kind):
    _assert_denied(_send(broker, _payload(target={"kind": kind})))


@pytest.mark.parametrize("extra", [
    {"authorized": True}, {"approved": True}, {"policy_override": True},
    {"urgent": True}, {"priority": 9999}, {"skip_policy": True},
    {"caller": "annulon-core"}, {"uid": 0}, {"granted_duration_seconds": 86400},
    {"decision": "allow"}, {"reasons": []},
])
def test_no_extra_field_can_grant_anything(broker, extra):
    """The heart of the design: there is nowhere to write permission, and an
    unknown field is refused rather than ignored."""
    _assert_denied(_send(broker, _payload(**extra)),
                   expected=DenyReason.MALFORMED_REQUEST)
    assert broker._enforcer.applied == []


# --- the attacker lies about who it is -------------------------------------

def test_naming_yourself_in_the_body_does_not_make_you_that_caller(broker):
    """Identity comes from the kernel. The body's claim is ignored entirely."""
    response = _send(broker, _payload(requesting_component="annulon-core"),
                     caller=UNKNOWN_CALLER)
    _assert_denied(response, expected=DenyReason.CALLER_NOT_AUTHORIZED)


@pytest.mark.parametrize("claimed", ["annulon-broker", "root", "systemd",
                                     "annulon-core"])
def test_no_claimed_component_name_is_privileged(broker, claimed):
    try:
        payload = _payload(requesting_component=claimed)
    except ContractError:
        return                      # refused before it is even a request
    _assert_denied(_send(broker, payload, caller="unknown"))


# --- the attacker replays, duplicates and back-dates -----------------------

def test_a_duplicate_action_id_is_refused(broker):
    payload = _payload()
    assert _send(broker, dict(payload))["decision"] == "allow"
    _assert_denied(_send(broker, dict(payload)),
                   expected=DenyReason.REPLAYED_REQUEST)
    assert len(broker._enforcer.applied) == 1


def test_an_old_request_is_refused(broker):
    _assert_denied(
        _send(broker, _payload(
            requested_at=(NOW - timedelta(hours=1)).isoformat())),
        expected=DenyReason.REQUEST_EXPIRED)


def test_a_future_dated_request_is_refused(broker):
    """Back-dating forward would widen the window a captured request stays
    usable in."""
    _assert_denied(
        _send(broker, _payload(
            requested_at=(NOW + timedelta(hours=1)).isoformat())),
        expected=DenyReason.REQUEST_FROM_THE_FUTURE)


def test_a_claimed_policy_version_does_not_select_a_policy(broker):
    """policy_version is informational. The broker evaluates against its own
    policy regardless of what the caller says it was expecting."""
    response = _send(broker, _payload(policy_version="broker-policy/999"))
    assert response["decision"] == "allow"
    assert response["policy_version"] == broker.policy.version


# --- policy confusion (doctrine section 25) --------------------------------

@pytest.mark.parametrize("identifier", [
    " 1500", "1500 ", "\t1500", "1500\n", "+1500", "01500", "1500.0",
    "1_500", "1500​", "۱۵۰۰",       # Arabic-Indic digits
    "１５００",                               # fullwidth digits
    "१५००",                                                   # Devanagari digits
])
def test_a_target_that_merely_resembles_the_allowed_uid_is_refused(broker, identifier):
    """Unicode confusables and whitespace padding.

    `str.isdigit()` is true for several non-ASCII digit families, and `int()`
    accepts them — so a naive path could turn `١٥٠٠` into 1500. The contract
    forbids anything outside the expected shape before that can happen.
    """
    response = _send(broker, _payload(target={"identifier": identifier}))
    _assert_denied(response)
    assert broker._enforcer.applied == []


def test_unicode_digits_really_do_normalise_to_the_permitted_uid():
    """Proves the previous test is testing something.

    If these strings did not convert to 1500, refusing them would be
    trivially safe and the test would be theatre.
    """
    for confusable in ["۱۵۰۰", "１５００"]:
        assert confusable.isdigit()
        assert int(confusable) == PERMITTED_UID
        assert unicodedata.numeric(confusable[0]) in (1.0, 5.0, 0.0)


@pytest.mark.parametrize("value", [1500, 1500.0, True, None, [1500], {"uid": 1500}])
def test_a_non_string_identifier_is_never_coerced(broker, value):
    """KF-36's family: coercion is how a wrong type becomes a valid value."""
    _assert_denied(_send(broker, _payload(target={"identifier": value})))


@pytest.mark.parametrize("value", [1, True, "1", 1.0, None])
def test_schema_version_is_not_coerced(broker, value):
    """`True == 1` in Python, so a bare equality check accepted `true`."""
    response = _send(broker, _payload(schema_version=value))
    if value == 1 and value is not True and not isinstance(value, float):
        assert response["decision"] == "allow"
    else:
        _assert_denied(response)


def test_duplicate_json_keys_resolve_to_the_last_value(broker):
    """Python's decoder keeps the last occurrence.

    Worth pinning: a proxy or a differently-behaving parser in front of the
    broker could disagree, and a request that reads one way to a validator
    and another way to the enforcer is a classic bypass. The broker is the
    only parser in the path, and this records what it does.
    """
    raw = ('{"schema_version": 1, "type": "action_request", "request": '
           + json.dumps(_payload(duration_seconds=300))[:-1]
           + ', "duration_seconds": 99999}}')
    decoded = json.loads(raw)
    assert decoded["request"]["duration_seconds"] == 99999
    # 99999 seconds is beyond what the contract can represent at all, so it
    # is refused at decode rather than by policy. Either way it is denied;
    # what matters is that the *last* value is the one evaluated.
    _assert_denied(broker.handle(decoded, caller="annulon-core"),
                   expected=DenyReason.MALFORMED_REQUEST)


# --- policy cannot be expanded by request content --------------------------

def test_a_denied_request_does_not_widen_policy_for_the_next_one(broker):
    """Order independence (doctrine section 45): a refused attempt must leave
    no residue that helps the attempt after it."""
    before = (broker.policy.permitted_uids, broker.policy.max_ttl,
              broker.policy.permitted_actions)
    for uid in (0, 4242, 998, 999):
        _send(broker, _payload(target={"identifier": str(uid)}))
    after = (broker.policy.permitted_uids, broker.policy.max_ttl,
             broker.policy.permitted_actions)
    assert before == after
    _assert_denied(_send(broker, _payload(target={"identifier": "4242"})))


def test_an_authorized_request_does_not_widen_policy_either(broker):
    assert _send(broker, _payload())["decision"] == "allow"
    _assert_denied(_send(broker, _payload(target={"identifier": "4242"})))
    _assert_denied(_send(broker, _payload(duration_seconds=3600)))


def test_order_does_not_change_outcomes(tmp_path):
    """unauthorized-then-authorized and authorized-then-unauthorized must
    produce the same isolated results."""
    def sequence(order):
        config = BrokerConfig(
            host_id="host-alpha", boot_id="boot-7",
            socket_path=str(tmp_path / f"{order}.sock"),
            journal_path=tmp_path / f"{order}.jsonl",
            caller_uids={CORE_UID: "annulon-core"})
        instance = Broker(config, BrokerPolicy(
            permitted_uids=frozenset({PERMITTED_UID}),
            authorized_callers=frozenset({"annulon-core"})),
            enforcer=RecordingEnforcer(), clock=lambda: NOW)
        good = lambda: _send(instance, _payload())["decision"]
        bad = lambda: _send(instance, _payload(
            target={"identifier": "4242"}))["decision"]
        return [good(), bad()] if order == "good-first" else list(
            reversed([bad(), good()]))

    assert sequence("good-first") == sequence("bad-first") == ["allow", "deny"]


# --- the positive control ---------------------------------------------------

def test_a_legitimate_request_still_succeeds(broker):
    """A broker that denies everything is not secure, it is broken."""
    response = _send(broker, _payload())
    assert response["decision"] == "allow", response
    assert len(broker._enforcer.applied) == 1
