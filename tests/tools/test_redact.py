from __future__ import annotations

import pytest

from tests.tools.fixtures import FAKE_API_KEY, FAKE_AWS_KEY, FAKE_PASSWORD, FAKE_PRIVATE_KEY
from tools.redact import redact, summarize


def _assert_suppressed(text: str, *, secret: str, kind: str | None = None):
    result = redact(text)
    assert secret not in result.text, "secret survived redaction"
    assert result.findings, "redaction produced no finding"
    if kind:
        assert any(f.kind == kind for f in result.findings)
    return result


def test_fake_private_key_block():
    _assert_suppressed(FAKE_PRIVATE_KEY, secret="MIIEow", kind="private_key_block")


def test_fake_aws_access_key():
    _assert_suppressed(f"key = {FAKE_AWS_KEY}", secret=FAKE_AWS_KEY, kind="aws_access_key_id")


def test_fake_api_key():
    _assert_suppressed(f'api_key: "{FAKE_API_KEY}"', secret=FAKE_API_KEY)


def test_underscore_separated_password_name():
    """Regression: \\b fails after '_', which would have exposed SUDO_PASS."""
    _assert_suppressed(f'SUDO_PASS="{FAKE_PASSWORD}"', secret=FAKE_PASSWORD, kind="assigned_secret")


@pytest.mark.parametrize(
    "line",
    [
        'DB_PASSWORD=letmein99',
        'export API_KEY=abc123def456ghi789',
        'auth-token: "zzzz1111yyyy2222"',
    ],
)
def test_assigned_secret_variants(line):
    result = redact(line)
    assert result.findings, line


def test_connection_string_credentials():
    result = redact('url = "postgres://admin:s3cr3tpw@db.internal:5432/app"')
    assert "s3cr3tpw" not in result.text
    assert any(f.kind == "connection_string_credentials" for f in result.findings)


def test_jwt_and_bearer():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1rXw"
    result = redact(f"Authorization: Bearer {jwt}")
    assert jwt not in result.text


@pytest.mark.parametrize(
    "line",
    [
        "password = None",
        'password = os.environ["PW"]',
        "self.auth_token = get_token()",
        "timeout = 30",
        "floodlight_with_topoguard/src/main/java/Checker.java",
        "commit fbd80e0060d2d77cf69eed5935d493d3cf958ded",
        "def preprocess_sdn_data(df, feature_set=None):",
    ],
)
def test_non_secrets_are_preserved(line):
    """Over-redaction is the safe direction, but it must not destroy source."""
    result = redact(line)
    assert result.text == line, f"false positive on: {line}"
    assert result.clean


def test_findings_never_carry_the_value():
    result = redact(f'SUDO_PASS="{FAKE_PASSWORD}"')
    for finding in result.findings:
        rendered = finding.render()
        assert FAKE_PASSWORD not in rendered
        assert "REDACTED" in rendered
    assert FAKE_PASSWORD not in summarize(result.findings)


def test_multiple_secrets_on_separate_lines_all_reported():
    text = f'a = "{FAKE_AWS_KEY}"\nb = 1\nPASSWORD="{FAKE_PASSWORD}"\n'
    result = redact(text)
    assert FAKE_AWS_KEY not in result.text
    assert FAKE_PASSWORD not in result.text
    assert len({f.line for f in result.findings}) >= 2


def test_idempotent():
    once = redact(f'SUDO_PASS="{FAKE_PASSWORD}"').text
    assert redact(once).text == once


@pytest.mark.parametrize(
    "slug",
    [
        "feat/v2-architecture-01-cloud-agent-contract",
        "test/v2-response-02-containment-recovery",
        "spike/v2-platform-01-additional-profiles",
        "MAX_OUTSTANDING_PROBE_COUNT",
        "preprocess_sdn_data_and_split",
    ],
)
def test_single_case_slugs_are_not_mistaken_for_secrets(slug):
    """KF-24: long hyphenated branch names are high-entropy and mixed-class,
    so without an explicit slug rule the gateway masked them and made the
    architecture document unreadable."""
    assert redact(slug).clean, f"false positive on {slug}"


@pytest.mark.parametrize(
    "secret",
    [
        "wJalrXUtnFEMI_K7MDENG_bPxRfiCYEXAMPLEKEY",   # canonical AWS secret shape
        "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789AbCd",
    ],
)
def test_mixed_case_high_entropy_tokens_are_still_redacted(secret):
    """The companion half of KF-24. Widening the slug rule to accept mixed
    case let the canonical AWS secret through -- fixing over-redaction must
    not create under-redaction."""
    assert not redact(secret).clean, f"secret survived: {secret[:6]}..."


@pytest.mark.parametrize(
    "code",
    [
        "default_factory=CollectionQuality",
        "default_factory=MovementStateMachine",
        "Server_Side_Request_Forgery_Prevention_Cheat_Sheet",
        "max_outstanding=DEFAULT_MAX_OUTSTANDING",
    ],
)
def test_keyword_arguments_are_not_high_entropy_secrets(code):
    """KF-32: '=' is only ever trailing base64 padding. Allowing it mid-token
    made ordinary keyword arguments read as one high-entropy blob."""
    assert redact(code).clean, f"false positive on {code}"


@pytest.mark.parametrize(
    "secret",
    [
        "dGhpcyBpcyBhIHRlc3Qgc2VjcmV0IHZhbHVlIGhlcmU=",
        "YWFhYWJiYmJjY2NjZGRkZGVlZWVmZmZmZ2dnZ2hoaGg==",
    ],
)
def test_base64_with_trailing_padding_is_still_caught(secret):
    assert not redact(secret).clean, "trailing '=' padding must still match"


# --- KF-34: prose must not be mistaken for a secret assignment -------------

PROSE_THAT_IS_NOT_A_SECRET = [
    "peer-credential auth via LOCAL_PEERCRED",
    "the token for this session",
    "a private key to the host",
    "credential store",
    "auth via peer credentials",
    "token bucket rate limiting",
    "secret of success",
    "password policy applies",
    "access-key rotation guidance",
    "the api-key header name",
]

ASSIGNMENTS_THAT_ARE_SECRETS = [
    "password=hunter2",
    "API_KEY: AKIAIOSFODNN7EXAMPLE",
    "--password hunter2",
    'SUDO_PASS="s3cr3t!"',
    "token abc123XYZ789",
    "passphrase correcthorsebatterystaple",
    "private_key: /tmp/x.pem",
    "secret 'aVeryLongOpaqueValue12345'",
    "credential=swordfish",
    "run --token ghp_ABCdef123456",
]


@pytest.mark.parametrize("text", PROSE_THAT_IS_NOT_A_SECRET)
def test_prose_is_not_redacted(text):
    """Whitespace is a weak assignment signal; English is not a secret.

    The redactor blocking legitimate records is not a harmless failure: a
    guard that fires on ordinary sentences is one that gets disabled.
    """
    result = redact(text)
    assert not result.findings, f"{text!r} -> {[f.kind for f in result.findings]}"
    assert result.text == text


@pytest.mark.parametrize("text", ASSIGNMENTS_THAT_ARE_SECRETS)
def test_real_assignments_are_still_redacted(text):
    """The fix for KF-34 must not open the hole it was narrowing."""
    result = redact(text)
    assert result.findings, f"{text!r} was not redacted"


def test_hyphen_inside_a_word_is_not_a_command_line_flag():
    """The second defect found while fixing KF-34."""
    assert not redact("peer-credential auth").findings
    assert redact("--credential swordfish1").findings


def test_a_long_all_alphabetic_value_stays_suspicious():
    """A real passphrase can be all letters, so length still matters."""
    assert redact("passphrase correcthorsebatterystaple").findings
    assert not redact("passphrase policy").findings
