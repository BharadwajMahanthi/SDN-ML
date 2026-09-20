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
