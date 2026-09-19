"""Second-layer content redaction for anything leaving the local machine.

Path policy (``tools.context_policy``) stops whole files. This module stops
secrets that appear inside files that are otherwise legitimate to read --
a password pasted into a shell script, a key echoed by a command.

Honest limitation: this is pattern- and entropy-based. It will miss novel
secret formats and will sometimes over-redact. Over-redaction is the
intended failure direction. Do not describe it as complete DLP.

Known, deliberate limitations:

* Bare hex strings (>=32 chars) are NOT redacted by the entropy rule. Git
  object IDs are 40 hex characters and appear constantly in this project's
  tooling; redacting them would make git output unusable. A hex secret IS
  still caught when assigned to a secret-named variable.
* Values that are identifiers, attribute chains or calls are treated as
  references, not literals, so ``password = get_pw()`` is preserved.
* Novel secret formats with low entropy and no recognisable name will pass.

Findings never carry the matched value -- only kind, line number, severity.
Line numbers are exact for the first matching rule and approximate for later
rules when an earlier rule collapsed a multi-line block (e.g. a PEM key).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

HIGH = "HIGH"
MEDIUM = "MEDIUM"


@dataclass(frozen=True)
class Finding:
    kind: str
    line: int
    severity: str

    def render(self) -> str:
        return f"line {self.line}: {self.kind} [{self.severity}] value: REDACTED"


@dataclass(frozen=True)
class Result:
    text: str
    findings: tuple[Finding, ...]

    @property
    def clean(self) -> bool:
        return not self.findings


def _mask(kind: str) -> str:
    return f"<<REDACTED:{kind}>>"


# Ordered most-specific first; earlier rules win because replacement removes
# the text before later rules see it.
_RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "private_key_block",
        re.compile(
            r"-----BEGIN[ A-Z]*PRIVATE KEY-----.*?-----END[ A-Z]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        HIGH,
    ),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA)[0-9A-Z]{16}\b"), HIGH),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), HIGH),
    (
        "prefixed_api_key",
        re.compile(r"\b(?:sk|pk|rk)[-_](?:live|test|prod|proj)?[-_]?[A-Za-z0-9]{16,}\b"),
        HIGH,
    ),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), HIGH),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), HIGH),
    ("bearer_token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}"), HIGH),
    (
        "connection_string_credentials",
        re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@]+:[^\s/@]{1,200}@"),
        HIGH,
    ),
)

# NOTE: the boundaries are (?<![A-Za-z0-9]) / (?![A-Za-z0-9]) rather than \b so
# that underscore-separated names match. \b fails on SUDO_PASS because '_' is a
# word character -- that miss would have exposed a real credential in this repo.
_SECRET_NAME = re.compile(
    r"(?i)(?<![A-Za-z0-9])(pass(?:word|wd|phrase)?|pwd|secret(?:[_-]?key)?|token|"
    r"api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential|auth)"
    r"(?![A-Za-z0-9])"
    r"(?P<sep>\s*[:=]\s*|\s+)"
    r"(?P<value>\"[^\"\n]*\"|'[^'\n]*'|[^\s#;,)\]}]+)"
)

# Bare values that are references or placeholders, not literals.
_NOT_A_LITERAL = re.compile(
    r"^(None|True|False|null|nil|undefined|\"\"|''|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|"
    r"[A-Za-z_][A-Za-z0-9_]*[.(][A-Za-z0-9_.()\[\]'\"]*)$"
)

# '/' and '.' are deliberately excluded: including them made this rule match
# long file paths, which destroyed legitimate output. Entropy alone is not a
# sufficient signal -- a token must also look unlike an identifier or path.
_ENTROPY_CANDIDATE = re.compile(r"[A-Za-z0-9+=_-]{32,}")
_IDENTIFIERISH = re.compile(r"^[a-z0-9]+(?:_[a-z0-9]+)+$|^[A-Za-z]+$")


def _charclass_variety(token: str) -> int:
    return sum(
        bool(re.search(pattern, token))
        for pattern in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[+=_-]")
    )


def _shannon(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _looks_like_secret_value(value: str) -> bool:
    stripped = value.strip("\"'")
    if len(stripped) < 4:
        return False
    if _NOT_A_LITERAL.match(value.strip()):
        return False
    return True


def redact(text: str) -> Result:
    """Redact probable secrets. Returns the safe text plus valueless findings."""
    findings: list[Finding] = []

    def line_of(index: int, haystack: str) -> int:
        return haystack.count("\n", 0, index) + 1

    out = text
    for kind, pattern, severity in _RULES:
        def _sub(m: re.Match[str], _k: str = kind, _s: str = severity) -> str:
            findings.append(Finding(_k, line_of(m.start(), out), _s))
            return _mask(_k)

        out = pattern.sub(_sub, out)

    def _sub_named(m: re.Match[str]) -> str:
        value = m.group("value")
        if not _looks_like_secret_value(value):
            return m.group(0)
        findings.append(Finding("assigned_secret", line_of(m.start(), out), HIGH))
        prefix = m.group(0)[: m.start("value") - m.start(0)]
        return prefix + _mask("assigned_secret")

    out = _SECRET_NAME.sub(_sub_named, out)

    def _sub_entropy(m: re.Match[str]) -> str:
        token = m.group(0)
        if token.startswith("<<REDACTED:"):
            return token
        if _IDENTIFIERISH.match(token):
            return token          # snake_case / CamelCase name, not a secret
        if _charclass_variety(token) < 3:
            return token          # single-alphabet blob: too weak a signal
        if _shannon(token) < 3.8:
            return token
        findings.append(Finding("high_entropy_token", line_of(m.start(), out), MEDIUM))
        return _mask("high_entropy_token")

    out = _ENTROPY_CANDIDATE.sub(_sub_entropy, out)

    findings.sort(key=lambda f: (f.line, f.kind))
    return Result(out, tuple(findings))


def redact_lines(lines: list[str]) -> tuple[list[str], tuple[Finding, ...]]:
    result = redact("\n".join(lines))
    return result.text.split("\n"), result.findings


def summarize(findings: tuple[Finding, ...]) -> str:
    if not findings:
        return "redaction: none"
    kinds = Counter(f.kind for f in findings)
    detail = ", ".join(f"{k}x{v}" for k, v in sorted(kinds.items()))
    return f"redaction: {len(findings)} finding(s) [{detail}] -- values withheld"
