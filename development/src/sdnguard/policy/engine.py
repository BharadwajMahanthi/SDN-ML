"""Policy engine. Observe-only by default, and it cannot be otherwise by accident.

A detector says *what happened*. This module says *what to do about it*, and
the separation matters: a security tool that causes outages is itself a
security problem, so the decision to interfere with traffic must be explicit,
scoped, reversible and visible.

The default mode is OBSERVE. Enforcement requires all of:

1. the engine to be constructed in an enforcing mode,
2. a rule that matches the finding,
3. a scope and a TTL on the resulting decision,
4. the emergency disable not to be engaged.

Point 4 exists because the first thing an operator needs when a detector
misfires at 3am is one switch that stops it touching the network, without
stopping it reporting.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sdnguard.domain.events import (
    EnforcementAction,
    EnforcementDecision,
    FindingKind,
    SecurityFinding,
    Severity,
    Verdict,
)
from sdnguard.domain.identity import PortIdentity

__all__ = ["PolicyMode", "PolicyRule", "PolicyEngine", "EnforcementDisabled"]


class PolicyMode(enum.Enum):
    OBSERVE = "observe"      # record only; never touches the network
    ALERT = "alert"          # record and notify; still never touches it
    ENFORCE = "enforce"      # may act, subject to rules and the kill switch


class EnforcementDisabled(Exception):
    """The emergency disable is engaged. Reporting continues; action does not."""


@dataclass(frozen=True)
class PolicyRule:
    """One rule: what to do about a kind of finding at or above a severity."""

    kind: FindingKind
    action: EnforcementAction
    minimum_severity: Severity = Severity.HIGH
    ttl: timedelta = timedelta(minutes=5)
    require_verdict: Verdict = Verdict.SUSPICIOUS

    def matches(self, finding: SecurityFinding) -> bool:
        order = {Severity.INFO: 0, Severity.LOW: 1,
                 Severity.MEDIUM: 2, Severity.HIGH: 3}
        return (finding.kind is self.kind
                and finding.verdict is self.require_verdict
                and order[finding.severity] >= order[self.minimum_severity])


@dataclass
class PolicyEngine:
    """Maps findings to decisions. Holds no network access of its own."""

    mode: PolicyMode = PolicyMode.OBSERVE
    rules: tuple[PolicyRule, ...] = ()
    protected_ports: frozenset[PortIdentity] = frozenset()
    _disabled: bool = field(default=False, init=False)

    # -- emergency control -----------------------------------------------

    def disable_enforcement(self, reason: str = "operator request") -> None:
        """Stop acting on the network. Reporting is unaffected."""
        self._disabled = True
        self._disable_reason = reason

    def enable_enforcement(self) -> None:
        self._disabled = False

    @property
    def enforcement_disabled(self) -> bool:
        return self._disabled

    # -- protection ------------------------------------------------------

    def protect(self, *ports: PortIdentity) -> None:
        """Mark ports that must never be enforced against -- the management
        plane and the operator's own path. Quarantining those turns a false
        positive into a lockout with no way back in."""
        self.protected_ports = self.protected_ports | frozenset(ports)

    def is_protected(self, port: PortIdentity) -> bool:
        return port in self.protected_ports

    # -- decision --------------------------------------------------------

    def decide(self, finding: SecurityFinding,
               decided_at: datetime) -> EnforcementDecision:
        """Always returns a decision. Never raises for an ordinary finding:
        a policy that throws on unexpected input stops producing evidence
        exactly when something unusual is happening."""
        if self.mode is PolicyMode.OBSERVE:
            return EnforcementDecision.observe(
                finding.finding_id, decided_at, "observe-only mode")

        rule = next((r for r in self.rules if r.matches(finding)), None)

        if self.mode is PolicyMode.ALERT or rule is None:
            reason = ("alert-only mode" if self.mode is PolicyMode.ALERT
                      else "no enforcement rule matched")
            return EnforcementDecision.create(
                finding.finding_id, EnforcementAction.ALERT, decided_at, reason)

        if self._disabled:
            return EnforcementDecision.create(
                finding.finding_id, EnforcementAction.ALERT, decided_at,
                f"enforcement disabled ({getattr(self, '_disable_reason', 'unknown')}); "
                f"would have applied {rule.action.value}")

        if self.is_protected(finding.port):
            return EnforcementDecision.create(
                finding.finding_id, EnforcementAction.ALERT, decided_at,
                f"{finding.port} is protected; would have applied "
                f"{rule.action.value}")

        return EnforcementDecision.create(
            finding.finding_id, rule.action, decided_at,
            f"rule matched {finding.kind.value} at {finding.severity.value}",
            scope=finding.port, ttl=rule.ttl, reversible=True)

    def decide_all(self, findings: list[SecurityFinding],
                   decided_at: datetime) -> list[EnforcementDecision]:
        return [self.decide(f, decided_at) for f in findings]

    @staticmethod
    def default_rules() -> tuple[PolicyRule, ...]:
        """A conservative starting set. Proposed, not approved: these values
        belong in ACCEPTANCE_CRITERIA once an operator has agreed them."""
        return (
            PolicyRule(FindingKind.HOST_LOCATION_HIJACK,
                       EnforcementAction.QUARANTINE, Severity.HIGH,
                       timedelta(minutes=5)),
            PolicyRule(FindingKind.LINK_FABRICATION,
                       EnforcementAction.DROP, Severity.HIGH,
                       timedelta(minutes=5)),
        )
