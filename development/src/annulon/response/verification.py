"""Deciding whether containment actually happened.

This module is small and unusually important. It is the thing that can turn
"we ran an experiment" into "the host is contained", and every way that
conversion can go wrong is a way Annulon lies to an operator during an
incident.

Three questions are kept separate, per ADR-029, because collapsing them is
how an experiment that never ran gets reported as clean:

* **Completion** -- did the experiment actually execute end to end?
* **Observability** -- were the measurements themselves trustworthy?
* **Security outcome** -- what did the evidence show?

A run can complete with untrustworthy observation, and that is
``INCONCLUSIVE``, not success. A run whose verifier crashed is
``EVIDENCE_INCOMPLETE``, not a negative result. And containment is claimed
only when control-plane and data-plane evidence agree: a rule existing is not
traffic stopping, and traffic stopping without a rule is somebody else's
outage.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

__all__ = ["Completion", "Observability", "SecurityOutcome",
           "ContainmentEvidence", "Verdict", "assess"]


class Completion(enum.Enum):
    COMPLETE = "COMPLETE"
    EVIDENCE_INCOMPLETE = "EVIDENCE_INCOMPLETE"


class Observability(enum.Enum):
    """Whether the measurements can be believed at all."""

    TRUSTWORTHY = "TRUSTWORTHY"
    #: A control did not behave as a control must. Nothing measured in the
    #: same run can be relied on, including the results that look good.
    CONTROLS_FAILED = "CONTROLS_FAILED"
    PROBE_FAILED = "PROBE_FAILED"


class SecurityOutcome(enum.Enum):
    CONTAINED = "CONTAINED"
    #: The rule is installed and traffic still flows. Reported plainly rather
    #: than dressed up, because this is the case an operator most needs to
    #: know about.
    ACTION_EFFECT_NOT_VERIFIED = "ACTION_EFFECT_NOT_VERIFIED"
    NOT_CONTAINED = "NOT_CONTAINED"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass(frozen=True)
class ContainmentEvidence:
    """Everything the verdict is allowed to depend on.

    Deliberately explicit: each field is a separate measurement, and
    ``None`` means "not measured", which is never read as a pass. The
    harness fills these in from independent observation; nothing here is
    derived from the broker's own report of what it did.
    """

    #: Traffic with no action applied at all. The harness's own sanity check.
    negative_control_open: bool | None = None
    #: Traffic before the action, in the run that will apply one.
    baseline_open: bool | None = None
    #: Control-plane: a provably owned rule exists.
    rule_present: bool | None = None
    rule_ownership_proven: bool | None = None
    #: Data-plane: the target could not reach the destination.
    target_blocked: bool | None = None
    #: An unrelated workload kept working.
    non_target_open: bool | None = None
    #: The broker still answered while containment was in force.
    broker_responsive: bool | None = None
    #: Firewall state outside Annulon's table is unchanged.
    foreign_state_unchanged: bool | None = None
    #: After expiry: the rule is gone and traffic works again.
    rule_removed_after_expiry: bool | None = None
    traffic_restored_after_expiry: bool | None = None
    #: Anything that stopped the harness from measuring.
    harness_errors: tuple[str, ...] = ()

    def missing(self) -> tuple[str, ...]:
        """Measurements that were never taken.

        Absence is reported, never defaulted. A verifier that treats an
        unmeasured field as ``False`` invents a negative result; one that
        treats it as ``True`` invents a positive one.
        """
        return tuple(
            name for name, value in vars(self).items()
            if name != "harness_errors" and value is None)


@dataclass(frozen=True)
class Verdict:
    completion: Completion
    observability: Observability
    outcome: SecurityOutcome
    reasons: tuple[str, ...] = ()
    unmeasured: tuple[str, ...] = field(default_factory=tuple)

    @property
    def supports_containment_claim(self) -> bool:
        """The only property anything downstream should consult."""
        return (self.completion is Completion.COMPLETE
                and self.observability is Observability.TRUSTWORTHY
                and self.outcome is SecurityOutcome.CONTAINED)

    def to_dict(self) -> dict:
        return {"completion": self.completion.value,
                "observability": self.observability.value,
                "security_outcome": self.outcome.value,
                "reasons": list(self.reasons),
                "unmeasured": list(self.unmeasured),
                "supports_containment_claim": self.supports_containment_claim}


def assess(evidence: ContainmentEvidence) -> Verdict:
    """Turn measurements into a verdict, refusing every shortcut."""
    reasons: list[str] = []
    unmeasured = evidence.missing()

    # 1. Did the harness work at all? Checked first, because a broken
    #    harness invalidates everything downstream of it.
    if evidence.harness_errors:
        return Verdict(Completion.EVIDENCE_INCOMPLETE, Observability.PROBE_FAILED,
                       SecurityOutcome.INCONCLUSIVE,
                       tuple(f"harness: {e}" for e in evidence.harness_errors),
                       unmeasured)
    if unmeasured:
        return Verdict(Completion.EVIDENCE_INCOMPLETE, Observability.PROBE_FAILED,
                       SecurityOutcome.INCONCLUSIVE,
                       (f"{len(unmeasured)} measurement(s) were never taken",),
                       unmeasured)

    # 2. Were the controls valid? A failed control does not merely remove one
    #    data point -- it means the run cannot distinguish containment from a
    #    broken lab, so even a perfect-looking blocked target proves nothing.
    if not evidence.negative_control_open:
        reasons.append("negative control did not pass: traffic failed with no "
                       "action applied, so a block proves nothing")
    if not evidence.baseline_open:
        reasons.append("baseline traffic did not succeed before the action")
    if reasons:
        return Verdict(Completion.EVIDENCE_INCOMPLETE,
                       Observability.CONTROLS_FAILED,
                       SecurityOutcome.INCONCLUSIVE, tuple(reasons), unmeasured)

    # 3. Control plane and data plane must agree.
    control_plane = bool(evidence.rule_present and evidence.rule_ownership_proven)
    data_plane = bool(evidence.target_blocked)
    if control_plane and not data_plane:
        return Verdict(Completion.COMPLETE, Observability.TRUSTWORTHY,
                       SecurityOutcome.ACTION_EFFECT_NOT_VERIFIED,
                       ("a rule is installed but the target still reached the "
                        "destination",), unmeasured)
    if data_plane and not control_plane:
        # Traffic stopped without a provable rule. That is not containment;
        # it is an unexplained outage that happens to look like success.
        return Verdict(Completion.COMPLETE, Observability.CONTROLS_FAILED,
                       SecurityOutcome.INCONCLUSIVE,
                       ("traffic stopped but no provably owned rule exists; "
                        "the cause is unknown",), unmeasured)
    if not control_plane:
        # Only two states reach this line: both true, or both false. The two
        # disagreement cases returned above. Writing the condition as
        # `not control_plane and not data_plane` was redundant, and the
        # redundancy was invisible to tests -- flipping the `and` to `or`
        # changed nothing, which is how mutation testing pointed at it.
        return Verdict(Completion.COMPLETE, Observability.TRUSTWORTHY,
                       SecurityOutcome.NOT_CONTAINED,
                       ("no rule and no effect",), unmeasured)

    # 4. Containment happened. Now: was it *safe* and was it *temporary*?
    if not evidence.non_target_open:
        reasons.append("an unrelated workload was also blocked; containment "
                       "is not scoped")
    if not evidence.foreign_state_unchanged:
        reasons.append("firewall state outside Annulon's table changed")
    if not evidence.broker_responsive:
        reasons.append("the broker stopped answering during containment")
    if not evidence.rule_removed_after_expiry:
        reasons.append("the rule outlived its deadline")
    if not evidence.traffic_restored_after_expiry:
        reasons.append("traffic did not return after expiry")
    if reasons:
        # Blocking worked, but a safety property did not hold. Not a pass.
        return Verdict(Completion.COMPLETE, Observability.TRUSTWORTHY,
                       SecurityOutcome.INCONCLUSIVE, tuple(reasons), unmeasured)

    return Verdict(Completion.COMPLETE, Observability.TRUSTWORTHY,
                   SecurityOutcome.CONTAINED,
                   ("control plane and data plane agree; controls, scope, "
                    "management safety and expiry all held",), unmeasured)
