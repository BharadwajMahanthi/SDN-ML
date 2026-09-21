"""Attacking the verifier, because the verifier can lie for us.

Everything else in this campaign protects the host from Annulon. This file
protects the *operator* from Annulon's own reporting. The failure being
hunted is the one from KF-22: a run where nothing actually happened, reported
as a clean result.

The rule throughout: a broken measurement produces EVIDENCE_INCOMPLETE or
INCONCLUSIVE. It never produces CONTAINED.
"""

from __future__ import annotations

import itertools

import pytest

from annulon.response.verification import (
    Completion, ContainmentEvidence, Observability, SecurityOutcome, assess,
)


def _good(**overrides) -> ContainmentEvidence:
    """A fully successful run, which every test then damages in one way."""
    base = dict(
        negative_control_open=True, baseline_open=True, rule_present=True,
        rule_ownership_proven=True, target_blocked=True, non_target_open=True,
        broker_responsive=True, foreign_state_unchanged=True,
        rule_removed_after_expiry=True, traffic_restored_after_expiry=True)
    base.update(overrides)
    return ContainmentEvidence(**base)


def test_the_positive_control_passes():
    """A verifier that never says CONTAINED is useless, not safe."""
    verdict = assess(_good())
    assert verdict.outcome is SecurityOutcome.CONTAINED
    assert verdict.supports_containment_claim


# --- the verifier itself is broken -----------------------------------------

@pytest.mark.parametrize("error", [
    "destination server never started", "DNS resolution failed",
    "probe client could not start", "traffic verifier crashed",
    "scenario never executed", "expected output file missing",
    "subprocess exited 0 without running", "partial output truncated",
])
def test_a_broken_harness_can_never_produce_containment(error):
    """KF-22's family: every way an experiment can fail to happen."""
    verdict = assess(_good(harness_errors=(error,)))
    assert verdict.completion is Completion.EVIDENCE_INCOMPLETE
    assert verdict.outcome is SecurityOutcome.INCONCLUSIVE
    assert not verdict.supports_containment_claim


@pytest.mark.parametrize("field", [
    "negative_control_open", "baseline_open", "rule_present",
    "rule_ownership_proven", "target_blocked", "non_target_open",
    "broker_responsive", "foreign_state_unchanged",
    "rule_removed_after_expiry", "traffic_restored_after_expiry"])
def test_an_unmeasured_field_is_never_treated_as_a_pass(field):
    """Absence of a measurement is not evidence of anything."""
    verdict = assess(_good(**{field: None}))
    assert verdict.completion is Completion.EVIDENCE_INCOMPLETE
    assert field in verdict.unmeasured
    assert not verdict.supports_containment_claim


def test_a_run_with_no_measurements_at_all_is_not_clean():
    """The empty experiment. INV-001."""
    verdict = assess(ContainmentEvidence())
    assert verdict.completion is Completion.EVIDENCE_INCOMPLETE
    assert verdict.outcome is SecurityOutcome.INCONCLUSIVE
    assert len(verdict.unmeasured) == 10


# --- the controls are invalid ----------------------------------------------

def test_a_failed_negative_control_invalidates_the_whole_run():
    """If traffic fails with no action applied, a block proves nothing --
    including the block that looks successful."""
    verdict = assess(_good(negative_control_open=False))
    assert verdict.observability is Observability.CONTROLS_FAILED
    assert verdict.outcome is SecurityOutcome.INCONCLUSIVE
    assert "negative control" in verdict.reasons[0]


def test_a_failed_baseline_invalidates_the_run():
    verdict = assess(_good(baseline_open=False))
    assert verdict.outcome is SecurityOutcome.INCONCLUSIVE


# --- control plane and data plane disagree ---------------------------------

def test_a_rule_that_does_not_stop_traffic_is_reported_as_such():
    """The case an operator most needs to hear about."""
    verdict = assess(_good(target_blocked=False))
    assert verdict.outcome is SecurityOutcome.ACTION_EFFECT_NOT_VERIFIED
    assert not verdict.supports_containment_claim


def test_traffic_stopping_without_a_rule_is_not_containment():
    """An unexplained outage that happens to look like success.

    Reporting this as CONTAINED would mean claiming credit for someone
    else's broken network, and would hide that the action did nothing.
    """
    verdict = assess(_good(rule_present=False))
    assert verdict.outcome is SecurityOutcome.INCONCLUSIVE
    assert "no provably owned rule" in verdict.reasons[0]


def test_an_unowned_rule_does_not_count_as_control_plane_evidence():
    verdict = assess(_good(rule_ownership_proven=False))
    assert verdict.outcome is SecurityOutcome.INCONCLUSIVE


def test_no_rule_and_no_effect_is_an_honest_negative():
    verdict = assess(_good(rule_present=False, rule_ownership_proven=False,
                           target_blocked=False))
    assert verdict.outcome is SecurityOutcome.NOT_CONTAINED
    assert verdict.completion is Completion.COMPLETE


# --- blocking worked but a safety property did not -------------------------

@pytest.mark.parametrize("field,fragment", [
    ("non_target_open", "not scoped"),
    ("foreign_state_unchanged", "outside Annulon's table"),
    ("broker_responsive", "stopped answering"),
    ("rule_removed_after_expiry", "outlived its deadline"),
    ("traffic_restored_after_expiry", "did not return after expiry"),
])
def test_blocking_traffic_is_not_enough_on_its_own(field, fragment):
    """Containment that is unscoped, that breaks management, or that never
    ends is not a success even though the target stopped talking."""
    verdict = assess(_good(**{field: False}))
    assert verdict.outcome is SecurityOutcome.INCONCLUSIVE
    assert any(fragment in reason for reason in verdict.reasons)
    assert not verdict.supports_containment_claim


def test_several_safety_failures_are_all_reported():
    """An operator reading this wants every reason, not the first one."""
    verdict = assess(_good(non_target_open=False, broker_responsive=False,
                           traffic_restored_after_expiry=False))
    assert len(verdict.reasons) == 3


# --- structural properties --------------------------------------------------

def test_only_one_combination_out_of_every_single_field_failure_passes():
    """Property: damaging any single measurement removes the claim.

    Expressed as a sweep rather than an example, so a future field added
    without being consulted shows up here as a test that stops failing.
    """
    fields = [f for f in vars(_good()) if f != "harness_errors"]
    for field in fields:
        assert not assess(_good(**{field: False})).supports_containment_claim, field
        assert not assess(_good(**{field: None})).supports_containment_claim, field


def test_every_pair_of_failures_also_fails():
    """No combination of two defects cancels out into a pass."""
    fields = [f for f in vars(_good()) if f != "harness_errors"]
    for first, second in itertools.combinations(fields, 2):
        evidence = _good(**{first: False, second: False})
        assert not assess(evidence).supports_containment_claim, (first, second)


def test_the_verdict_serialises_without_losing_the_caveats():
    verdict = assess(_good(target_blocked=False))
    body = verdict.to_dict()
    assert body["security_outcome"] == "ACTION_EFFECT_NOT_VERIFIED"
    assert body["supports_containment_claim"] is False
    assert body["reasons"]
