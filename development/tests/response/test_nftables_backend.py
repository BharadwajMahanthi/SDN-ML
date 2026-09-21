"""The packet-filter backend, attacked rather than demonstrated.

Most of this file is about the backend being *wrong* or *lied to*: nft
reporting success without installing anything, a rule vanishing underneath
us, a foreign rule that resembles ours, handles that move, malformed JSON
coming back. The question throughout is whether Annulon can be made to claim
containment that does not exist, or to delete something it does not own.

Tests needing a real kernel are marked and skip elsewhere; the physical
evidence lives in `docs/evidence/`. Nothing here claims containment — that
claim requires real packets, and these are unit tests.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from annulon.response.contract import (
    ActionRequest, ActionType, Target, TargetKind,
)
from annulon.response.enforcement import EnforcementError, EnforcementOutcome
from annulon.response.journal import OwnedResource
from annulon.response.nftables import (
    CHAIN_NAME, COMMENT_PREFIX, Coverage, MAX_COMMENT_BYTES, NftablesEnforcer,
    Ownership, TABLE_NAME, _build_comment, _parse_comment, coverage_for,
)

NOW = datetime(2026, 9, 21, 12, tzinfo=timezone.utc)
LATER = NOW + timedelta(minutes=5)


def _request(request_id="req-abcdef012345", uid=1500, destination=None):
    return ActionRequest(
        request_id=request_id,
        action_type=ActionType.TEMPORARY_EGRESS_RESTRICTION,
        target=Target(TargetKind.SERVICE_UID, "h", "b", str(uid), "worker"),
        duration=timedelta(minutes=5), reason="test", finding_id="finding-00000001",
        requested_at=NOW, requesting_component="annulon-core",
        destination_cidr=destination)


class ScriptedNft(NftablesEnforcer):
    """A backend whose nft invocations are scripted.

    Not a mock of the backend: the real parsing, ownership and verification
    logic all run. Only the kernel is replaced, so these tests exercise
    exactly the code that decides whether to trust nft.
    """

    def __init__(self, table_state=None, *, fail_on=(), bad_json=False,
                 state_after_failure=None):
        self.calls: list[list[str]] = []
        self.stdin: list[str] = []
        self._state = table_state if table_state is not None else []
        self._fail_on = fail_on
        self._bad_json = bad_json
        #: What the kernel holds *after* a failed command. Models the case
        #: that matters: nft reports an error having already installed the
        #: rule. Without this the idempotency pre-check short-circuits and
        #: the failure path is never reached.
        self._state_after_failure = state_after_failure
        super().__init__(binary="/nonexistent/nft")

    @staticmethod
    def _locate() -> str:
        return "/nonexistent/nft"

    def _run(self, argv, *, stdin=None):
        self.calls.append(argv)
        if stdin is not None:
            self.stdin.append(stdin)
        for marker in self._fail_on:
            if marker in (stdin or "") or marker in " ".join(argv):
                if self._state_after_failure is not None:
                    self._state = self._state_after_failure
                raise EnforcementError(f"scripted failure on {marker}")
        if "list" in argv:
            if self._bad_json:
                return "{not json"
            return json.dumps({"nftables": self._state})
        return ""


def _rule(handle, comment, chain=CHAIN_NAME):
    return {"rule": {"family": "inet", "table": TABLE_NAME, "chain": chain,
                     "handle": handle, "comment": comment}}


# --- ownership --------------------------------------------------------------

def test_a_rule_we_cannot_prove_we_created_is_never_deleted():
    """The single most important behaviour in this module.

    A security tool that deletes firewall rules it does not understand is
    worse than one that does nothing.
    """
    backend = ScriptedNft([_rule(7, "some operator's own rule")])
    records = backend.rules()
    assert [r.ownership for r in records] == [Ownership.UNKNOWN]
    assert backend.reconcile() == ()
    # Releasing an unrelated action reports absence and, crucially, issues no
    # delete at all.
    result = backend.release(
        OwnedResource("nftables", "inet/annulon/egress/req-whatever"))
    assert result.outcome is EnforcementOutcome.ALREADY_ABSENT
    assert not any("delete" in sent for sent in backend.stdin)


def test_a_rule_bearing_our_action_id_that_we_cannot_prove_is_refused():
    """A comment from a future version, or one written to imitate ours.

    Answering "already absent" here would be the dangerous outcome: the
    caller marks the action released while OS state remains, and nothing
    ever looks again.
    """
    backend = ScriptedNft([_rule(9, "annulon;v=99;a=req-abcdef012345;u=1500")])
    with pytest.raises(EnforcementError, match="ownership is unknown"):
        backend.release(
            OwnedResource("nftables", "inet/annulon/egress/req-abcdef012345"))
    assert not any("delete" in sent for sent in backend.stdin)


def test_a_forged_comment_that_imitates_ours_is_not_accepted():
    """A rule someone else wrote that looks Annulon-shaped."""
    for forged in ["annulon", "annulon;v=9;a=req-x", "annulon;a=req-x",
                   "annulon;v=1;a=", "ANNULON;v=1;a=req-x", " annulon;v=1;a=req-x"]:
        backend = ScriptedNft([_rule(1, forged)])
        assert backend.rules()[0].ownership is Ownership.UNKNOWN, forged


def test_removing_our_table_is_refused_when_it_holds_anything_unproven():
    """Removing the table would take the unknown rule with it."""
    backend = ScriptedNft([_rule(1, "not ours")])
    with pytest.raises(EnforcementError, match="unproven ownership"):
        backend.remove_own_table()


def test_a_rule_in_another_chain_is_not_ours():
    backend = ScriptedNft([_rule(1, _build_comment("req-abcdef012345", 1500, LATER),
                                 chain="someone-elses-chain")])
    assert backend.rules() == ()


def test_ownership_round_trips():
    comment = _build_comment("req-abcdef012345", 1500, LATER)
    action_id, uid, expires = _parse_comment(comment)
    assert (action_id, uid) == ("req-abcdef012345", 1500)
    assert expires == LATER.replace(microsecond=0)


def test_the_ownership_comment_stays_inside_the_kernel_limit():
    """Exceeding it fails the whole apply, which would be a containment
    outage caused by a long identifier."""
    longest = "r" + "a" * 62 + "z"
    comment = _build_comment(longest, 65535, LATER)
    assert len(comment.encode()) <= MAX_COMMENT_BYTES


def test_an_identifier_is_not_a_handle():
    """Handles are reassigned across a ruleset reload, so a journal entry
    naming one could later point at somebody else's rule."""
    backend = ScriptedNft([_rule(11, _build_comment("req-abcdef012345", 1500, LATER))])
    resource = backend.find("req-abcdef012345").resource
    assert "11" not in resource.identifier
    assert resource.identifier.endswith("req-abcdef012345")


# --- the backend being lied to ---------------------------------------------

def test_nft_reporting_success_without_installing_a_rule_is_not_success():
    """A backend that trusts a return code can report containment that does
    not exist. The kernel is asked afterwards, every time."""
    backend = ScriptedNft([])                    # add "succeeds", table stays empty
    result = backend.apply(_request(), expires_at=LATER)
    assert result.outcome is EnforcementOutcome.UNCERTAIN
    assert "no rule is visible" in result.detail
    assert result.may_hold_os_state, "uncertain state must still be reconciled"


def test_nft_reporting_failure_after_installing_a_rule_is_uncertain_not_failed():
    """The opposite lie. Rounding this to FAILED would orphan the rule."""
    comment = _build_comment("req-abcdef012345", 1500, LATER)
    backend = ScriptedNft([], fail_on=("comment",),
                          state_after_failure=[_rule(3, comment)])
    result = backend.apply(_request(), expires_at=LATER)
    assert result.outcome is EnforcementOutcome.UNCERTAIN
    assert result.may_hold_os_state


def test_a_rule_that_survives_deletion_is_an_error_not_a_success():
    comment = _build_comment("req-abcdef012345", 1500, LATER)
    backend = ScriptedNft([_rule(3, comment)])   # list always returns it
    with pytest.raises(EnforcementError, match="still present"):
        backend.release(OwnedResource("nftables", "inet/annulon/egress/req-abcdef012345"))


def test_releasing_something_already_gone_is_not_an_error():
    backend = ScriptedNft([])
    result = backend.release(OwnedResource("nftables", "inet/annulon/egress/req-gone0001"))
    assert result.outcome is EnforcementOutcome.ALREADY_ABSENT


def test_applying_twice_converges_instead_of_stacking_rules():
    """A retry after an uncertain outcome must not leave two rules behind."""
    comment = _build_comment("req-abcdef012345", 1500, LATER)
    backend = ScriptedNft([_rule(3, comment)])
    result = backend.apply(_request(), expires_at=LATER)
    assert result.outcome is EnforcementOutcome.APPLIED
    # ensure_structure legitimately sends table/chain adds; what must not
    # appear is a second *rule*, which is the only payload carrying a comment.
    assert not any("comment" in s for s in backend.stdin), "a duplicate rule was added"


def test_malformed_json_from_nft_is_an_error_not_an_empty_ruleset():
    """Reading a parse failure as "no rules" would make every foreign rule
    invisible and every owned rule look already-released."""
    backend = ScriptedNft([], bad_json=True)
    with pytest.raises(EnforcementError, match="unreadable"):
        backend.rules()


def test_an_nft_timeout_is_surfaced():
    backend = ScriptedNft([], fail_on=("list",))
    with pytest.raises(EnforcementError):
        backend.rules()


# --- command construction ---------------------------------------------------

def test_commands_are_json_and_never_assembled_as_text():
    """The injection property: nft's own parser never sees our data."""
    backend = ScriptedNft([])
    backend.apply(_request(destination="10.1.2.3/32"), expires_at=LATER)
    assert backend.stdin, "nothing was sent to nft"
    for payload in backend.stdin:
        parsed = json.loads(payload)             # must be valid JSON, always
        assert "nftables" in parsed
    assert all("-j" in call for call in backend.calls if call and call[0] == "-j")


@pytest.mark.parametrize("hostile", [
    "; rm -rf /", "`id`", "$(id)", "10.0.0.1 drop; accept", "\n", "‮",
    "' OR 1=1 --", "10.0.0.1/32\nadd rule inet annulon egress accept",
])
def test_a_hostile_destination_never_reaches_nft(hostile):
    """It is refused by the contract before the backend is involved, and the
    backend re-parses independently rather than trusting that."""
    from annulon.response.contract import ContractError
    with pytest.raises(ContractError):
        _request(destination=hostile)


def test_a_hostile_identifier_cannot_reach_the_ownership_comment():
    from annulon.response.contract import ContractError
    for hostile in ["1500; drop", "1500\n", "../1500", "1500 accept"]:
        with pytest.raises(ContractError):
            Target(TargetKind.SERVICE_UID, "h", "b", hostile, "w")


def test_the_comment_writer_refuses_unexpected_characters():
    """Defence in depth: if a future field skips validation, this still holds."""
    with pytest.raises(EnforcementError, match="unexpected characters"):
        _build_comment("req abcdef", 1500, LATER)


# --- coverage (KF-38) -------------------------------------------------------

def test_an_ipv4_scoped_rule_does_not_claim_to_restrict_ipv6():
    """Measured in the lab: a v6 connection from the contained uid stayed
    OPEN under a v4-scoped rule. The capability is named accordingly."""
    assert coverage_for("10.0.0.1/32") is Coverage.IPV4_ONLY
    assert not coverage_for("10.0.0.1/32").is_complete_egress
    assert coverage_for("2001:db8::1/128") is Coverage.IPV6_ONLY
    assert coverage_for(None) is Coverage.ALL_FAMILIES
    assert coverage_for(None).is_complete_egress


def test_coverage_is_reported_on_the_result():
    """So nothing downstream can describe a partial restriction as egress
    containment without contradicting the record."""
    comment = _build_comment("req-abcdef012345", 1500, LATER)
    backend = ScriptedNft([_rule(3, comment)])
    result = backend.apply(_request(destination="10.1.2.3/32"), expires_at=LATER)
    assert "coverage=ipv4_only" in result.detail


def test_inspect_state_publishes_the_measured_limitations():
    backend = ScriptedNft([])
    state = backend.inspect_state()
    assert "shared" in state["scoping"] or "uid" in state["scoping"]
    semantics = state["measured_semantics"]
    assert semantics["established_connections"].startswith("blocked")
    assert "NOT restricted" in semantics["ipv6_under_an_ipv4_scoped_rule"]


def test_the_backend_refuses_to_pretend_when_nft_is_absent():
    from annulon.response.nftables import NftablesUnavailable
    import annulon.response.nftables as module
    original = module._NFT_CANDIDATES
    module._NFT_CANDIDATES = ("/definitely/not/here",)
    try:
        import shutil
        real_which, shutil.which = shutil.which, lambda _: None
        try:
            assert NftablesEnforcer.available() is False
            with pytest.raises(NftablesUnavailable):
                NftablesEnforcer()
        finally:
            shutil.which = real_which
    finally:
        module._NFT_CANDIDATES = original
