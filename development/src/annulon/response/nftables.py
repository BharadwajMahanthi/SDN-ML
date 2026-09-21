"""The first real privileged backend: Linux packet-filter containment.

This is the only module in the system that changes operating-system state,
and it is deliberately the narrowest thing that can do the job.

**Annulon owns one table and touches nothing else.** Every object it creates
lives in `inet annulon`. It never flushes the ruleset, never edits a table it
did not create, and never removes a rule whose ownership it cannot prove from
that rule's own metadata. The failure mode being avoided is a security tool
that, during an incident, deletes the operator's firewall.

**Commands are never assembled as text.** `nft` is driven through its JSON
interface (`nft -j -f -`) with a structure built from typed, already-validated
values. There is no string concatenation into a parser anywhere here, so a
hostile value cannot change the shape of a command -- at worst it is a bad
argument that the kernel rejects.

**Ownership is read from JSON, never from the text listing.** Measured: a
rule comment containing `"` renders `nft -a list` ambiguous, so the text
output can be forged by the very data being classified. `nft -j list` carries
the comment as a string field and is unaffected. Parsing the text output
would have been a way for a crafted comment to make a foreign rule look
owned, or an owned rule look foreign.

`meta skuid` is the scoping primitive: the rule matches packets originating
from one uid. Its limits are stated in `inspect_state` and in the ADR -- it
scopes by the socket's owning uid, which is precise for a dedicated service
account and meaningless for a shared one.
"""

from __future__ import annotations

import enum
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone

from annulon.response.contract import ActionRequest, ActionType
from annulon.response.enforcement import (
    EnforcementError, EnforcementOutcome, EnforcementResult,
)
from annulon.response.journal import OwnedResource

__all__ = ["NftablesEnforcer", "Ownership", "RuleRecord", "NftablesUnavailable",
           "Coverage", "coverage_for", "TABLE_FAMILY", "TABLE_NAME",
           "CHAIN_NAME", "COMMENT_PREFIX", "MAX_COMMENT_BYTES"]

TABLE_FAMILY = "inet"
TABLE_NAME = "annulon"
CHAIN_NAME = "egress"
COMMENT_PREFIX = "annulon"
COMMENT_VERSION = "1"
#: The kernel's limit on a rule comment. Exceeding it makes the whole apply
#: fail, which would be a containment outage caused by a long identifier.
MAX_COMMENT_BYTES = 128
#: Where the binary is allowed to be. An absolute path from a fixed list,
#: never something resolved out of PATH at call time.
_NFT_CANDIDATES = ("/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft")
_COMMAND_TIMEOUT = 15.0
_MAX_OUTPUT_BYTES = 4 * 1024 * 1024
#: Everything that may appear in a comment we write. Anything else means the
#: value never came from a validated contract field.
_COMMENT_SAFE = re.compile(r"\A[A-Za-z0-9._:=;-]+\Z")


class NftablesUnavailable(EnforcementError):
    """The backend cannot operate here. Never degraded into a no-op."""


class Coverage(enum.Enum):
    """Which address families a rule actually restricts.

    Reported on every result because an IPv4-scoped rule leaves IPv6 wide
    open, measured: with `ip daddr` matching a v4 destination, a v6
    connection from the same uid stayed OPEN. Calling that "egress
    restricted" would be false, so the backend names the coverage and the
    caller has to say what it really achieved (KF-38).
    """

    IPV4_ONLY = "ipv4_only"
    IPV6_ONLY = "ipv6_only"
    ALL_FAMILIES = "all_families"

    @property
    def is_complete_egress(self) -> bool:
        return self is Coverage.ALL_FAMILIES


def coverage_for(destination_cidr: str | None) -> Coverage:
    """What a rule for this destination will and will not restrict."""
    if not destination_cidr:
        # No address match at all: the inet family covers v4 and v6, which
        # the bypass experiment confirmed by observing a v6 connection from
        # the contained uid time out.
        return Coverage.ALL_FAMILIES
    import ipaddress
    network = ipaddress.ip_network(destination_cidr, strict=False)
    return Coverage.IPV4_ONLY if network.version == 4 else Coverage.IPV6_ONLY


class Ownership(enum.Enum):
    """Who a rule belongs to, decided from its own metadata.

    ``UNKNOWN`` is the important one. A rule sitting in Annulon's table whose
    comment does not parse is *not* assumed to be ours and is never removed
    automatically: deleting something we cannot prove we created is exactly
    the behaviour this module exists to avoid. It is reported instead.
    """

    OWNED = "owned"
    UNKNOWN = "unknown"        # in our table, unprovable -> report, never delete
    FOREIGN = "foreign"        # outside our table -> never touched at all


@dataclass(frozen=True)
class RuleRecord:
    """One rule as the kernel currently holds it."""

    handle: int
    ownership: Ownership
    action_id: str = ""
    uid: int | None = None
    expires_at: datetime | None = None
    comment: str = ""

    @property
    def resource(self) -> OwnedResource:
        return OwnedResource(NftablesEnforcer.backend_id,
                             _identifier(self.action_id))


def _identifier(action_id: str) -> str:
    """A stable name for an owned rule.

    Deliberately not the handle. Handles are reassigned across a ruleset
    reload, so a journal entry naming one could, after a restart, point at a
    different rule -- possibly somebody else's.
    """
    return f"{TABLE_FAMILY}/{TABLE_NAME}/{CHAIN_NAME}/{action_id}"


def _action_id_of(identifier: str) -> str:
    return identifier.rsplit("/", 1)[-1]


def _build_comment(action_id: str, uid: int, expires_at: datetime) -> str:
    comment = (f"{COMMENT_PREFIX};v={COMMENT_VERSION};a={action_id};"
               f"u={uid};x={int(expires_at.timestamp())}")
    if not _COMMENT_SAFE.match(comment):
        # Unreachable from a validated request; a guard against a future
        # field being added without the same validation.
        raise EnforcementError("refusing to write a comment with unexpected "
                               "characters")
    if len(comment.encode()) > MAX_COMMENT_BYTES:
        raise EnforcementError(
            f"ownership comment is {len(comment.encode())} bytes, over the "
            f"{MAX_COMMENT_BYTES}-byte kernel limit")
    return comment


def _parse_comment(comment: object) -> tuple[str, int | None, datetime | None]:
    """Read ownership out of a comment, trusting nothing about its shape."""
    if not isinstance(comment, str) or not comment.startswith(COMMENT_PREFIX + ";"):
        return "", None, None
    fields: dict[str, str] = {}
    for part in comment.split(";")[1:]:
        key, _, value = part.partition("=")
        if key:
            fields[key] = value
    if fields.get("v") != COMMENT_VERSION or not fields.get("a"):
        # A comment from a version we do not understand is not ours to
        # remove. Reported as UNKNOWN rather than guessed at.
        return "", None, None
    uid = int(fields["u"]) if fields.get("u", "").isdigit() else None
    expires = None
    if fields.get("x", "").isdigit():
        expires = datetime.fromtimestamp(int(fields["x"]), tz=timezone.utc)
    return fields["a"], uid, expires


class NftablesEnforcer:
    """Reversible, uid-scoped egress containment through nftables."""

    backend_id = "nftables"

    def __init__(self, *, binary: str | None = None,
                 timeout: float = _COMMAND_TIMEOUT) -> None:
        self._binary = binary or self._locate()
        self._timeout = timeout

    @staticmethod
    def _locate() -> str:
        for candidate in _NFT_CANDIDATES:
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
        found = shutil.which("nft")
        if found:
            # Resolved once, at construction, and then fixed. Not looked up
            # again per call, so a later PATH change cannot redirect it.
            return os.path.realpath(found)
        raise NftablesUnavailable("nft is not installed; this backend refuses "
                                  "to pretend it can contain anything")

    @classmethod
    def available(cls) -> bool:
        try:
            cls._locate()
        except NftablesUnavailable:
            return False
        return True

    # -- process invocation ----------------------------------------------

    def _run(self, argv: list[str], *, stdin: str | None = None) -> str:
        """One nft invocation. Fixed argv, no shell, bounded, with a timeout."""
        try:
            completed = subprocess.run(          # noqa: S603 - fixed argv, no shell
                [self._binary, *argv], input=stdin, capture_output=True,
                text=True, timeout=self._timeout, check=False, shell=False,
                env={"PATH": "/usr/sbin:/sbin:/usr/bin:/bin", "LC_ALL": "C"})
        except subprocess.TimeoutExpired as exc:
            raise EnforcementError(f"nft timed out after {self._timeout}s") from exc
        except OSError as exc:
            raise NftablesUnavailable(f"cannot execute nft: {exc}") from exc
        if len(completed.stdout) > _MAX_OUTPUT_BYTES:
            raise EnforcementError("nft produced an implausibly large output")
        if completed.returncode != 0:
            raise EnforcementError(
                f"nft failed ({completed.returncode}): "
                f"{completed.stderr.strip()[:200]}")
        return completed.stdout

    def _apply_json(self, commands: list[dict]) -> None:
        self._run(["-j", "-f", "-"], stdin=json.dumps({"nftables": commands}))

    def _list_table(self) -> list[dict]:
        """Current contents of Annulon's table, as JSON. Never text."""
        try:
            raw = self._run(["-j", "list", "table", TABLE_FAMILY, TABLE_NAME])
        except EnforcementError as exc:
            if "No such file or directory" in str(exc) or "does not exist" in str(exc):
                return []                       # table not created yet
            raise
        try:
            return json.loads(raw).get("nftables", [])
        except (json.JSONDecodeError, AttributeError) as exc:
            raise EnforcementError(f"unreadable nft JSON: {exc}") from exc

    # -- structure --------------------------------------------------------

    def ensure_structure(self) -> None:
        """Create Annulon's own table and chain. Idempotent.

        The chain has ``policy accept``: it exists to hold specific drop
        rules, not to become a default-deny firewall. A chain that defaulted
        to drop would black-hole the host the moment it was created.
        """
        self._apply_json([
            {"add": {"table": {"family": TABLE_FAMILY, "name": TABLE_NAME}}},
            {"add": {"chain": {"family": TABLE_FAMILY, "table": TABLE_NAME,
                               "name": CHAIN_NAME, "type": "filter",
                               "hook": "output", "prio": 0, "policy": "accept"}}},
        ])

    # -- the Enforcer interface -------------------------------------------

    def supports(self, action_type: ActionType) -> bool:
        return action_type in (ActionType.TEMPORARY_EGRESS_RESTRICTION,
                               ActionType.RELEASE_RESTRICTION)

    def apply(self, request: ActionRequest, *,
              expires_at: datetime) -> EnforcementResult:
        uid = request.target.uid
        if uid is None:
            raise EnforcementError("this backend scopes by uid; the target "
                                   "does not carry one")
        comment = _build_comment(request.request_id, uid, expires_at)
        self.ensure_structure()

        coverage = coverage_for(request.destination_cidr)
        existing = self.find(request.request_id)
        if existing is not None:
            # Idempotent: a retry after an uncertain outcome must converge,
            # not stack a second identical rule.
            return EnforcementResult(
                existing.resource, EnforcementOutcome.APPLIED,
                f"rule already present; coverage={coverage.value}", _now())

        expressions: list[dict] = [
            {"match": {"op": "==", "left": {"meta": {"key": "skuid"}},
                       "right": uid}}]
        if request.destination_cidr:
            expressions.append(_destination_match(request.destination_cidr))
        expressions.append({"drop": None})

        try:
            self._apply_json([{"add": {"rule": {
                "family": TABLE_FAMILY, "table": TABLE_NAME, "chain": CHAIN_NAME,
                "comment": comment, "expr": expressions}}}])
        except EnforcementError:
            # The add may have partially landed. Ask the kernel rather than
            # assuming; an unverified failure that actually created a rule is
            # how state gets orphaned.
            if self.find(request.request_id) is not None:
                return EnforcementResult(
                    OwnedResource(self.backend_id, _identifier(request.request_id)),
                    EnforcementOutcome.UNCERTAIN,
                    "nft reported failure but a matching rule exists", _now())
            raise

        record = self.find(request.request_id)
        if record is None:
            return EnforcementResult(
                OwnedResource(self.backend_id, _identifier(request.request_id)),
                EnforcementOutcome.UNCERTAIN,
                "nft reported success but no rule is visible", _now())
        return EnforcementResult(
            record.resource, EnforcementOutcome.APPLIED,
            f"handle {record.handle}; coverage={coverage.value}", _now())

    def release(self, resource: OwnedResource) -> EnforcementResult:
        """Remove exactly one rule, identified by its own ownership comment.

        Never by position, never by handle carried from an earlier boot, and
        never when ownership does not parse.
        """
        action_id = _action_id_of(resource.identifier)
        record = self.find(action_id)
        if record is None:
            # Before concluding the rule is gone, check whether something
            # bearing this action id is present that we cannot prove we own
            # -- a comment from a future format version, or one another tool
            # wrote to look like ours. "Absent" would be the wrong answer:
            # the caller would mark the action released while OS state
            # remains, and reconciliation would never look again.
            impostor = self._unprovable_bearing(action_id)
            if impostor is not None:
                raise EnforcementError(
                    f"a rule at handle {impostor.handle} carries this action "
                    f"id but its ownership is {impostor.ownership.value}; "
                    "refusing to delete it")
            return EnforcementResult(resource, EnforcementOutcome.ALREADY_ABSENT,
                                     "no matching owned rule", _now())
        if record.ownership is not Ownership.OWNED:
            raise EnforcementError(
                f"refusing to delete a rule whose ownership is "
                f"{record.ownership.value}")
        self._apply_json([{"delete": {"rule": {
            "family": TABLE_FAMILY, "table": TABLE_NAME, "chain": CHAIN_NAME,
            "handle": record.handle}}}])
        if self.find(action_id) is not None:
            raise EnforcementError("the rule is still present after deletion")
        return EnforcementResult(resource, EnforcementOutcome.RELEASED,
                                 f"handle {record.handle} removed", _now())

    def reconcile(self) -> tuple[OwnedResource, ...]:
        """Only rules whose ownership is provable. Unknown ones are reported
        through :meth:`inspect_state`, not silently swept up."""
        return tuple(r.resource for r in self.rules()
                     if r.ownership is Ownership.OWNED)

    # -- inspection --------------------------------------------------------

    def rules(self) -> tuple[RuleRecord, ...]:
        records: list[RuleRecord] = []
        for item in self._list_table():
            rule = item.get("rule") if isinstance(item, dict) else None
            if not isinstance(rule, dict) or rule.get("chain") != CHAIN_NAME:
                continue
            handle = rule.get("handle")
            if not isinstance(handle, int):
                continue
            comment = rule.get("comment", "")
            action_id, uid, expires = _parse_comment(comment)
            ownership = Ownership.OWNED if action_id else Ownership.UNKNOWN
            records.append(RuleRecord(handle, ownership, action_id, uid,
                                      expires, comment if isinstance(comment, str) else ""))
        return tuple(records)

    def find(self, action_id: str) -> RuleRecord | None:
        for record in self.rules():
            if record.ownership is Ownership.OWNED and record.action_id == action_id:
                return record
        return None

    def _unprovable_bearing(self, action_id: str) -> RuleRecord | None:
        """A rule mentioning this action id that we cannot prove we own.

        Matched on the raw comment text, because by definition its structure
        did not parse. Reported, never deleted.
        """
        for record in self.rules():
            if record.ownership is not Ownership.OWNED and action_id in record.comment:
                return record
        return None

    def inspect_state(self) -> dict:
        """A description of host state an operator can act on.

        ``unknown`` being non-empty is a signal, not a cleanup task: something
        is in Annulon's table that Annulon cannot prove it created.
        """
        records = self.rules()
        return {
            "backend": self.backend_id,
            "table": f"{TABLE_FAMILY} {TABLE_NAME}",
            "owned": [r.action_id for r in records if r.ownership is Ownership.OWNED],
            "unknown": [r.handle for r in records if r.ownership is Ownership.UNKNOWN],
            "scoping": "meta skuid -- the uid owning the sending socket. "
                       "Precise for a dedicated service account; meaningless "
                       "for a uid shared by several workloads. Measured: an "
                       "unrelated process under the same uid is also "
                       "contained.",
            "measured_semantics": {
                "new_connections": "blocked",
                "established_connections": "blocked (measured: a connection "
                                           "opened by the target uid before "
                                           "the rule stopped working)",
                "forked_children": "blocked",
                "execed_binaries": "blocked",
                "uid_escape": "not possible without privilege (PermissionError)",
                "ipv6_under_an_ipv4_scoped_rule": "NOT restricted -- see KF-38",
            },
        }

    def foreign_tables(self) -> tuple[str, ...]:
        """Every table on the host that is not ours.

        Used by experiments to assert that containment changed nothing else.
        """
        raw = self._run(["-j", "list", "tables"])
        tables = []
        for item in json.loads(raw).get("nftables", []):
            table = item.get("table") if isinstance(item, dict) else None
            if not isinstance(table, dict):
                continue
            name = f"{table.get('family')} {table.get('name')}"
            if name != f"{TABLE_FAMILY} {TABLE_NAME}":
                tables.append(name)
        return tuple(sorted(tables))

    def remove_own_table(self) -> None:
        """Remove Annulon's table -- and only if nothing unknown is in it.

        For lab teardown. It refuses when an unprovable rule is present,
        because removing the table would take that rule with it.
        """
        unknown = [r for r in self.rules() if r.ownership is not Ownership.OWNED]
        if unknown:
            raise EnforcementError(
                f"refusing to remove the table: {len(unknown)} rule(s) of "
                "unproven ownership would go with it")
        self._apply_json([{"delete": {"table": {"family": TABLE_FAMILY,
                                                "name": TABLE_NAME}}}])


def _destination_match(cidr: str) -> dict:
    """A destination match built from a validated CIDR.

    ``ActionRequest`` has already parsed this with ``ipaddress``; it is
    re-parsed here so the backend does not depend on a caller's promise.
    """
    import ipaddress
    network = ipaddress.ip_network(cidr, strict=False)
    protocol = "ip" if network.version == 4 else "ip6"
    right: object
    if network.prefixlen == network.max_prefixlen:
        right = str(network.network_address)
    else:
        right = {"prefix": {"addr": str(network.network_address),
                            "len": network.prefixlen}}
    return {"match": {"op": "==",
                      "left": {"payload": {"protocol": protocol, "field": "daddr"}},
                      "right": right}}


def _now() -> datetime:
    return datetime.now(timezone.utc)
