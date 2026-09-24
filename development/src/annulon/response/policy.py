"""Broker-owned authorization policy.

This module is the reason the broker exists. It evaluates a request against
policy the requesting core cannot read, write or influence, and it starts
from deny.

Two structural choices carry most of the weight:

* **Every check runs, then the result is combined.** Short-circuiting on the
  first failure would make the audit record depend on check order, and an
  operator reading a denial wants all the reasons, not the first one.
* **Protected scopes are not expressible in a request.** A caller cannot ask
  for an exemption because there is no field for one. The protections are
  properties of the broker's own configuration.

The policy is deliberately small. It is easier to argue that fifteen explicit
checks are correct than that one flexible rule engine is safe.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from annulon.response.contract import (
    ActionRequest,
    ActionType,
    AuthorizationDecision,
    ContractError,
    DenyReason,
    MAX_TTL,
    Target,
    TargetKind,
)

__all__ = ["BrokerPolicy", "PolicyError", "ProtectedScopes", "DEFAULT_POLICY_VERSION"]

DEFAULT_POLICY_VERSION = "broker-policy/1"


class PolicyError(ValueError):
    """The policy itself is unusable. The broker denies everything rather
    than falling back to a permissive default."""


def _unmap_v4_in_v6(network: "ipaddress.IPv4Network | ipaddress.IPv6Network"):
    """The IPv4 form of a v4-mapped IPv6 network, or ``None``.

    Only a host-sized mapped address is unmapped: a wider v6 prefix that
    merely overlaps the mapped range is not equivalent to any single v4
    network, and pretending otherwise would be a guess.
    """
    if network.version != 6 or network.prefixlen != 128:
        return None
    mapped = getattr(network.network_address, "ipv4_mapped", None)
    if mapped is None:
        return None
    return ipaddress.ip_network(f"{mapped}/32", strict=False)


@dataclass(frozen=True)
class ProtectedScopes:
    """Things no response may ever touch, whatever the core proposes.

    Each entry exists because losing it would either disable the operator's
    ability to intervene or disable Annulon's own ability to recover -- the
    two situations in which a security tool becomes the incident.
    """

    #: UIDs that must never be contained: the broker's own identity, the
    #: core's (so it can still report), and system/management accounts.
    protected_uids: frozenset[int] = frozenset({0})
    protected_service_names: frozenset[str] = frozenset({
        "annulon-broker", "annulon-core", "sshd", "amazon-ssm-agent",
        "systemd", "snapd"})
    #: Destinations that must remain reachable. Containing these would cut
    #: the management path and leave the host unrecoverable except by
    #: rebuild -- the SSM endpoints and instance metadata in particular.
    protected_destinations: tuple[str, ...] = (
        "169.254.169.254/32",     # instance metadata
        "127.0.0.0/8",            # loopback: local IPC and health checks
        # IPv6 equivalents. Omitting these was a real gap: once IPv6
        # containment worked, a workload could be cut off from its v6
        # management path while the v4 one was protected (KF-55). A
        # protection that covers one address family is not a protection.
        "::1/128",                # v6 loopback
        "fd00:ec2::254/128",      # AWS instance metadata over IPv6
        "fe80::/10",              # link-local: neighbour discovery
    )

    def covers_uid(self, uid: int | None) -> bool:
        return uid is not None and uid in self.protected_uids

    def covers_service(self, name: str) -> bool:
        return bool(name) and name in self.protected_service_names

    def covers_destination(self, cidr: str | None) -> bool:
        """True when a requested destination overlaps protected space.

        ``None`` means unscoped egress, which necessarily includes the
        protected destinations, so it is treated as covering them.
        """
        if cidr is None:
            return True
        try:
            requested = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return True        # unparseable is treated as protected, not open
        # A v4-mapped v6 address is the same destination wearing a different
        # spelling. Comparing it only against the v6 list would let
        # `::ffff:127.0.0.1` slip past the loopback protection.
        unmapped = _unmap_v4_in_v6(requested)
        if unmapped is not None:
            requested = unmapped
        for protected in self.protected_destinations:
            network = ipaddress.ip_network(protected, strict=False)
            if requested.version == network.version and requested.overlaps(network):
                return True
        return False


@dataclass
class BrokerPolicy:
    """What the broker will permit. Loaded from a broker-owned file."""

    version: str = DEFAULT_POLICY_VERSION
    permitted_actions: frozenset[ActionType] = frozenset(
        {ActionType.TEMPORARY_EGRESS_RESTRICTION, ActionType.RELEASE_RESTRICTION})
    permitted_target_kinds: frozenset[TargetKind] = frozenset({TargetKind.SERVICE_UID})
    #: Only these UIDs may be contained at all. An allowlist rather than a
    #: denylist: a new service on the host is not containable until someone
    #: decides it should be.
    permitted_uids: frozenset[int] = frozenset()
    authorized_callers: frozenset[str] = frozenset({"annulon-core"})
    max_ttl: timedelta = timedelta(minutes=10)
    max_active_actions: int = 4
    max_requests_per_minute: int = 30
    #: How stale a request may be. Bounds the window in which a captured
    #: request could be replayed before the nonce cache even matters.
    max_request_age: timedelta = timedelta(seconds=30)
    max_clock_skew: timedelta = timedelta(seconds=5)
    require_destination_scope: bool = False
    protected: ProtectedScopes = field(default_factory=ProtectedScopes)

    # -- loading ---------------------------------------------------------

    @staticmethod
    def load(path: Path) -> "BrokerPolicy":
        """Load broker-owned policy. Any problem is fatal to permissiveness:
        an unreadable policy yields a broker that denies, never one that
        allows by default."""
        try:
            raw = json.loads(Path(path).read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise PolicyError(f"policy unreadable: {exc}") from exc
        if not isinstance(raw, dict):
            raise PolicyError("policy must be an object")
        try:
            actions = frozenset(ActionType(a) for a in raw.get(
                "permitted_actions", [t.value for t in ActionType]))
            kinds = frozenset(TargetKind(k) for k in raw.get(
                "permitted_target_kinds", [TargetKind.SERVICE_UID.value]))
            uids = frozenset(int(u) for u in raw.get("permitted_uids", []))
            protected_uids = frozenset(int(u) for u in raw.get(
                "protected_uids", [0]))
        except (ValueError, TypeError) as exc:
            raise PolicyError(f"policy contains an unknown value: {exc}") from exc

        ttl = timedelta(seconds=int(raw.get("max_ttl_seconds", 600)))
        if ttl > MAX_TTL:
            raise PolicyError(
                f"policy max_ttl {ttl} exceeds the contract ceiling {MAX_TTL}")
        overlap = uids & protected_uids
        if overlap:
            # A UID that is both permitted and protected is a contradiction,
            # and resolving it silently either way would be a guess.
            raise PolicyError(
                f"uid(s) {sorted(overlap)} are both permitted and protected")

        return BrokerPolicy(
            version=str(raw.get("version", DEFAULT_POLICY_VERSION)),
            permitted_actions=actions, permitted_target_kinds=kinds,
            permitted_uids=uids,
            authorized_callers=frozenset(
                str(c) for c in raw.get("authorized_callers", ["annulon-core"])),
            max_ttl=ttl,
            max_active_actions=int(raw.get("max_active_actions", 4)),
            max_requests_per_minute=int(raw.get("max_requests_per_minute", 30)),
            require_destination_scope=bool(raw.get("require_destination_scope", False)),
            protected=ProtectedScopes(
                protected_uids=protected_uids,
                protected_service_names=frozenset(
                    str(s) for s in raw.get("protected_service_names", [
                        "annulon-broker", "annulon-core", "sshd",
                        "amazon-ssm-agent", "systemd", "snapd"])),
                protected_destinations=tuple(
                    str(d) for d in raw.get("protected_destinations", [
                        "169.254.169.254/32", "127.0.0.0/8"]))))

    # -- evaluation ------------------------------------------------------

    def evaluate(self, request: ActionRequest, *, caller: str,
                 now: datetime, host_id: str, boot_id: str,
                 active_actions: int, recent_request_rate: int,
                 seen_request_ids: frozenset[str]) -> AuthorizationDecision:
        """Default deny. Every check runs; all failures are reported.

        The caller identity comes from the transport's peer credentials, not
        from the request body, which is why it is a separate argument.
        """
        reasons: list[DenyReason] = []

        if request.action_type not in self.permitted_actions:
            reasons.append(DenyReason.UNKNOWN_ACTION_TYPE)
        if request.target.kind not in self.permitted_target_kinds:
            reasons.append(DenyReason.UNKNOWN_TARGET_KIND)
        if caller not in self.authorized_callers:
            reasons.append(DenyReason.CALLER_NOT_AUTHORIZED)

        if request.request_id in seen_request_ids:
            reasons.append(DenyReason.REPLAYED_REQUEST)

        age = now - request.requested_at
        if age > self.max_request_age:
            reasons.append(DenyReason.REQUEST_EXPIRED)
        if age < -self.max_clock_skew:
            # A future-dated request is either a clock problem or an attempt
            # to extend the replay window. Neither is acceptable.
            reasons.append(DenyReason.REQUEST_FROM_THE_FUTURE)

        target = request.target
        if not target.same_boot(host_id, boot_id):
            reasons.append(DenyReason.TARGET_NOT_CURRENT)
        if self.protected.covers_uid(target.uid) or \
                self.protected.covers_service(target.service_name):
            reasons.append(DenyReason.TARGET_PROTECTED)
        elif target.uid is not None and target.uid not in self.permitted_uids:
            reasons.append(DenyReason.TARGET_NOT_PERMITTED)

        if request.duration > self.max_ttl:
            # Denied, never silently shortened. Quietly granting less than
            # was asked for makes the caller's record disagree with the
            # broker's about what is in force.
            reasons.append(DenyReason.DURATION_EXCEEDS_POLICY)

        if request.action_type is ActionType.TEMPORARY_EGRESS_RESTRICTION:
            if self.require_destination_scope and request.destination_cidr is None:
                reasons.append(DenyReason.SCOPE_TOO_BROAD)
            if request.destination_cidr is not None and \
                    self.protected.covers_destination(request.destination_cidr):
                reasons.append(DenyReason.DESTINATION_PROTECTED)
            if active_actions >= self.max_active_actions:
                reasons.append(DenyReason.TOO_MANY_ACTIVE_ACTIONS)

        if recent_request_rate > self.max_requests_per_minute:
            reasons.append(DenyReason.RATE_LIMIT_EXCEEDED)

        if reasons:
            return AuthorizationDecision.deny(
                request.request_id, tuple(dict.fromkeys(reasons)), self.version,
                now, f"{len(reasons)} policy check(s) failed")
        return AuthorizationDecision.allow(
            request, self.version, now, request.duration,
            "all policy checks passed")
