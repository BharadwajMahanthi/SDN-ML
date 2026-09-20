"""The core's side of the broker boundary.

This module runs in the unprivileged process. It can ask; it cannot decide,
and it cannot act. That asymmetry is why it is so small: there is nothing
here to compromise usefully.

The one behaviour worth arguing about is what happens when the broker is not
there. The answer is :data:`ResponseOutcome.ENFORCEMENT_UNAVAILABLE`, and the
core must surface that rather than routing around it. A fallback path -- the
core applying a rule itself when the broker is down -- would hand the core
exactly the privilege the whole design removes, and it would appear during an
incident, which is precisely when the broker is most likely to be missing and
when a compromised core is most likely to be asking.

So there is no fallback. Containment either happens through the broker or is
reported as not having happened.
"""

from __future__ import annotations

import enum
import secrets
import socket
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable

from annulon.response import ipc
from annulon.response.contract import (
    ActionRequest, ActionType, DenyReason, SCHEMA_VERSION, Target,
)

__all__ = ["BrokerClient", "ResponseOutcome", "ContainmentResult",
           "new_request_id"]


class ResponseOutcome(enum.Enum):
    """What the core learned about its request.

    ``ENFORCEMENT_UNAVAILABLE`` is deliberately distinct from ``DENIED``.
    "Policy refused this" and "nothing was asked" demand different operator
    responses, and collapsing them would let a broker outage read as a clean
    policy decision.
    """

    APPLIED = "applied"
    VERIFIED = "verified"
    DENIED = "denied"
    ENFORCEMENT_UNAVAILABLE = "enforcement_unavailable"
    FAILED = "failed"

    @property
    def contained(self) -> bool:
        """Whether the host is actually believed to be contained.

        Only ``VERIFIED`` counts. ``APPLIED`` means the broker installed
        something; independent measurement that traffic stopped is a
        different claim, and this property refuses to conflate them.
        """
        return self is ResponseOutcome.VERIFIED


@dataclass(frozen=True)
class ContainmentResult:
    outcome: ResponseOutcome
    request_id: str
    reasons: tuple[DenyReason, ...] = ()
    detail: str = ""
    expires_at: datetime | None = None

    @property
    def denied_because_unauthorized(self) -> bool:
        return DenyReason.CALLER_NOT_AUTHORIZED in self.reasons


def new_request_id() -> str:
    """A fresh, unguessable request id.

    Unguessable because a predictable id lets an attacker who can reach the
    socket pre-register a nonce and have a legitimate request rejected as a
    replay -- denial of containment by collision.
    """
    return "req-" + secrets.token_hex(12)


class BrokerClient:
    """A thin, stateless caller. One connection per request."""

    def __init__(self, socket_path: str, *, component: str = "annulon-core",
                 timeout: float = 5.0,
                 clock: Callable[[], datetime] | None = None) -> None:
        self._path = socket_path
        self._component = component
        self._timeout = timeout
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def request_egress_restriction(
            self, target: Target, *, duration: timedelta, reason: str,
            finding_id: str, destination_cidr: str | None = None,
            request_id: str | None = None) -> ContainmentResult:
        request = ActionRequest(
            request_id=request_id or new_request_id(),
            action_type=ActionType.TEMPORARY_EGRESS_RESTRICTION,
            target=target, duration=duration, reason=reason,
            finding_id=finding_id, requested_at=self._clock(),
            requesting_component=self._component,
            destination_cidr=destination_cidr)
        return self.send(request)

    def release(self, action_id: str, target: Target, *,
                reason: str = "released by the core") -> ContainmentResult:
        request = ActionRequest(
            request_id=new_request_id(),
            action_type=ActionType.RELEASE_RESTRICTION, target=target,
            duration=timedelta(seconds=1), reason=reason,
            finding_id=action_id, requested_at=self._clock(),
            requesting_component=self._component)
        return self.send(request)

    def send(self, request: ActionRequest) -> ContainmentResult:
        message = {"schema_version": SCHEMA_VERSION,
                   "type": "action_request", "request": request.to_dict()}
        try:
            connection = ipc.connect(self._path, timeout=self._timeout)
        except (OSError, ipc.IpcError) as exc:
            # The broker is not reachable. Reported, never worked around.
            return ContainmentResult(
                ResponseOutcome.ENFORCEMENT_UNAVAILABLE, request.request_id,
                detail=f"broker unreachable: {type(exc).__name__}")
        try:
            with connection:
                ipc.write_message(connection, message)
                body = ipc.read_message(connection)
        except (OSError, ipc.IpcError) as exc:
            return ContainmentResult(
                ResponseOutcome.ENFORCEMENT_UNAVAILABLE, request.request_id,
                detail=f"broker did not answer: {type(exc).__name__}")
        return _interpret(body, request.request_id)

    def status(self) -> dict | None:
        """Broker status, or ``None`` when it cannot be reached."""
        try:
            connection = ipc.connect(self._path, timeout=self._timeout)
            with connection:
                ipc.write_message(connection, {
                    "schema_version": SCHEMA_VERSION, "type": "status_request"})
                return ipc.read_message(connection)
        except (OSError, ipc.IpcError):
            return None


def _interpret(body: dict, request_id: str) -> ContainmentResult:
    """Turn a broker response into an outcome, trusting none of its shape.

    The broker is the trusted party here, but a malformed answer still must
    not be read as success: an unparseable response becomes
    ``ENFORCEMENT_UNAVAILABLE``, because the core does not know what happened.
    """
    if body.get("enforcement") == "unavailable":
        return ContainmentResult(ResponseOutcome.ENFORCEMENT_UNAVAILABLE,
                                 request_id, detail=str(body.get("detail", ""))[:256])
    decision = body.get("decision")
    if decision == "deny":
        reasons = tuple(
            r for r in (_deny_reason(v) for v in body.get("reasons", []) or [])
            if r is not None)
        return ContainmentResult(ResponseOutcome.DENIED, request_id, reasons,
                                 str(body.get("detail", ""))[:256])
    if decision != "allow":
        return ContainmentResult(ResponseOutcome.ENFORCEMENT_UNAVAILABLE,
                                 request_id, detail="unreadable broker response")
    state = body.get("state")
    outcome = {"applied": ResponseOutcome.APPLIED,
               "effect_verified": ResponseOutcome.VERIFIED,
               "released": ResponseOutcome.APPLIED,
               # "applied but not verified" is not containment.
               "effect_not_verified": ResponseOutcome.APPLIED,
               }.get(state, ResponseOutcome.FAILED)
    expires = body.get("expires_at")
    try:
        expires_at = datetime.fromisoformat(expires) if expires else None
    except (TypeError, ValueError):
        expires_at = None
    return ContainmentResult(outcome, request_id, (),
                             str(body.get("detail", ""))[:256], expires_at)


def _deny_reason(value: object) -> DenyReason | None:
    try:
        return DenyReason(value)
    except ValueError:
        return None
