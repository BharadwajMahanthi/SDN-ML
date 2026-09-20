"""The boundary between deciding an action and performing it.

The broker authorizes; an enforcement backend performs. Keeping them apart
matters because the authorization logic is where the safety argument lives
and the backend is where the privilege lives, and they should be reviewable
separately.

A backend is given an already-authorized grant and returns the resource it
created. It is never given a command, a rule body, or anything else the core
composed: the backend builds its own arguments from typed fields, so a
malicious value in a request can at worst be a bad *argument*, never a new
command.

The real backend lands in V2-SAFE-03. What exists here is the interface, the
outcome vocabulary, and a recording backend used only by tests. There is no
default backend on purpose: a broker constructed without one refuses to
enforce rather than silently doing nothing while reporting success.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

from annulon.response.contract import ActionRequest, ActionType, Target
from annulon.response.journal import OwnedResource

__all__ = ["EnforcementOutcome", "EnforcementResult", "Enforcer",
           "EnforcementError", "UnavailableEnforcer", "RecordingEnforcer"]


class EnforcementError(Exception):
    """The backend could not carry out an authorized action."""


class EnforcementOutcome(enum.Enum):
    """What actually happened at the OS.

    ``APPLIED`` and ``VERIFIED`` are distinct: installing a rule and
    observing that traffic stopped are different claims, and only the second
    is evidence. ``UNCERTAIN`` exists because "we do not know whether OS
    state was created" is a real outcome and must not be rounded to either
    success or failure -- it is the state that requires reconciliation.
    """

    APPLIED = "applied"
    VERIFIED = "verified"
    FAILED = "failed"
    UNCERTAIN = "uncertain"
    ALREADY_ABSENT = "already_absent"
    RELEASED = "released"


@dataclass(frozen=True)
class EnforcementResult:
    resource: OwnedResource | None
    outcome: EnforcementOutcome
    detail: str = ""
    observed_at: datetime | None = None

    @property
    def may_hold_os_state(self) -> bool:
        """Whether the host may now carry state this backend must clean up."""
        return self.outcome in (EnforcementOutcome.APPLIED,
                                EnforcementOutcome.VERIFIED,
                                EnforcementOutcome.UNCERTAIN)


@runtime_checkable
class Enforcer(Protocol):
    """A backend that can create and remove one narrow kind of OS state."""

    #: Stable name recorded in the journal, e.g. the packet-filter backend.
    backend_id: str

    def supports(self, action_type: ActionType) -> bool:
        """Whether this backend implements the action at all."""

    def apply(self, request: ActionRequest, *, expires_at: datetime) -> EnforcementResult:
        """Create the OS state for an authorized action.

        Receives the typed request, never a rendered command. Must be safe to
        call twice for the same request: a retry after an uncertain outcome
        has to converge, not accumulate rules.
        """

    def release(self, resource: OwnedResource) -> EnforcementResult:
        """Remove exactly the resource named, and nothing adjacent to it."""

    def reconcile(self) -> tuple[OwnedResource, ...]:
        """Report the resources this backend currently owns on the host.

        Compared against the journal at startup: anything owned but not
        journalled is an orphan to remove, and anything journalled but absent
        is a record to close.
        """


class UnavailableEnforcer:
    """The backend used when none is configured. Refuses everything.

    This is the default because the alternative -- a broker that authorizes
    an action and quietly performs nothing while reporting success -- is the
    worst possible failure. An operator would believe a host was contained
    when it was not.
    """

    backend_id = "unavailable"

    def supports(self, action_type: ActionType) -> bool:
        return False

    def apply(self, request: ActionRequest, *, expires_at: datetime) -> EnforcementResult:
        raise EnforcementError(
            "no enforcement backend is configured; the broker will not report "
            "an action as applied when nothing was applied")

    def release(self, resource: OwnedResource) -> EnforcementResult:
        raise EnforcementError("no enforcement backend is configured")

    def reconcile(self) -> tuple[OwnedResource, ...]:
        return ()


class RecordingEnforcer:
    """A test double that maintains real state transitions in memory.

    Not a mock in the "assert it was called" sense: it tracks which resources
    exist, refuses to release one it never created, and converges on retry --
    so tests can exercise reconciliation, double-apply and orphan removal
    deterministically. The real backend must satisfy the same contract suite.

    It is never reachable from a production entry point, and no capability is
    ever claimed on the strength of it.
    """

    backend_id = "recording"

    def __init__(self, *, fail_on: frozenset[str] = frozenset(),
                 uncertain_on: frozenset[str] = frozenset()) -> None:
        self._resources: dict[str, OwnedResource] = {}
        self._fail_on = fail_on
        self._uncertain_on = uncertain_on
        self.applied: list[str] = []
        self.released: list[str] = []

    def supports(self, action_type: ActionType) -> bool:
        return action_type in (ActionType.TEMPORARY_EGRESS_RESTRICTION,
                               ActionType.RELEASE_RESTRICTION)

    def _identifier(self, target: Target, request_id: str) -> str:
        return f"{self.backend_id}/{target.kind.value}/{target.identifier}/{request_id}"

    def apply(self, request: ActionRequest, *, expires_at: datetime) -> EnforcementResult:
        self.applied.append(request.request_id)
        if request.request_id in self._fail_on:
            return EnforcementResult(None, EnforcementOutcome.FAILED,
                                     "injected failure")
        identifier = self._identifier(request.target, request.request_id)
        resource = OwnedResource(self.backend_id, identifier, request.requested_at)
        if request.request_id in self._uncertain_on:
            # State may or may not exist. Recorded as owned, because
            # forgetting a resource that might exist is the unsafe direction.
            self._resources[identifier] = resource
            return EnforcementResult(resource, EnforcementOutcome.UNCERTAIN,
                                     "injected uncertainty")
        self._resources[identifier] = resource      # idempotent by identifier
        return EnforcementResult(resource, EnforcementOutcome.APPLIED, "recorded")

    def release(self, resource: OwnedResource) -> EnforcementResult:
        self.released.append(resource.identifier)
        if resource.identifier not in self._resources:
            return EnforcementResult(resource, EnforcementOutcome.ALREADY_ABSENT,
                                     "nothing to remove")
        del self._resources[resource.identifier]
        return EnforcementResult(resource, EnforcementOutcome.RELEASED, "removed")

    def reconcile(self) -> tuple[OwnedResource, ...]:
        return tuple(self._resources.values())

    def plant_orphan(self, identifier: str) -> OwnedResource:
        """Create owned state with no journal record, for reconciliation tests."""
        resource = OwnedResource(self.backend_id, identifier)
        self._resources[identifier] = resource
        return resource
