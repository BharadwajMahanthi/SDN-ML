"""Capability manifest: what is supported, what is configured, what is healthy.

The rule this module exists to enforce (V2 §6, §13): **SUPPORTED does not mean
ACTIVE AND HEALTHY**, and a missing sensor must never be reported as full
protection. Collapsing the three questions into one boolean is how a product
comes to claim coverage it does not have.

    support        can this build, on this platform, do it at all?
    configuration  has the operator turned it on and supplied what it needs?
    health         is it working right now?

A feature is only ``effective`` when all three line up. Anything else
downgrades the agent's overall state, and the reason is always reportable.
"""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass, field

__all__ = [
    "SCHEMA_VERSION", "PlatformProfile", "Support", "Configuration", "Health",
    "AgentState", "Capability", "CapabilityManifest",
]

SCHEMA_VERSION = 1


class PlatformProfile(enum.Enum):
    LINUX_HOST = "linux_host"
    SDN_CONTROLLER = "sdn_controller"
    UNKNOWN = "unknown"

    @classmethod
    def parse(cls, value: object) -> "PlatformProfile":
        try:
            return cls(value)
        except ValueError:
            return cls.UNKNOWN


class Support(enum.Enum):
    SUPPORTED = "supported"
    UNSUPPORTED_ON_PROFILE = "unsupported_on_profile"
    NOT_IMPLEMENTED = "not_implemented"


class Configuration(enum.Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    NOT_CONFIGURED = "not_configured"


class Health(enum.Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


class AgentState(enum.Enum):
    """Overall runtime state. Each value has a defined cause, so none of them
    is a label applied by judgement."""

    HEALTHY = "healthy"
    DEGRADED_COLLECTION = "degraded_collection"
    DEGRADED_EXPORT = "degraded_export"
    POLICY_EXPIRED = "policy_expired"
    ENFORCEMENT_UNAVAILABLE = "enforcement_unavailable"
    EVIDENCE_INCOMPLETE = "evidence_incomplete"


@dataclass(frozen=True)
class Capability:
    name: str
    support: Support
    configuration: Configuration = Configuration.NOT_CONFIGURED
    health: Health = Health.NOT_APPLICABLE
    detail: str = ""

    def __post_init__(self) -> None:
        if not self.name or not isinstance(self.name, str):
            raise ValueError("capability name required")
        if self.support is not Support.SUPPORTED:
            # An unsupported feature cannot be healthy; saying otherwise is
            # precisely the overclaim this model exists to prevent.
            if self.health not in (Health.NOT_APPLICABLE, Health.UNKNOWN):
                raise ValueError(
                    f"{self.name}: health {self.health.value} is meaningless "
                    f"when support is {self.support.value}")
        if self.configuration is not Configuration.ENABLED:
            if self.health is Health.HEALTHY:
                raise ValueError(
                    f"{self.name}: cannot be HEALTHY while configuration is "
                    f"{self.configuration.value}")

    @property
    def effective(self) -> bool:
        """The only combination that entitles the product to claim the
        capability is actually protecting anything."""
        return (self.support is Support.SUPPORTED
                and self.configuration is Configuration.ENABLED
                and self.health is Health.HEALTHY)

    @property
    def contributes_degradation(self) -> bool:
        """Configured but not working. Not configured is a choice; configured
        and broken is a degradation."""
        return (self.support is Support.SUPPORTED
                and self.configuration is Configuration.ENABLED
                and self.health in (Health.DEGRADED, Health.FAILED, Health.UNKNOWN))

    def to_dict(self) -> dict:
        return {"name": self.name, "support": self.support.value,
                "configuration": self.configuration.value,
                "health": self.health.value, "detail": self.detail,
                "effective": self.effective}

    @staticmethod
    def from_dict(raw: dict) -> "Capability":
        def parse(enum_cls, value, fallback):
            try:
                return enum_cls(value)
            except ValueError:
                return fallback
        return Capability(
            name=str(raw.get("name", "")),
            support=parse(Support, raw.get("support"), Support.NOT_IMPLEMENTED),
            configuration=parse(Configuration, raw.get("configuration"),
                                Configuration.NOT_CONFIGURED),
            health=parse(Health, raw.get("health"), Health.UNKNOWN),
            detail=str(raw.get("detail", "")))


@dataclass
class CapabilityManifest:
    profile: PlatformProfile
    agent_version: str
    capabilities: dict[str, Capability] = field(default_factory=dict)
    schema_version: int = SCHEMA_VERSION

    def declare(self, capability: Capability) -> None:
        self.capabilities[capability.name] = capability

    def update_health(self, name: str, health: Health, detail: str = "") -> Capability:
        current = self.capabilities[name]
        updated = Capability(current.name, current.support, current.configuration,
                             health, detail or current.detail)
        self.capabilities[name] = updated
        return updated

    # -- questions the product must answer honestly ----------------------

    def effective(self) -> list[str]:
        return sorted(n for n, c in self.capabilities.items() if c.effective)

    def degraded(self) -> list[str]:
        return sorted(n for n, c in self.capabilities.items()
                      if c.contributes_degradation)

    def state(self) -> AgentState:
        """Derived from evidence, never asserted.

        Only collection degradation is derivable today, because collection is
        the only thing this build observes. Export, policy expiry and
        enforcement availability have no inputs yet and are therefore not
        fabricated -- their absence is the honest answer.
        """
        return (AgentState.DEGRADED_COLLECTION if self.degraded()
                else AgentState.HEALTHY)

    def covers(self, name: str) -> bool:
        capability = self.capabilities.get(name)
        return bool(capability and capability.effective)

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "profile": self.profile.value,
            "agent_version": self.agent_version,
            "state": self.state().value,
            "capabilities": [c.to_dict() for _, c in sorted(self.capabilities.items())],
            "effective": self.effective(),
            "degraded": self.degraded(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    @staticmethod
    def from_dict(raw: object) -> "CapabilityManifest":
        if not isinstance(raw, dict):
            raise ValueError("manifest must be an object")
        manifest = CapabilityManifest(
            PlatformProfile.parse(raw.get("profile")),
            str(raw.get("agent_version", "")))
        for entry in raw.get("capabilities") or []:
            if isinstance(entry, dict):
                try:
                    manifest.declare(Capability.from_dict(entry))
                except ValueError:
                    # An inconsistent entry from a newer or faulty producer is
                    # recorded as unknown-health rather than dropped, so it
                    # cannot silently improve the reported posture.
                    manifest.declare(Capability(
                        str(entry.get("name", "unnamed")),
                        Support.NOT_IMPLEMENTED, Configuration.NOT_CONFIGURED,
                        Health.UNKNOWN, "inconsistent capability entry"))
        return manifest
