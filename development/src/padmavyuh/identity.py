"""Cross-domain entity references.

Deliberately one small abstraction rather than twenty identity classes. The
requirement (V2 §9) is that identity is never reduced to one unqualified
string, while strongly typed identities can arrive later without breaking
readers.

The ``namespace`` field is what makes that possible, and it is the field that
solves process identity. A PID is not unique -- PIDs are reused -- so a
process instance is referenced as::

    EntityRef(PROCESS_INSTANCE, namespace="host=h1;boot=b7", identifier="1234@88231")

The namespace qualifies the identifier by the scope in which it is unique.
V2-CORE-01 does not collect Linux processes; it only has to avoid making
correct process identity impossible later, and a bare ``pid=1234`` would
have done exactly that.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass

__all__ = ["EntityKind", "EntityRef", "MAX_NAMESPACE", "MAX_IDENTIFIER"]

MAX_NAMESPACE = 128
MAX_IDENTIFIER = 256
_SAFE = re.compile(r"^[\x20-\x7e]*$")      # printable ASCII; no control bytes


class EntityKind(enum.Enum):
    """Open by intent: unknown kinds decode to ``UNKNOWN`` rather than failing,
    so a newer sensor cannot break an older reader."""

    HOST = "host"
    BOOT_SESSION = "boot_session"
    WORKLOAD = "workload"
    PROCESS_INSTANCE = "process_instance"
    PRINCIPAL = "principal"
    CLOUD_RESOURCE = "cloud_resource"
    NETWORK_ENDPOINT = "network_endpoint"
    SDN_SWITCH = "sdn_switch"
    SDN_PORT = "sdn_port"
    SDN_ATTACHMENT = "sdn_attachment"
    AI_TASK = "ai_task"
    AI_MODEL = "ai_model"
    AI_TOOL = "ai_tool"
    UNKNOWN = "unknown"

    @classmethod
    def parse(cls, value: object) -> "EntityKind":
        try:
            return cls(value)
        except ValueError:
            return cls.UNKNOWN


class InvalidEntityRef(ValueError):
    """A reference that cannot safely be stored or compared."""


@dataclass(frozen=True, order=True)
class EntityRef:
    kind: EntityKind
    namespace: str
    identifier: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, EntityKind):
            raise InvalidEntityRef("kind must be an EntityKind")
        for name, limit in (("namespace", MAX_NAMESPACE),
                            ("identifier", MAX_IDENTIFIER)):
            value = getattr(self, name)
            if not isinstance(value, str):
                raise InvalidEntityRef(f"{name} must be a str")
            if len(value) > limit:
                raise InvalidEntityRef(f"{name} exceeds {limit} characters")
            if not _SAFE.match(value):
                raise InvalidEntityRef(
                    f"{name} contains control or non-ASCII bytes; identity "
                    "must be comparable and loggable without ambiguity")
        if not self.identifier:
            raise InvalidEntityRef("identifier must not be empty")

    @classmethod
    def of(cls, kind: EntityKind | str, identifier: str,
           namespace: str = "") -> "EntityRef":
        return cls(EntityKind.parse(kind) if isinstance(kind, str) else kind,
                   namespace, identifier)

    def to_dict(self) -> dict:
        return {"kind": self.kind.value, "namespace": self.namespace,
                "identifier": self.identifier}

    @staticmethod
    def from_dict(raw: object) -> "EntityRef":
        if not isinstance(raw, dict):
            raise InvalidEntityRef("entity reference must be an object")
        return EntityRef(EntityKind.parse(raw.get("kind")),
                         str(raw.get("namespace", "")),
                         str(raw.get("identifier", "")))

    def __str__(self) -> str:
        scope = f"[{self.namespace}]" if self.namespace else ""
        return f"{self.kind.value}{scope}:{self.identifier}"
