"""Evidence: what was observed, what was inferred, and what is missing.

The distinction this module exists to keep alive:

    a kernel sensor reported a process execution
    a model produced the number 0.82

Both may end up supporting the same finding. They are not the same kind of
thing, and downstream policy must be able to tell them apart. So every piece
of evidence carries its *kind*, its *origin*, and its *ancestry*.

Three rules are enforced by the types rather than by convention:

* **A model score is not a probability.** ``model_score`` exists so a
  statistical result can be recorded honestly. It is explicitly not
  calibrated, and nothing in this module converts it into one.
* **Missing evidence is not negative evidence.** "No probe reply was seen"
  and "the host is gone" are different claims. The first is a
  :class:`MissingEvidence`; the second would be an inference some other rule
  must justify.
* **Different detector names are not different observations.** Three
  detectors reading one event share an origin group, and the graph records
  that, so corroboration cannot be manufactured by adding detectors.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from datetime import datetime

__all__ = [
    "SCHEMA_VERSION", "EvidenceKind", "Stance", "MissingReason",
    "Evidence", "MissingEvidence", "EvidenceError", "LineageError",
    "EvidenceGraph", "MAX_PARENTS", "MAX_SOURCE_EVENTS", "MAX_LINEAGE_DEPTH",
    "MAX_SUMMARY_CHARS",
]

SCHEMA_VERSION = 1
MAX_PARENTS = 16
MAX_SOURCE_EVENTS = 32
MAX_LINEAGE_DEPTH = 8
MAX_FANOUT = 64
MAX_SUMMARY_CHARS = 512
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{3,63}$")


class EvidenceKind(enum.Enum):
    """How this evidence came to exist.

    The ordering from top to bottom is roughly from "the system saw it" to
    "someone asserted it". It is deliberately not a numeric weight: turning
    it into one would reintroduce the scoring this model rejects.
    """

    DIRECT_OBSERVATION = "direct_observation"        # a sensor reported it
    DERIVED_FACT = "derived_fact"                    # computed from observations
    DETERMINISTIC_RULE_RESULT = "deterministic_rule_result"
    HEURISTIC_ASSESSMENT = "heuristic_assessment"
    STATISTICAL_MODEL_RESULT = "statistical_model_result"
    EXTERNAL_ASSERTION = "external_assertion"        # a feed, another product
    HUMAN_ASSERTION = "human_assertion"

    @property
    def is_observation(self) -> bool:
        return self is EvidenceKind.DIRECT_OBSERVATION

    @property
    def is_inference(self) -> bool:
        return self in (EvidenceKind.DERIVED_FACT,
                        EvidenceKind.DETERMINISTIC_RULE_RESULT,
                        EvidenceKind.HEURISTIC_ASSESSMENT,
                        EvidenceKind.STATISTICAL_MODEL_RESULT)


class Stance(enum.Enum):
    """What this evidence does to a finding."""

    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    CONTEXT = "context"          # relevant, but neither for nor against


class MissingReason(enum.Enum):
    """Why an expected piece of evidence is not here.

    Every value describes a *collection* failure or gap. None of them means
    "the thing did not happen" -- that inference is not available from
    absence alone.
    """

    SENSOR_UNAVAILABLE = "sensor_unavailable"
    CAPABILITY_UNSUPPORTED = "capability_unsupported"
    NOT_CONFIGURED = "not_configured"
    SEQUENCE_GAP = "sequence_gap"
    QUEUE_OVERFLOW = "queue_overflow"
    NOT_YET_ARRIVED = "not_yet_arrived"
    RETENTION_EXPIRED = "retention_expired"


class EvidenceError(ValueError):
    """Evidence that cannot be stored or reasoned about safely."""


class LineageError(EvidenceError):
    """The ancestry graph is unsafe: a cycle, unknown parent or excess depth."""


def _check_id(value: object, name: str) -> str:
    if not isinstance(value, str) or not _ID.match(value):
        raise EvidenceError(f"malformed {name}: {value!r}")
    return value


@dataclass(frozen=True)
class Evidence:
    """One interpretation of, or reference to, one or more observations.

    ``attributes`` carries bounded metadata only. Raw material -- a command
    line, a file, a prompt, a packet -- is referenced through
    ``artifact_ref`` and never copied here, so one sensitive observation
    cannot become ten sensitive findings.
    """

    evidence_id: str
    kind: EvidenceKind
    stance: Stance
    origin_group: str
    summary: str
    observed_at: datetime | None
    produced_at: datetime
    source_event_ids: tuple[str, ...] = ()
    parent_evidence_ids: tuple[str, ...] = ()
    attributes: dict = field(default_factory=dict)
    artifact_ref: str | None = None
    #: A raw model output. NOT a probability, and nothing here converts it
    #: into one. See ADR-035.
    model_score: float | None = None
    model_id: str | None = None
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _check_id(self.evidence_id, "evidence_id")
        if not isinstance(self.kind, EvidenceKind):
            raise EvidenceError("kind must be an EvidenceKind")
        if not isinstance(self.stance, Stance):
            raise EvidenceError("stance must be a Stance")
        if not self.origin_group or not isinstance(self.origin_group, str):
            raise EvidenceError(
                "origin_group is required: evidence without a stated "
                "collection origin cannot be checked for corroboration")
        if not isinstance(self.summary, str) or not self.summary:
            raise EvidenceError("summary required")
        if len(self.summary) > MAX_SUMMARY_CHARS:
            raise EvidenceError(f"summary exceeds {MAX_SUMMARY_CHARS} characters")
        if len(self.source_event_ids) > MAX_SOURCE_EVENTS:
            raise EvidenceError(f"more than {MAX_SOURCE_EVENTS} source events")
        if len(self.parent_evidence_ids) > MAX_PARENTS:
            raise EvidenceError(f"more than {MAX_PARENTS} parents")
        if len(set(self.parent_evidence_ids)) != len(self.parent_evidence_ids):
            raise EvidenceError("duplicate parent evidence id")
        if self.evidence_id in self.parent_evidence_ids:
            raise LineageError(f"{self.evidence_id} is its own parent")
        for parent in self.parent_evidence_ids:
            _check_id(parent, "parent_evidence_id")
        if self.model_score is not None:
            if self.kind is not EvidenceKind.STATISTICAL_MODEL_RESULT:
                raise EvidenceError(
                    "model_score is only meaningful on a "
                    "STATISTICAL_MODEL_RESULT")
            if not isinstance(self.model_score, (int, float)) or isinstance(
                    self.model_score, bool):
                raise EvidenceError("model_score must be a number")
            if self.model_id is None:
                raise EvidenceError(
                    "a model score without a model identity cannot be "
                    "interpreted or reproduced")
        if self.observed_at is not None and self.observed_at.tzinfo is None:
            raise EvidenceError("observed_at must be timezone-aware")
        if self.produced_at.tzinfo is None:
            raise EvidenceError("produced_at must be timezone-aware")

    @property
    def is_derived(self) -> bool:
        return bool(self.parent_evidence_ids)

    def to_dict(self) -> dict:
        payload = {
            "schema_version": self.schema_version,
            "evidence_id": self.evidence_id,
            "kind": self.kind.value,
            "stance": self.stance.value,
            "origin_group": self.origin_group,
            "summary": self.summary,
            "observed_at": self.observed_at.isoformat() if self.observed_at else None,
            "produced_at": self.produced_at.isoformat(),
            "source_event_ids": list(self.source_event_ids),
            "parent_evidence_ids": list(self.parent_evidence_ids),
            "attributes": dict(self.attributes),
            "artifact_ref": self.artifact_ref,
        }
        if self.model_score is not None:
            # Named so no consumer can mistake it for a calibrated number.
            payload["model_score_uncalibrated"] = self.model_score
            payload["model_id"] = self.model_id
        return payload


@dataclass(frozen=True)
class MissingEvidence:
    """Something the detector expected and did not get.

    Deliberately a separate type from :class:`Evidence`. If absence were
    modelled as evidence with a stance, it would eventually be counted, and
    "we did not see it" would quietly become "it did not happen".
    """

    expected: str
    reason: MissingReason
    origin_group: str
    detail: str = ""

    def __post_init__(self) -> None:
        if not self.expected:
            raise EvidenceError("expected description required")
        if not isinstance(self.reason, MissingReason):
            raise EvidenceError("reason must be a MissingReason")
        if len(self.expected) > MAX_SUMMARY_CHARS:
            raise EvidenceError("expected description too long")

    @property
    def is_collection_fault(self) -> bool:
        """True when the gap is a sensor problem rather than a configuration
        choice. A fault means the picture is incomplete through failure."""
        return self.reason in (MissingReason.SENSOR_UNAVAILABLE,
                               MissingReason.SEQUENCE_GAP,
                               MissingReason.QUEUE_OVERFLOW,
                               MissingReason.RETENTION_EXPIRED)

    def to_dict(self) -> dict:
        return {"expected": self.expected, "reason": self.reason.value,
                "origin_group": self.origin_group, "detail": self.detail}


class EvidenceGraph:
    """A bounded, cycle-safe store of evidence and its ancestry.

    Traversal limits are not tidiness. Evidence may be derived from
    attacker-influenced input, so an unbounded walk over an
    attacker-shaped graph is a denial-of-service primitive.
    """

    def __init__(self, *, max_depth: int = MAX_LINEAGE_DEPTH,
                 max_nodes: int = 512) -> None:
        self.max_depth = max_depth
        self.max_nodes = max_nodes
        self._items: dict[str, Evidence] = {}

    def add(self, evidence: Evidence) -> Evidence:
        if evidence.evidence_id in self._items:
            raise EvidenceError(f"duplicate evidence_id {evidence.evidence_id}")
        if len(self._items) >= self.max_nodes:
            raise EvidenceError(f"graph holds {len(self._items)} nodes (limit "
                                f"{self.max_nodes})")
        for parent in evidence.parent_evidence_ids:
            if parent not in self._items:
                raise LineageError(
                    f"{evidence.evidence_id} names unknown parent {parent}; "
                    "ancestry must be resolvable to be checkable")
        self._items[evidence.evidence_id] = evidence
        # Adding only ever references existing nodes, so a cycle is
        # impossible by construction -- but verify, because the property is
        # what the traversal bounds depend on.
        self._assert_acyclic(evidence.evidence_id)
        return evidence

    def get(self, evidence_id: str) -> Evidence | None:
        return self._items.get(evidence_id)

    def _assert_acyclic(self, start: str) -> None:
        """Depth-first with an explicit *path*, not a global visited set.

        KF-27: using one visited set treats a diamond as a cycle. Two
        derivations that share an ancestor -- E4 from E2 and E3, both from
        E1 -- is the ordinary shape of correlated evidence, and rejecting it
        would break the very case this model exists to represent. Only a node
        repeating on the current path is a cycle.
        """
        path: list[str] = []
        on_path: set[str] = set()
        settled: set[str] = set()
        stack: list[tuple[str, bool]] = [(start, False)]
        while stack:
            node, leaving = stack.pop()
            if leaving:
                on_path.discard(node)
                path.pop()
                settled.add(node)
                continue
            if node in on_path:
                raise LineageError(f"cycle in ancestry at {node}")
            if node in settled:
                continue
            if len(path) > self.max_depth:
                raise LineageError(
                    f"ancestry deeper than {self.max_depth} from {start}")
            on_path.add(node)
            path.append(node)
            stack.append((node, True))
            item = self._items.get(node)
            if item is None:
                continue
            for parent in item.parent_evidence_ids:
                stack.append((parent, False))

    def ancestry(self, evidence_id: str) -> tuple[str, ...]:
        """All ancestors, bounded. Used to decide whether two pieces of
        evidence actually rest on the same observation."""
        found: list[str] = []
        seen: set[str] = {evidence_id}
        frontier = [(evidence_id, 0)]
        while frontier:
            node, depth = frontier.pop()
            if depth >= self.max_depth:
                continue
            item = self._items.get(node)
            if item is None:
                continue
            for parent in item.parent_evidence_ids:
                if parent in seen:
                    continue
                seen.add(parent)
                found.append(parent)
                frontier.append((parent, depth + 1))
        return tuple(sorted(found))

    def root_event_ids(self, evidence_id: str) -> frozenset[str]:
        """Every source event this evidence ultimately rests on.

        This is the function that prevents manufactured corroboration: two
        findings whose evidence shares a root event are not two
        observations, however many detectors sit in between.
        """
        ids: set[str] = set()
        for node in (evidence_id, *self.ancestry(evidence_id)):
            item = self._items.get(node)
            if item is not None:
                ids.update(item.source_event_ids)
        return frozenset(ids)

    def __len__(self) -> int:
        return len(self._items)

    def __contains__(self, evidence_id: object) -> bool:
        return evidence_id in self._items
