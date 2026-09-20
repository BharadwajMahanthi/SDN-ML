"""Findings and assessments: a security hypothesis and what we make of it.

An event is a fact within the limits of its sensor. A finding is an
interpretation, and this module keeps the two apart.

Two questions are answered separately and never by the same field:

    severity     if this were true, how bad could it be?
    confidence   how strongly does the available evidence support it?

A critical-severity finding may rest on weak evidence, and a strong-evidence
finding may be trivial. Collapsing them into one number destroys exactly the
distinction an operator needs, and produces the unearned precision this
project already rejected once -- the legacy detector's hardcoded ``0.93``.

Assessments are append-only. New evidence produces a *new* assessment that
supersedes the last; the previous conclusion is retained, because forensic
value lies in what we believed at the time and why it changed.
"""

from __future__ import annotations

import enum
import json
import re
from dataclasses import dataclass, field, replace
from datetime import datetime

from annulon.evidence import (
    Evidence,
    EvidenceGraph,
    EvidenceKind,
    MissingEvidence,
    Stance,
)

__all__ = [
    "SCHEMA_VERSION", "Severity", "Confidence", "ConfidenceBasis",
    "AssessmentOutcome", "FindingState", "CollectionHealth", "ResponseClass",
    "Assessment", "Finding", "FindingError", "summarize_evidence",
    "EvidenceSummary", "MAX_EVIDENCE_PER_FINDING", "MAX_ASSESSMENTS",
]

SCHEMA_VERSION = 1
MAX_EVIDENCE_PER_FINDING = 64
MAX_MISSING_PER_FINDING = 32
MAX_ASSESSMENTS = 32
MAX_RATIONALE_CHARS = 4096
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{3,63}$")


class Severity(enum.Enum):
    """Potential impact *if the finding is true*. Nothing about certainty."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __lt__(self, other: "Severity") -> bool:
        return self.value < other.value


class Confidence(enum.Enum):
    """Evidential strength. Ordinal on purpose: a number here would invite
    arithmetic that the underlying evidence cannot justify."""

    UNASSESSED = 0
    WEAK = 1
    MODERATE = 2
    STRONG = 3

    def __lt__(self, other: "Confidence") -> bool:
        return self.value < other.value


class ConfidenceBasis(enum.Enum):
    """*Why* the confidence is what it is. Always recorded alongside it, so a
    reader can tell a kernel observation from a model's opinion."""

    NONE = "none"
    DIRECT_OBSERVATION = "direct_observation"
    DETERMINISTIC_INVARIANT = "deterministic_invariant"
    MULTI_ORIGIN_CORROBORATION = "multi_origin_corroboration"
    HEURISTIC = "heuristic"
    STATISTICAL_MODEL = "statistical_model"
    HUMAN_REVIEW = "human_review"
    EXTERNAL_INTELLIGENCE = "external_intelligence"


class AssessmentOutcome(enum.Enum):
    """Insufficient information is a legitimate answer, not a failure to
    decide. Nothing is forced into attack-or-benign."""

    SUPPORTED = "supported"
    NOT_SUPPORTED = "not_supported"
    INCONCLUSIVE = "inconclusive"
    CONTRADICTED = "contradicted"


class FindingState(enum.Enum):
    """Lifecycle, distinct from the evidentiary conclusion.

    RESOLVED means the case is closed, never that an attack was proven.
    """

    OPEN = "open"
    CORROBORATED = "corroborated"
    DISPUTED = "disputed"
    INCONCLUSIVE = "inconclusive"
    RESOLVED = "resolved"
    RETRACTED = "retracted"


class CollectionHealth(enum.Enum):
    """The collection context an assessment was made in."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


class ResponseClass(enum.Enum):
    """What *kind* of response this finding could justify. Metadata only:
    authorisation and execution belong to V2-SAFETY, not here."""

    OBSERVE_ONLY = "observe_only"
    INVESTIGATE = "investigate"
    INCREASE_TELEMETRY = "increase_telemetry"
    TEMPORARY_CONTAINMENT = "temporary_containment"


class FindingError(ValueError):
    """A finding that cannot be stored or reasoned about safely."""


@dataclass(frozen=True)
class EvidenceSummary:
    """A structural description of a finding's evidence. Deliberately counts
    and groups only -- there is no fused score here, because a formula over
    poorly defined evidence is worse than an explicit rule."""

    supporting: int
    contradicting: int
    context: int
    missing: int
    missing_from_fault: int
    origin_groups: tuple[str, ...]
    shared_root_events: bool
    statistical_only: bool

    @property
    def distinct_origins(self) -> int:
        """Distinct *collection origins*, which is not a claim of statistical
        independence -- only that the material came from different places."""
        return len(self.origin_groups)

    def to_dict(self) -> dict:
        return {
            "supporting": self.supporting, "contradicting": self.contradicting,
            "context": self.context, "missing": self.missing,
            "missing_from_fault": self.missing_from_fault,
            "origin_groups": list(self.origin_groups),
            "distinct_origins": self.distinct_origins,
            "shared_root_events": self.shared_root_events,
            "statistical_only": self.statistical_only,
        }


def summarize_evidence(evidence: tuple[Evidence, ...],
                       missing: tuple[MissingEvidence, ...],
                       graph: EvidenceGraph | None = None) -> EvidenceSummary:
    """Describe the shape of a finding's evidence. No fusion, no probability.

    ``shared_root_events`` is the important output: when every supporting
    item traces back to the same source event, several detectors agreeing is
    one observation seen several ways, not corroboration.
    """
    supporting = [e for e in evidence if e.stance is Stance.SUPPORTS]
    contradicting = [e for e in evidence if e.stance is Stance.CONTRADICTS]
    context = [e for e in evidence if e.stance is Stance.CONTEXT]
    origins = tuple(sorted({e.origin_group for e in supporting}))

    shared_roots = False
    if graph is not None and len(supporting) > 1:
        root_sets = [graph.root_event_ids(e.evidence_id) for e in supporting]
        root_sets = [r for r in root_sets if r]
        if len(root_sets) > 1:
            common = set.intersection(*(set(r) for r in root_sets))
            shared_roots = bool(common)

    statistical_only = bool(supporting) and all(
        e.kind is EvidenceKind.STATISTICAL_MODEL_RESULT for e in supporting)

    return EvidenceSummary(
        supporting=len(supporting), contradicting=len(contradicting),
        context=len(context), missing=len(missing),
        missing_from_fault=sum(1 for m in missing if m.is_collection_fault),
        origin_groups=origins, shared_root_events=shared_roots,
        statistical_only=statistical_only)


@dataclass(frozen=True)
class Assessment:
    """One evaluation of a finding at a point in time. Immutable."""

    assessment_id: str
    outcome: AssessmentOutcome
    severity: Severity
    confidence: Confidence
    basis: ConfidenceBasis
    collection_health: CollectionHealth
    rationale: str
    assessed_at: datetime
    summary: EvidenceSummary
    supersedes: str | None = None
    allowed_responses: tuple[ResponseClass, ...] = (ResponseClass.OBSERVE_ONLY,)
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not _ID.match(self.assessment_id):
            raise FindingError(f"malformed assessment_id {self.assessment_id!r}")
        for name, cls in (("outcome", AssessmentOutcome), ("severity", Severity),
                          ("confidence", Confidence), ("basis", ConfidenceBasis),
                          ("collection_health", CollectionHealth)):
            if not isinstance(getattr(self, name), cls):
                raise FindingError(f"{name} must be a {cls.__name__}")
        if not self.rationale:
            raise FindingError("rationale required: an assessment without a "
                               "stated reason cannot be reviewed")
        if len(self.rationale) > MAX_RATIONALE_CHARS:
            raise FindingError("rationale exceeds its bound")
        if self.assessed_at.tzinfo is None:
            raise FindingError("assessed_at must be timezone-aware")
        if self.confidence is Confidence.UNASSESSED and \
                self.basis is not ConfidenceBasis.NONE:
            raise FindingError("an unassessed confidence has no basis")
        if self.confidence is not Confidence.UNASSESSED and \
                self.basis is ConfidenceBasis.NONE:
            raise FindingError("confidence without a stated basis is not "
                               "reviewable")

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "assessment_id": self.assessment_id,
            "outcome": self.outcome.value,
            "severity": self.severity.name,
            "confidence": self.confidence.name,
            "confidence_basis": self.basis.value,
            "collection_health": self.collection_health.value,
            "rationale": self.rationale,
            "assessed_at": self.assessed_at.isoformat(),
            "evidence_summary": self.summary.to_dict(),
            "supersedes": self.supersedes,
            "allowed_responses": [r.value for r in self.allowed_responses],
        }


@dataclass
class Finding:
    """A security hypothesis, its evidence, and the history of what we made
    of it. Evidence is append-only; assessments supersede rather than
    overwrite."""

    finding_id: str
    kind: str
    entity_refs: tuple = ()
    evidence: tuple[Evidence, ...] = ()
    missing: tuple[MissingEvidence, ...] = ()
    assessments: tuple[Assessment, ...] = ()
    state: FindingState = FindingState.OPEN
    created_at: datetime | None = None
    schema_version: int = SCHEMA_VERSION
    _graph: EvidenceGraph | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not _ID.match(self.finding_id):
            raise FindingError(f"malformed finding_id {self.finding_id!r}")
        if not self.kind:
            raise FindingError("kind required")

    # -- evidence --------------------------------------------------------

    def attach(self, evidence: Evidence) -> "Finding":
        if len(self.evidence) >= MAX_EVIDENCE_PER_FINDING:
            raise FindingError(
                f"finding already holds {MAX_EVIDENCE_PER_FINDING} evidence items")
        if any(e.evidence_id == evidence.evidence_id for e in self.evidence):
            raise FindingError(f"duplicate evidence {evidence.evidence_id}")
        self.evidence = self.evidence + (evidence,)
        return self

    def note_missing(self, missing: MissingEvidence) -> "Finding":
        if len(self.missing) >= MAX_MISSING_PER_FINDING:
            raise FindingError("too many missing-evidence notes")
        self.missing = self.missing + (missing,)
        return self

    def resolve_missing(self, expected: str) -> bool:
        """Called when evidence that was missing finally arrives."""
        remaining = tuple(m for m in self.missing if m.expected != expected)
        changed = len(remaining) != len(self.missing)
        self.missing = remaining
        return changed

    # -- assessment ------------------------------------------------------

    def assess(self, assessment: Assessment) -> "Finding":
        """Append an assessment. The previous one is kept, always."""
        if len(self.assessments) >= MAX_ASSESSMENTS:
            raise FindingError(f"more than {MAX_ASSESSMENTS} assessments")
        if self.assessments and assessment.supersedes != self.current.assessment_id:
            raise FindingError(
                "a new assessment must name the one it supersedes, so the "
                "history reads as a chain rather than a pile")
        self.assessments = self.assessments + (assessment,)
        self.state = _state_for(assessment, self.state)
        return self

    @property
    def current(self) -> Assessment | None:
        return self.assessments[-1] if self.assessments else None

    @property
    def history(self) -> tuple[Assessment, ...]:
        return self.assessments

    def summarize(self, graph: EvidenceGraph | None = None) -> EvidenceSummary:
        return summarize_evidence(self.evidence, self.missing, graph or self._graph)

    # -- explanation -----------------------------------------------------

    def explain(self) -> str:
        """A deterministic explanation built from the structured record.

        Produced from the evidence, never by a language model. An LLM may one
        day summarise this for an operator, but it may not author or alter
        the record it summarises.
        """
        current = self.current
        lines = [f"Finding: {self.kind} ({self.finding_id})",
                 f"State: {self.state.value}"]
        if current is None:
            lines.append("Status: no assessment has been made")
            return "\n".join(lines)
        lines += [
            f"Status: {current.outcome.value}",
            f"Severity: {current.severity.name} (impact if true)",
            f"Confidence: {current.confidence.name} "
            f"(basis: {current.basis.value})",
            f"Reason: {current.rationale}",
        ]
        for label, stance in (("Supporting", Stance.SUPPORTS),
                              ("Contradictory", Stance.CONTRADICTS),
                              ("Context", Stance.CONTEXT)):
            items = [e for e in self.evidence if e.stance is stance]
            if items:
                lines.append(f"{label}:")
                lines += [f"  - {e.summary} [{e.evidence_id}, {e.kind.value},"
                          f" origin {e.origin_group}]" for e in items]
        if self.missing:
            lines.append("Missing:")
            lines += [f"  - {m.expected} ({m.reason.value})" for m in self.missing]
        lines.append(f"Collection: {current.collection_health.value}")
        if current.summary.shared_root_events:
            lines.append("Note: supporting evidence shares a source event, so "
                         "it is one observation seen several ways, not "
                         "independent corroboration.")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "finding_id": self.finding_id,
            "kind": self.kind,
            "state": self.state.value,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "entity_refs": [r.to_dict() if hasattr(r, "to_dict") else str(r)
                            for r in self.entity_refs],
            "evidence": [e.to_dict() for e in self.evidence],
            "missing": [m.to_dict() for m in self.missing],
            "assessments": [a.to_dict() for a in self.assessments],
        }

    def to_json(self, max_bytes: int = 256 * 1024) -> str:
        payload = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        if len(payload.encode()) > max_bytes:
            raise FindingError(f"serialized finding exceeds {max_bytes} bytes")
        return payload


def _state_for(assessment: Assessment, previous: FindingState) -> FindingState:
    """Lifecycle follows the conclusion, except where an operator has closed
    the case -- a resolved or retracted finding stays that way until someone
    reopens it explicitly."""
    if previous in (FindingState.RESOLVED, FindingState.RETRACTED):
        return previous
    return {
        AssessmentOutcome.SUPPORTED: FindingState.CORROBORATED,
        AssessmentOutcome.CONTRADICTED: FindingState.DISPUTED,
        AssessmentOutcome.INCONCLUSIVE: FindingState.INCONCLUSIVE,
        AssessmentOutcome.NOT_SUPPORTED: FindingState.INCONCLUSIVE,
    }[assessment.outcome]
