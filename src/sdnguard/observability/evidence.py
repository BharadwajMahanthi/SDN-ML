"""Structured findings store.

The legacy detector's only output was ``logger.warn``, so nothing downstream
could act on a detection and the collection scripts had nothing to collect.
This is the replacement: an in-memory, bounded, queryable record of findings
and the decisions taken about them, serialisable as an evidence bundle.

Ground truth deliberately does *not* live here. The experiment harness keeps
what it did; this store keeps what the system detected. Comparing them is a
separate step, which is what makes the comparison meaningful.
"""

from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Iterator

from sdnguard.domain.events import (
    EnforcementDecision,
    FindingKind,
    SecurityFinding,
    Severity,
    Verdict,
)
from sdnguard.domain.host import MacAddress
from sdnguard.domain.identity import PortIdentity

__all__ = ["EvidenceRecord", "EvidenceStore"]


@dataclass(frozen=True)
class EvidenceRecord:
    """A finding plus whatever was decided about it."""

    finding: SecurityFinding
    decision: EnforcementDecision | None = None

    def to_dict(self) -> dict:
        payload = {"finding": self.finding.to_dict()}
        if self.decision is not None:
            payload["decision"] = {
                "decision_id": self.decision.decision_id,
                "action": self.decision.action.value,
                "scope": str(self.decision.scope) if self.decision.scope else None,
                "decided_at": self.decision.decided_at.isoformat(),
                "expires_at": (self.decision.expires_at.isoformat()
                               if self.decision.expires_at else None),
                "reason": self.decision.reason,
                "enforcing": self.decision.is_enforcing,
            }
        return payload


class EvidenceStore:
    """Bounded ring of findings, queryable by the dimensions that matter."""

    def __init__(self, *, max_records: int = 10_000) -> None:
        if max_records < 1:
            raise ValueError("max_records must be positive")
        self._records: deque[EvidenceRecord] = deque(maxlen=max_records)
        self._by_id: dict[str, EvidenceRecord] = {}

    def record(self, finding: SecurityFinding,
               decision: EnforcementDecision | None = None) -> EvidenceRecord:
        entry = EvidenceRecord(finding, decision)
        if len(self._records) == self._records.maxlen:
            evicted = self._records[0]
            self._by_id.pop(evicted.finding.finding_id, None)
        self._records.append(entry)
        self._by_id[finding.finding_id] = entry
        return entry

    def attach_decision(self, finding_id: str,
                        decision: EnforcementDecision) -> EvidenceRecord | None:
        existing = self._by_id.get(finding_id)
        if existing is None:
            return None
        updated = EvidenceRecord(existing.finding, decision)
        self._by_id[finding_id] = updated
        for index, entry in enumerate(self._records):
            if entry.finding.finding_id == finding_id:
                self._records[index] = updated
                break
        return updated

    # -- queries ---------------------------------------------------------

    def get(self, finding_id: str) -> EvidenceRecord | None:
        return self._by_id.get(finding_id)

    def all(self) -> list[EvidenceRecord]:
        return list(self._records)

    def by_kind(self, kind: FindingKind) -> list[EvidenceRecord]:
        return [r for r in self._records if r.finding.kind is kind]

    def by_verdict(self, verdict: Verdict) -> list[EvidenceRecord]:
        return [r for r in self._records if r.finding.verdict is verdict]

    def by_severity(self, minimum: Severity) -> list[EvidenceRecord]:
        order = {Severity.INFO: 0, Severity.LOW: 1,
                 Severity.MEDIUM: 2, Severity.HIGH: 3}
        return [r for r in self._records
                if order[r.finding.severity] >= order[minimum]]

    def by_mac(self, mac: MacAddress) -> list[EvidenceRecord]:
        return [r for r in self._records if r.finding.identity.mac == mac]

    def by_port(self, port: PortIdentity) -> list[EvidenceRecord]:
        return [r for r in self._records if r.finding.port == port]

    def between(self, start: datetime, end: datetime) -> list[EvidenceRecord]:
        return [r for r in self._records if start <= r.finding.detected_at <= end]

    def enforced(self) -> list[EvidenceRecord]:
        return [r for r in self._records
                if r.decision is not None and r.decision.is_enforcing]

    # -- bundling --------------------------------------------------------

    def bundle(self, *, label: str = "", extra: dict | None = None) -> dict:
        """A reproducible evidence bundle. Contains only detector output --
        ground truth is the harness's business, and keeping them apart is
        what makes a comparison meaningful."""
        return {
            "label": label,
            "schema": "sdnguard.evidence/1",
            "record_count": len(self._records),
            "records": [r.to_dict() for r in self._records],
            **({"context": extra} if extra else {}),
        }

    def to_json(self, *, label: str = "", extra: dict | None = None) -> str:
        return json.dumps(self.bundle(label=label, extra=extra),
                          indent=2, sort_keys=True)

    def counts(self) -> dict[str, int]:
        summary: dict[str, int] = {}
        for record in self._records:
            key = record.finding.kind.value
            summary[key] = summary.get(key, 0) + 1
        return dict(sorted(summary.items()))

    # -- introspection ---------------------------------------------------

    def __len__(self) -> int:
        return len(self._records)

    def __iter__(self) -> Iterator[EvidenceRecord]:
        return iter(self._records)

    @property
    def capacity(self) -> int:
        return self._records.maxlen
