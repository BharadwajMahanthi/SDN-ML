"""The broker's durable record of privileged actions.

The journal answers one question that nothing else can: *after an
unscheduled restart, what OS state does this host still hold because of
Annulon?* If that question has no answer, every crash leaves rules behind
that nobody will remove, and a "temporary" restriction becomes permanent.

Properties, and why each is not optional:

* **Written before the OS is touched, not after.** A record appended after a
  successful apply is useless in the case it exists for -- a crash between
  the two. The intent is journalled first, so a crash mid-apply leaves a
  record saying "this may hold OS state", which reconciliation can act on.
* **Append-only and fsynced.** A buffered write that a crash discards is not
  a durable record. Each append is flushed and ``fsync``-ed before the call
  returns.
* **Backend-agnostic.** The journal records *that* a resource is owned and by
  which backend, never how to manipulate it. No privileged tool is named
  here, which is what lets the text-based privileged-action guard cover this
  module rather than exempt it.
* **Bounded, with rotation that cannot lose the live set.** A journal that
  grows forever fills the disk. One that truncates blindly forgets actions
  that still hold OS state. Rotation therefore carries the non-terminal
  records forward into the new file before the old one is retired.
* **One JSON object per line, strictly parsed.** A corrupt tail -- the normal
  consequence of a power loss mid-write -- costs exactly the lines that are
  unparseable, and is reported rather than silently dropped.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path

from annulon.response.contract import ActionState, ActionType, ContractError, Target

__all__ = ["JournalError", "JournalEntry", "ActionJournal", "OwnedResource",
           "MAX_JOURNAL_BYTES", "MAX_JOURNAL_RECORDS"]

#: 4 MiB, roughly 20k records. A host producing more privileged actions than
#: that between rotations has a problem the journal cannot fix.
MAX_JOURNAL_BYTES = 4 * 1024 * 1024
#: A second, independent bound. Size alone is not enough: it is reached only
#: after the records are already written, whereas the count is checked as
#: they arrive.
MAX_JOURNAL_RECORDS = 20_000


class JournalError(Exception):
    """The journal cannot be read or written safely."""


@dataclass(frozen=True)
class OwnedResource:
    """An OS object Annulon created and is therefore responsible for removing.

    ``backend`` and ``identifier`` together are what reconciliation matches
    against live system state. Nothing outside this identifier is ever
    touched: the broker removes what it created and nothing adjacent to it.
    """

    #: Which enforcement backend owns it. The backend names itself; this
    #: module never spells a privileged tool's name, so the text-based
    #: privileged-action guard stays meaningful here.
    backend: str
    #: Backend-defined and opaque to the journal: matched, never parsed.
    identifier: str
    created_at: datetime | None = None

    def to_dict(self) -> dict:
        return {"backend": self.backend, "identifier": self.identifier,
                "created_at": self.created_at.isoformat() if self.created_at else None}

    @staticmethod
    def from_dict(raw: object) -> "OwnedResource | None":
        if raw is None:
            return None
        if not isinstance(raw, dict):
            raise JournalError("owned_resource must be an object")
        created = raw.get("created_at")
        return OwnedResource(
            backend=str(raw.get("backend", "")),
            identifier=str(raw.get("identifier", "")),
            created_at=datetime.fromisoformat(created) if created else None)


@dataclass(frozen=True)
class JournalEntry:
    """One privileged action, as the broker last knew it."""

    action_id: str
    action_type: ActionType
    target: Target
    state: ActionState
    policy_version: str
    requested_by: str
    requested_at: datetime
    #: When the action actually took effect on the OS. ``None`` until applied.
    activated_at: datetime | None = None
    #: When it must be gone by. Independent of activation so that a crash
    #: between authorize and apply still leaves a deadline to enforce.
    expires_at: datetime | None = None
    owned_resource: OwnedResource | None = None
    detail: str = ""
    sequence: int = 0

    def to_dict(self) -> dict:
        return {
            "action_id": self.action_id, "action_type": self.action_type.value,
            "target": self.target.to_dict(), "state": self.state.value,
            "policy_version": self.policy_version,
            "requested_by": self.requested_by,
            "requested_at": self.requested_at.isoformat(),
            "activated_at": self.activated_at.isoformat() if self.activated_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "owned_resource": self.owned_resource.to_dict() if self.owned_resource else None,
            "detail": self.detail[:256], "sequence": self.sequence,
        }

    @staticmethod
    def from_dict(raw: object) -> "JournalEntry":
        if not isinstance(raw, dict):
            raise JournalError("journal record must be an object")
        try:
            return JournalEntry(
                action_id=str(raw["action_id"]),
                action_type=ActionType(raw["action_type"]),
                target=Target.from_dict(raw["target"]),
                state=ActionState(raw["state"]),
                policy_version=str(raw.get("policy_version", "")),
                requested_by=str(raw.get("requested_by", "")),
                requested_at=datetime.fromisoformat(raw["requested_at"]),
                activated_at=(datetime.fromisoformat(raw["activated_at"])
                              if raw.get("activated_at") else None),
                expires_at=(datetime.fromisoformat(raw["expires_at"])
                            if raw.get("expires_at") else None),
                owned_resource=OwnedResource.from_dict(raw.get("owned_resource")),
                detail=str(raw.get("detail", "")),
                sequence=int(raw.get("sequence", 0)))
        except (KeyError, ValueError, TypeError, ContractError) as exc:
            raise JournalError(f"unusable journal record: {exc}") from exc

    @property
    def holds_os_state(self) -> bool:
        return self.state.holds_os_state


class ActionJournal:
    """Append-only, fsynced, bounded, and recoverable."""

    def __init__(self, path: Path, *,
                 max_bytes: int = MAX_JOURNAL_BYTES,
                 max_records: int = MAX_JOURNAL_RECORDS) -> None:
        self._path = Path(path)
        self._max_bytes = max_bytes
        self._max_records = max_records
        self._sequence = 0
        #: Latest known record per action, in insertion order.
        self._latest: dict[str, JournalEntry] = {}
        #: Lines that could not be parsed on load. Surfaced, never hidden: a
        #: corrupt journal is itself a finding about the host.
        self.corrupt_records: int = 0
        self._path.parent.mkdir(parents=True, mode=0o750, exist_ok=True)
        self._load()

    # -- reading ---------------------------------------------------------

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            text = self._path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise JournalError(f"journal unreadable: {exc}") from exc
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                entry = JournalEntry.from_dict(json.loads(line))
            except (json.JSONDecodeError, JournalError):
                # A truncated final line is the expected shape of a power
                # loss. Counted and reported; never treated as absence.
                self.corrupt_records += 1
                continue
            self._latest[entry.action_id] = entry
            self._sequence = max(self._sequence, entry.sequence)

    @property
    def path(self) -> Path:
        return self._path

    def entries(self) -> tuple[JournalEntry, ...]:
        """Latest state of every action the journal knows about."""
        return tuple(self._latest.values())

    def get(self, action_id: str) -> JournalEntry | None:
        return self._latest.get(action_id)

    def unreconciled(self) -> tuple[JournalEntry, ...]:
        """Actions that may still hold OS state.

        This is the startup work list. An action in ``APPLYING`` is included
        even though it may never have reached the OS -- checking for a rule
        that is not there is cheap; leaving one behind is not.
        """
        return tuple(e for e in self._latest.values() if e.holds_os_state)

    def active_count(self) -> int:
        return len(self.unreconciled())

    def recent_request_ids(self, limit: int = 4096) -> frozenset[str]:
        """Action IDs from the journal, newest first, for replay defence
        across a restart. Bounded, so it is a mitigation and not a guarantee;
        request freshness is what actually bounds the replay window."""
        ordered = sorted(self._latest.values(), key=lambda e: e.sequence, reverse=True)
        return frozenset(e.action_id for e in ordered[:limit])

    # -- writing ---------------------------------------------------------

    def append(self, entry: JournalEntry) -> JournalEntry:
        """Durably record one action state. Returns the record as written."""
        self._sequence += 1
        stamped = replace(entry, sequence=self._sequence)
        line = json.dumps(stamped.to_dict(), separators=(",", ":"),
                          sort_keys=True, allow_nan=False)
        if len(line) > 16 * 1024:
            raise JournalError("single record exceeds 16 KiB")
        self._latest[stamped.action_id] = stamped
        try:
            with open(self._path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            # A privileged action whose intent cannot be recorded must not
            # proceed: the caller treats this as a hard failure.
            raise JournalError(f"journal append failed: {exc}") from exc
        self._rotate_if_needed()
        return stamped

    def record(self, *, action_id: str, action_type: ActionType, target: Target,
               state: ActionState, policy_version: str, requested_by: str,
               requested_at: datetime, activated_at: datetime | None = None,
               expires_at: datetime | None = None,
               owned_resource: OwnedResource | None = None,
               detail: str = "") -> JournalEntry:
        return self.append(JournalEntry(
            action_id=action_id, action_type=action_type, target=target,
            state=state, policy_version=policy_version, requested_by=requested_by,
            requested_at=requested_at, activated_at=activated_at,
            expires_at=expires_at, owned_resource=owned_resource, detail=detail))

    def transition(self, action_id: str, state: ActionState, *,
                   activated_at: datetime | None = None,
                   owned_resource: OwnedResource | None = None,
                   detail: str = "") -> JournalEntry:
        """Record a new state for an action the journal already knows."""
        current = self._latest.get(action_id)
        if current is None:
            raise JournalError(f"no journalled action {action_id!r} to transition")
        return self.append(replace(
            current, state=state,
            activated_at=activated_at if activated_at is not None else current.activated_at,
            owned_resource=owned_resource if owned_resource is not None
            else current.owned_resource,
            detail=detail or current.detail))

    # -- rotation --------------------------------------------------------

    def _rotate_if_needed(self) -> None:
        try:
            size = self._path.stat().st_size
        except OSError:
            return
        if size <= self._max_bytes and len(self._latest) <= self._max_records:
            return
        self.rotate()

    def rotate(self) -> int:
        """Retire the journal, carrying forward everything still live.

        Records that still hold OS state are rewritten into the new journal
        first, so rotation can never be the reason an owned rule is
        forgotten. Terminal records are preserved in the ``.1`` file for
        audit and then drop out of the working set.

        Returns the number of records carried forward.
        """
        carried = sorted(self.unreconciled(), key=lambda e: e.sequence)
        temporary = None
        try:
            handle = tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=str(self._path.parent),
                prefix=self._path.name + ".", suffix=".new", delete=False)
            temporary = Path(handle.name)
            with handle:
                for entry in carried:
                    handle.write(json.dumps(entry.to_dict(), separators=(",", ":"),
                                            sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            archive = self._path.with_suffix(self._path.suffix + ".1")
            if self._path.exists():
                os.replace(self._path, archive)
            os.replace(temporary, self._path)
            temporary = None
            self._fsync_directory()
        except OSError as exc:
            raise JournalError(f"journal rotation failed: {exc}") from exc
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink()
        self._latest = {e.action_id: e for e in carried}
        return len(carried)

    def _fsync_directory(self) -> None:
        fd = os.open(str(self._path.parent), os.O_RDONLY)
        try:
            os.fsync(fd)
        except OSError:
            pass                       # not all filesystems support it
        finally:
            os.close(fd)
