# DECISIONS

Architecture decision records. Supersede rather than delete.

## ADR-001 — JSONL-per-bucket rolling journal, not SQLite

- **Status**: accepted (owner directive, 2026-09-20)
- **Problem**: the rolling journal needs whole-week deletion, a strict byte
  cap, crash recovery, inspectability and cross-agent portability.
- **Alternatives**: SQLite (real transactions and locking, but bucket
  rotation becomes `DELETE` + `VACUUM` and a hard byte cap is harder to hold).
- **Decision**: one JSONL file per seven-effective-day bucket; whole-bucket
  rotation is a `rename` then `unlink`.
- **Evidence**: `tests/memory/` — 59 passed, including the four crash points
  and the exact byte-cap boundary.
- **Cost**: no query engine; the index must be rebuilt rather than joined.

## ADR-002 — the journal is authoritative, the index is an accelerator

- **Status**: accepted
- **Decision**: `index.json` is fully reconstructible; the JSONL append is the
  commit point, and `state.json` is healed from the journal by `reconcile()`.
- **Evidence**: `test_missing_index_loses_nothing`,
  `test_crash_after_append_before_state_update_is_healed`.

## ADR-003 — retention window is 85–91 effective days, not a guaranteed 91

- **Status**: accepted
- **Decision**: a bucket ending on effective day E is eligible at
  `effective_day >= E + 85`. Weekly deletion immediately after 91 days means
  retained detail varies from 85 to 91 days. Guaranteeing at least 91 days
  with whole-week deletion would require holding up to 97.
- **Evidence**: `test_retained_window_is_85_to_91_days_not_a_guaranteed_91`.

## ADR-004 — the Java POC is reference material, not a system to repair

- **Status**: accepted (owner direction, 2026-09-20; supersedes the earlier
  "P2 = reproduce every audit finding" plan)
- **Problem**: the previous plan made repairing a known-broken student POC a
  prerequisite for building the product.
- **Decision**: Java is archaeology. Audit findings become
  `KNOWN_FAILURE → PYTHON DESIGN REQUIREMENT → REGRESSION TEST` rows in
  `PYTHON_MIGRATION_MATRIX.md`. No Java is repaired, and no JDK is installed,
  unless a specific unanswered behavioural question requires execution.
- **Evidence**: `LEGACY_CAPABILITY_MAP.md`, `LEGACY_SECURITY_MODEL.md`.
- **Cost**: legacy behaviour is established by static reading only, so some
  intent stays `LEGACY_AMBIGUOUS` and is resolved by design choice rather than
  by observation. Those choices are recorded as such.

## ADR-005 — security logic must not touch framework packet objects

- **Status**: accepted
- **Problem**: the legacy module threaded `OFPacketIn`, `IDevice` and
  `IOFSwitch` through its security logic, so nothing could be tested without a
  running controller — a major reason the POC was never validated.
- **Decision**: a normalisation boundary. Below it, only typed domain events
  (`HostObservation`, `MovementEvent`, `ProbeResult`). The OpenFlow adapter is
  thin and swappable, and framework selection is deferred.
- **Benefit**: the entire movement state machine and detection path are
  unit-testable on macOS with no OVS, which unblocks work while B-1 stands.
- **Cost**: one extra mapping layer; adapter fidelity needs its own tests.

## ADR-006 — ARP, not ICMP, is the default liveness probe

- **Status**: accepted
- **Problem**: the legacy prober used ICMP from a hardcoded `10.0.1.100`, an
  address on no topology in this repository, so a reply could never correlate.
  An ARP implementation existed but was abandoned with no recorded rationale.
- **Decision**: ARP by default — link-local, no routable controller address
  required, cannot be answered off-subnet. ICMP remains available as an option.
  Every probe carries a single-use nonce and a mandatory deadline.
- **Evidence**: `LEGACY_SECURITY_MODEL.md` §5–7.
- **Risk**: ARP-based liveness is spoofable by an on-segment attacker, so a
  probe reply is evidence, never proof. Recorded in the threat model when written.
