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

## ADR-016 — OS-Ken is the candidate OpenFlow framework, pending a conformance spike

- **Status**: accepted as *candidate*; final selection remains NOT_RUN until
  P5-OF-02's fake adapter is matched against a real OS-Ken adapter.
- **Problem**: the security core needs a way onto the wire. The legacy
  tutorial answer was Ryu, and the roadmap explicitly forbids choosing
  because an old tutorial did.
- **Evidence** (`RESEARCH_LEDGER.md` R-001..R-005, verified 2026-09-20 from
  the PyPI JSON API, not from memory):
  - Ryu 4.34 last released **2020-05-27** and declares no `requires_python`.
  - OS-Ken 4.2.2 released **2026-08-20**, `requires_python >=3.10`,
    classifiers through 3.13, Apache-2.0.
  - Faucet is an application built on this layer, not an alternative to it.
- **Decision**: build against OS-Ken, but only behind the adapter contract.
- **What is NOT established**: protocol conformance, OpenFlow version
  coverage, throughput, and behaviour under switch reconnect are all
  `NOT_RUN`. Classifiers are self-declared. Nothing here justifies calling
  the choice validated.
- **Cost of being wrong**: bounded by ADR-005 and ADR-017 -- the framework is
  confined to the adapter, so replacing it does not touch the security core.

## ADR-017 — eventlet must not escape the adapter

- **Status**: accepted
- **Problem**: OS-Ken depends on `eventlet>=0.27.0` (R-003), a green-thread
  library that monkey-patches the standard library's I/O. That is a
  concurrency model, not an implementation detail: code written for it
  behaves differently from plain-threaded or asyncio code, and mixing the two
  produces deadlocks that only appear under load.
- **Decision**: `eventlet` may be imported **only** inside the OpenFlow
  adapter package. The security core stays synchronous and non-blocking,
  communicating with the adapter through a bounded queue. The existing
  framework-independence test already enforces the import boundary
  mechanically.
- **Consequence**: the core can be driven by a fake adapter, by a test, by a
  replay harness, or by a different framework later, with no change.
- **Risk**: eventlet's long-term direction has been debated in the OpenStack
  ecosystem. Version 0.41.2 (2026-08-14) is current, so this is a
  watch-item, not a blocker. Re-check before P11.

## ADR-020 — the new system lives entirely under `development/`

- **Status**: accepted (owner direction, 2026-09-20)
- **Problem**: `src/sdnguard/` sat beside `src/models.py`, `src/eda.py` and the
  other legacy ML modules. Deleting the legacy tree would have meant picking
  files out of a shared directory, which is exactly the situation that makes
  people keep dead code rather than risk removing it.
- **Decision**:

  ```
  development/src/sdnguard   the system being built
  development/tests          its tests
  development/infra          the lab that exercises it

  tools/, tests/tools, tests/memory, docs/, memory/   project governance
  everything else at the repository root              legacy
  ```

- **Consequence**: the legacy tree can be deleted, or moved to its own branch,
  in one operation with no risk to the product. `pyproject.toml` carries the
  only wiring (`pythonpath`, `testpaths`), so nothing else needs to know.
- **Not moved**: the context firewall, the memory system and the durable docs
  stay at the root. They are project governance that outlives the legacy code
  and would have to be moved back if they went into `development/`.
- **Evidence**: 805 tests green immediately after the move, with no source
  edits -- only `git mv` and two lines of `pyproject.toml`.

## ADR-021 — SSM Run Command as the only lab access path

- **Status**: accepted
- **Problem**: the lab needs administrative access, and the obvious answer is
  SSH. SSH means an inbound rule, a key pair to store and rotate, and a
  standing decision about which CIDR may reach port 22.
- **Decision**: the security group has **no ingress rules at all** and the
  stack contains **no key pair**. Access is `aws ssm send-command` through an
  instance role carrying only `AmazonSSMManagedInstanceCore`.
- **Consequence**: nothing is reachable from the internet, there is no key to
  leak, and every command is recorded in CloudTrail. The template asserts the
  absence of ingress and key pairs in a self-check rather than trusting review.
- **Cost**: no interactive shell without the session-manager plugin. In
  practice this pushed the lab toward scripted, reproducible steps, which is
  what the evidence requirements wanted anyway.

## ADR-022 — AWS CLI stays out of the generic safe_exec path

- **Status**: accepted
- **Problem**: `aws` is in `denied_commands` in `tools/context_policy.yaml`
  from P0. The owner has now authorised AWS work, so the obvious move is to
  allow it.
- **Decision**: keep `aws` denied in `safe_exec`. AWS access happens only
  through the reviewed scripts in `development/infra/lab/`, which are read
  before they run and whose output is deliberately unbounded so that cleanup
  verification cannot be truncated.
- **Why**: a generic allow would let any agent -- including Codex, or a future
  session -- spend money through a convenience path. Confining it to named
  scripts keeps the spend surface small and reviewable.
- **Honest limitation**: this is a guardrail on `safe_exec`, not on the agent.
  Direct shell access can still call `aws`, as it did here. The firewall
  constrains its own tools; it has never claimed to constrain everything.
