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

## ADR-023 — assumable role with temporary credentials replaces root keys

- **Status**: accepted. Root keys remain **active** pending an owner action
  that must not be automated.
- **Problem** (KF-19): the project was operating on root account long-term
  access keys. Root keys cannot be scoped, cannot be constrained by a
  permission boundary, and cannot be contained after a leak without closing
  the account.
- **Options considered**, in the owner's stated order of preference:
  1. *IAM Identity Center* — `sso-admin list-instances` returns **0**. Enabling
     it means enabling AWS Organizations, an account-structure change with
     consequences well beyond this project. Not appropriate to do autonomously.
  2. *Assumable role with temporary STS credentials* — **chosen**.
  3/4. Not needed.
- **Decision**:

  ```
  sdnguard-operator (IAM user)   sole permission: sts:AssumeRole on one role
        |  long-term key, near-worthless alone
        v
  sdnguard-lab-role              least privilege, 1-hour sessions
  ```

  The CLI profile `sdnguard` carries `role_arn` + `source_profile`, so every
  command runs on temporary credentials. All lab scripts default to it.
- **Least privilege derived from use, not convenience**: permissions were
  enumerated from the operations P6 actually performs. CloudFormation is scoped
  to the lab stack names; `iam:PassRole` is limited to the lab instance role
  and to `ec2.amazonaws.com`; there is no user, policy or key management at
  all, so the credential cannot widen itself; every regional statement carries
  an `aws:RequestedRegion` condition pinning it to `ap-south-1`.
- **Evidence**: `development/infra/lab/verify_credentials.sh` — 19 expected
  outcomes, 0 unexpected. Ten denials including `iam:CreateUser`,
  `iam:AttachUserPolicy`, `iam:CreateAccessKey`, `iam:PutRolePolicy` against
  its own role, and every cross-region attempt.
- **Residual risk**: the operator's long-term key still exists on the
  workstation. It is a large improvement on a root key, not an elimination of
  long-term credentials. Identity Center remains the better end state.

## ADR-024 — a denial probe must be proven to reach authorization

- **Status**: accepted
- **Problem** (KF-20): the first credential test reported
  `ec2:RunInstances in us-east-1` as "NOT DENIED - PRIVILEGE TOO BROAD". It
  was neither. EC2 validates the AMI identifier *before* evaluating IAM, so
  the request failed with `InvalidAMIID.Malformed` and never reached
  authorization. The probe tested nothing.
- **Why this matters beyond one test**: the failure mode is symmetric. A probe
  that never reaches authorization can just as easily be read as a *pass*,
  which would mean asserting a least-privilege property that was never tested.
  That is the same species of error as the legacy project's tautological
  detection.
- **Decision**: every denial probe has three possible outcomes -- denied,
  allowed, or **inconclusive** (rejected before authorization) -- and
  inconclusive never counts as a pass. Region-scoped probes use `--dry-run`
  with a **positive control** in the permitted region, so the probe is
  demonstrated to reach IAM before its denial elsewhere is believed.
- **Evidence**: `ec2:CreateSecurityGroup --dry-run` returns `DryRunOperation`
  in `ap-south-1` and `UnauthorizedOperation` in `us-east-1`.

## ADR-025 — no artificial dead ends

- **Status**: accepted (owner direction, 2026-09-20). Permanent project rule,
  recorded in `AGENTS.md` and `PROJECT_CONTRACT.md`.
- **Problem**: this project is built from an incomplete research POC. The
  default failure mode for such work is to treat the absence of a library,
  an OS feature or a published solution as a terminal condition, and either
  stop or retreat to the legacy implementation.
- **Decision**: the objective is defined by required capabilities and security
  properties, never by whichever libraries happen to exist. On failure:
  understand the actual requirement, check for a safe existing solution,
  evaluate alternatives, adapt a component, or implement the missing piece
  ourselves behind a clean interface, then test and measure it.
- **Explicitly rejected fallbacks**: repairing Floodlight, reintroducing
  legacy behaviour for compatibility, substituting fake tests for physical
  evidence, and redesigning the architecture because an adapter changed.
- **Guard against the opposite error**: "implement it ourselves" is bounded.
  Cryptography, TLS, OS networking and complete protocol stacks are not
  rewritten without a narrow documented necessity. Prefer a small auditable
  custom component over a large unnecessary reinvention.
- **Consequence for P6**: if OS-Ken lacks something, the response is to patch
  or wrap it behind `adapter/`, or implement the minimum protocol subset --
  not to abandon real OpenFlow testing.

## ADR-027 — Padmavyuh v2: general cloud workload security, SDN as one pack

- **Status**: accepted (owner direction + `PADMAVYUH_ARCHITECTURE_V2.md`, 2026-09-20)
- **Previous scope**: SDN/OpenFlow security. **New scope**: a local-first
  security agent for an ordinary Linux cloud server, with SDN topology
  integrity as one optional protection pack.
- **Preserved**: the entire Python domain model, state machines, probe engine,
  policy engine, evidence store, lab harness, separated ground truth, and the
  P6 physical chain evidence. Nothing is deleted or renamed by this decision.
- **Superseded**: the assumption that SDN is the whole product. `PortIdentity`
  is not a host identity, and the port-down precondition has no host analogue;
  V2 §3 forbids inheriting either into general host protection.
- **Migration impact**: additive. A shared `padmavyuh` package appears only
  when a second consumer exists; extraction before that is speculation.
  Completed P-task IDs and their evidence are retained and are **not**
  retroactively relabelled as covering host or AI capability.
- **Authority**: V2 ranks above `PROJECT_CONTRACT.md` and unsuperseded ADRs;
  an owner instruction still ranks above V2.

## ADR-028 — process separation, not import separation, for eventlet

- **SUPERSEDES**: ADR-017 (eventlet confined to the adapter package)
- **REASON**: ADR-017 enforced the boundary with an AST import guard. V2 §3 is
  correct that *import restrictions alone do not establish a process-wide
  concurrency boundary*. `eventlet.monkey_patch()` rewrites the standard
  library for the entire process, so the guard proves nothing about runtime
  behaviour if the host agent and the SDN adapter ever share a process. The
  guard was necessary and is retained; it was never sufficient.
- **MIGRATION IMPACT**: the SDN adapter runs as its own supervised process and
  communicates with the core over a typed boundary. The host agent must never
  import or inherit eventlet. The existing AST guard stays as a cheap early
  signal, now explicitly labelled as necessary-but-not-sufficient. No code
  moves on this branch; the constraint binds V2-CORE-01 onward.

## ADR-029 — forced termination must be recorded, not silently succeed

- **SUPERSEDES**: the KF-22 remedy as implemented
- **REASON**: KF-22 was fixed with `os._exit(0)`, which bypasses cleanup
  handlers and stdio flushing. V2 §3 is right that this makes a killed run
  indistinguishable from a completed one -- the same failure family as KF-22
  itself, where an empty run could be read as "nothing detected".
- **MIGRATION IMPACT**: every experiment writes a **completion manifest**
  recording whether it ended normally, by deadline, by signal or by force;
  the event writer performs a durable drain before exit; and port/process
  cleanup is verified independently rather than assumed. An experiment without
  a manifest is `EVIDENCE_INCOMPLETE`, never a negative result.
- **Status**: accepted; implementation is the first item of the next branch.

## ADR-030 — severity and confidence are separate axes

- **EXTENDS**: ADR-014 (severity is a label in one policy object)
- **REASON**: V2 §9. A low-confidence event may be catastrophic; a
  high-confidence one may be trivial. Collapsing them into one number hides
  exactly the distinction an operator needs, and invites the unearned
  precision this project already rejected once (the legacy hardcoded 0.93).
- **MIGRATION IMPACT**: the shared finding model carries severity, a
  confidence *basis* (which evidence, from which sensors), and explicit
  contradictory and missing evidence. Findings must also carry evidence
  lineage so that three detectors consuming one event are not counted as three
  independent confirmations (V2 §10).

## ADR-031 — the merge gate is executable, not documented

- **Status**: accepted
- **Problem** (KF-23): a branch merged with a required framework guard red.
  The rule existed in `AGENTS.md`; a documented rule did not stop it.
- **Decision**: `tools/merge_gate.py` is the canonical merge path. Only `PASS`
  (and `NOT_APPLICABLE` for checks whose spec permits it) is merge-eligible.
  `FAIL`, `NOT_RUN`, `INCONCLUSIVE` and `STALE` all refuse. **There is no
  override flag.**
- **Decisions come from exit status plus a JUnit artifact, never from text.**
  Parsing "816 passed" is precisely how an optimistic summary became a merge.
  A test module that prints `999 passed` and then fails is recorded as `FAIL`.
- **A skipped required check is not a pass.** pytest exits 0 when every test
  skips and 5 when nothing is collected; both become `INCONCLUSIVE`.
- **Evidence is bound to a commit.** A gate produced against an earlier HEAD
  is `STALE`.
- **Eligibility is re-derived at validation time** from the per-check
  statuses. A defect found by the gate's own tests: `validate()` originally
  trusted the stored `merge_eligible` boolean, so a buggy producer or a
  hand-edited artifact could assert its own eligibility. Producer and
  validator now share one evaluator.
- **The artifact is runtime state, never committable**, so a gate result
  cannot be carried between branches or edited into a commit.
- **Evidence**: 26 tests, the central one driving a real `--no-ff` merge in a
  throwaway repository — reproducing the exact KF-23 shape (everything green
  except `framework_guards`) and proving `main` is untouched.

## ADR-032 — `repo_query explicit-file` closes the untracked-document gap

- **Status**: accepted
- **Problem**: `tree` and `grep` index tracked files only, a deliberate P0
  choice so untracked scratch cannot become context by accident. The cost
  surfaced when `PADMAVYUH_ARCHITECTURE_V2.md` was added but unstaged and the
  gateway could not see it.
- **Decision**: one bounded operation that reads exactly one caller-named
  path, tracked or not. It never enumerates, globs or recurses — a glob is
  treated as a literal filename. Root containment, symlink-escape, blocked and
  opaque patterns, line limits and redaction all still apply.
- **Why this is not a new exfiltration path**: the caller must already know
  the exact path, and every existing control is unchanged. Broad indexing
  stays tracked-only, asserted by a test.

## ADR-034 — the product and shared package are named Annulon

- **Status**: accepted (owner direction, 2026-09-20)
- **Problem**: the working name was taken directly from the architecture
  document's metaphor. The owner asked for a distinct name not already in use.
- **Decision**: **Annulon**, from *annulus*, a ring. The product is concentric
  rings of independent verification, which carries the original concept
  without borrowing the word. The Python package is `annulon`.
- **Availability checked, not assumed** (2026-09-20): free on PyPI, free on
  npm, and zero matching repositories on GitHub. Two alternatives were
  rejected on collision -- `sentrion` has six GitHub projects including an
  unrelated "SentrionAI", and `limenar` has adjacent names in use.
- **Scope of the rename**: the package, its imports and the prose I authored.
  The owner's `PADMAVYUH_ARCHITECTURE_V2.md` keeps its filename, and earlier
  ADRs keep their original wording -- history is preserved, not rewritten.
- **Metaphor discipline unchanged**: layered defence remains a design
  metaphor. More rings do not automatically mean more security, and no single
  ring is advertised as perfect.

## ADR-035 — severity, confidence and model score are three different things

- **Status**: accepted. Implements ADR-030.
- **Decision**: an assessment carries *severity* (impact if true), *confidence*
  (evidential strength, ordinal), and a *confidence basis* (why). A statistical
  result carries `model_score_uncalibrated` plus a mandatory `model_id`, and
  nothing in the codebase converts it into a probability.
- **Why ordinal, not numeric**: `0.92` is meaningless without a defined
  meaning, a documented calibration procedure, an identified dataset and an
  evaluation. None of those exist, so a number here would be the legacy
  detector's hardcoded `0.93` with extra steps.
- **Enforced by test**: no `risk_score` field exists; no arithmetic relates
  severity to confidence; a confidence without a basis is refused; a model
  score without a model identity is refused.

## ADR-036 — missing evidence is a separate type from evidence

- **Status**: accepted
- **Problem**: absence has several causes -- the thing did not happen, the
  sensor was down, the queue overflowed, the capability is unsupported. If
  absence is modelled as evidence with a stance it will eventually be
  counted, and "we did not see it" becomes "it did not happen".
- **Decision**: `MissingEvidence` is its own type with no stance, and every
  `MissingReason` describes a *collection* gap. Collection faults are
  distinguished from configuration choices, and a fault degrades the
  assessment's collection health.
- **Concrete consequence**: an unanswered liveness probe is recorded as
  missing evidence, never as evidence the host departed. That is the legacy
  reasoning error, now impossible to express.

## ADR-037 — corroboration is checked by lineage, not by detector count

- **Status**: accepted
- **Problem**: three detectors reading one event are not three confirmations.
  Nothing prevents a product from claiming otherwise.
- **Decision**: evidence carries `origin_group` and `parent_evidence_ids`;
  `EvidenceGraph.root_event_ids` resolves what a piece of evidence ultimately
  rests on, and a summary flags `shared_root_events`. The deterministic
  explanation says so in words.
- **Honest limit**: `origin_group` means *distinct collection origin*. It is
  **not** a claim of statistical independence, and the docstring says so
  because the field name invites the stronger reading.
- **Deliberately absent**: weighted sums, Bayesian fusion, Dempster-Shafer.
  A sophisticated formula over poorly defined evidence is worse than an
  explicit rule. Fusion is evaluated against real experiments in V2-CORR-01.

## ADR-038 — netlink proc connector is the baseline host sensor

- **Status**: accepted, on measurement rather than popularity.
- **Method**: ground truth written only by the launcher, each candidate
  observing independently, compared afterwards. Ubuntu 24.04.4,
  kernel 7.0.0-1012-aws, t3a.large.

| Workload | proc connector | /proc poll 100 ms | /proc poll 10 ms |
|---|---|---|---|
| 500 x `/bin/true` | **500/500** | **0/500** | **0/500** |
| 100 x `sleep 250ms` | 100/100 | 100/100 | 100/100 |

- **Decision**: the netlink process connector (`CN_IDX_PROC`) is the baseline
  discovery sensor. It needs no compiler, no BPF toolchain, no third-party
  package and no BTF -- a raw socket and `struct` -- and it observed every
  process in both workloads.
- **`/proc` is demoted from discovery to enrichment.** It may be read for a
  PID the connector has already reported, to obtain argv and credentials. It
  is never the mechanism by which a process is discovered. The race where the
  process exits before `/proc` is read becomes a `PARTIAL_FIELDS` quality
  flag on an event we already have, rather than an event we never had.
- **eBPF is the upgrade path, not the baseline.** Measured directly with
  `bpftrace` on `sys_enter_execve`: 507 events captured including all 500
  target binaries, *with filenames*. It offers push semantics and argv
  together, which the connector cannot. It is deferred because it adds a
  toolchain and a kernel-version surface for a capability the baseline can
  approximate, and it sits behind the same `HostSensor` interface so adopting
  it later changes one package.
- **Rejected**: `/proc` polling as a discovery mechanism, at any interval.
  10 ms was no better than 100 ms, and the failure is structural rather than
  a tuning problem.
- **Not evaluated**: auditd (absent on the image, and its rule configuration
  is a deployment surface in its own right). Recorded as an option, not a
  dismissal.

## ADR-039 — a sensor must declare what it cannot see

- **Status**: accepted. Comes directly from the V2-HOST-01 measurement and is
  the more important half of it.
- **Observation**: both polling sensors missed 500 of 500 short-lived
  processes and reported `lossy: false`. They were not wrong -- a drop
  counter reports only the loss a sensor *noticed*, and polling never
  notices. A sensor that misses everything while reporting healthy is more
  dangerous than one that fails loudly, because downstream "no findings"
  reads as "nothing happened".
- **Decision**: `SensorHealth` carries `attests_completeness` and a
  `blind_spot` description, and exposes `trustworthy_absence`. A detector
  asks that question before treating silence as meaningful. Polling declares
  it cannot attest; the connector attests only until the kernel signals a
  drop, after which it stops.
- **Consequence for the evidence model**: this is what feeds
  `MissingReason.SENSOR_UNAVAILABLE` and the degraded collection health that
  forces an assessment to `INCONCLUSIVE` (ADR-036). The two halves now meet.

## ADR-040 — nothing stays verified: periodic whole-system re-verification

- **Status**: accepted (owner direction: "always check once in a while all")
- **Problem**: every invariant in this project was verified once, at the
  moment it was built. A guard can be narrowed, a policy edited, a package
  added outside a boundary, an AWS resource left running, an allowance left
  in place after it stopped being needed. None of these announce themselves,
  and the tests that would catch them are not the tests anyone is running
  while working on something else.
- **Decision**: `tools/verify_all.py` re-checks every standing invariant in
  one pass -- working tree, branch hygiene, memory integrity, the context
  firewall, framework boundaries, committed secrets, the full suite, and
  optionally live AWS state. Run it between tasks, not only when something
  feels wrong.
- **Two design rules, both learned immediately**: a check that always warns
  is a check everyone ignores, so the secret scan **fails** on anything
  outside an explicit list of known fixtures with stated reasons; and the
  list itself is checked for entries that no longer apply, so allowances
  cannot quietly accumulate.
- **Evidence it was worth building**: the first run found KF-32 in a shipped
  module, and raising the bar from WARN to FAIL immediately surfaced two more
  files nobody had accounted for.

## ADR-041 — the agent proves its sensor is alive rather than assuming it

- **Status**: accepted
- **Problem**: `running=True` because a socket is open asserts almost
  nothing. The descriptor survives the kernel ceasing delivery, a filter
  installed underneath, a dropped subscription, or a dead collector thread.
  In each case the agent reports healthy and sees nothing, and downstream
  "no findings" reads as "nothing happened". No counter can catch it,
  because there is nothing to count.
- **Decision**: the agent periodically execs a nonce-named marker of its own
  and confirms it observed it. A failed probe sets the sensor to FAILED and
  removes the claim that its silence is meaningful, which propagates into
  collection health and from there into assessments (ADR-036, ADR-039).
- **Details that matter**: the nonce means a stale event from an earlier
  probe cannot satisfy the current one; events drained while hunting for the
  marker are put back, so self-checking never destroys evidence; an
  un-probed monitor reports *not* healthy, because reporting healthy on no
  evidence is the habit being broken; and a host that genuinely cannot exec
  disables the check explicitly rather than silently failing it forever.

## ADR-042 — a component may request an action; it may not authorize one

- **Status**: accepted
- **Decision**: `ActionRequest` has **no field** in which a caller can assert
  that its request is permitted. The only type carrying an authorization
  outcome is `AuthorizationDecision`, produced by the broker from a request
  plus broker-owned policy, with no deserialiser that can yield an ALLOW.
- **Why absent rather than ignored**: a boolean on the request would
  eventually be trusted by something. Making the field non-existent is
  cheaper to defend than making every consumer remember to disregard it.
- **No execution primitive in the contract**: there is no `RunShell`,
  `ExecuteCommand` or equivalent, and no free-text command anywhere. A broker
  that accepts a command string is an RPC wrapper around root with extra steps.
- **An unknown field in a serialised request is refused, not ignored.** A
  caller that believes it sent something meaningful must not be silently
  misunderstood by a privileged component.
- **PID is not an available target kind.** A PID authorized now may be a
  different process by the time the action is applied. Only identities whose
  validity can be re-checked at apply time are permitted, and unimplemented
  kinds are not declared at all -- declaring one invites a policy that appears
  to cover something it cannot.

## ADR-043 — broker policy is independent of core honesty

- **Status**: accepted
- **Decision**: fifteen explicit checks, all of which run before the result is
  combined, starting from deny. It is easier to argue that fifteen stated
  checks are correct than that one flexible rule engine is safe.
- **All failures are reported, not the first.** Short-circuiting would make
  the audit record depend on check order, and an operator reading a denial
  wants every reason.
- **Permitted UIDs are an allowlist**, so a new service on the host is not
  containable until someone decides it should be.
- **An oversized TTL is denied, never silently shortened.** Quietly granting
  less than was asked for leaves the caller's record and the broker's
  disagreeing about what is in force.
- **Protected scopes are not requestable.** There is no exemption field.
  Protected destinations include the instance metadata endpoint and loopback,
  because cutting the management path leaves a host unrecoverable except by
  rebuild.
- **An unusable policy is fatal to permissiveness**: an unreadable or
  self-contradictory policy yields a broker that denies, never one that
  allows by default. A UID that is both permitted and protected is refused
  at load, because resolving that contradiction silently either way is a guess.

## ADR-044 — the privileged-action invariant is enforced by test

- **Status**: accepted. Project-level invariant.
- **Statement**: no component other than the authorized response broker may
  perform Annulon privileged response actions.
- **Enforcement**: `test_privileged_action_invariant.py` parses every
  production module and fails if one imports `subprocess`, `ctypes`, `pty` or
  `multiprocessing`, calls a process or privilege primitive, references a
  privileged tool by name, uses `shell=True`, or imports `pickle`. Exemptions
  are an explicit list of three modules, each with a stated reason.
- **Why mechanical**: a rule written only in a document erodes. KF-23 already
  demonstrated that for merge gates.

## ADR-045 — the legacy Java and research tree leaves `main`

- **Status**: accepted (owner direction, 2026-09-20)
- **Decision**: everything inherited from the Floodlight/TopoGuard research
  prototype is removed from `main` and preserved on the long-lived branch
  `legacy/java-topoguard-research`.
- **Removed**: `floodlight_with_topoguard/` (the vendored Java controller),
  `apache-ant-1.10.15/` (a build tool committed into the repository, 45 MB),
  `mininet_archive/`, `zeek/`, `labels/`, `plots/`, the `clab-*` directories
  and topology files, the legacy shell orchestration, the old ML modules
  (`src/*.py`, `main.py`), both notebooks, `dataset_sdn.csv`, the dissertation
  PDF, the legacy CI workflow and the trivial `assert 1 + 1 == 2` test.
- **Kept deliberately**: `docs/LEGACY_CAPABILITY_MAP.md` and
  `docs/LEGACY_SECURITY_MODEL.md`. The *recovered knowledge* is the valuable
  part of that work -- what the research intended, and which behaviours were
  rejected on evidence. Deleting those would discard the reasoning while
  keeping only the conclusions.
- **Branch retention exception**: `legacy/java-topoguard-research` is a
  long-lived archive and is exempt from the delete-on-merge rule. It is never
  merged, so the rule does not reach it.
- **Verification**: 1369 tests pass unchanged after removal, which is itself
  evidence that nothing in the product depended on the legacy tree.
- **Honest note**: git history retains the deleted files; the working tree no
  longer carries them. Removing them from history would require a rewrite,
  which is not warranted and was not requested.

## ADR-046 — the broker decides; only a backend acts

**Status**: accepted, implemented in V2-SAFE-02.

**Problem.** V2-SAFE-01 pre-declared `annulon/response/broker.py` exempt from
the privileged-action invariant, on the reasoning that the broker is the
single privileged path and therefore the module allowed to hold an execution
primitive.

**What changed.** Implementing the broker showed the exemption was not
needed. The broker imports no execution module, calls no execution primitive
and names no privileged tool. All of that lives behind the `Enforcer`
interface in a backend module.

**Decision.** The broker is held to the same invariant as every other module,
and a dedicated test asserts it is absent from `PRIVILEGED_EXEMPT` as well as
free of primitives. Only the enforcement backend is exempt.

**Why it matters.** The broker is the component that parses input from the
process most likely to be compromised. It is therefore the component that
should contain the least worth reaching. Separating "decide" from "act" also
means the authorization argument and the privileged mechanism can be reviewed
independently, which is not true when one module does both.

**Cost.** The backend boundary must carry typed values rather than rendered
commands, which is slightly more code than calling a tool directly. That cost
is the point.

## ADR-047 — caller identity comes from the kernel, and the broker refuses to run without it

**Status**: accepted, implemented in V2-SAFE-02.

**Problem.** The broker must know which process is asking. A request body
that names its sender is a claim, not evidence, and filesystem permissions on
a socket narrow who *can* connect without establishing who *did*.

**Decision.** A Unix domain socket with kernel-supplied peer credentials:
`SO_PEERCRED` on Linux, `LOCAL_PEERCRED`/`LOCAL_PEERPID` on Darwin. The uid is
mapped to a policy identity through broker-owned configuration. A uid that is
not in that map becomes `UNKNOWN_CALLER`, which no policy grants. Root is not
special-cased: a privileged local process is not automatically the core.

On a platform with no peer-credential mechanism the broker **refuses to
start**. Degrading to trusting the payload would be security theatre, and
TCP on loopback was rejected outright — it is reachable by every local
process and carries no identity.

**Consequence.** macOS is a genuine development platform for this component
rather than a degraded one: the same authentication property holds, verified
by tests that run against a real socket.

## ADR-048 — intent is journalled before the OS is touched

**Status**: accepted, implemented in V2-SAFE-02.

**Problem.** An unscheduled restart between authorizing an action and
applying it, or between applying it and recording it, leaves the host holding
state nobody knows about. A "temporary" restriction then becomes permanent.

**Decision.** The broker writes an `APPLYING` record, fsynced, *before*
calling the backend, and the outcome afterwards. Reconciliation at startup
works in both directions: state owned but not journalled is an orphan and is
removed; a record whose state is absent is closed so it stops counting
against the active-action ceiling. An `UNCERTAIN` backend outcome keeps the
action in a state that still counts as holding OS state, because forgetting a
rule that might exist is the unsafe direction.

**Cost.** Two synchronous writes per action, measured at 0.138 ms per
denial-path request including fsync. Acceptable for an operation that is rare
by design and rate-limited.

## ADR-049 — adversarial verification doctrine

**Status**: accepted, permanent, applies retroactively to every campaign.

**Problem.** The suite had grown to 1,513 tests, and that number was starting
to function as an argument. It is not one. A suite that confirms expected
examples says nothing about whether a security property survives hostile
input, partial failure, restart or an incorrect assumption — and Annulon's
own history is mostly defects that passing tests did not catch: KF-22 (a
hung controller produced an empty run that looked clean), KF-23 (a branch
merged with a red guard), KF-36 (four ALLOW-producing defects in code that
had full unit coverage).

**Decision.** QA is adversarial verification. The full doctrine is recorded
in `docs/PROJECT_CONTRACT.md` and the verification matrix in
`docs/TEST_EVALUATION_MASTER_PLAN.md`. Security invariants are machine-readable
in `docs/invariants.json` and each maps to tests and evidence.

**Consequences.**

- Campaign reports state assurance classes, defects found, surviving
  mutations, flaky tests, inconclusive results, claims *not* supported and
  known blind spots — not a test total.
- Mutation testing covers security-critical predicates; any mutation that
  materially weakens ALLOW/DENY semantics must be killed, and survivors are
  recorded as defects or gaps rather than averaged into a percentage.
- Established frameworks (NIST SSDF, OWASP ASVS, NIST SP 800-115, MITRE
  ATT&CK, MITRE ATLAS) are used as requirement sources and threat taxonomies.
  Mapping a control is never claimed as certification, and a framework
  version is never asserted without checking an authoritative source.
- Defect-seeded testing: every KF is generalised to its bug *family*, and the
  family is tested.
- Defect density is information. Four defects at one boundary means that
  boundary had a weak model, so scrutiny there increases rather than closing.

**Cost.** Campaigns take longer and report more uncomfortable results. That
is the intended effect.

## ADR-050 — enforcement coverage is named, never implied

**Status**: accepted, implemented in V2-SAFE-03.

**Problem.** A `meta skuid` + `ip daddr` rule restricts one address family.
Measured in the lab: with such a rule in force, the contained uid still
reached an IPv6 destination. Describing that as "egress restriction" is
false, and the falseness is invisible in the code.

**Decision.** Every enforcement result carries a `Coverage` value —
`ipv4_only`, `ipv6_only` or `all_families` — with `is_complete_egress` true
only for the last. A partial restriction cannot be described as complete
egress containment without contradicting the record the backend produced.

**Also recorded**: the measured semantics of the mechanism, published by
`inspect_state()` rather than only in prose — new connections blocked,
established connections blocked, forked children and execed binaries blocked,
uid escape not possible without privilege, IPv6 not restricted under a v4
rule, and an unrelated process sharing the target uid also contained.

**Limitation accepted for now.** `meta skuid` scopes by uid, not by workload.
For a dedicated service account that is precise; for a shared account it
means collateral containment. Per doctrine §36 this is now demonstrated
physically rather than documented, and cgroup- or unit-based targeting is the
open question for production.

## ADR-051 — mutation testing gates security-critical predicates

**Status**: accepted, implemented in V2-SAFE-04.

**Problem.** The suite was green while every authorization boundary could be
moved by one character without a single test failing (KF-42). Line coverage
did not show it: the lines executed either way. Only asking "if this check
were weakened, would anything notice?" exposed it.

**Decision.** `tools/mutate.py` applies one AST mutation at a time —
comparison flips, `and`/`or` swaps, `not` removal, guard-body deletion — and
runs a nominated test selection against the mutated source. Survivors are
reported individually and recorded as defects or testing gaps.

Scope is narrow on purpose. Run repository-wide this produces thousands of
irrelevant survivors in logging and formatting, and the number stops meaning
anything. It is pointed at authorization predicates, policy, the contract,
the backend and the verifier, where one inverted comparison is a privilege
change.

**Not a percentage.** "94% killed" is not a security statement. "The
protected-target check can be deleted without any test failing" is. Each
survivor is named, and an equivalent mutation is justified in writing rather
than counted as a pass.

**Operational note.** The tool rewrites source in place so pytest imports the
mutated module, which makes concurrent use hazardous — it corrupted a
concurrent test run before a lock was added (KF-41). It now holds an
exclusive lock and restores the original source on SIGINT/SIGTERM.

## ADR-052 — containment does not survive a reboot

**Status**: accepted, documented in V2-SAFE-05.

**Problem.** nftables rules live in kernel memory. Annulon installs no
persistence unit, so a reboot clears every restriction it created. That had
never been decided — it was simply what happened.

**Decision.** Keep it, and say so. A temporary restriction that outlived the
process which understood why it existed would be a restriction nobody can
explain and nobody will remove, and the deadline that made it temporary would
be gone with the journal's owner.

**Consequence, stated rather than hidden.** A genuinely dangerous workload is
unrestricted between boot and the core re-detecting it. That window is real,
and closing it is a detection problem, not a persistence one: the correct fix
is for the core to re-evaluate on startup, never for a rule to survive the
component that justified it.

**What the broker actually observes.** It cannot detect a reboot. It sees a
journal claiming active actions and a kernel holding none — the same shape as
a stale record, resolved the same way. The important part is that those
records are *closed*, because otherwise the active-action ceiling fills with
entries for rules that no longer exist and the broker refuses all new
containment. Tested.

**Revisit when** the agent is expected to hold containment across a
deliberate reboot during an incident. That needs a persistence mechanism with
its own expiry evaluated at boot, which is a larger design than a systemd
unit that replays rules.
