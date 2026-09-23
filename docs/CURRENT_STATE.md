# CURRENT STATE

> **Product name: Annulon** (ADR-034). Shared package `annulon`;
> the SDN integration remains `sdnguard`.
>
> **Scope changed 2026-09-20 (ADR-027).** The product is a local-first security
> agent for an ordinary Linux cloud server. SDN topology integrity is one
> optional protection pack. Everything below that predates this line describes
> the SDN pack, whose evidence remains valid within that scope.

Updated at the close of P1. Status vocabulary: VERIFIED / SUPPORTED_BY_STATIC_ANALYSIS /
REPORTED / HYPOTHESIS / NOT_RUN / BLOCKED.

## Verified progress

| Milestone | Status | Evidence |
|---|---|---|
| P0 context firewall | VERIFIED | `pytest tests/tools` — 82 passed |
| P1 project memory | VERIFIED | `pytest tests/memory` — 59 passed |
| P2 legacy comprehension + migration spec | VERIFIED (docs) | LEGACY_CAPABILITY_MAP, LEGACY_SECURITY_MODEL, PYTHON_MIGRATION_MATRIX, ARCHITECTURE |
| P3-DOMAIN-01 value identities | VERIFIED | 163 domain tests; 306 total |
| P3-DOMAIN-02 host types | VERIFIED | 238 domain tests; 381 total |
| P3-DOMAIN-03 security events | VERIFIED | 290 domain tests; 433 total |
| P3-DOMAIN-05 clock abstraction | VERIFIED | 309 domain tests; 452 total |
| P3-DOMAIN-04 property tests | VERIFIED | 6 invariant families; 481 total |
| P4-TOPO-01 port state | VERIFIED | 508 total |
| P4-TOPO-02 switch/link lifecycle | VERIFIED | 532 total |
| P4-HOST-01 host table | VERIFIED | 560 total |
| P4-MOVE-01/02 movement state machine | VERIFIED | 609 total |
| P4-PROBE-01/02 probe manager | VERIFIED | 640 total |
| P4-DETECT-01/02 detectors | VERIFIED | 665 total |
| P4-POLICY-01 / EVIDENCE-01 | VERIFIED | 38 policy tests; 730 total |
| **P4 complete** | VERIFIED | full chain, no OpenFlow dependency |
| P5-OF-01 framework selection | VERIFIED (ADR) | OS-Ken candidate; conformance NOT_RUN |
| P5-OF-02/03/07 adapter + controller | VERIFIED | 26 adapter tests; 766 total |
| P5-OF-04/05/06 packet normalisation | VERIFIED | 37 parser tests; 803 total |
| P5-OF-06/08/09, real adapter | UNBLOCKED | lab substrate now exists |
| **P6-LAB-01 Linux/OVS lab** | **VERIFIED ON REAL HARDWARE** | Ubuntu 24.04.4, kernel 7.0.0-1012-aws, OVS 3.3.9, dpid 0000aabbccddeeff |
| P6-CLOUD-SEC-00 credentials | VERIFIED | scoped role, temporary sessions, 19 checks / 0 unexpected |
| **P6-OF-01 / LAB-02 / LAB-03** | **VERIFIED ON REAL OVS** | real OpenFlow 1.3 session, real PacketIn -> HostObservation, ground truth matched |
| Stage 2+ | NOT_RUN | — |

## Repository layout (ADR-020)

The legacy Floodlight/TopoGuard tree has been removed from `main` (ADR-045)
and preserved on the long-lived branch `legacy/java-topoguard-research`. The
repository is now Python only:

```
development/src/annulon      the platform
development/src/sdnguard     SDN integration, one optional pack
development/infra            lab and experiments
tools/ docs/ memory/         governance
```

The recovered-knowledge documents are kept deliberately: the reasoning about
what the research intended, and which behaviours were rejected, is the part
worth having.

## What exists

- `development/src/sdnguard/` — the system (domain, topology, hosts, probes,
  detection, policy, observability, adapter, controller)
- `development/infra/` — the AWS/Linux/OVS lab
- `tools/context_policy.{yaml,py}`, `redact.py`, `repo_query.py`,
  `safe_exec.py`, `safe_test.py`, `safe_diff.py`
- `memory/policy.json`, `tools/memory_store.py`, `tools/memory.py`,
  `tools/agent_session.py`
- Eight durable documents in `docs/`, `AGENTS.md`, `CLAUDE.md` (import only)

## What does NOT exist yet

`src/sdnguard/domain/identity.py` — `DatapathId`, `PortNumber`,
`PortIdentity` as frozen value types, standard library only.

No controller, no OVS lab, no detector, no policy engine, no feature pipeline,
no model artifact, no AWS lab. The Java Floodlight tree is untouched and is
reference material only (ADR-004).

## Blockers

- **B-1** RESOLVED (2026-09-20). An AWS EC2 lab now provides a real OVS
  kernel datapath: `openvswitch` module loaded, datapath types `[netdev,
  system]`, four namespaces on explicit veth pairs, traffic proven to cross
  the datapath with **zero packets** on the EC2 management interface.
- **B-5** MITIGATED. Normal operation runs on temporary STS credentials from
  `sdnguard-lab-role` (ADR-023), verified by 19 allow/deny/control checks with
  0 unexpected results. Root keys are still active. See below.

## ROOT_KEY_REPLACEMENT_READY — OWNER_ACTION_REQUIRED

The replacement credential path is live and proven. Deactivating the root keys
is deliberately **not** automated, because a mistake there locks the account.

Exact manual steps for the owner:

1. Sign in to the AWS console **as root**.
2. Account menu -> **Security credentials**.
3. Under **Access keys**, find the key currently configured on this
   workstation's `default` CLI profile.
4. Choose **Deactivate** first, not Delete.
5. Confirm the project still works: `development/infra/lab/verify_credentials.sh`
   should still report 0 unexpected, since it uses the `sdnguard` profile.
6. Once satisfied, return and **Delete** the deactivated key.
7. Optional but recommended: enable MFA on the root user and stop using it
   for anything except account-level administration.

Afterwards, KF-19 can be closed and P11-AWS-02 becomes completable. Until
then P11-AWS-02 must be reported as incomplete.
- **B-2** The legacy Java build expects JDK 11; the host has JDK 17 and
  `build.xml` pins `source/target=1.6`. Marked
  `LEGACY_JAVA_RUNTIME_NOT_REQUIRED_FOR_CURRENT_MIGRATION`. Not a blocker; no
  JDK will be installed unless a specific unanswered behavioural question
  requires executing Java. Status: OPEN, not on the critical path.

## Governance

The merge gate is executable (`tools/merge_gate.py`, ADR-031). `python
tools/merge_gate.py run --task <ID>` produces a commit-bound result; `merge`
refuses anything that is not PASS, with no override. KF-23 is covered by a
test that performs a real merge attempt in a throwaway repository.

## V2 status

| Track | State |
|---|---|
| SDN pack (P0–P6) | physically evidenced; see the table above |
| V2 shared core | **V2 SHARED SEMANTICS FOUNDATION** — completion semantics, common event envelope, entity refs, capability manifest |
| Cloud host agent | **real process -> event -> evidence -> finding, on real Linux** with a passing negative control; no containment |
| AI security | NOT_RUN |

No host, cloud, identity or AI protection capability exists: there is no
sensor, no agent, no host detection and no containment. Completed SDN task IDs
are **not** evidence for any of them. What V2-CORE-01 delivers is contracts
and their tests, not protection.

## Current task

P2-MIGRATION-01 complete. The objective changed by owner direction: the Java
POC is archaeology, not a system to repair. Audit findings are retained in
KNOWN_FAILURES.md and converted into Python design requirements and tests via
PYTHON_MIGRATION_MATRIX.md.

## Exact next action

**V2-SAFE-02** on branch `feat/v2-safe-02-privileged-broker`: the separate
broker process, authenticated local IPC with peer credentials, and a bounded
durable action journal. The contract and policy exist and refuse a
compromised core in unit tests; nothing is physically enforced yet.


## Owner action — committed lab CA private keys (KF-35)

Three Containerlab CA private keys are in the public history of `main`. They
are gone from the current tree and are low-impact (ephemeral lab TLS, no
access to any real system), but they are real private keys in a public
repository. Removing them requires rewriting published history, which is an
owner decision.

Option A — accept and move on. Defensible: the keys are worthless outside a
lab that no longer exists, and the tree is already clean. No action.

Option B — purge from history:

```bash
# Requires git-filter-repo. Rewrites every commit; all clones must be re-cloned.
git filter-repo --invert-paths --path-glob '*/.tls/ca/ca.key' --path-glob '*/.tls/ca/ca.pem'
git push --force origin main legacy/java-topoguard-research
```

Coordinate before running it: a force-push to a public repository breaks
every existing clone and fork, and the archive branch must be rewritten in
the same pass or it will reintroduce the blobs.

## Owner action — publishing is blocked by repository permissions

`git push` to `origin` fails with HTTP 403. The authenticated GitHub account
is `mbkirusa`; the repository is `BharadwajMahanthi/SDN-ML`, and that account
has no write access to it.

Consequence: `main` is **25 commits ahead of `origin/main`** locally, and the
archive branch `legacy/java-topoguard-research` exists only on this machine.
Until this is resolved, the published repository still shows the Java tree
and does not contain any Annulon work.

Resolution is owner-level, either:

- authenticate as the repository owner — `gh auth login` as
  `BharadwajMahanthi`, or add that account with `gh auth switch`; or
- grant `mbkirusa` write access to the repository.

Then:

```bash
git push origin legacy/java-topoguard-research   # publish the archive first
git push origin main
```

Publishing the archive branch discloses nothing new: its blobs are already in
`origin/main` (see KF-35).


## V2-SAFE-02 — the privileged broker (complete, 2026-09-21)

A separate broker process now owns every privileged action. The core can ask;
it cannot decide and it cannot act.

**Verified by execution:**

- Caller identity comes from the kernel, over a real Unix socket:
  `SO_PEERCRED` on Linux, `LOCAL_PEERCRED`/`LOCAL_PEERPID` on Darwin. A uid
  absent from the broker's own map is `UNKNOWN_CALLER`, which no policy
  grants. Root is not special-cased into the core.
- The broker refuses to start where peer credentials are unavailable, rather
  than trusting the payload.
- Experiments A–F all pass: unauthorized caller, authorized request, unknown
  action type, protected target and destination, oversized TTL, and broker
  unavailable yielding `ENFORCEMENT_UNAVAILABLE` — which is a distinct
  outcome from `DENIED`, with no fallback path in which the core acts itself.
- Intent is journalled and fsynced *before* the OS is touched; a test fails
  the backend mid-apply and asserts the journal already knew.
- Restart, expiry and reconciliation: the replay cache is rebuilt from the
  journal, orphaned state is removed, and records whose state is gone are
  closed so they stop counting against the active-action ceiling.
- Fuzzing found four defects that produced an **ALLOW**, all now fixed and
  regression-tested (KF-36). 3,000 seeded randomised cases plus exhaustive
  per-field hostile values reach the backend zero times, with a positive
  control proving a valid request still succeeds.
- **Cross-platform, same code:** 363 response tests pass on macOS natively
  and on a real Linux kernel (6.12.76-linuxkit, aarch64) via
  `development/infra/local/lab.sh`.

**Not yet verified:** nothing is physically enforced. The only backends are
`UnavailableEnforcer`, which refuses, and `RecordingEnforcer`, which is a
test double reachable from no production entry point. Real `nftables`
containment is V2-SAFE-03. Until then, no containment claim is supported by
anything but unit evidence.

Measured: 0.138 ms per denial-path request including the fsync.


## V2-SAFE-03 — first physical containment (complete, 2026-09-21)

**FIRST ANNULON PHYSICAL CONTAINMENT**, on a real Linux kernel.

    HOST:               macOS (arm64)
    ENFORCEMENT KERNEL: Docker Desktop Linux VM, Linux 6.12.76-linuxkit
    MECHANISM:          Linux nftables, meta skuid

Verdict from `annulon.response.verification`, not from the harness:
`COMPLETE / TRUSTWORTHY / CONTAINED`, zero unmeasured fields.

Target: dedicated synthetic uid 1500. Traffic before OPEN, during
TimeoutError, after OPEN; unrelated uid 1600 OPEN throughout; negative control
OPEN; foreign tables unchanged; expiry driven by the broker's own sweeper.

**Adversarial results that changed the product:**

- KF-38: an IPv4-scoped rule leaves IPv6 open. The capability is now named
  *IPv4 egress restriction*, and every result carries a `Coverage` value.
- KF-37: `nft` text output is forgeable by the comment it describes;
  ownership is read from JSON only.
- KF-39: the bypass harness measured root's socket rather than the target
  uid's and nearly reported a false "established connections survive"
  finding. Corrected: established connections are blocked.

**Measured mechanism semantics** (published by `inspect_state()`): new
connections blocked, established blocked, fork blocked, exec blocked, uid
escape not possible without privilege, shared uid also contained, IPv6 not
restricted under a v4 rule.

**NOT_RUN:** mutation testing, concurrency, full crash matrix, load, soak,
packaging, and any containment claim on Ubuntu/EC2.


## V2-SAFE-04 — the authorization boundary, attacked (complete, 2026-09-21)

The core is treated as hostile: every request in `test_compromised_core.py`
is syntactically valid and each one tries to obtain slightly more authority
than policy grants.

**Mutation testing became a gate (ADR-051).** `tools/mutate.py` flips
comparisons, swaps `and`/`or`, removes `not` and deletes guard bodies one at
a time, then asks whether the suite notices. It found that the suite was
green while every authorization boundary could be moved by one character
(KF-42). Results after closing the gaps:

| module | killed | survived |
|---|---|---|
| `contract.py` | 91 | 0 |
| `nftables.py` | 72 | 0 |
| `policy.py` | 47 | 1 (verified equivalent) |
| `broker.py` | 52 | 0 |
| `verification.py` | 34 | 0 |

**Defects found and fixed:**

- KF-40 — a target uid had several spellings. Arabic-Indic, Devanagari and
  fullwidth digits all satisfy `isdigit()` and convert via `int()`, so
  `١٥٠٠` resolved to uid 1500 and was authorized;
  `01500` was a second spelling of the same uid. Now canonical ASCII only.
- KF-41 — the mutation tool corrupted a concurrent test run by rewriting
  source in place. Now holds an exclusive lock and restores on signal.
- KF-42 — every limit tested inside and outside its range, never at it.

**`verify_all.py` gained `security_invariants`**, which asserts every
invariant in `docs/invariants.json` maps to test files that exist. It failed
on its first run: three invariants pointed at paths that had never existed.

**Physical evidence** (`docs/evidence/v2-safe-04-unauthorized.json`): eight
unauthorized requests through the live socket to a broker wired to the real
nftables backend. All denied; the *whole* `nft` ruleset byte-identical before
and after each one; traffic unchanged; no rule created by any denial. The
positive control in the same run was applied and contained, so "everything
was denied" cannot be explained by a broken broker.

**NOT_RUN:** load, soak, packaging, supply chain, reboot semantics, and
anything on Ubuntu or x86_64.


## V2-SAFE-05 — crash, restart and reconciliation (complete, 2026-09-21)

The broker is killed at every meaningful point in an action's life, and the
only question asked after each restart is whether the durable record agrees
with what the host actually holds.

**Physical evidence** (`docs/evidence/v2-safe-05-recovery.json`) — all
against a real kernel, with a rule genuinely installed and the broker
genuinely discarded:

| case | result |
|---|---|
| containment survived broker death | yes, traffic still blocked |
| deadline survived the restart | new broker expired it, rule removed, traffic restored |
| rule present with no journal entry | removed as an orphan |
| journal active with rule missing | record closed |
| foreign rule inside Annulon's own table | **left untouched**, classified UNKNOWN |
| table removal while a foreign rule is present | refused |

The foreign-rule case is the one worth the effort. A rule shaped like ours
but carrying an unknown format version was installed directly with `nft`;
reconciliation left it in place, reported it as unknown, and refused to
remove the table it sits in.

**Unit crash matrix**: crash before authorization, during apply, after apply
before journal, during TTL, during release; journal write failure; truncated
journal tail; clock rollback and forward jump. Plus four concurrency races —
duplicate request, expiry versus release, the active ceiling under a race,
and reconciliation running against live requests.

**Reboot semantics (ADR-052)**: containment deliberately does *not* survive a
reboot, and the records for it are closed on restart so the active-action
ceiling does not fill with entries for rules that no longer exist. The
resulting exposure window between boot and re-detection is recorded rather
than hidden.

**NOT_RUN:** load, soak, packaging, supply chain, and anything on Ubuntu or
x86_64.


## Status correction — SAFE implementation vs SAFE assurance

    V2-SAFE-01..05   IMPLEMENTATION COMPLETE
    SAFETY ASSURANCE PARTIAL

Carried as explicit assurance obligations, not reopened branches:

| id | obligation | state |
|---|---|---|
| SAFE-AWS-REF-01 | Ubuntu / x86_64 independent validation | **CLOSED 2026-09-24** |
| SAFE-IPV6-01 | IPv6 containment | OPEN (KF-38) |
| SAFE-PACKAGE-01 | clean package / install validation | OPEN |
| SAFE-LOAD-01 | load and stress | OPEN |
| SAFE-SOAK-01 | long-running lifecycle | OPEN |
| SAFE-FULLCHAIN-01 | DETECT → DECIDE → CONTAIN → VERIFY → RECOVER | **CLOSED 2026-09-24** |

## V2-HOST-04A — network sensor evaluation (complete, 2026-09-21)

Four mechanisms measured on one kernel against one independent ground truth.
Selected: a **private tracefs instance** with three tracepoints (ADR-053).
Evidence: `docs/evidence/v2-host-04a-sensor-evaluation.json`.

Headline measurements:

- `/proc/net/tcp` polling **rejected on evidence**: 1 ESTABLISHED sighting
  against 44,389 TIME_WAIT sightings for 500 connections. Its 93.8 % capture
  rate counts connections that had already closed.
- Tracepoints captured **500 of 500** attempts, and `ESTABLISHED` transitions
  matched the server's accept count exactly.
- **Every successful connection returned `-115` (EINPROGRESS)**, so the
  connect return value cannot be used to decide success.
- eBPF alone reads `start_boottime` in-kernel (match to 0.26 ms), which would
  solve PID reuse and the exit race at source. Named `NETWORK_TELEMETRY_EBPF`,
  NOT_RUN.
- The sensor sees host PIDs: the workload was PID 20 in its container and
  84658 to the sensor.


## V2-HOST-04B — the network observation contract (complete, 2026-09-21)

Strictly typed from the start, because KF-36 showed coercion is how a wrong
type becomes a valid value.

- `NetworkOperation` declares only what the selected sensor can truthfully
  distinguish: attempt, result, established, closed. `SEND` and `ACCEPT` are
  deliberately absent until a mechanism is measured that reports them.
- `ConnectionOutcome.PENDING` exists because `EINPROGRESS` is neither success
  nor failure, and is the *common* case for any socket with a timeout.
- `AttributionConfidence` makes a PID-only attribution visible as such.
  `instance_key` combines tgid with a start time, so PID reuse produces two
  different identities.
- `SocketSemantic` forbids the unqualified word "owner": the process that
  creates a socket, connects it and writes to it can all differ.
- `flow_key` includes the network namespace, because one address pair can
  exist in several namespaces at once.
- IPv6 is first-class here, unlike containment where it is a stated gap.

**KF-43, found before shipping**: `re.compile(r"^...$")` admits a trailing
newline in Python, so a "printable ASCII only" guard accepted `"worker\n"`.
Fourteen patterns repo-wide had the same shape, including `identity.py`'s
control-byte check, the privileged action contract, and the redactor's
identifier heuristic — where the failure direction was *under*-redaction. All
converted to `\A...\Z`, with `tests/tools/test_validation_anchors.py`
enforcing it repository-wide and proving the hazard is real before forbidding
it.


## V2-HOST-04C — the network collector (complete, 2026-09-21)

Process-attributed IP connection observation against a real kernel.
Evidence: `docs/evidence/v2-host-04c-network-sensor.json`, all twelve checks
COMPLETE.

| measurement | result |
|---|---|
| short-lived burst captured | **500 / 500**, workload already exited |
| ground truth agreement | server accepted 500 |
| destinations resolved | 500 |
| **process attribution accuracy** | **1.0** (500 of 500 correct PID) |
| kernel + queue loss | 0 |
| softirq events naming a process | **0** |
| same-uid processes distinguishable | yes |
| false-silence control | 50 connections occurred, 0 observed, health degraded |

**The design inverted during this task (KF-45).** `sys_enter_connect` looks
like the natural source and is not: tracefs renders its argument as a
pointer, so it cannot supply a destination, port or address family, and it
fires for AF_UNIX — which made the interpreter's own startup look like four
network connections. The primary event is now the `TCP_CLOSE -> TCP_SYN_SENT`
transition, which is IP-only by construction, carries full addressing, and
was measured correct in 35 of 35 task-context events.

**KF-44**: the reader deadlocked on shutdown because `close()` from another
thread waits on the lock a blocked buffered `read()` holds. Rewritten on a
non-blocking descriptor with `select`.

**A v4-mapped address on a dual-stack socket is reported as IPv4**, because
the packet on the wire is IPv4. Recording it as IPv6 would let an IPv4 policy
miss it — the KF-38 mistake one layer up.

**NOT_RUN / not covered**: UDP, pre-existing connections (post-start activity
only), PID-reuse under physical forcing, container namespace attribution,
AWS/Ubuntu, and in-kernel process-instance identity (`NETWORK_TELEMETRY_EBPF`).


## V2-HOST-04D — network sensor liveness (complete, 2026-09-21)

**Security property established**: Annulon can actively demonstrate that the
selected network observation path is *currently* able to observe a kernel
network event, and refuses to treat silence as meaningful when it cannot.

**Tested environment**: Docker Desktop Linux VM, kernel `6.12.76-linuxkit`,
aarch64, host PID namespace, `NETWORK_TELEMETRY_TRACEFS`. Evidence:
`docs/evidence/v2-host-04d-network-liveness.json`, all twelve checks COMPLETE.

| case | result |
|---|---|
| positive control | connection opened **and** observed, latency 0.0013 s, `HEALTHY` |
| primary tracepoint disabled | reader thread **alive**, fd open, probe `FAILED`, absence untrusted |
| false silence | 30 connections made, 30 accepted, **0 observed**, `attests_completeness` false |
| recovery | later clean probe `HEALTHY`, earlier failure still on record |
| cancellation | 0.002 s |
| shutdown with probe history | 0.204 s, no KF-44 recurrence |

**What the disabled-tracepoint case shows** is the whole point of the branch:
a liveness check based on `thread.is_alive()` would have reported healthy
while the sensor was completely blind and real traffic was flowing.

**Design points** (ADR-054): the receipt is taken *after* the bounded queue
and the normaliser, so a saturated userspace path cannot be reported healthy
because parsing still works; the fresh ephemeral port is the nonce and the
match also requires our own pid, loopback, the selected `TCP_SYN_SENT`
semantic, transport, family and window; `consider()` reads and returns
without consuming, so self-checking cannot destroy evidence; and internal
traffic is recognised from the ports this monitor actually bound, never from
a field on the event.

**Health semantics reuse the existing model.** `network_collection_health`
returns `SensorHealth`, so detectors keep asking `trustworthy_absence`
(ADR-039). A failed probe removes the right to treat silence as meaningful
and never becomes evidence that something happened.

**Claims NOT supported by 04D**: external connectivity, DNS, or reachability
of any remote host — the probe is loopback and proves only that a kernel
network event reaches an Annulon observation. Forced kernel ring-buffer
overrun was not induced physically in this run; the degraded-on-loss path is
covered by unit tests over `LossCounters`, not by a physical overrun.

**Mutation coverage**: `liveness.py` 81 killed of 83, 2 survivors both
proven equivalent (`<` vs `<=` on monotonic floats; a history trim whose
final length is identical either way — demonstrated, not asserted). The first
pass left 22 survivors, every one in a predicate this branch relies on.

**Still NOT_RUN**: `NETWORK_TELEMETRY_EBPF`, UDP, pre-existing connections,
physically forced PID reuse, container namespace attribution, IPv6 liveness
on a v6-capable network, physically forced ring-buffer overrun, and
everything on Ubuntu / x86_64.


## The V2-HOST-04E / 04F boundary (owner-set, strict)

**04E establishes that the network evidence itself is hard to fool within its
declared capability. It does not close SAFE-FULLCHAIN-01.**

04F is where a trusted network event participates in the ordinary-host
vertical slice on the reference profile:

    real prohibited network attempt
      -> healthy real network sensor
      -> correct process/workload attribution
      -> detector independently produces a finding
      -> policy proposes a bounded response
      -> broker independently authorizes
      -> real nftables backend
      -> real traffic effect verified independently
      -> benign service remains available
      -> expiry / restart / recovery

Two conditions bind 04F, and neither is satisfiable by 04E:

- **SAFE-AWS-REF-01 requires the intended reference profile**, Ubuntu on
  x86_64. Reproducing the linuxkit/aarch64 result again is not independent
  validation of a different kernel build, architecture or host type.
- **SAFE-FULLCHAIN-01 requires the detector's finding and the verifier's
  traffic result to be independently produced.** A harness that requests
  containment directly proves only the response half of the chain — the half
  V2-SAFE-03 already proved. The detector has to reach the finding on its own
  from sensor evidence, and the traffic verifier has to measure the effect
  without consulting Annulon.

**Documentation debt for 04F, not 04E**: `docs/ACCEPTANCE_CRITERIA.md` still
states that host criteria are undefined and that no host release evidence
exists. That was stale before 04D and is more so now. 04F should carry a
scoped host/reference-profile acceptance update so the project has one
authoritative statement of what the AWS reference run actually closes.
Redesigning all acceptance targets is out of scope for both branches.


## V2-HOST-04E — adversarial verification of network telemetry (complete, 2026-09-22)

**Security property tested**: for `NETWORK_TELEMETRY_TRACEFS` on the tested
environment, Annulon does not convert ambiguous, stale, reordered,
cross-process, cross-namespace, degraded, malformed or adversarial telemetry
into a stronger statement than the evidence supports.

**Physical environment**: Docker Desktop Linux VM, kernel
`6.12.76-linuxkit`, aarch64, host PID namespace. Evidence:
`docs/evidence/v2-host-04e-adversarial.json`, fifteen checks COMPLETE.

| scenario | measured |
|---|---|
| 6 concurrent processes, one uid, one destination | 150 connections, 150 accepted, **150 observed, 6 distinct pids, 0 unlaunched pids attributed** |
| connect result semantics | 152 `pending`, 3 `established`, 0 pending misread as established; no result invented a destination |
| softirq attribution | 304 completions, **0 named a process** |
| 20 short-lived processes | all exited before scoring; 40/40 observed; **all attribution weak, none claimed instance binding** |
| bounded burst, 800 connections | 800 observed, queue drained to 0, loss counted and consistent with health |
| false silence | 40 made, 40 accepted, **0 observed**, thread alive, `trustworthy_absence` false |
| recovery | `HEALTHY` again, failed interval still recorded |

**Defects found and fixed:**

- **Flow identity was structurally inert.** `flow_key` used
  `network_namespace or 0` while the normaliser hardcodes `None`, so every
  observation shared namespace `0` and `None == 0`. The contract advertised
  namespace-aware flow identity that production never had. Unknown now
  renders `ns:unknown` and never equals a known namespace, and
  `flow_key_is_namespace_qualified` tells a consumer whether equality means
  anything. The tracefs tier cannot determine an observed socket's namespace,
  and stamping the sensor's own would be fabrication.
- **KF-46** — `dport=\u0661\u0665\u0660\u0660` parsed as port 1500.
  KF-40's family reappearing in a parser written after the rule was
  generalised. Now canonical ASCII decimal only.
- **KF-47** — a connect attempt was recognised from `newstate` alone, so a
  line with no `oldstate` produced a confident attempt. Both halves of the
  declared `TCP_CLOSE -> TCP_SYN_SENT` transition are now required.
- **KF-48** — an anomalous *positive* connect return was coerced to zero and
  classified `ESTABLISHED`. `connect()` never returns a positive value, so
  the coercion turned an unexplained reading into the strongest possible
  claim. Found by mutation testing, not by a hand-written case. It now maps
  to `OTHER_ERROR`.

**Claims supported**: within `NETWORK_TELEMETRY_TRACEFS` on this environment,
process-attributed IP connection observation separates same-uid processes
under concurrency, survives process exit without upgrading attribution,
refuses interrupt-context process context, keeps attempt / syscall result /
established state as distinct facts, and makes loss and blindness visible.

**Claims explicitly NOT supported**: `NETWORK_TELEMETRY_EBPF`; UDP;
physically forced PID reuse; container namespace attribution; pre-existing
connection discovery; IPv6 external behaviour; Ubuntu / x86_64; production
load limits; reconnaissance or exfiltration detection; network containment;
and **SAFE-FULLCHAIN-01, which 04E does not close**.

**Not induced**: kernel ring-buffer overrun. The 800-connection burst
produced zero loss, so the degraded-on-loss path remains covered by unit
tests over `LossCounters` rather than by a physical overrun.

### Mutation results, with every survivor accounted for

`contract.py` **0 survivors of 96**, from 17. `normalize.py` from 12
survivors down to the set below. Each remaining one is demonstrated
equivalent by execution, not labelled:

| site | why it is equivalent |
|---|---|
| `local.family is IPV6 and remote.family is IPV6` | `_endpoint()` is called with the *same* `family` for both ends, so they can never differ; `and` and `or` select identically |
| `if not address` | an empty address reaches `ip_address("")`, which raises `ValueError` and is caught by the same `except` that the guard's early return feeds |
| `parsed.version != family.version` | without it, `Endpoint` raises `NetworkContractError` for the mismatch and is caught by the same handler |
| `if mapped is None` in `_unmap` | without it, `Endpoint(str(None), ...)` raises `NetworkContractError` and is caught identically |

Two survivors were **real gaps** and are now covered: `_read_boot_time` had
no test at all (trace timestamps are seconds since boot and unanchorable
without it), and the partial v4-mapping case — a dual-stack socket with a
v4-mapped local address talking to a genuine IPv6 peer — would have been
half-unmapped into a mixed-family record the contract then rejects, silently
losing a real observation.

One survivor was **redundant code** rather than a missing test: after the
KF-48 fix the positive-return branch returned exactly what the fall-through
returns. It was removed. Redundant code in a security path is a place for a
future edit to diverge unnoticed.


## V2-HOST-04F (part 1) — the full chain, on the development platform

**COMPLETE on `docker-desktop-linux-vm`, kernel `6.12.76-linuxkit`, aarch64.**
Evidence: `docs/evidence/v2-host-04f-fullchain-docker.json`.

    DETECT   6 supported findings, attribution=correlated, reached independently
    DECIDE   policy proposed -> broker APPLIED under its own policy
    CONTAIN  nftables rule OWNED, uid 1500, scoped to one address and port
    VERIFY   forbidden:  OPEN -> TimeoutError -> OPEN
    BENIGN   permitted:  OPEN -> OPEN -> OPEN
             bystander:  OPEN throughout
    RECOVER  expired by the broker, rule removed, traffic restored

The detector reached its finding from sensor evidence alone; the harness
never told it a violation occurred. The traffic verifier is a separate
process that never consults Annulon.

**Stage controls, each proving its stage is load-bearing:**

| control | result |
|---|---|
| detector permits the traffic | same traffic, no finding, nothing contained |
| broker absent | `ENFORCEMENT_UNAVAILABLE`, no false claim of blocking, traffic still open |
| sensor disabled | 6 connections made, 1 observed, no SUPPORTED finding, absence untrusted |

**Defects found and fixed: KF-49, KF-50, KF-51** (see KNOWN_FAILURES).
KF-51 is the important one — enforcement was coarser than detection and took
out the workload's legitimate service. `destination_port` now flows through
contract, proposal and backend.

**This does NOT close SAFE-FULLCHAIN-01 or SAFE-AWS-REF-01.** Both require
the same experiment on the intended reference profile, Ubuntu on x86_64.
Reproducing an aarch64 linuxkit result is not independent validation of a
different kernel build, architecture or host type.

**Blocking the reference run**: the available AWS identity is **root**
(KF-19). Running the reference lab on root credentials would violate the
least-privilege requirement and repeat a finding the project already
recorded, so scoped credentials are a prerequisite rather than a convenience.


## V2-HOST-04G — the reference full chain on Ubuntu x86_64 (complete, 2026-09-24)

**SAFE-AWS-REF-01 and SAFE-FULLCHAIN-01 are closed.**

**Profile**: `REF-HOST/ubuntu-ec2-x86_64` — Ubuntu 24.04.4 LTS, kernel
`7.0.0-1012-aws`, x86_64, EC2 `t3a.large`, pinned AMI, no inbound ports, SSM
only. Evidence:
`docs/evidence/v2-host-04g-fullchain-ubuntu-x86_64.json`.

Unlike the development platform, this kernel has `CONFIG_CONNECTOR=y` and
`CONFIG_PROC_EVENTS=y`, so the proc connector, nftables and `SO_PEERCRED` are
all available — the capability probe reports all three.

    DETECT   6 supported findings, attribution=correlated, reached independently
    DECIDE   policy proposed -> broker APPLIED under its own policy
    CONTAIN  nftables rule OWNED, uid 1500, scoped to one address and port
    VERIFY   forbidden:  OPEN -> TimeoutError -> OPEN
    BENIGN   permitted:  OPEN -> OPEN -> OPEN
             bystander:  OPEN throughout
    RECOVER  expired by the broker, rule removed, traffic restored
    VERDICT  CONTAINED, claim supported

All three stage controls passed on this platform: detector-permits-it,
broker-absent, sensor-disabled.

**Attribution under a real kernel**: 34 resolved, 30 process-gone, 0
start-time mismatches. Roughly half of short-lived connections still cannot
be bound to a workload even with eager resolution, which is the measured cost
of not having in-kernel process identity and remains the argument for
`NETWORK_TELEMETRY_EBPF`.

**Credential posture**: the lab ran entirely on 1-hour STS credentials from
`sdnguard-lab-role`, verified 19 expected / 0 unexpected / 0 inconclusive
including ten denials. Root was used for exactly one IAM call — minting the
entry-user key, because AWS refuses to let a root account assume a role — and
that key was deleted afterwards. KF-19 remains open.

**Cost and cleanup**: one `t3a.large` for under an hour. `destroy.sh`
reported CLEANUP VERIFIED with zero billable resources remaining; only the
IAM baseline stack persists, which has no running cost.

**Defects found**: KF-52 (an evidence artifact misnamed its own platform),
KF-53 (the deploy transfer had stopped shipping new experiments).


## V2-INT-01 — one evidence boundary, and claims that must be earned (complete, 2026-09-24)

**SDN findings now join the host findings on one boundary.**
`sdnguard/v2/findings.py` maps a detector's `SecurityFinding` onto the shared
model. SDN identity survives as an `SDN_ATTACHMENT` entity whose namespace
carries the network scope, so a correlator can join on an attachment without
knowing what a datapath id is. Severity maps across; **confidence does not**
— a `HIGH` fabricated link whose verdict is `INCONCLUSIVE` stays weak.

**No SDN finding offers containment.** Fabric enforcement is `NOT_RUN`, and
advertising a response nothing can carry out would invite a policy layer to
propose it.

**Four boundaries moved from "holds by absence" to "holds by test"**
(`test_pack_trust_boundaries.py`): observing packs cannot reach the response
machinery beyond the typed contract and the asking client; the proposal layer
cannot construct a decision; the broker holds no execution primitive; and
exactly two named modules may spawn a process — the enforcement backend and
the process sensor's own nonce marker, each listed with its reason.

**`docs/capabilities.json` is now the single statement of what is claimed.**

| status | capabilities |
|---|---|
| SUPPORTED (6) | host process telemetry, network telemetry, sensor liveness, egress detection, IPv4 containment, SDN topology detection |
| NOT_RUN (3) | `NETWORK_TELEMETRY_EBPF`, IPv6 containment, SDN fabric containment |
| NOT_IMPLEMENTED (3) | fleet, cloud control-plane telemetry, AI tool authorization |

`tools/verify_all.py` gained `capability_claims`, which refuses a `SUPPORTED`
claim with no evidence, no profile, an unknown profile or an evidence file
that does not exist, and refuses a `NOT_RUN` entry that claims a profile.
Demonstrated to fail on a planted bogus claim and pass once removed.

**Remaining before the assurance case**: packaging from a built artifact in a
clean environment (`SAFE-PACKAGE-01`), load (`SAFE-LOAD-01`) and soak
(`SAFE-SOAK-01`).
