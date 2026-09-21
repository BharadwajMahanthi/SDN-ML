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
| SAFE-AWS-REF-01 | Ubuntu / x86_64 independent validation | OPEN |
| SAFE-IPV6-01 | IPv6 containment | OPEN (KF-38) |
| SAFE-PACKAGE-01 | clean package / install validation | OPEN |
| SAFE-LOAD-01 | load and stress | OPEN |
| SAFE-SOAK-01 | long-running lifecycle | OPEN |
| SAFE-FULLCHAIN-01 | DETECT → DECIDE → CONTAIN → VERIFY → RECOVER | OPEN |

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
