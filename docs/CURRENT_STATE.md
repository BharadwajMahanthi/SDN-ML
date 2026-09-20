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
