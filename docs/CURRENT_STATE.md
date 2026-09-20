# CURRENT STATE

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
| Stage 2+ | NOT_RUN | — |

## Repository layout (ADR-020)

`development/` holds the new system and nothing else. Everything at the root
that is not `tools/`, `tests/tools`, `tests/memory`, `docs/` or `memory/` is
legacy, and is due for deletion or removal to its own branch. That is the
owner's call; the split is already complete on this side.

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
- **B-5** The lab runs on root AWS credentials. See KF-19. Status: OPEN, HIGH.
- **B-2** The legacy Java build expects JDK 11; the host has JDK 17 and
  `build.xml` pins `source/target=1.6`. Marked
  `LEGACY_JAVA_RUNTIME_NOT_REQUIRED_FOR_CURRENT_MIGRATION`. Not a blocker; no
  JDK will be installed unless a specific unanswered behavioural question
  requires executing Java. Status: OPEN, not on the critical path.

## Current task

P2-MIGRATION-01 complete. The objective changed by owner direction: the Java
POC is archaeology, not a system to repair. Audit findings are retained in
KNOWN_FAILURES.md and converted into Python design requirements and tests via
PYTHON_MIGRATION_MATRIX.md.

## Exact next action

**P6-OF-01** on branch `feat/p6-openflow-01-osken-adapter`: implement the real
OS-Ken adapter behind the P5 contract, with `os_ken` and `eventlet` confined
to the adapter package and that confinement enforced by the existing AST test.
The lab substrate is proven; recreate it with
`development/infra/lab/create.sh` and tear it down with `destroy.sh`.
