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
| P4 deterministic security core | NOT_RUN | next |
| Stage 2+ | NOT_RUN | — |

## What exists

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

- **B-1** BLOCKS REAL OVS INTEGRATION ON CURRENT HOST. macOS + Docker Desktop
  cannot provide an observable kernel datapath. It does **not** block the
  Python architecture, domain model, state machine, or any unit/property test.
  Later options: Linux VM, dedicated Linux machine, or AWS EC2 test host.
  Status: OPEN, scoped.
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

**P4-TOPO-01** on branch `feat/p4-topology-01-port-state`: port records and
HOST/SWITCH/UNKNOWN classification driven by LLDP observation, plus the
per-host port-down evidence flag recovered from `PortProperty` (rows S-01,
S-02, S-03). P3 is complete: the domain model is framework-independent and
every invariant has a property test.
