# Test and evaluation master plan

Created by V2-ARCH-01. P13 consumes evidence from this plan rather than
assembling claims retrospectively.

## System under test

Two distinct assurance scopes, never merged into one claim:

- **SDN pack** — the OpenFlow/OVS integration. Physically evidenced today.
- **Cloud host agent** — an ordinary Ubuntu VM with no OVS. Not started.

## Threat model

Adversary levels A1–A5 per V2 §5. The first production claim targets **A1/A2
only**, within tested telemetry and authorization boundaries. A3
(guest-root/kernel) is explicitly out of claim: no same-kernel agent can be
assumed to report truth against an adversary controlling that kernel.

## Platform profiles

Profile 1, the only one to be validated first: Ubuntu 24.04 LTS x86_64 on a
cloud VM. Windows, containers and serverless remain explicit, funded expansion
tracks — not silently dropped promises, and not claimed by parity.

## Evidence classes

Every claim carries exactly one status: `VERIFIED`,
`SUPPORTED_BY_STATIC_ANALYSIS`, `DIAGNOSTIC_MEASUREMENT`, `PROPOSED`,
`NOT_RUN`, `BLOCKED`, `EVIDENCE_INCOMPLETE`.

## Test classes and what each must include

| Class | Requirement |
|---|---|
| Development tests | run without cloud or lab; deterministic; fake clocks, never sleeps |
| Integration tests | real sensor or real datapath; connection asserted, never inferred |
| Adversarial tests | independent ground truth written only by the harness |
| Negative controls | same scenario, detection disabled; a finding here invalidates the harness |
| Benign controls | matched benign scenario; a finding here is a false positive, counted |
| Fault injection | sensor loss, event loss, restart, management outage, response failure |
| Performance | predeclared workload and environment; burstable instances are diagnostic only |

## Methodology rules

An empty run is **not** a negative result. Every experiment emits a completion
manifest (ADR-029); a run without one is `EVIDENCE_INCOMPLETE`. Ground truth
and detector output are written by different components and compared only
afterwards. Thresholds are predeclared, never tuned to produce a desired
outcome. Correlated evidence is tracked by lineage so one event cannot be
counted as several confirmations.

## Known limitations of this plan

No statistical power analysis yet; sample sizes are currently too small for
false-positive-rate claims. Cross-layer correlation scenarios do not exist.
No independent qualified security review has occurred; two agents agreeing is
not independent review.

## Project terminology (V2-CORE-02)

These are the project-wide definitions. Where a document uses one of these
words it means this, and nothing looser.

| Term | Definition |
|---|---|
| **Observation** | What a sensor reported, factual *within the limits of that sensor*. An `Event`. |
| **Evidence** | An interpretation of, or reference to, one or more observations. Carries its kind, origin and ancestry. |
| **Finding** | A security hypothesis that evidence supports or challenges. Never the same object as an event. |
| **Assessment** | One evaluation of a finding at a point in time. Append-only; a new assessment supersedes rather than overwrites. |
| **Severity** | Potential impact **if the finding is true**. Says nothing about certainty. |
| **Confidence** | How strongly the available evidence supports the finding. Ordinal, never a probability. |
| **Confidence basis** | *Why* the confidence is what it is, recorded alongside it. |
| **Contradictory evidence** | Evidence that argues against the hypothesis. First-class, not a score decrement. |
| **Missing evidence** | Something expected that did not arrive. A collection gap, never evidence that the thing did not happen. |
| **Inconclusive** | A legitimate outcome. Insufficient information is an answer, not a failure to decide. |
| **Independent collection origin** | Material from a different collection source. **Not** a claim of statistical independence. |

A finding whose supporting evidence shares a source event is one observation
seen several ways. It is reported as such, in the record and in the
explanation.

## Measured sensor baseline (V2-HOST-01)

Ubuntu 24.04.4, kernel 7.0.0-1012-aws, t3a.large. Ground truth written only
by the launcher; each sensor observed independently.

| Workload | proc connector | /proc poll 100 ms | /proc poll 10 ms |
|---|---|---|---|
| 500 short-lived (`/bin/true`) | 500/500 | 0/500 | 0/500 |
| 100 long-lived (250 ms) | 100/100 | 100/100 | 100/100 |

`bpftrace` on `sys_enter_execve` captured all 500 target execs with filenames.

**The result that shaped the design**: both polling sensors reported zero
loss while missing everything. Detection rate alone is therefore not a
sufficient sensor metric; every evaluation must also record whether the
sensor can attest to completeness.

## Verification matrix — V2-SAFE-03, Linux egress containment

Per ADR-049 this records assurance *classes* and what is not covered, not a
test total.

### REQUIREMENT → THREAT → CONTROL → TEST → EVIDENCE → LIMITATION

**Property: the core cannot execute privileged containment.**
- Threat: compromised core.
- Control: separate broker; backend behind a typed interface; broker holds no
  execution primitive.
- Tests: `test_privileged_action_invariant.py` (AST guard incl. the broker
  itself), `test_broker_ipc.py` (Experiments A–F), `test_broker_fuzz.py`.
- Physical evidence: `docs/evidence/v2-safe-03-containment.json`.
- Limitation: kernel or root compromise is outside the claim.

**Property: Annulon never deletes firewall state it cannot prove it created.**
- Threat: a security tool removing the operator's firewall during an incident.
- Control: own table only; ownership read from rule metadata; unprovable rules
  reported, never removed.
- Tests: forged comments, version-mismatched comments, rules in other chains,
  table removal refused, release of a rule bearing our id but unprovable.
- Physical evidence: `foreign_tables` identical before and after (`ip nat`).
- Limitation: ownership rests on a rule comment; a root attacker can write one.

**Property: containment is claimed only when control plane and data plane agree.**
- Threat: reporting containment while traffic still flows.
- Control: `annulon.response.verification.assess`.
- Tests: `test_verifier_integrity.py` — 8 harness-failure modes, every field
  unmeasured, every single-field failure, every *pair* of failures.
- Physical evidence: false-pass control (destination server never started) →
  `EVIDENCE_INCOMPLETE`.

### Assurance classes

| Class | State |
|---|---|
| UNIT | 431 response tests |
| PROPERTY | single- and pairwise-failure sweeps over the verifier; coverage sweep |
| FUZZ | IPC decoder + broker: 3,000 seeded randomised cases, exhaustive per-field hostile values |
| INTEGRATION | broker over a real Unix socket with kernel peer credentials |
| PHYSICAL E2E | real nftables, real packets, Docker Desktop Linux VM |
| NEGATIVE CONTROL | no-action run; false-pass control |
| FAULT INJECTION | nft false success, false failure, vanishing rule, malformed JSON, timeout |
| BYPASS | shared uid, IPv6, established connections, fork, exec, setuid, alternate destination |
| MUTATION | **NOT_RUN** — scheduled for V2-SAFE-04 |
| CONCURRENCY | **NOT_RUN** — scheduled for V2-SAFE-05 |
| CRASH/RECOVERY | partial (restart, reconciliation); full matrix in V2-SAFE-05 |
| LOAD / SOAK | **NOT_RUN** |
| PACKAGING / SUPPLY CHAIN | **NOT_RUN** |

### Platform matrix

| Environment | Status |
|---|---|
| macOS native (arm64) | unit/property/fuzz/integration SUPPORTED; no kernel enforcement |
| Docker Desktop Linux VM (6.12.76-linuxkit aarch64) | nftables containment VALIDATED; proc connector absent |
| Ubuntu AWS x86_64 | **NOT_RUN** for containment — required independent reference |

Two runs on one Docker VM are one platform validation, not two.

### Claims supported

- A uid-scoped IPv4 egress restriction is installed, blocks the target's new
  *and* established connections, blocks forked children and execed binaries,
  leaves an unrelated uid unaffected, leaves foreign tables unchanged, and is
  removed on the broker's own deadline with traffic restored.

### Claims NOT supported

- "Egress restricted" without qualification — IPv6 is not covered by a
  v4-scoped rule (KF-38).
- Any containment claim on Ubuntu/EC2 — not yet run there.
- Per-workload targeting — `skuid` contains every process under the uid,
  demonstrated physically.
- Behaviour under concurrency, load, or the full crash matrix.

### Known blind spots

- UDP, DNS and loopback paths untested under a scoped rule.
- Ownership comments are forgeable by root.
- No mutation testing yet on authorization predicates.
