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
