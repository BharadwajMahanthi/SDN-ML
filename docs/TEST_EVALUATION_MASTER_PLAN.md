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
