# ACCEPTANCE CRITERIA

> Rebaselined against V2 (ADR-027). The numerical targets below belong to the
> **SDN pack**. The cloud host agent has its own criteria, stated in the
> section that follows, and does not inherit these. `P13-SDN` and
> `P13-cloud-agent` are different assurance scopes and must never be merged
> into one claim.

All numerical targets below are **PROPOSED — NOT APPROVED, NOT MEASURED**.
They are placeholders to be replaced with owner-approved values before any
benchmarking, and must never be reported as measurements.

## Environment and workload (to be fixed before benchmarking)

Not yet defined for the SDN pack. Requires the P3 Linux/OVS lab to exist.

## Proposed targets (unapproved)

| Metric | Proposed | Status |
|---|---|---|
| Supported switches | 8 | PROPOSED |
| Supported hosts | 64 | PROPOSED |
| Packet-in events/sec | 500 | PROPOSED |
| Detection latency p50 / p95 / p99 | 50 / 200 / 500 ms | PROPOSED |
| Enforcement latency p95 | 1 s | PROPOSED |
| False-positive rate (benign mobility) | < 1% | PROPOSED |
| Controller restart recovery | < 30 s | PROPOSED |
| Soak duration | 4 h | PROPOSED |

## Met today

| Gate | Target | Measured | Status |
|---|---|---|---|
| Firewall suite | all pass | 82 passed | VERIFIED |
| Memory suite | all pass | 59 passed | VERIFIED |
| Rolling memory cap | ≤ 8 MiB incl. transaction reserve | enforced pre-append | VERIFIED |

## Release gates not met

Independent qualified review of security-critical assumptions and
enforcement: **NOT PERFORMED**. Agreement between two agents is not
independent review (V2 §19).

Per V2 §19 a release candidate additionally requires evidence for
installation, enrollment, sensor health, ordinary-host detection, scoped
response, recovery, management outage, bounded resources, policy/update trust,
and customer-data boundaries. **None of these exist.** The first production
claim targets adversary levels A1/A2 only; A3 is explicitly out of claim.


---

# Cloud host agent — acceptance criteria

These are **capability criteria, not performance targets.** No latency or
throughput number below is approved or measured; the host agent's performance
work is `SAFE-LOAD-01` and `V2-PERF`, and nothing here may be reported as a
measurement.

A capability is `SUPPORTED` only on a **reference profile** where it has been
physically demonstrated, with independently produced evidence. Reproducing a
result on the development platform is not validation of the reference one.

## Reference profiles

| id | profile | role |
|---|---|---|
| `REF-DEV` | Docker Desktop Linux VM, linuxkit kernel, aarch64, container | development and integration evidence |
| `REF-HOST` | Ubuntu LTS x86_64 on EC2 `t3a.large`, pinned AMI, no inbound ports, SSM only | **the reference profile** |

`REF-DEV` results never promote a capability to `SUPPORTED` on `REF-HOST`.
The kernel build, the architecture and container-versus-host isolation all
differ, and each has already produced a different answer at least once
(`CONFIG_CONNECTOR` absent on linuxkit; PID namespace mismatch).

## What closes each obligation

| obligation | closed when |
|---|---|
| `SAFE-AWS-REF-01` | the full chain runs on `REF-HOST` with its own evidence artifact |
| `SAFE-FULLCHAIN-01` | DETECT→DECIDE→CONTAIN→VERIFY→RECOVER completes on `REF-HOST` with the detector's finding and the traffic verification **independently produced**, and every stage control passing |
| `SAFE-IPV6-01` | IPv6 egress restriction is enforced and verified, or the capability is renamed to exclude it |
| `SAFE-PACKAGE-01` | the chain runs from an installed artifact in a clean environment, not a repository checkout |
| `SAFE-LOAD-01` | load and stress characterised with loss, health and correctness under load reported together |
| `SAFE-SOAK-01` | a long run shows no leak in memory, descriptors, journal, replay cache or timers |

## Host capability criteria

Each row is `SUPPORTED` only with an evidence artifact naming the profile.

| capability | criterion |
|---|---|
| process telemetry | short-lived processes observed with a declared completeness attestation; a negative control produces zero findings |
| network telemetry | process-attributed IP connection observation; loss counted; false silence becomes degraded, never clean |
| sensor liveness | health requires an actively demonstrated observation of a probe the sensor caused, not a live thread |
| attribution | same-uid processes distinguishable; weak attribution visible as weak; no accusation without a resolvable workload |
| detection | deterministic, falsifiable rule; no finding while collection is degraded; detector cannot act |
| authorization | broker-owned policy the core cannot read; default deny; every limit enforced at its boundary |
| containment | reversible, time-bounded, no broader than the detection that justified it; benign traffic on the same host unaffected |
| effect verification | control-plane and data-plane evidence must agree; disagreement is `ACTION_EFFECT_NOT_VERIFIED` |
| recovery | expiry driven by the privileged process; a restart never extends an action; foreign state never deleted |

## Explicitly out of scope for the current assurance case

Universal security. Detection of untested attack classes. Any claim that
defenders always win. The assurance case is scoped to the specific malicious
actions physically tested, and says so.
