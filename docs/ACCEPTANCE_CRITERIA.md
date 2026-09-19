# ACCEPTANCE CRITERIA

All numerical targets below are **PROPOSED — NOT APPROVED, NOT MEASURED**.
They are placeholders to be replaced with owner-approved values before any
benchmarking, and must never be reported as measurements.

## Environment and workload (to be fixed before benchmarking)

Not yet defined. Requires the P3 Linux/OVS lab to exist.

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
independent review.
