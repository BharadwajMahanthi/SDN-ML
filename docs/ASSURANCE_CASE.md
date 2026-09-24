# Annulon assurance case — A1 and A2

> **Scope statement, read this first.** This document claims that a small,
> named set of malicious actions was physically defeated on named platforms,
> with evidence anyone can re-run. It does **not** claim Annulon is secure,
> that it detects attacks it has not been tested against, or that a defender
> using it will win. Those claims would be unfalsifiable, and a security
> product that makes them is asking to be trusted rather than checked.
>
> Every capability's status, profile, evidence and limitations are in
> `docs/capabilities.json`, which `tools/verify_all.py` refuses to let drift.

---

## The two claims

**A1 — Bounded privilege.**
*Compromise, malfunction, hallucination or bad logic in the Annulon core does
not yield arbitrary privileged operating-system execution.*

**A2 — Truthful observation.**
*Annulon does not convert ambiguous, missing, degraded or adversarial input
into a stronger security statement than the evidence supports.*

A1 is about what an attacker who owns the core can do. A2 is about whether
anything Annulon says can be believed. They are separate because a system can
satisfy either alone and still be useless: a perfectly bounded agent that
lies about what it saw, or a truthful agent that hands an attacker root.

---

## A1 — Bounded privilege

### The argument

A compromised core can ask for exactly one thing: a time-bounded egress
restriction on a uid that broker policy already permits, scoped to a
destination and port, at a rate policy already caps. It cannot name a new
action, reach a protected uid or destination, extend a TTL, replay a grant,
or cause execution.

This holds because of four structural properties, each held by a test rather
than by convention:

| property | mechanism | held by |
|---|---|---|
| a component may request, not authorize | no field in `ActionRequest` can assert permission; no `from_dict` yields an ALLOW | `test_action_contract.py` |
| the caller is identified by the kernel | `SO_PEERCRED` / `LOCAL_PEERCRED`; an unmapped uid is `UNKNOWN_CALLER`, which no policy grants; root is not special-cased | `test_broker_ipc.py` |
| the broker decides but cannot act | it holds no execution primitive at all | `test_privileged_action_invariant.py`, ADR-046 |
| exactly one module executes | the packet-filter backend, plus the process sensor's own nonce marker, each listed with a reason | `test_pack_trust_boundaries.py` |

### What was physically attempted, and defeated

On `REF-HOST` (Ubuntu 24.04.4, kernel 7.0.0-1012-aws, x86_64) and `REF-DEV`
unless stated. Evidence: `v2-safe-04-unauthorized.json`,
`v2-host-04g-fullchain-ubuntu-x86_64.json`.

| malicious action attempted | outcome |
|---|---|
| contain root (uid 0) | denied `target_protected` |
| contain a uid outside the allowlist | denied `target_not_permitted` |
| contain `sshd`, `amazon-ssm-agent`, `annulon-broker`, `annulon-core` | denied `target_protected` |
| cut the instance metadata endpoint | denied `destination_protected` |
| restrict `0.0.0.0/0` | denied `destination_protected` |
| request a TTL beyond policy | denied `duration_exceeds_policy` |
| replay a previously granted request | denied `replayed_request`, backend untouched |
| submit a stale or future-dated request | denied `request_expired` / `request_from_the_future` |
| target a previous boot | denied `target_not_current` |
| invent an action type (`run_shell`, `execute_command`, `raw_nftables`) | refused at decode |
| add a permission-shaped field (`authorized`, `policy_override`, `skip_policy`, `decision: allow`) | refused as an unknown field, eleven variants |
| claim to be the core in the request body | ignored; identity comes from the kernel |
| flood requests | rate-limited |

**And the part that matters most:** for all eight physical unauthorized
requests, the **entire `nft` ruleset was byte-identical before and after**,
traffic was unchanged, and no rule was created by any denial. A denial that
perturbed the ruleset would mean the attacker achieved something by asking.

A positive control ran in the same experiment: an authorized request was
applied and contained. Without it, "everything was denied" would equally
mean the broker is broken.

### A1 limitations, stated

- **Kernel or root compromise is outside the claim.** An attacker who is
  already root can write the ownership comments the backend trusts, remove
  the broker, or change the policy file. A1 bounds a compromised *core*, not
  a compromised *host*.
- A caller that can already run as the core's uid **is** the core. A1 bounds
  what it can do, not whether it can ask.
- Containment does not survive a reboot, by design (ADR-052).
- The broker's own configuration is trusted. Nothing validates it against an
  external authority.

---

## A2 — Truthful observation

### The argument

Annulon separates four things that are usually conflated: severity from
confidence, absence from ignorance, applied from verified, and attempted from
established. Each separation is enforced by a type, not a convention.

| conflation avoided | mechanism |
|---|---|
| severity ≠ confidence | `Assessment` carries both; a `HIGH` finding with an `INCONCLUSIVE` verdict stays `WEAK` |
| absence ≠ innocence | `trustworthy_absence` must hold before silence means anything; liveness must be actively proved |
| applied ≠ verified | control-plane and data-plane evidence must agree; disagreement is `ACTION_EFFECT_NOT_VERIFIED` |
| attempted ≠ established | `EINPROGRESS` is `PENDING`; a connect return never implies a socket state |
| several detectors ≠ several witnesses | lineage: one root event is one origin group |

### What was physically attempted, and defeated

| adversarial scenario | outcome |
|---|---|
| 6 concurrent same-uid processes to one destination | 150/150 attributed to the right pid, **0 unlaunched pids named** |
| 304 interrupt-context completions with attractive `comm` values | **0 named a process** |
| 20 short-lived processes, all exited before scoring | all observed, attribution stayed weak, **none fabricated instance binding** |
| a reused pid whose start time disagrees | resolution refused |
| stale observation replayed into a new liveness probe | rejected |
| another process connecting to the liveness listener | did not certify the sensor |
| a forged `is_self_test` field | ignored; internal status comes from in-process state |
| the primary tracepoint disabled while the thread stayed alive | probe `FAILED`, absence untrusted |
| 30 real connections while the sensor was blind | **0 observed**, `attests_completeness` false |
| 4,000 connections against a saturated queue | 0.63 % coverage, 47,965 drops **counted**, completeness withdrawn |
| 3,000 seeded fuzz cases + exhaustive per-field hostile values | zero reached the backend; positive control still passes |

### A2 limitations, stated

- **Short-lived connections are now attributable**, because identity is
  captured when the process connector reports a start rather than read from
  `/proc` afterwards: measured 40 of 40 against 0 of 40 for the previous
  behaviour (ADR-057). The residual window is a process that connects before
  its start notification is processed, which only an in-kernel capture
  removes. `NETWORK_TELEMETRY_EBPF` remains NOT_RUN.
- Flow identity is **not namespace-qualified** on the tracefs tier, and the
  data says so via `flow_key_is_namespace_qualified`.
- Detection covers a deterministic egress allowlist. **No behavioural,
  statistical or ML detection exists**, and none is claimed.
- UDP is not covered. Pre-existing connections are not discovered.
- The longest soak is 15 minutes. RSS growth flattened across it, which is
  consistent with allocator warm-up and does not prove the absence of a slow
  leak. Multi-hour runs are NOT_RUN.
- Ownership comments are forgeable by root.

---

## Evidence index

| artifact | what it establishes | profile |
|---|---|---|
| `v2-safe-03-containment.json` | first physical containment with negative and non-target controls | REF-DEV |
| `v2-safe-04-unauthorized.json` | eight unauthorized requests, ruleset byte-identical | REF-DEV |
| `v2-safe-05-recovery.json` | crash, restart, reconciliation; foreign rule untouched | REF-DEV |
| `v2-host-04a-sensor-evaluation.json` | `/proc` polling rejected on measurement | REF-DEV |
| `v2-host-04c-network-sensor.json` | 500/500 capture, false-silence control | REF-DEV |
| `v2-host-04d-network-liveness.json` | liveness fails with the thread alive and the sensor blind | REF-DEV |
| `v2-host-04e-adversarial.json` | attribution under concurrency, softirq, short-lived processes | REF-DEV |
| `v2-host-04f-fullchain-docker.json` | full chain, development platform | REF-DEV |
| **`v2-host-04g-fullchain-ubuntu-x86_64.json`** | **full chain on the reference profile** | **REF-HOST** |
| `v2-pkg-01-clean-install.json` | the installed artifact works with no repository present | REF-DEV |
| `v2-load-soak.json` | truthful degradation under saturation; bounded resources | REF-DEV |
| `v2-rel-01-attribution.json` | short-lived process attribution, 0/40 to 40/40 | REF-DEV |
| `v2-rel-ipv6-containment.json` | IPv6 egress containment enforced and verified | REF-DEV |
| `v2-rel-02-signed-install.json` | six release substitutions refused | REF-DEV |
| **`v2-rel-03-refhost-validation.json`** | **signed install and 15-minute soak on the reference profile** | **REF-HOST** |

---

## What would falsify these claims

An assurance case that cannot be attacked is not one. Concretely:

- **A1 fails** if any input to the broker produces an ALLOW that policy does
  not permit, if a denial changes OS state, if any module outside the named
  set executes, or if a request field influences authorization.
- **A2 fails** if any observation is attributed to a process the sensor could
  not identify, if `trustworthy_absence` is true while events were lost, if a
  finding reaches `SUPPORTED` under degraded collection, or if containment is
  claimed without agreeing control-plane and data-plane evidence.

Each of those has at least one test that fails when the property is removed,
and mutation testing confirms the tests notice: `contract.py` 0 survivors of
96, `nftables.py` 0 of 72, `broker.py` 0 of 52, `verification.py` 0 of 34,
`policy.py` and `normalize.py` with only demonstrated equivalents remaining.

## Defect history as evidence

Forty-eight recorded failures (`docs/KNOWN_FAILURES.md`), the majority found
by the project's own adversarial testing rather than in production. The ones
that most support these claims are the ones where a control was **wrong**:
four ALLOW-producing coercion defects (KF-36), every authorization boundary
movable by one character (KF-42), enforcement coarser than detection (KF-51),
an evidence artifact misnaming its own platform (KF-52), and a commit that
bypassed the merge gate (KF-54).

A project that has never found a defect in its own controls has not looked.

## Not claimed

Universal security. Detection of untested attack classes. Protection against
a compromised kernel or an attacker already running as root. Fleet, cloud and
AI capabilities — all `NOT_IMPLEMENTED`. SDN fabric containment and in-kernel
process identity — `NOT_RUN`. Key rotation and revocation, artifact
provenance attestation, and multi-hour soak — `NOT_RUN`. Any performance
target. That defenders always win.

## A third claim, added at release

**A3 — Trustworthy delivery.** *A host does not install an artifact the
project did not sign, and cannot be downgraded to an older signed release
except to the version the current one explicitly names.*

Physically attempted and refused on both profiles: an artifact swapped after
signing, a manifest edited after signing, a signature from an untrusted key,
a manifest carrying an unknown field, a rollback to an unnamed version, and a
genuine but older signed release — every byte of which verifies. On
`REF-HOST` the same genuine artifact was refused against a key file that did
not contain its signer, then accepted against one that did.

A3 does **not** cover key rotation, key revocation, or provenance beyond the
signature; and the signing key's own protection is outside the software.
