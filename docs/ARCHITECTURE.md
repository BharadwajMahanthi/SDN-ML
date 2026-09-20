# ARCHITECTURE

> The target architecture is now `PADMAVYUH_ARCHITECTURE_V2.md` (ADR-027).
> This document describes the SDN pack, which remains one integration inside
> it. `V2_RECONCILIATION.md` maps the components below onto V2.

Status language: this is a **prototype under design**. Nothing here is
production-ready, proven or validated.

## Today (VERIFIED)

Two support layers exist and are tested (143 tests): the context firewall
(`tools/context_policy*`, `redact.py`, `repo_query.py`, `safe_*.py`) and the
project memory (`tools/memory_store.py`, `memory.py`, `agent_session.py`).

No controller, detector, policy engine or feature pipeline exists yet. The
Java tree is reference material only and is not on the delivery path.

## Target Python system (SPECIFIED, not built)

```
              OpenFlow Adapter          (framework-specific, thin, swappable)
                     │
                     ▼
            Event Normalization         ─── typed domain events cross here
                     │                      no framework object goes below
        ┌────────────┴────────────┐
        ▼                         ▼
  Topology State             Host State
  (ports, port typing,       (host table, locations,
   port-down evidence)        TTL-bounded)
                                  │
                                  ▼
                          Movement Engine        (state machine, pure)
                                  │
                                  ▼
                        Validation / Probe       (nonce, deadline, expiry)
                                  │
                                  ▼
                         Detection Engine        (deterministic first)
                                  │
                                  ▼
                           Policy Engine         (observe-only by default)
                                  │
                                  ▼
                       Enforcement Adapter       (scoped, expiring, reversible)
```

**The boundary rule**: below *Event Normalization* nothing imports an
OpenFlow library. Security logic consumes `HostObservation`, `MovementEvent`,
`ProbeResult` — plain typed values — so it is testable on macOS with no OVS.

Packet forwarding stays in the data plane. Expensive work (training, reports,
research) never runs inside a controller callback; the path between
normalisation and detection uses a bounded queue with explicit overload
behaviour.

## Host movement state machine (P2-C)

Derived from the recovered intent in `LEGACY_SECURITY_MODEL.md`, not from
Java control flow.

```
            observation
   UNKNOWN ─────────────► LEARNED ◄──────────────────┐
                             │                       │
              location change│                       │ observation at
                             ▼                       │ accepted location
                      MOVE_OBSERVED                  │
                             │                       │
              evaluate evidence, emit probe          │
                             ▼                       │
                        VALIDATING ──────────────────┤
                       ╱     │      ╲                │
        probe reply   ╱      │       ╲  deadline,    │
        from OLD     ╱       │        ╲ no reply     │
                    ▼        ▼         ▼             │
         SUSPICIOUS_MOVE  INCONCLUSIVE  MOVE_ACCEPTED┘
                    │        │
                    ▼        ▼
                  (finding emitted; policy decides)
```

| Element | Definition |
|---|---|
| **States** | `UNKNOWN`, `LEARNED`, `MOVE_OBSERVED`, `VALIDATING`, `SUSPICIOUS_MOVE`, `MOVE_ACCEPTED`, `INCONCLUSIVE` |
| **Events** | `observation(HostObservation)`, `probe_reply(ProbeResult)`, `deadline(ProbeRequest)`, `switch_lost(DatapathId)`, `port_down(PortIdentity)` |
| **Guards** | `location != current_location`; `probe.nonce` matches an outstanding request; `now <= probe.deadline`; the reply arrived on the **old** port |
| **Actions** | record evidence; issue a probe with a fresh nonce; emit a `SecurityFinding`; update the host table |
| **Timeouts** | every probe carries a mandatory deadline; `VALIDATING` **must** leave on `deadline` if no reply arrives; host locations expire on a TTL |
| **Invariants** | (1) a host has at most one accepted location; (2) every `VALIDATING` host has exactly one outstanding probe; (3) no state collection is unbounded; (4) a probe resolves exactly once — reply or deadline, never both |
| **Failure modes** | probe unsendable (switch gone) → `INCONCLUSIVE`; duplicate reply → ignored, invariant 4 holds; out-of-order events → ordered by observation timestamp; controller restart → all hosts re-enter `UNKNOWN`, no stale accepted location survives |

**Deliberate difference from the legacy design**: `MOVE_ACCEPTED` reached via
`deadline` is recorded as *weak* evidence. Absence of a probe reply is equally
consistent with packet loss, so it is never treated as proof of a legitimate
move. `INCONCLUSIVE` exists precisely so the system is not forced to choose.

The state machine is pure: it takes events and returns `(new_state, actions)`.
It is unit-testable with no network, no OVS and no OpenFlow library — all of
it runs on macOS today.

## Framework selection

**NOT_RUN.** The OpenFlow adapter is deliberately the last thing chosen, and
the boundary rule above means the choice cannot leak into security logic.
OS-Ken is a candidate to evaluate on protocol coverage, Python version
support, maintenance, event and concurrency model, OVS compatibility and
licence — not a decision.


## Shared V2 contracts (V2-CORE-01)

`development/src/padmavyuh/` — domain-neutral, standard library only, and
asserted by test to import neither an OpenFlow framework nor `sdnguard`.

```
completion.py   experiment lifecycle and completion manifests (ADR-029)
identity.py     EntityRef: kind + namespace + identifier
events.py       the common envelope, bounds, and the decode boundary
capability.py   support / configuration / health, and agent state
```

Dependency direction is one-way and enforced:

```
sdnguard/v2/mapping.py  ──consumes──▶  padmavyuh
padmavyuh               ──never──▶     sdnguard
```

Three design rules carried by the code rather than by convention:

* **No `risk_score` in an event.** Raw observation and interpreted finding are
  different things; one number that later code mistakes for
  severity-and-confidence is what ADR-030 forbids.
* **No field for raw material.** Prompts, file contents and packet payloads
  are referenced or hashed, never carried, so minimisation is structural.
* **`SUPPORTED` never implies `ACTIVE AND HEALTHY`.** A capability is only
  effective when support, configuration and health all line up.
