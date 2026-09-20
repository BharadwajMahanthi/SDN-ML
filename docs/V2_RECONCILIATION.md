# V2 reconciliation — current repository against PADMAVYUH_ARCHITECTURE_V2

Produced by V2-ARCH-01. This is a migration design, not a refactor. Nothing
in `development/src/sdnguard/` is moved or renamed by this branch.

Authority order applied: owner instruction > `PADMAVYUH_ARCHITECTURE_V2.md` >
`PROJECT_CONTRACT.md` > unsuperseded ADRs > `CURRENT_STATE.md` >
`PYTHON_MIGRATION_MATRIX.md` > legacy Floodlight behaviour.

## 1. What the V2 document changes

The product is an installable local-first agent for an ordinary Linux cloud
server. SDN topology integrity becomes **one optional protection pack**. The
minimum useful installation must work with no Floodlight, OpenFlow, OVS,
Mininet, Kubernetes or LLM present.

The current chain — namespace host → veth → OVS datapath → OpenFlow 1.3 →
OS-Ken → adapter → `HostObservation` → `HostTable` — is retained, and V2 §3
is explicit that it is *software-datapath integration evidence*, not evidence
of attack detection, endpoint protection or a protected cloud account. That
matches what this repository already claims.

## 2. Component inventory

### 2a. Reusable as shared primitives — extract under tests, do not copy

| Component | Why it generalises | Change needed for V2 |
|---|---|---|
| `clock.py` | monotonic-vs-wall split is domain-neutral | none |
| `observability/evidence.py` | bounded, queryable finding store | add lineage + provenance fields |
| `policy/engine.py` | modes, kill switch, protected scopes, always-answers | actions become host actions too |
| `domain/events.py` finding/decision half | typed findings, scoped expiring reversible decisions | **split severity from confidence**; add contradictory/missing evidence |
| `probes/manager.py` | issue → correlate → expire exactly once, bounded, nonce-authenticated | generalise to "active verification", currently port-typed |
| `adapter/contract.py` `SendResult` | typed result instead of exception for ordinary failure | reuse verbatim as the broker result type |
| bounded-collection discipline (`hosts/table.py`, `topology/ports.py`) | refuse rather than evict, so an attacker cannot flush evidence | reuse as a documented pattern |

### 2b. SDN-specific — stays in `sdnguard`, becomes the SDN pack

`domain/identity.py` (DatapathId/PortNumber/PortIdentity), `topology/*`,
`hosts/movement.py`, `detection/deterministic.py`, `adapter/{osken,normalize,fake}.py`,
`controller/app.py`.

V2 §3 is explicit that SDN identities and the port-down assumption must **not**
be inherited by general host protection. `PortIdentity` is not a host identity,
and "a legitimate move is preceded by port-down" has no host analogue.

### 2c. New shared components required

`contracts/` (common event envelope and entity identities, capability
manifest, evidence/lineage, typed actions), `agent/` (lifecycle, local state,
health), `collectors/` (sensor adapters), `response/` (unprivileged client),
and a separate privileged broker. Nothing here exists today.

## 3. Conflicts found

### C1 — ADR-017 is insufficient as written (must be superseded)

ADR-017 confines `eventlet` to one module and enforces it with an AST import
guard. V2 §3: *"Import restrictions alone do not establish a process-wide
concurrency boundary."* That is correct and my guard does not address it.
`eventlet.monkey_patch()` rewrites the standard library for the **whole
process**, so an import guard says nothing about what happens at runtime if
the host agent and the SDN adapter ever share a process. The fix is process
separation, not a stricter lint. See ADR-028.

### C2 — the KF-22 shutdown fix is wrong in a way V2 caught

I resolved KF-22 with `os._exit(0)`. V2 §3: it bypasses cleanup handlers and
stdio flushing, and *"forced termination must be recorded distinctly, not
silently treated as clean experiment success."* Correct. A run that was killed
and a run that finished are currently indistinguishable in the evidence. This
is the same failure family as KF-22 itself — an experiment whose abnormal end
is invisible. Requires a completion manifest, a durable event drain, and
independent process/port cleanup evidence. See ADR-029.

### C3 — severity and confidence are one axis (extend ADR-014)

ADR-014 puts severity in one policy object. V2 §9 requires severity and
confidence basis to stay separate: a low-confidence event may be catastrophic,
a high-confidence one trivial. Extends rather than supersedes.

### C4 — correlated evidence could be double-counted

Nothing today tracks evidence lineage. V2 §10's requirement — three detectors
consuming one event are not three confirmations — is not yet expressible.

### C5 — teardown verification is weaker than V2 §19 requires

`destroy.sh` compares account-wide resource counts to a baseline. V2 §19:
*"an account-wide resource count greater than an old baseline is not ownership
evidence"*, and delete only resources proven owned by that stack. Our checks
are tag-filtered, which is closer to correct than a raw count, but the
elastic-IP, load-balancer and NAT-gateway checks are account-wide. Narrow them
to stack-owned resources and record evidence before teardown.

## 4. Trust boundaries adopted

V2 §5 zones 1–7. The consequence for this repository: the Python analysis core
runs **unprivileged**; a separate small broker holds the narrow privileged
capability; sensors are a third zone. There is no single root Python daemon,
and `tools/` are development governance, never production privileged
executables.

Adversary levels: the first production claim targets **A1/A2** only. A3
(guest-root/kernel) explicitly cannot be claimed by a same-kernel agent.

## 5. Migration plan — vertical slices, not skeleton sprawl

1. **V2-CORE-01** `feat/v2-core-01-events-capabilities` — common event
   envelope, entity identities, capability manifest with degraded states.
   Gate: SDN regression tests stay green; no `sdnguard` file moves.
2. **V2-CORE-02** — evidence model with lineage and contradictory/missing
   evidence; severity separated from confidence basis.
3. **V2-SAFE-01** `feat/v2-response-01-privileged-broker` — typed actions and
   independent authorization. No arbitrary shell endpoint, ever.
4. **V2-HOST-01** `feat/v2-host-01-linux-sensor-adapter` — sensor evaluation
   and adapter, on a plain Ubuntu VM with no OVS installed.
5. **V2-HOST-02**, then the §20 crossover milestone.

`sdnguard` is touched only to *extract* shared code under existing tests, once
a second consumer exists. Extraction before a second consumer is speculation.

## 6. What this branch deliberately does not do

No package renames, no `annulon/` tree of empty modules, no re-labelling of
completed P-tasks. V2 §32: every component added must have a real
responsibility, a typed contract, tests and evidence.
