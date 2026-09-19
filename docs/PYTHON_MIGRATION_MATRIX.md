# PYTHON MIGRATION MATRIX

Authoritative plan for the Python system. This matrix matters more than
repairing Java. Status: `UNDERSTOOD` → `SPECIFIED` → `IMPLEMENTING` →
`UNIT_VERIFIED` → `INTEGRATION_VERIFIED` → `DEFERRED`.

Every row's "Legacy defect" column is the bridge required by the owner:
`KNOWN_FAILURE → PYTHON DESIGN REQUIREMENT → REGRESSION TEST`.

## Domain model (Stage 1)

| ID | Capability | Legacy | Intended behaviour | Legacy defect | Python module | Interface | Required test | Status |
|---|---|---|---|---|---|---|---|---|
| M-01 | Datapath identity | L-02 | 64-bit switch id | boxed `Long` reference compare | `sdnguard/domain/identity.py` | `DatapathId` (frozen) | equality/hash for `0x0000aabbccddeeff`, `2**63-1`, values far outside −128..127 | UNIT_VERIFIED |
| M-02 | Port number | L-02 | 32-bit OF port | boxed `Short` reference compare | `domain/identity.py` | `PortNumber` (frozen) | reject negative; accept OF reserved ports | UNIT_VERIFIED |
| M-03 | Port identity | L-02 | `(dpid, port)` value key | `==` used on objects | `domain/identity.py` | `PortIdentity` (frozen) | two independently built instances compare equal and hash identically; usable as a dict key | UNIT_VERIFIED |
| M-04 | Host identity | §1 | MAC + optional IP, explicitly *observational* | MAC treated as identity | `domain/host.py` | `HostIdentity` | MAC normalisation; two hosts sharing a MAC are distinguishable by location | UNIT_VERIFIED |
| M-05 | Host location | §2 | `PortIdentity` + first/last seen | none | `domain/host.py` | `HostLocation` | ordering by `last_seen`; immutability | UNIT_VERIFIED |
| M-06 | Host observation | L-05 | normalised packet event | framework objects passed throughout | `domain/events.py` | `HostObservation` | constructible without any OpenFlow library | UNIT_VERIFIED |
| M-07 | Movement event | L-06 | old → new location | multi-AP hosts skipped | `domain/events.py` | `MovementEvent` | multi-location host produces an event, not a skip | UNIT_VERIFIED |
| M-08 | Probe request/result | L-07/08 | nonce, deadline, target | mutable shared fields, no deadline | `domain/probe.py` | `ProbeRequest`, `ProbeResult` | nonce uniqueness; deadline mandatory; frozen | UNIT_VERIFIED |
| M-09 | Security finding | L-09 | typed, machine-readable | log lines only | `domain/finding.py` | `SecurityFinding` | stable id; serialisable; carries evidence refs | UNIT_VERIFIED |
| M-11 | Clock and deadline | — | injected time; monotonic for decisions, wall for evidence | legacy had no clock abstraction and no probe timeout at all | `sdnguard/clock.py` | `Clock`, `SystemClock`, `ManualClock`, `Deadline` | wall-clock regression must not un-expire or early-expire a deadline | UNIT_VERIFIED |
| M-10 | Enforcement decision | L-10 | scoped, reversible, expiring | absent | `domain/policy.py` | `EnforcementDecision` | every decision carries a scope and a TTL | UNIT_VERIFIED |

## Host and topology state (Stage 2)

| ID | Capability | Legacy | Intended | Legacy defect | Python module | Test | Status |
|---|---|---|---|---|---|---|---|
| S-01 | Port registry | L-04 | ports per switch | ports added after `switchAdded` untracked | `topology/ports.py` | late port appears; `switchRemoved` reclaims | UNIT_VERIFIED |
| S-02 | Port typing | L-03 | SWITCH/HOST/ANY from LLDP | dead `receiveTrafficFromPort` disagrees with inline logic | `topology/port_state.py` | LLDP promotes ANY→SWITCH; host traffic promotes ANY→HOST | UNIT_VERIFIED |
| S-03 | Port-down evidence | L-03 | per-host shutdown flag | never cleared on switch loss | `topology/port_state.py` | flag set on down, cleared on re-observation, dropped with the switch | UNIT_VERIFIED |
| S-04 | Host table | §1 | single authority incl. ARP | broadcast returns before learning | `hosts/table.py` | ARP populates the table | UNIT_VERIFIED |
| S-06 | Switch lifecycle + generations | L-04 | connect/disconnect/reconnect | no generation concept, so a reconnect kept stale state and in-flight events were indistinguishable | `topology/switches.py` | stale generation rejected after reconnect | UNIT_VERIFIED |
| S-07 | Inter-switch links | L-05 | unordered port pair | none modelled | `topology/links.py` | unordered pairs; endpoint on a host port is inconsistent | UNIT_VERIFIED |
| S-05 | Bounded state | §9 | TTL + maxima everywhere | three unbounded maps | `hosts/table.py`, `probes/manager.py` | 10k synthetic hosts stay within a configured bound | UNIT_VERIFIED |

## Security logic (Stages 3–4)

| ID | Capability | Legacy | Intended | Legacy defect | Python module | Test | Status |
|---|---|---|---|---|---|---|---|
| D-01 | Movement state machine | L-06 | explicit states/guards/timeouts | implicit, partly unreachable | `hosts/movement.py` | full transition table; unreachable states proven absent | UNIT_VERIFIED |
| D-02 | Port-Down pre-condition | §4 | evidence, not proof | logged then ignored | `detection/deterministic.py` | move without port-down raises suspicion, does not convict | UNIT_VERIFIED |
| D-03 | Liveness post-condition | §4 | probe old location | unreachable branch | `probes/manager.py` | reply ⇒ SUSPICIOUS; no reply by deadline ⇒ ACCEPTED (weak) | UNIT_VERIFIED |
| D-04 | Probe correlation | L-08 | nonce + type + deadline | ICMP *code* compared to a *type* constant | `probes/correlation.py` | forged reply without the nonce is rejected; echo request never matches a reply | UNIT_VERIFIED |
| D-05 | Probe expiry | §10 | every probe expires | no timer at all | `probes/timeout.py` | unanswered probe resolves exactly once at its deadline | UNIT_VERIFIED |
| D-06 | Link-fabrication defence | L-05 | LLDP from HOST port is hostile | reachable and roughly correct | `detection/deterministic.py` | LLDP on a HOST port emits a finding and consumes the packet | UNIT_VERIFIED |
| D-07 | Host traffic from SWITCH port | L-05 | `LEGACY_AMBIGUOUS` | `STOP` commented out | `detection/deterministic.py` | finding emitted; no enforcement by default | UNIT_VERIFIED |
| D-08 | Findings output | L-09 | typed and queryable | log lines only | `observability/evidence.py` | finding is serialisable and retrievable by id | SPECIFIED |

## Deferred

| ID | Capability | Reason | Status |
|---|---|---|---|
| X-01 | Enforcement adapter | Stage 6; observe-only until acceptance criteria exist | DEFERRED |
| X-02 | ML detection | Stage 8; deterministic protection must be measurable first | DEFERRED |
| X-03 | Zeek path | duplicates TopoGuard; revisit only if it adds measurable value | DEFERRED |
| X-04 | REST/API surface | Stage 6; needs an authentication design | DEFERRED |
| X-05 | AWS lab | Stage 10 | DEFERRED |

## Will not be ported

| Legacy | Reason |
|---|---|
| `Port.equals`/`hashCode` | defective by construction; replaced by a value type |
| `PortProperty.receiveTrafficFromPort` | dead code contradicting the live path |
| `HostProber.generateARPPing` as written | wrong opcode (`OP_RARP_REQUEST`); the ARP *concept* is kept and reimplemented |
| `ControllerIP` constant | replaced by per-segment probe source selection |
| `BigInteger.toByteArray()` address conversion | replaced by `ipaddress` |
| `ip.hashCode()` as an address | relies on an undocumented JDK detail |
| Logging as the detection interface | replaced by typed findings |
| `org.sdnplatform.sync` | clustering is out of scope |
| Upstream Floodlight modules (firewall, loadbalancer, virtualnetwork, …) | not used by this project |

## Implementation log

| Task | Branch | Rows | Result |
|---|---|---|---|
| P3-DOMAIN-01 | `feat/p3-domain-01-value-identities` | M-01, M-02, M-03 | UNIT_VERIFIED — 163 domain tests, 306 total |
| P3-DOMAIN-02 | `feat/p3-domain-02-host-types` | M-04, M-05, M-06 | UNIT_VERIFIED — 238 domain tests, 381 total |
| P3-DOMAIN-03 | `feat/p3-domain-03-security-events` | M-07, M-08, M-09, M-10 | UNIT_VERIFIED — 290 domain tests, 433 total |
| P3-DOMAIN-05 | `feat/p3-domain-05-time-abstraction` | M-11 (new) | UNIT_VERIFIED — 309 domain tests, 452 total |
| P3-DOMAIN-04 | `test/p3-domain-04-properties` | all M-* | UNIT_VERIFIED — 6 invariant families, 338 domain tests, 481 total |
| P4-TOPO-01 | `feat/p4-topology-01-port-state` | S-01, S-02, S-03 | UNIT_VERIFIED — 23 topology tests, 508 total |
| P4-TOPO-02 | `feat/p4-topology-02-link-state` | S-06, S-07 (new) | UNIT_VERIFIED — 43 topology tests, 532 total |
| P4-HOST-01 | `feat/p4-hosts-01-host-table` | S-04, S-05 | UNIT_VERIFIED — 24 host tests, 560 total |
| P4-MOVE-01/02 | `feat/p4-movement-01-state-machine` | D-01 | UNIT_VERIFIED — 71 host tests incl. full transition matrix + benign/adversarial decision table, 609 total |
| P4-PROBE-01/02 | `feat/p4-probes-01-manager` | D-03, D-04, D-05 | UNIT_VERIFIED — 31 probe tests, 640 total |
| P4-DETECT-01/02 | `feat/p4-detection-01-host-hijack` | D-02, D-06, D-07 | UNIT_VERIFIED — 19 detection tests, 665 total |

Delivered beyond the specified minimum, with reasons:

- `DatapathId.from_signed` / `to_signed` — OpenFlow libraries with Java
  heritage hand out datapath ids as signed longs, so `0xFFFFFFFFFFFFFFFF`
  arrives as `-1`. Keeping that conversion in one tested place stops it being
  re-derived, differently, in each adapter.
- `PortNumber` rejects `0` and the unassigned gap between `OFPP_MAX` and
  `OFPP_IN_PORT`, so an adapter bug surfaces at the boundary rather than as a
  silent lookup miss inside the security logic.
- `tests/domain/test_no_framework_dependencies.py` enforces ADR-005 by AST
  inspection: the core may import the standard library and itself, nothing else.
