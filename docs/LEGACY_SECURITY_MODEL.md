# LEGACY SECURITY MODEL — recovered intent

What the POC was *trying* to do, reconstructed from source and separated from
what it actually does. Everything here is `LEGACY_STATICALLY_UNDERSTOOD`
unless marked `LEGACY_AMBIGUOUS`.

The four-column discipline is applied throughout:
**DOES** / **INTENDED** / **SECURITY REQUIRES** / **PYTHON WILL DO**.

---

## The attack being defended against

Host Location Hijacking. An attacker on port P2 forges a victim's identity so
the controller relocates the victim's attachment point to P2, after which
traffic destined for the victim is delivered to the attacker. The companion
attack, Link Fabrication, injects LLDP from a host port to create a phantom
inter-switch link.

## 1. How is a host learned?

- **DOES** — two disconnected mechanisms. Upstream `DeviceManagerImpl` learns
  devices and fires `deviceAdded`/`deviceMoved`. Independently, `PortManager`
  keeps its own `mac_port` map, populated in `processPacketInMessage` — but
  only from **non-broadcast** frames, so ARP never contributes.
- **INTENDED** — one authoritative host table keyed by MAC, mapping to a
  `(switch, port)` location.
- **SECURITY REQUIRES** — a single host table; a MAC alone is an *observation*,
  never an authenticated identity.
- **PYTHON WILL DO** — one `HostTable` fed exclusively by normalised
  `HostObservation` events, including ARP.

## 2. What constitutes a host location?

- **DOES** — `Port(dpid: Long, port_number: Short)`, compared by reference.
- **INTENDED** — the pair `(datapath id, ingress port)`. Confirmed: every
  per-port structure is keyed by it.
- **SECURITY REQUIRES** — immutable value semantics over the **full 64-bit**
  DPID space.
- **PYTHON WILL DO** — frozen `PortIdentity(DatapathId, PortNumber)`.

## 3. What event indicates movement?

- **DOES** — upstream `deviceMoved(IDevice)`, handled only when
  `getOldAP().length == 1`.
- **INTENDED** — any relocation of a known host.
- **SECURITY REQUIRES** — multi-AP hosts must not be silently exempt; being
  seen in several places is itself the suspicious signal.
- **PYTHON WILL DO** — a `MovementEvent` for every location change, with
  multi-location hosts escalated rather than skipped.

## 4. Legitimate migration vs hijack — the actual discriminator

This is the core recovered insight, and it comes from
`PortProperty.hosts: Map<MAC, Boolean>`, where the boolean means *"a port-down
signal was observed for this host."* Two independent conditions:

**Pre-condition (Port-Down).** A real host that physically moves causes its old
port to go down first. `handlePortDown` sets the flag for every host on that
port. In `deviceMoved`, a flag still `false` means the host "moved" while its
old port stayed up — physically implausible, therefore suspicious.

**Post-condition (Liveness).** Probe the **old** location. A genuinely departed
host cannot answer. A reply proves the host never left, so the new location is
an impostor.

- **DOES** — logs a warning for the pre-condition; the post-condition branch is
  unreachable (wrong ICMP field, off-subnet source address). No timeout, so the
  "no reply ⇒ genuine migration" conclusion is never drawn.
- **SECURITY REQUIRES** — both conditions as *evidence*, neither as proof.
  Port-Down is attacker-influenceable; absence of a probe reply is equally
  consistent with packet loss.
- **PYTHON WILL DO** — a scored decision over multiple evidence sources with an
  explicit `INCONCLUSIVE` outcome, never a silent default to "benign".

## 5–7. Why probe, what is probed, what reply is expected

- **DOES** — ICMP echo request out the **old** port; `OFPacketOut` with an
  explicit output action; expects an echo reply whose source is the host and
  whose destination is `ControllerIP`. `ControllerIP` is `10.0.1.100`, on no
  topology in this repository.
- **INTENDED** — an active liveness test aimed at the previous attachment
  point, deliberately unicast out one port so that only a host still physically
  present there can answer.
- **LEGACY_AMBIGUOUS** — ARP was implemented (`generateARPPing`) and then
  abandoned in favour of ICMP with no recorded rationale. ARP is the better
  primitive: it is link-local, needs no routable controller address, and cannot
  be answered off-subnet.
- **SECURITY REQUIRES** — an unpredictable, single-use correlation token, so a
  reply cannot be forged or replayed; a deadline; and a source address that is
  actually reachable on that segment.
- **PYTHON WILL DO** — ARP-based probe by default, ICMP optional; a nonce in the
  payload; a `ProbeRequest`/`ProbeResult` pair with an explicit deadline.

## 8. Intended outcome per situation

| Situation | Legacy does | Python will do |
|---|---|---|
| Probe reply received | log "still reachable"; drop the packet | `SUSPICIOUS_MOVE` finding with evidence refs |
| Probe unanswered | nothing — no timer exists | on deadline → `MOVE_ACCEPTED` (weak evidence, recorded as such) |
| Probe never sent | silently skipped | `INCONCLUSIVE`, finding emitted |
| Repeated movement | no handling | rate-limited; repetition raises suspicion |
| Switch disconnects | `switchRemoved` is a no-op | invalidate that switch's locations and cancel its probes |
| Host disappears | no handling | location expires on a timer |
| LLDP from HOST port | log + `Command.STOP` | same, plus a typed finding |
| Host traffic from SWITCH port | log only; `STOP` commented out | `LEGACY_AMBIGUOUS`; Python defaults to observe-only |

## 9–10. State lifetime

- **DOES** — `port_list`, `mac_port` and `probedPorts` are unbounded `HashMap`s
  with no expiry and no eviction on switch removal. `probedPorts` grows on every
  move forever.
- **SECURITY REQUIRES** — every collection bounded; every probe expiring; state
  exhaustion is an attack surface, not an operational detail.
- **PYTHON WILL DO** — TTL-bounded stores with explicit maxima and metrics, plus
  a state-exhaustion test.

## 11. Intended response after detection

- **DOES** — a log line. No REST surface, no structured event, no enforcement.
- **LEGACY_AMBIGUOUS** — no response design is recoverable from source.
- **PYTHON WILL DO** — typed `SecurityFinding` → `policy/engine.py` decision →
  observe-only by default; enforcement is scoped, expiring, auditable and
  reversible, and is enabled only by explicit policy.

---

## Concepts worth keeping

1. Location as `(dpid, port)` — correct and durable.
2. Port-Down as a **pre-condition** for legitimate migration — genuinely good,
   and the clearest recovered intent.
3. Active liveness probing of the **old** location as a **post-condition** —
   the right shape for the check.
4. Port typing (`SWITCH`/`HOST`/`ANY`) driven by LLDP observation — a sound,
   cheap basis for link-fabrication defence.
5. Consuming a suspect LLDP rather than acting on it — a proportionate
   countermeasure.

## Concepts to discard

1. Reference equality for identity.
2. MAC address as sufficient identity.
3. Absence of a probe reply treated as proof of anything.
4. Unbounded, never-expiring state.
5. Logging as the detection interface.
6. Ignoring hosts with more than one prior attachment point.
