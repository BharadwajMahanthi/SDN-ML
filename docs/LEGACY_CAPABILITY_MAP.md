# LEGACY CAPABILITY MAP

Archaeology of the Java/Floodlight POC. The Java code is a **source of
intent**, not a definition of correctness.

Evidence tags: `LEGACY_STATICALLY_UNDERSTOOD` (read, not executed),
`LEGACY_EXECUTED` (actually run), `LEGACY_AMBIGUOUS` (intent unclear).
**Nothing in this document is `LEGACY_EXECUTED`.** No Java was run; the
toolchain is marked `LEGACY_JAVA_RUNTIME_NOT_REQUIRED_FOR_CURRENT_MIGRATION`.

Scope note: only `net.floodlightcontroller.topologysecurity` is
project-specific. Everything else under `net.floodlightcontroller.*` and
`org.sdnplatform.*` is upstream Floodlight. The only other local edits are
OpenFlow port 6653 in the properties file and `java.util.Base64` usage in
`org.sdnplatform.sync.internal.rpc.AbstractRPCChannelHandler` — a JDK
compatibility fix with no security meaning.

---

## L-01 Module lifecycle

- **File/class**: `topologysecurity/TopoloyUpdateChecker.java` (`IFloodlightModule`)
- **Responsibility**: register the security module with the controller
- **Events received**: `init()`, `startUp()`
- **State**: `portManager`, `hostProber`, static `logger`
- **Output**: registers `PortManager` as a `PACKET_IN` listener and an
  `IOFSwitchListener`; registers itself as `IDeviceListener` and
  `ILinkDiscoveryListener`
- **Dependencies**: `IFloodlightProviderService`, `IDeviceService`, `ILinkDiscoveryService`
- **Intended security role**: entry point for topology-integrity checking
- **Known defects**: `getName()` returns `null` (used by Floodlight's listener
  ordering); `getModuleServices()`/`getServiceImpls()` return `null`
- **Python replacement**: `controller/app.py` wiring + explicit service registry
- **Confidence**: HIGH — `LEGACY_STATICALLY_UNDERSTOOD`

## L-02 Port identity

- **File/class**: `TopoloyUpdateChecker.java` — package-private `class Port`
- **Responsibility**: `(dpid, port_number)` key for all per-port state
- **Intended security role**: the anchor of "where a host is"
- **Known defects**: `equals()` compares boxed `Long`/`Short` by **reference**,
  so it is correct only for values inside Java's integer cache (−128..127);
  `hashCode()` is value-based, so the map hashes correctly but compares wrongly.
  Separately, `processPacketInMessage` compares two `Port` objects with `==`.
- **Python replacement**: frozen `PortIdentity(DatapathId, PortNumber)` value type
- **Confidence**: HIGH — `LEGACY_STATICALLY_UNDERSTOOD`

## L-03 Port classification and host bookkeeping

- **File/class**: `topologysecurity/PortProperty.java`, `enum DeviceType{SWITCH,HOST,ANY}`
- **Responsibility**: per-port device type plus `Map<MACAddress, Boolean> hosts`
  where the boolean means **"a port-down/shutdown signal was observed for this
  host at this port"**
- **Transitions**: `addHost` → `false`; `receivePortDown()` → sets **all** hosts
  on the port to `true`; `disableHostShutDown(mac)` → back to `false`;
  `receivePortShutDown()` → clears the host set and resets type to `ANY`
- **Intended security role**: supplies the *pre-condition* evidence for host
  migration (see L-06)
- **Known defects**: `receiveTrafficFromPort(...)` is never called — dead code
  that duplicates, and disagrees with, the inline logic in `processPacketInMessage`
- **Python replacement**: `topology/port_state.py` + `hosts/location.py`
- **Confidence**: HIGH — `LEGACY_STATICALLY_UNDERSTOOD`

## L-04 Switch and port lifecycle

- **File/class**: `TopoloyUpdateChecker.PortManager` (`IOFSwitchListener`)
- **Events received**: `switchAdded`, `switchPortChanged(DELETE|DOWN)`
- **Actions**: `handleSwitchAdd` seeds `port_list` from `sw.getPorts()`;
  `handlePortDown` calls `PortProperty.receivePortDown()`
- **Known defects**: `switchRemoved` is a no-op with a `TODO`, so state is never
  reclaimed; `handlePortDown` dereferences the map result without a null check;
  ports appearing after `switchAdded` are never tracked
- **Python replacement**: `controller/switches.py` with explicit lifecycle and
  bounded, expiring state
- **Confidence**: HIGH — `LEGACY_STATICALLY_UNDERSTOOD`

## L-05 Packet-in processing and link-fabrication defence

- **File/class**: `TopoloyUpdateChecker.PortManager.processPacketInMessage`
- **Events received**: `OFPacketIn`
- **Logic**: probe-reply correlation → LLDP handling → host learning
- **Intended security role**: two of TopoGuard's checks —
  (a) **LLDP from a HOST port** is a link-fabrication attempt; countermeasure is
  to consume the packet (`Command.STOP`);
  (b) **first-hop host traffic from a SWITCH port** is a topology anomaly
- **Known defects**: the `host_location == switch_port` comparison at the head
  of the host branch is a reference comparison and is therefore **always false**,
  making check (b) and the `disableHostShutDown` bookkeeping unreachable;
  `eth.isBroadcast()` returns early *before* host learning, so ARP — the main
  host announcement — never populates `mac_port`; `mac_port` is never updated
  after a legitimate move
- **Python replacement**: `controller/events.py` normalisation +
  `detection/deterministic.py`
- **Confidence**: HIGH on the defects, MEDIUM on intent for check (b) —
  `LEGACY_AMBIGUOUS` (the violation is logged but the `return Command.STOP`
  is commented out, so the intended response is unclear)

## L-06 Host movement detection

- **File/class**: `TopoloyUpdateChecker.deviceMoved` (`IDeviceListener`)
- **Events received**: `deviceMoved(IDevice)`
- **Inputs**: `device.getOldAP()` — upstream returns *unexpired* previous
  attachment points (`Device.java:561`)
- **Logic**: act only when exactly one old AP exists → look up that port's
  `PortProperty` → if the host's shutdown flag is `false`, log
  *"Host Move ... without Port ShutDown"* → send a probe to the old location
  and remember it in `probedPorts`
- **Intended security role**: TopoGuard's host-location-hijack precondition check
- **Known defects**: `port_list.get(previousPort)` can return `null` (NPE);
  hosts with more than one old AP are silently ignored; no probe timeout exists,
  so the "no reply ⇒ genuine migration" conclusion is never reached and
  `probedPorts` grows without bound
- **Python replacement**: `hosts/movement.py` state machine + `probes/manager.py`
- **Confidence**: HIGH — `LEGACY_STATICALLY_UNDERSTOOD`

## L-07 Host probing

- **File/class**: `TopoloyUpdateChecker.HostProber`
- **Responsibility**: emit an ICMP echo request out the **old** port via
  `OFPacketOut`, and remember `(port → [HostEntity(mac, ip)])`
- **Known defects**: source address hardcoded to `10.0.1.100`, which is on no
  topology in this repository, so a reply can never satisfy the correlation
  test; `setDestinationAddress(ip.hashCode())` relies on an undocumented
  OpenJDK `Inet4Address` implementation detail; `generateARPPing` is dead code
  and uses `OP_RARP_REQUEST`; `targetMAC`/`targetIP` are mutable instance fields
  shared across concurrent probes; `BigInteger.valueOf(int).toByteArray()`
  drops leading zero bytes
- **Python replacement**: `probes/manager.py` (issue, correlate, expire) with an
  immutable correlation token
- **Confidence**: HIGH on defects; MEDIUM on why ICMP replaced ARP —
  `LEGACY_AMBIGUOUS` (the ARP path is commented out with no rationale)

## L-08 Probe-reply correlation

- **File/class**: `processPacketInMessage`, ICMP branch
- **Logic**: on an ICMP packet whose *code* equals `ICMP.ECHO_REPLY`, match
  `(src_ip, src_mac, dst_ip == ControllerIP)` against `probedPorts`; on a match,
  log *"Host Move ... is still reachable"*, remove the entry, `Command.STOP`
- **Intended security role**: the postcondition check — old location still alive
  ⇒ the move was a spoof
- **Known defects**: `ICMP.ECHO_REPLY` is a *type* constant (`0x0`) compared
  against `getIcmpCode()`, so it matches almost any ICMP message; combined with
  L-07's address defect the branch is effectively unreachable in the lab
- **Python replacement**: `probes/correlation.py` with explicit type checking and
  a nonce carried in the probe payload
- **Confidence**: HIGH — `LEGACY_STATICALLY_UNDERSTOOD`

## L-09 Detection output

- **File/class**: all of the above
- **Output**: `logger.warn(...)` **only**
- **Notable**: the package exposes **no REST resource** and writes no structured
  event, no database row and no alert file. There is no machine-readable
  detection output of any kind.
- **Consequence**: the data-collection scripts that scrape
  `/wm/core/...` could never have retrieved a detection result, independently of
  whether the controller was running
- **Python replacement**: `observability/evidence.py` — typed `SecurityFinding`
  records with stable IDs, plus a read API
- **Confidence**: HIGH — `LEGACY_STATICALLY_UNDERSTOOD`

## L-10 Enforcement

- **Present**: none, beyond `Command.STOP` on a suspect LLDP packet
- **Intended**: unclear from the code
- **Python replacement**: `policy/engine.py` + `policy/enforcement.py`, observe-only first
- **Confidence**: `LEGACY_AMBIGUOUS` — no enforcement design is recoverable from source

## L-11 Experiment orchestration, collection and ML (non-controller)

Legacy shell scripts, Containerlab topologies, REST scrapers, notebooks and
`src/*.py`. Their defects are recorded in `KNOWN_FAILURES.md`. None of them
constrain the Python controller design; they are rebuilt in later stages.

- **Python replacement**: a Linux harness (Stage 5) and a leakage-free feature
  pipeline (Stage 8)
- **Confidence**: HIGH — these were analysed directly earlier in the project
