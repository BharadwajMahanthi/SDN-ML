# KNOWN FAILURES

Rejected approaches and regressions to avoid repeating.

## Defects found while building the firewall (P0)

| ID | Defect | Why it mattered | Fix |
|---|---|---|---|
| KF-01 | `\b` word boundary fails after `_` | `SUDO_PASS="…"` — the actual credential in `simulate_attack.sh` — was not redacted | anchors changed to `(?<![A-Za-z0-9])` |
| KF-02 | `/` included in the entropy character class | masked whole file paths, destroying legitimate output | `/` and `.` excluded; require ≥3 character classes and non-identifier shape |
| KF-03 | `safe_exec` echoed the command line verbatim | a secret passed as an argument escaped output redaction | the command line is redacted like any other output |
| KF-04 | allowlist matched raw basenames | `sys.executable` is `python3.12`, so every local Python call was refused | version-suffix normalisation |

## Defects found while building memory (P1)

| ID | Defect | Fix |
|---|---|---|
| KF-05 | `_check_quota` measured usage before the metadata write, so a hand-computed boundary was off by one byte | boundary is now measured empirically in the test; store behaviour was correct |
| KF-06 | the lock file counts toward the storage quota, and its payload embedded `os.getpid()` and `time.time()` — both variable-width — so total usage jittered between runs and the quota boundary was nondeterministic (~30% flaky) | fixed-width lock payload; regression test asserts usage is stable across 20 lock cycles |

## Approaches rejected

- **SQLite for the journal** — see ADR-001.
- **Wall-clock cron purge** — forbidden. GC runs only inside a verified
  development checkpoint, never on a timer.
- **Catch-up deletion after an idle gap** — forbidden. A 40-day absence must
  not retire 40 days of memory.

## Legacy defect → Python requirement → regression test (P3+)

This is the conversion the owner mandated in place of repairing Java.

### KF-07 — reference equality for switch-port identity

- **Legacy**: `TopoloyUpdateChecker.Port.equals` compared boxed `Long`/`Short`
  with `!=`, i.e. by reference. Correct only inside Java's integer cache
  (−128..127). `hashCode` was value-based, so entries hashed to the right
  bucket and then failed the equality check. A lab using datapath ids 1, 2 and
  3 could never have exposed it.
- **Python requirement**: switch and port identity are frozen value types with
  equality and hashing over the full unsigned 64-bit space.
- **Regression test**:
  `tests/domain/test_identity.py::test_independently_constructed_dpids_are_equal_and_hash_alike`
  parametrised over 15 values including `0x0000AABBCCDDEEFF`, `2**63`,
  `2**64-1`, and both `127` and `128` to straddle the old cache boundary.
  Status: VERIFIED.

### KF-08 — `dataclass(frozen=True, slots=True)` reports the wrong error

- **Found**: while testing immutability. `slots=True` rebuilds the class, so
  the generated frozen `__setattr__` closes over a stale class reference.
  Assigning a *known* field raises `FrozenInstanceError`, but assigning an
  *unknown* attribute raises `TypeError: super(type, obj): obj must be an
  instance or subtype of type`. Protection holds; the error is misleading.
- **Fix**: declare `__slots__` manually, which restores a consistent
  `FrozenInstanceError`. That in turn broke pickling, because the default
  unpickling path uses `setattr`; a `_ValueObject` mixin restores state via
  `object.__setattr__`.
- **Regression tests**: `test_slots_prevent_attribute_injection`,
  `test_survives_a_pickle_round_trip`. Status: VERIFIED.

### KF-09 — broadcast frames returned before host learning

- **Legacy**: `processPacketInMessage` called `if (eth.isBroadcast()) return
  Command.CONTINUE;` *above* the host-learning branch, so ARP -- the primary
  way a host announces itself -- never populated `mac_port`.
- **Python requirement**: a broadcast frame is a first-class host observation.
  `HostObservation` carries `is_broadcast` as data rather than as a reason to
  discard the event.
- **Regression test**: `tests/domain/test_host.py::test_broadcast_arp_is_a_valid_observation`.
  Status: VERIFIED at the domain layer; the adapter-level guarantee lands in P5-OF-07.

### KF-10 — MAC treated as host identity

- **Legacy**: the host table was keyed on MAC alone, so one MAC at two ports
  collapsed into a single record -- which is precisely the state a location
  hijack creates, making the attack invisible to every layer above.
- **Python requirement**: `HostIdentity` pairs MAC with an explicit, coarse
  `confidence` *label* (never a number), and observations of one MAC at
  different ports remain distinct values.
- **Regression test**: `test_same_mac_at_two_ports_stays_distinguishable`,
  `test_confidence_is_a_label_not_a_number`. Status: VERIFIED.

### KF-11 — no clock abstraction, so no probe could ever time out

- **Legacy**: timeouts did not exist. `probedPorts` entries were created and
  never resolved, so the "no reply implies legitimate migration" branch was
  unreachable and the map grew without bound.
- **Python requirement**: time is injected. Elapsed-time decisions use a
  *monotonic* source so that an NTP step, VM migration or manual correction
  cannot un-expire a probe or expire a live one early; wall-clock time is used
  only for timestamps that evidence bundles must display.
- **Regression tests**: `tests/domain/test_clock.py::test_deadline_survives_a_wall_clock_step_backwards`
  and `::test_deadline_does_not_expire_early_on_a_wall_clock_jump_forward`.
  Status: VERIFIED.

### KF-12 — switch removal never reclaimed port state

- **Legacy**: `PortManager.switchRemoved` was an empty method with a `TODO`,
  so `port_list` and `mac_port` accumulated entries for the process lifetime.
  Combined with the unbounded `probedPorts`, three collections grew without
  limit -- a state-exhaustion surface reachable by anyone who could make
  switches connect and disconnect.
- **Python requirement**: `PortRegistry.remove_switch(dpid)` drops every port
  of a departed switch, and every collection has an explicit limit that
  *refuses* growth rather than evicting silently. Silent eviction would let
  an attacker flush a victim's record.
- **Regression tests**: `tests/topology/test_ports.py::test_removing_a_switch_reclaims_all_of_its_ports`,
  `::test_port_count_is_bounded_and_refuses_rather_than_evicting`. Status: VERIFIED.

### KF-13 — silent eviction would let an attacker erase the evidence

- **Found while designing the host table.** The obvious way to bound a host
  table is LRU eviction. That is wrong here: an attacker who can generate
  traffic from many MACs can force the eviction of a victim's record, and
  with it the prior location that makes their own move detectable.
- **Python requirement**: bounded collections *refuse* growth and say so.
  Capacity exhaustion becomes a visible operational condition rather than
  silent evidence loss.
- **Regression test**: `tests/hosts/test_table.py::test_host_count_is_bounded_and_refuses_rather_than_evicting`
  asserts the victim's record survives the refusal. Status: VERIFIED.

### KF-14 — pruning rule that hid ordinary relocation as multi-homing

- **Found by a failing test during P4-HOST-01.** `without_stale` always kept
  the primary location, which is correct for routine pruning but wrong when
  a *new* location is being added: a host that moved after the location TTL
  retained its stale old sighting and appeared concurrently multi-homed.
  Multi-homing is the hijack signal, so this would have produced false
  positives for entirely ordinary relocation.
- **Fix**: `keep_primary` distinguishes the two needs, and the non-empty
  invariant moved to `HostTable._store`, the single point where records enter
  the table.
- **Regression tests**: `::test_old_location_ages_out_and_the_move_becomes_plain`,
  `::test_a_stored_record_always_has_at_least_one_location`. Status: VERIFIED.
