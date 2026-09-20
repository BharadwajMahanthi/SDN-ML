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

### KF-15 — probe replies could be forged by any on-segment attacker

- **Legacy**: the reply check compared source IP, source MAC and a hardcoded
  controller IP. Every one of those is forgeable by an attacker on the same
  segment, and there was no nonce at all. An attacker could therefore have
  *manufactured* a hijack verdict against a host that had legitimately moved.
- **Python requirement**: three independent checks must all pass -- a
  single-use unguessable nonce, the probed host's MAC, and the port the probe
  was actually sent to. An unmatched reply is not an error; it is simply not
  evidence.
- **Regression tests**: `tests/probes/test_manager.py::test_all_three_checks_are_required`,
  `::test_an_unknown_nonce_is_not_evidence`, and
  `tests/hosts/test_movement_scenarios.py::test_attack_forged_probe_reply_with_a_guessed_id_is_rejected`.
  Status: VERIFIED.

### KF-16 — lingering table entries made every relocation look multi-homed

- **Found by the P4 integration test, not by a unit test.** The host table
  retains a previous location until its TTL expires. The detector treated any
  `concurrent_locations > 1` as concurrent presence, so an entirely ordinary
  relocation inside the TTL window produced a `HOST_MULTI_LOCATION` finding.
  Multi-homing is a hijack signal, so this was a false-positive generator on
  the most common benign event in the system.
- **Distinction that fixes it**: a stale table entry is *bookkeeping*; a probe
  reply is *observation*. Multi-location is now reported only when validation
  did not establish that the host left -- `SUSPICIOUS_MOVE` or
  `INCONCLUSIVE`, never `MOVE_ACCEPTED`.
- **Regression tests**: `tests/detection/test_deterministic.py::test_benign_relocation_is_not_reported_as_multi_location`,
  `tests/integration/test_p4_pipeline.py::test_benign_relocation_emits_no_finding_at_all`.
  Status: VERIFIED.

### KF-17 — clearing state before reading it leaked every host on a departed switch

- **Found by an adapter test.** `on_switch_disconnected` called
  `ports.remove_switch()` *before* iterating that switch's ports to forget
  the hosts attached to them. The iteration therefore found nothing and every
  host survived its switch -- the same class of leak as KF-12, reintroduced
  by statement order in the very code written to fix it.
- **Fix**: capture the port list before clearing the registry.
- **Lesson recorded**: a cleanup path needs a test that asserts what is *gone*,
  not only that the call was made.
- **Regression test**: `tests/adapter/test_contract_and_controller.py::test_disconnect_does_not_leak_hosts_on_multiple_ports`.
  Status: VERIFIED.

### KF-18 — ICMP type compared against a code field

- **Legacy**: `icmp.getIcmpCode() == ICMP.ECHO_REPLY`, where `ECHO_REPLY` is
  a *type* constant equal to `0x0`. Echo request, TTL-exceeded and
  destination-unreachable all carry code 0, so every one of them would have
  satisfied the probe-reply test.
- **Python requirement**: `ParsedFrame.is_icmp_echo_reply` checks the ICMP
  *type*, and the correlation test additionally requires a nonce, the probed
  host's MAC and the probed port (KF-15).
- **Regression test**: `tests/adapter/test_normalize.py::test_the_legacy_icmp_confusion_cannot_recur`
  asserts all three of those messages fail the check while carrying code 0.
  Status: VERIFIED.

### KF-19 — the lab is driven by root account access keys (HIGH, unresolved)

- **Found during P6-LAB-01 preflight.** `sts:GetCallerIdentity` returns a
  **root** principal. Root access keys cannot be scoped, cannot be constrained
  by a permission boundary, and cannot be contained after a leak without
  closing the account. This contradicts the project's own contract, which
  requires least-privilege IAM and short-lived credentials.
- **Status**: MITIGATED, not closed (2026-09-20). Normal operation now runs on
  temporary STS credentials from `sdnguard-lab-role`, reached through an IAM
  user whose only permission is to assume it (ADR-023). Root keys are still
  **active**; deactivating them is an owner action that must not be automated.
  See `ROOT_KEY_REPLACEMENT_READY` in CURRENT_STATE.md for the exact steps.
- **Recommendation**: create an IAM principal scoped to EC2, CloudFormation
  and SSM in `ap-south-1`, switch to it, and **delete the root access keys**.
- **Carried into**: P11-AWS-02, which cannot honestly be called complete while
  the lab runs on root credentials.

### KF-20 — a denial probe that never reached IAM authorization

- **Found while verifying the new credential.** The probe
  `ec2:RunInstances --region us-east-1` with a fake AMI id was reported as
  "NOT DENIED - PRIVILEGE TOO BROAD". The policy was correct; EC2 validates
  the AMI identifier before evaluating IAM, so the call failed with
  `InvalidAMIID.Malformed` and the region condition was never exercised.
- **Why it matters**: the error is symmetric. The same probe could as easily
  have been counted as a pass, asserting a least-privilege property that was
  never tested -- the same species of error as the legacy project's
  tautological detection.
- **Fix**: denial probes now have three outcomes, with *inconclusive* never
  counting as a pass, and region-scoped probes carry a positive control that
  proves they reach authorization (ADR-024).
- **Regression evidence**: `verify_credentials.sh` reports
  `19 expected, 0 unexpected, 0 inconclusive`, with
  `ec2:CreateSecurityGroup --dry-run` returning `DryRunOperation` in
  ap-south-1 and `UnauthorizedOperation` in us-east-1. Status: VERIFIED.

### KF-21 — two OpenFlow listeners raced for port 6653

- **Found on first real controller start.** The launcher spawned
  `OpenFlowController()` while `AppManager.instantiate_apps()` had already
  started os_ken's `OFPHandler`, whose `start()` spawns one. The loser raised
  inside an eventlet timer.
- **Why it mattered**: harmless noise on that run, but it would have masked a
  genuine bind failure, which is exactly the condition KF-22 turned out to be.
- **Fix**: let the framework own the listener. Regression: the experiment
  runner asserts exactly one listener and aborts otherwise.

### KF-22 — the controller never terminated, voiding the next experiment

- **Found by the experiment runner's own abort guard.** `--seconds 45` left a
  controller alive at 231 seconds, still holding port 6653. The next
  controller's bind failed silently, OVS logged `Connection refused`, and the
  run produced an **empty** event journal.
- **Why this is the most serious defect so far**: an empty run is
  indistinguishable from "nothing was detected". A negative control that
  silently failed to start would have *passed* -- manufacturing exactly the
  tautological result this project exists to avoid.
- **Root cause**: returning from `main()` does not end the process; os_ken
  leaves greenthreads and a hub running. SIGTERM set the stop flag, the loop
  broke, and the interpreter stayed up.
- **Fix**: explicit `manager.close()` then `os._exit(0)`; escalating
  TERM-then-KILL in the runner; and the runner now waits for a **normalised
  `switch_connected` event** before running any scenario, aborting if it never
  arrives. Status: VERIFIED -- the guard caught this defect in practice.

### KF-23 — a merge gate was skipped (process failure, not code)

- **What happened.** `feat/p6-openflow-01-osken-adapter` was merged into
  `main` while `test_the_whole_p4_core_imports_no_openflow_library` was
  failing. Three separate guards scan for framework imports; adding
  `adapter/osken.py` required updating all three, and only two were updated.
  The full suite was run, the failure was visible in its output, and the merge
  proceeded anyway.
- **Why it matters more than the one-line fix.** The explicit rule is "do not
  skip a failed merge gate merely to reach the next task". Reporting a green
  suite when it was red is the same category of error as the legacy project's
  tautological detection, committed by the process rather than the code.
- **Code fix**: the P4 guard now enumerates the core packages explicitly
  rather than scanning the whole tree, because the P4 claim is about the core
  and `adapter/` is the framework boundary by design. A companion test asserts
  the package list matches the directory tree, so a new package cannot quietly
  escape the guard.
- **Process fix**: the suite result must be read before the merge command is
  issued, not in the same command. Three overlapping guards with different
  scopes was itself the trap -- each now states what it covers and why.
- **Now enforced in code** (ADR-031). `tools/merge_gate.py` refuses any
  non-PASS required check, decides from exit status and a JUnit artifact
  rather than text, and binds evidence to a commit. The regression test
  reproduces the exact KF-23 shape and drives a real merge attempt.
- Status: code VERIFIED; process failure now VERIFIED as mechanically blocked.

### KF-25 — the gate trusted its own artifact's eligibility flag

- **Found by the gate's own tests during V2-GOV-01.** `validate()` read the
  stored `merge_eligible` boolean instead of re-deriving eligibility from the
  per-check statuses. A producer bug -- or a hand-edited artifact -- could
  therefore assert its own merge eligibility, which is the whole property the
  gate exists to provide.
- **Fix**: producer and validator share one `evaluate()` function, and a
  disagreement between the artifact's boolean and its own checks is itself a
  refusal. Regression: `test_a_forged_merge_eligible_flag_is_ignored`.
  Status: VERIFIED.

### KF-24 — the redactor masked branch names, then leaked an AWS secret shape

- **Found while reading the V2 architecture document.** Long hyphenated branch
  names such as `feat/v2-response-01-privileged-broker` are high-entropy and
  mixed-class, so the entropy rule masked them and made the milestone table
  unreadable. The same family as KF-02, which fixed `/` but not `-`.
- **Then the fix regressed the other way.** Widening the identifier rule to
  accept mixed case let `wJalrXUtnFEMI_K7MDENG_bPxRfiCYEXAMPLEKEY` -- the
  canonical AWS secret example -- through as an "identifier". Fixing
  over-redaction created under-redaction of a real secret shape.
- **Discriminator**: a slug is single-case with separators; a secret is
  mixed-case and high-entropy. Both directions now have tests, because only
  testing the direction you just fixed is how the second bug was introduced.
- Status: VERIFIED, 89 firewall tests.

### Known limitation — prose over-redaction

The `assigned_secret` rule matches a secret-ish word followed by a value, so
ordinary prose like "credential theft" and "signature checks" is masked when
reading documents. This is the safe direction and the meaning stays
recoverable from context, so it is recorded rather than fixed; tightening it
risks the KF-24 regression again.

### KF-26 — the event decoder crashed on a malformed array field

- **Found by fuzzing during V2-CORE-01.** A payload whose `entity_refs` was a
  JSON object rather than an array reached an unguarded slice and raised
  `KeyError` out of the decoder. At a trust boundary the answer to malformed
  input is a rejection; an exception escaping into the caller is a crash the
  agent cannot afford.
- **Fix**: `_as_list` coerces and bounds any list-shaped field before use.
- **Regression**: `test_a_non_list_entity_refs_field_is_rejected_not_a_crash`
  plus 6000 fuzz cases across random and structurally-valid-but-mutated
  payloads. Status: VERIFIED.
