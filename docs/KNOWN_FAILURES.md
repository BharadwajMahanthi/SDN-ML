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

### KF-27 — a diamond ancestry was rejected as a cycle

- **Found by the evidence-model tests.** The cycle check used a single
  visited set across the whole traversal, so a node reachable by two paths --
  E4 derived from E2 and E3, both derived from E1 -- was reported as a cycle.
- **Why it mattered**: that shape is not an edge case, it is the ordinary
  structure of correlated evidence, and it is precisely the structure this
  model exists to represent. The check would have rejected the main case.
- **Fix**: depth-first with an explicit path set; only a node repeating on
  the current path is a cycle. Regression: `test_a_diamond_is_not_a_cycle`
  and `test_a_diamond_ancestry_resolves_to_one_root`. Status: VERIFIED.

### KF-28 — the deployment shipped a hand-kept package list

- **Found when the sensor experiment failed with `No module named 'annulon'`.**
  `deploy.sh` copied `development/src/sdnguard` by name, so it silently
  stopped shipping the full source the day a second package appeared.
- **Fix**: iterate every package under `development/src`. A hand-kept list is
  a defect waiting for the next addition.

### KF-29 — the payload outgrew the SSM inline limit

- The base64 transfer exceeded SSM's 97 KB cap once `annulon` was included.
  Rather than add an S3 bucket and its IAM grant, the transfer is chunked and
  the reassembled tarball is checksum-verified before extraction -- a
  truncated chunk would otherwise surface later as a confusing import error.

### KF-30 — `cp -R dir/` flattened both packages into one directory

- The trailing slash copies a directory's *contents*. Both packages landed
  directly in `src/`, so neither was importable. Trivial, and it cost a
  deployment cycle; noted because the failure mode was a confusing
  `ModuleNotFoundError` rather than an obvious copy error.

### KF-31 — two names for one predicate drifted apart

- **Found immediately by a test when liveness was added.** `collection_complete`
  and `trustworthy_absence` answered the same question through separate
  implementations. Liveness was wired into one and not the other, so a sensor
  *proven dead by its own probe* still reported that its silence was
  meaningful -- exactly the property the probe exists to deny.
- **Fix**: one implementation, the other delegates. Two names are kept
  because a detector and an operator ask the question differently, but there
  is now only one answer.
- **General lesson recorded**: duplicated predicates do not stay equal. When
  a safety property has two accessors, one must call the other.

### KF-32 — the entropy rule treated keyword arguments as secrets

- **Found by `tools/verify_all.py` on its first run**, which is the whole
  argument for periodic whole-system re-verification: the defect had been
  sitting in a shipped, tested module and no existing test looked for it.
- `=` was in the entropy candidate class, so `default_factory=CollectionQuality`
  matched as one 33-character high-entropy token. `=` is only ever *trailing*
  base64 padding, so it now appears only in that position. `Title_Snake_Case`
  doc anchors needed their own rule, discriminated from a mixed-case secret
  by each segment being capital-then-lowercase -- `wJalrXUtnFEMI_K7MDENG`
  has capitals *inside* a segment and is still redacted.
- **Regression**: both directions tested, as KF-24 taught.

### KF-33 — the privileged-action guard confused `re.compile` with `compile`

- **Found on the guard's first run.** It applied the forbidden-builtin list to
  attribute calls as well as bare names, so every module containing a regex
  failed. A guard that fires on ordinary code gets weakened or ignored, which
  would have been the real damage.
- **Fix**: bare `Name` calls are checked against the builtin denylist;
  attribute calls only against process and privilege primitives.

### KF-34 — the redactor read prose as a secret assignment and blocked memory writes

- **Found while recording owner rules.** A memory checkpoint describing
  "peer-credential auth via LOCAL_PEERCRED" was refused as
  `MEMORY_FORBIDDEN_CONTENT: probable secret material (assigned_secret)`.
- **Cause**: the assignment rule accepted bare whitespace as an assignment
  operator (`(?P<sep>\s*[:=]\s*|\s+)`), so any sentence containing
  `credential`, `token`, `key`, `secret` or `auth` followed by a four-letter
  word became a HIGH finding. `credential auth` parsed as `credential = auth`.
- **Why it mattered even though it fails closed.** No data leaked — the store
  refused the write. But durable record-keeping is itself a safety property
  here, and a redactor that blocks legitimate records is one that gets
  bypassed. A guard that fires on ordinary prose does not stay enabled.
- **Fix**: a whitespace-separated value is treated as prose when it is a
  plain alphabetic word of at most 15 characters and the name carries no
  command-line flag marker. `=` and `:` separators are unchanged, flags
  (`--password hunter2`) still match, and long all-alphabetic values stay
  suspicious because a real passphrase can be all letters.
- **Second defect during the fix**: the first flag-marker pattern matched the
  hyphen *inside* `peer-credential`, so the prose case was still treated as
  `-credential <value>`. The flag marker now requires a non-alphanumeric
  character before the dash. Both directions are tested.

### KF-35 — three RSA private keys are committed, and the secret check could not see them

- **Found while preparing to publish the archive branch.** A filename scan of
  `legacy/java-topoguard-research` returned `clab-sdn-simple/.tls/ca/ca.key`,
  `clab-sdn-complex/.tls/ca/ca.key` and `clab-win-test-lab/.tls/ca/ca.key`,
  each beginning `-----BEGIN RSA PRIVATE KEY-----`.
- **They are already public.** The same blobs are present in `origin/main`,
  which is a public GitHub repository, introduced by commit `bea42bf`. They
  are removed from the tip of the current `main` tree but remain in history.
  Publishing the archive branch therefore discloses nothing new; the
  disclosure already happened.
- **Why `committed_secrets` missed them.** That check filters to text source
  extensions (`.py`, `.sh`, `.yaml`, …) before scanning. A `.key` or `.pem`
  file is skipped entirely — the guard against committed secrets could not
  see the most secret-shaped files in the repository.
- **Fix**: a separate `key_material` check in `tools/verify_all.py` scans
  *every* tracked file for private-key headers with no extension filter, and
  reports the path without ever printing the body. Allowances live in
  `EXPECTED_KEY_MATERIAL` and a stale one is reported.
- **Assessed impact: LOW, but the keys must be treated as compromised.** They
  are Containerlab-generated CA keys for ephemeral local lab TLS. They sign
  certificates only for throwaway lab containers, and grant no access to AWS,
  to any host, or to any production system. Containerlab regenerates them per
  deployment, so nothing depends on them.
- **OWNER_ACTION_REQUIRED**: purging them from history rewrites a published
  public branch and cannot be done unilaterally. See `docs/CURRENT_STATE.md`.

### KF-36 — the broker allowed privileged actions built from coerced garbage

Four defects, all found by the V2-SAFE-02 fuzz suite, all of which produced
an **ALLOW** rather than a crash. Each was a case of the decoder being
helpful where it should have been strict.

- **`str()` coercion laundered wrong types.** `ActionRequest.from_dict` read
  every text field through `str(raw.get(field, ""))`. A JSON `null` reason
  became the string `"None"` — non-empty, under the length cap, and
  therefore an acceptable justification for a privileged action. An integer
  `request_id` of `9223372036854775808` became a string that matched the id
  pattern and was allowed. Fixed with `_require_str`/`_require_int`, which
  refuse a wrong type instead of reinterpreting it.
- **`True` passed as schema version 1.** `bool` is a subclass of `int` in
  Python, so `raw.get("schema_version") != SCHEMA_VERSION` was false for
  `true`. `_require_int` rejects `bool` explicitly.
- **A blank reason was accepted.** `if not self.reason` passes for `" "`.
  An action with no stated reason is unauditable, which defeats the point of
  recording one. Now `reason.strip()` must be non-empty, and control
  characters are refused in `reason` and `policy_version` alike: a newline in
  a field that lands in an audit record is a log-forging primitive.
- **`policy_version` was unbounded.** Every other recorded string had a cap.
  Now 64 characters.
- **`json` accepted `NaN` and `Infinity`.** Non-standard tokens Python's
  decoder allows by default. Nothing in the contract can represent them, and
  a float that compares false against itself has no place in a privileged
  decision. `read_message` now passes `parse_constant` and rejects them.

The common lesson is that every one of these was a *coercion*, not a missing
check. The checks were present and were being handed values that had already
been reshaped into acceptable form.

Three test defects were found in the same pass and are worth recording so
they are not reintroduced: a cap-sized message deadlocked a socketpair
because the send was not on its own thread; reusing one `request_id` across
fuzz cases made replay protection look like a contract failure; and low
active-action ceilings in the fuzz fixture denied everything after the
fourth case for an unrelated reason, hiding the property under test.

### KF-37 — `nft` text output can be forged by the data it describes

- **Found while choosing how to read rule ownership.** A rule comment
  containing a double quote makes `nft -a list` render ambiguously:
  `comment "annulon;a=a-1;evil" ; rm -rf /"`. Anything parsing that text
  could be steered by the comment it is trying to classify — a crafted
  comment could make a foreign rule look Annulon-owned, or hide an owned one.
- **Fix**: ownership is read exclusively from `nft -j list`, where the
  comment is a JSON string field and round-trips verbatim. Commands are
  likewise written through `nft -j -f -` from a structure built of typed
  values, so nft's own grammar never sees Annulon data. Verified: the same
  hostile comment round-trips through JSON unchanged.
- **Generalised** (doctrine §51): the bug family is *a tool's human-readable
  output being used as a machine interface*. Any other place that parses CLI
  text where a structured mode exists is now suspect.

### KF-38 — an IPv4-scoped rule does not restrict IPv6

- **Found by the bypass experiment**, not by reasoning about the code. Under
  a rule matching `meta skuid 1500` and an IPv4 destination, an IPv6
  connection from the same uid stayed `OPEN`.
- **Why it matters**: "egress restricted" would have been a false claim. An
  attacker reaching a dual-stack destination is unaffected by the v4 rule.
- **Measured contrast**: an *unscoped* rule (no destination match) in the
  `inet` family does cover both families — the same v6 probe timed out.
- **Fix**: `Coverage` (`ipv4_only` / `ipv6_only` / `all_families`) is computed
  per action and reported on every enforcement result, with
  `is_complete_egress` false for a single-family rule. The capability is now
  named *IPv4 egress restriction* where that is what it is. Full dual-family
  destination scoping is not yet implemented and is `NOT_RUN`.

### KF-39 — the bypass harness measured the wrong process's socket

- **Nearly produced a false finding.** The "established connection" probe
  opened its socket in the experiment's own root process, which
  `meta skuid 1500` never matches. It reported that a pre-existing
  connection survived containment — which would have been a serious gap, and
  was entirely an artefact of the harness.
- **Corrected**: the connection is now opened and resumed by a subprocess
  running as the target uid. Re-measured, the established connection is
  **blocked** (`TimeoutError`), so the drop does apply to existing flows.
- **Also fixed in the same pass**: the forked-child probe's output was lost
  because `os._exit` skips flushing, so a measured path silently reported
  nothing. Both `fork` and `exec` are now observed blocked.
- **Doctrine §11 in practice**: the harness must measure the thing the claim
  is about. This one was measuring a different identity entirely, and it
  failed in the direction that invents a defect rather than hiding one —
  which is the safer direction, but still a defect in the evidence chain.

### KF-41 — the mutation tester corrupted a concurrent test run

- **Found while running mutation testing in the background.** Four unrelated
  `test_nftables_backend.py` tests failed in a full-suite run and passed in
  isolation. The cause was not in the tests: a mutation run was holding
  `verification.py` rewritten on disk at that moment, so the suite imported
  mutated source.
- **Why it is a real defect, not a usage mistake.** A tool that rewrites
  source in place while other processes may import it produces failures that
  point at the wrong code. The cost is paid by whoever debugs the next
  mysterious failure — and under this project's own doctrine, a flaky
  security test blocks its claim, so a tool that manufactures flakiness
  attacks the evidence chain directly.
- **Fix**: an exclusive lock file refuses a second concurrent run with an
  explanation; `atexit` and SIGINT/SIGTERM handlers restore the original
  source even when the run is killed. Previously, interrupting a run left
  mutated source on disk indefinitely.
- **Generalised** (doctrine §51): the family is *test infrastructure that
  mutates shared state other processes depend on*. Also applies to the lab
  scripts, which now use their own nftables table and their own container
  network for the same reason.
- **Recurrence in V2-HOST-04E, and the real fix.** The lock stopped a second
  *mutation* run but nothing stopped an ordinary `pytest` invocation, and a
  full-suite run started while a mutation was applied reported **21 unrelated
  failures** that passed on a re-run. The advisory rule in `AGENTS.md` did
  not prevent it — the same shape as KF-46, where a generalised rule lived in
  a document while the defect lived in new code. A repository `conftest.py`
  now refuses any test run while the lock is held, unless it carries the
  environment marker `tools/mutate.py` sets for its own pytest subprocesses.
  Silent corruption became a loud refusal, which is what the rule should have
  been in the first place.

### KF-40 — a target uid had several spellings, including non-ASCII digits

- **Found by the compromised-core suite**, in the policy-confusion cases the
  doctrine requires (§25).
- **The defect**: a `service_uid` identifier was validated with
  `str.isdigit()` and converted with `int()`. Both accept Arabic-Indic
  (`١٥٠٠`), Devanagari (`१५००`) and fullwidth
  (`１５００`) digits, so those strings resolved to uid 1500 and were
  authorized. Leading zeros (`01500`) gave the same uid a second spelling.
- **Was it exploitable?** Not directly, and the suite says so rather than
  overstating it. Both the permitted-uid check and the protected-uid check
  go through `.uid`, so they agreed with each other: a protected uid written
  in confusables was still protected. The danger is structural — one
  identity with several representations is how a future check that compares
  *strings* comes to disagree with one that compares *numbers*, and the
  journal recorded a spelling that the installed rule did not use.
- **Fix**: a `service_uid` identifier must match `^(0|[1-9][0-9]{0,9})$` —
  canonical ASCII decimal, no sign, no padding, no Unicode digit variants —
  and must be within the kernel's uid range. `Target.uid` no longer
  re-derives a number from anything that merely looks like one.
- **The test proves the threat is real** before asserting the fix: it
  verifies that those confusable strings genuinely satisfy `isdigit()` and
  convert to 1500. Without that, refusing them would be trivially safe and
  the test would be theatre.
- **Generalised** (doctrine §51): the family is *validating a value with one
  function and using it with another*. `isdigit`/`int`, `strip`/`==`,
  `lower`/`in` and normalisation before comparison are all the same shape.

### KF-42 — every authorization limit was tested inside its range, never at it

- **Found by mutation testing**, which is the only reason it was found at
  all: the suite was green, and stayed green with the checks altered.
- **The pattern**: `request age`, `clock skew`, `rate limit`, `active-action
  ceiling`, `TTL`, `policy max_ttl`, `replay-cache size` and the `rate
  window` were each exercised well inside their range and well outside it,
  and never *at* the boundary. Flipping `>` to `>=` — the classic off-by-one
  that turns "exceeds the limit" into "is at the limit" — changed
  authorization semantics in every one of those places with no test failing.
- **The worst instance**: `if ttl > MAX_TTL` in `BrokerPolicy.load`. Mutated
  to `>=`, a policy at exactly the contract ceiling becomes unloadable — and
  an unloadable policy denies everything, so this is a silent, total
  containment outage. Nothing detected it.
- **A second pattern**: guards that never fired. Deleting the
  `permitted_target_kinds` check survived because only one `TargetKind`
  exists and it is permitted by default, so the guard was never exercised.
  The same was true of most of `contract.py`'s type guards, which the JSON
  decode path can never reach — they exist for programmatic misuse, and
  nothing constructed those objects wrongly on purpose.
- **Fix**: `test_authorization_boundaries.py` and `test_contract_guards.py`
  cover before / exact / after for every limit, and construct every type
  incorrectly on purpose. Results: `contract.py` 0 survivors of 91,
  `nftables.py` 0 of 72, `policy.py` 1 of 48 (verified equivalent —
  `ip_network(None)` raises, so the `except` returns the same value).
- **Generalised** (doctrine §51): the family is *a limit whose boundary is
  never the test input*, and *a guard that no test can reach*. Both are
  invisible to coverage tools, because the line executes either way.

### KF-43 — `$` in a validation regex accepted a trailing newline

- **Found by the network contract's own adversarial suite**, before shipping,
  which is the first time in this project a defect of this family has been
  caught at that stage rather than after.
- **The defect**: `re.compile(r"^[\x20-\x7e]{1,64}$")` looks like it forbids
  control characters, and does — except that Python's `$` also matches
  immediately *before* a trailing newline. `"worker\n"` passed validation.
  The same pattern let `"obs-1\n"` through as an observation id.
- **Why it matters**: both fields reach logs and audit records. A newline in
  an identity field is a log-forging primitive, which is exactly the hazard
  `reason` and `policy_version` were hardened against in KF-36. The guard was
  present and looked correct.
- **Fix**: `\A...\Z` throughout, which has no newline exemption. Both fields
  are also type-checked before the regex, because `re.match(None)` raises
  `TypeError` rather than the contract's own error, and the decoder above
  catches only the contract error.
- **Generalised** (doctrine §51): the family is *an anchor that does not mean
  what it appears to mean*. KF-01 was `\b` failing after an underscore; this
  is `$` admitting a newline. Every validation regex in the repository is now
  suspect until checked, and `fullmatch` or `\A...\Z` is the standard.

### KF-44 — closing the trace pipe from another thread deadlocked the sensor

- **Found by the sensor hanging** in its first live run: the container sat
  for minutes producing nothing, with the main thread parked in
  `futex_wait_queue`.
- **Cause**: the reader iterated a buffered file object over `trace_pipe`,
  which blocks until an event arrives. `stop()` then called `close()` from
  another thread. In CPython, `io.BufferedReader.close()` acquires the same
  internal lock the blocked `read()` is holding, so shutdown waited forever
  for a read that was waiting for traffic that had stopped.
- **Why it matters beyond a hang**: a sensor that cannot be stopped cannot be
  restarted, and the shutdown path runs during exactly the incident where
  restarting matters. It also silently defeats liveness checks, which would
  see a thread that is alive and conclude health.
- **Fix**: a raw non-blocking descriptor with `select` and a 0.2 s timeout,
  so the reader wakes on its own and observes the stop flag. `stop()` joins
  the thread *before* closing, because the reader owns the descriptor while
  it runs. Partial reads are buffered, since a read can land mid-line and
  parsing the fragment would discard a real event while counting it unparsed.
- **Generalised** (doctrine §51): the family is *closing or mutating a
  blocking resource from a thread that does not own it*. KF-41 was the
  mutation tool rewriting source another process was importing; this is the
  same shape at a smaller scale.

### KF-45 — the connect syscall tracepoint cannot say what was connected to

- **Found while explaining a discrepancy**: the sensor counted 9 connect
  attempts where the workload had made 5. Consistently four extra, every run.
- **Cause**: `sys_enter_connect` fires for *every* address family. The four
  extras were AF_UNIX connects made by the Python interpreter during startup.
  Worse, tracefs renders the syscall's argument as a pointer
  (`uservaddr: ffffda4bd498`), not as an address — so the entry event cannot
  supply the destination, the port, or even the address family. A sensor
  built on it alone would report "a connection to somewhere" and count local
  socket activity as network activity.
- **Root cause**, stated plainly: the syscall tracepoint has the right
  *process* context and the wrong *content*; the socket tracepoint has the
  right content and, at ESTABLISHED, the wrong process context.
- **Fix — the design inverted.** The primary process-attributed event is now
  `inet_sock_set_state` on the `TCP_CLOSE -> TCP_SYN_SENT` transition, which
  is IP-only by construction, carries `saddr`, `daddr`, `sport`, `dport`,
  `family`, `protocol` and the v6 forms, and runs in task context. Measured:
  **35 of 35 task-context transitions carried the correct PID.** The syscall
  pair is kept for the outcome errno and for attempts that never reach
  SYN_SENT, correlated by pid and time rather than treated as authoritative.
- **What this changes about the claim**: the capability is
  process-attributed *IP* connection observation. Local socket activity is
  not counted as network activity, which it would have been.

### KF-46 — the network parser converted non-ASCII digits into a real port

- **Found by the 04E adversarial suite**, in the family the doctrine's §51
  rule said to look for: KF-40 was `str.isdigit()` plus `int()` accepting
  Arabic-Indic, Devanagari and fullwidth digits in a *uid*, and the same pair
  was used for a *port* in a parser written afterwards.
- **The defect**: `raw_port.isdigit()` then `int(raw_port)` turned
  `dport=١٥٠٠` into port 1500. A destination expressible in several
  spellings defeats any policy that compares ports as text, and lets one
  logical destination present as two observations or two as one.
- **Fix**: `\A(0|[1-9][0-9]{0,4})\Z` — canonical ASCII decimal, no padding,
  no sign, in range by construction. The test proves the confusables really
  do convert to 1500 before asserting they are refused, so it is not
  theatre.
- **The lesson is about process, not about digits.** Generalising KF-40 into
  a rule was correct and still did not prevent the recurrence, because the
  rule lived in a document while the defect lived in a new parser. The
  durable fix is that a *test* now encodes the family, in both the privileged
  contract and the network contract.

### KF-47 — a connect attempt was recognised from the destination state alone

- **Found by the same suite**, by deleting the `oldstate` field.
- **The defect**: the normaliser matched `newstate == "TCP_SYN_SENT"` and
  ignored `oldstate`. ADR-053 declares the primary semantic to be the
  *transition* `TCP_CLOSE -> TCP_SYN_SENT`; the implementation accepted any
  event whose destination state was SYN_SENT, including a line carrying no
  `oldstate` at all. A malformed or partial line therefore produced a
  confident connect attempt.
- **Fix**: both halves of the transition are required, so the code now means
  what the ADR says. Events that do not match are counted as ignored rather
  than silently dropped.
- **Severity**: low in practice — SYN_SENT is reached from CLOSE in normal
  operation — but it is precisely the "stronger statement than the evidence
  supports" shape 04E exists to find, and it made a missing field
  indistinguishable from a complete one.

### KF-48 — an anomalous positive connect return was upgraded to ESTABLISHED

- **Found by mutation testing in 04E**, not by any hand-written case.
- **The defect**: tracefs prints syscall returns unsigned, so the normaliser
  folded large values to a signed errno and then did
  `if value > 0: value = 0  # a success return, not an errno`. But
  `connect()` returns 0 or a negative errno and **never** a positive value.
  A small positive return — which the kernel is not supposed to produce —
  was therefore rewritten to zero and classified `ESTABLISHED`.
- **Why it matters**: this is the exact shape 04E exists to find. An
  unexplained value was converted into the strongest possible claim, rather
  than the weakest. Anything that could make the field anomalous — a parser
  change, a different tracefs format, a truncated line reassembled wrongly —
  would have produced confident "connection established" records.
- **Fix**: a positive return is left alone and maps to `OTHER_ERROR`:
  unexplained, which is what it is. Zero still means established, and that
  positive control is tested so the fix cannot degrade into refusing
  everything.
- **Generalised** (doctrine §51): the family is *a normalisation step that
  rewrites an out-of-range value into an in-range one*. Coercion upward is
  always the dangerous direction; the same shape produced KF-36's
  `str(None) -> "None"` and KF-46's non-ASCII digits.

### KF-49 — attribution was resolved too late to attribute anything

- **Found by the first full-chain run**, which stopped honestly rather than
  guessing: the detector produced no supported finding.
- **Measured**: the sensor observed all 12 connection attempts and recorded
  the correct pid, but resolution ran as a batch afterwards and `/proc`
  found the process gone for **11 of the 12**. Zero observations could be
  bound to a workload.
- **Root cause**: enrichment was a *stage* rather than part of the pump. A
  short-lived workload exits in well under the time between batches.
- **Fix**: resolution happens inside the drain loop, so the gap between the
  event and the `/proc` read is milliseconds rather than seconds — which is
  what a continuously draining agent does anyway.
- **Residual, stated rather than closed**: a process that connects and exits
  inside one drain interval is still unattributable. That is the strongest
  argument for `NETWORK_TELEMETRY_EBPF`, which captures `start_boottime`
  in-kernel at event time and removes the race at source. Still NOT_RUN.

### KF-50 — the full chain was aimed at a destination the broker protects

- **Found on the second run**: the chain reached the broker and was denied
  `destination_protected`.
- **Cause**: the experiment's services were on `127.0.0.1`, and `127.0.0.0/8`
  is protected because the broker's own IPC and health checks run over it.
- **Not a product defect** — the safety property working exactly as designed
  against a badly aimed experiment. Recorded because the failure mode is
  instructive: a containment capability that cannot be demonstrated against
  loopback is a *feature*, and an experiment that quietly removed the
  protection to get a green result would have destroyed the evidence.
- **Fix in the experiment**: a non-loopback host address, which is also what
  real egress looks like.

### KF-51 — enforcement was coarser than the detection that justified it

- **Found by the benign-continuity requirement**, which is the only reason it
  surfaced: the containment worked, and took out traffic it should not have.
- **Measured**: the workload's prohibited service and its permitted service
  shared an address and differed only by port. The backend matched
  `ip daddr` alone, so restricting the destination blocked **both** —
  `workload_to_permitted: TimeoutError` while the detector's rule was about
  one port.
- **Why it matters more than it looks**: a containment that breaks
  legitimate traffic is one an operator turns off, and then nothing is
  contained at all. Granularity mismatch between detection and enforcement
  is a route to that outcome.
- **Fix**: an optional `destination_port` carried through contract ->
  proposal -> nftables, with the contract refusing a port without an address
  (a port alone would restrict that service everywhere, which is not a
  narrowing anyone can reason about). Verified: forbidden service blocked,
  permitted service on the same address stays reachable throughout.
