# Audit backlog — unverified candidate findings

An adversarial audit on 2026-10-16 fanned seven readers across the
governance tooling, the privileged broker, the network evidence pipeline,
detection and attribution, the supply chain, the honesty of the project's
own claims, and input validation repo-wide. It produced **66 candidate
findings**.

**Almost none of them are verified.** Each finding was to be judged by three
independent readers instructed to refute it; the run exhausted its session
budget after 47 of 205 agents, so only the governance and supply-chain
dimensions completed that step. Everything below that is not marked
CONFIRMED or CLOSED is **one reader's unreviewed claim**, which is weaker
evidence than anything else in `docs/`. Several are probably wrong. They are
recorded because discarding them would lose real work, and because a finding
nobody wrote down is indistinguishable from a finding nobody had.

Status vocabulary is the project's own. A candidate here is `REPORTED` at
best, and becomes a KF only after it is reproduced by execution.

**Nothing in this file is a claim about the product.** It is a to-do list
for triage. Do not cite it as evidence of a defect or of an absence of one.

| # | severity | file:line | category | claim |
|---|---|---|---|---|
| 1 | **critical** | `development/src/annulon/detect/attribution.py:131` | attribution-correctness | **CLOSED (KF-65)** — The pid-reuse guard is unreachable in the delivery path: nothing ever supplies `expected_start_ticks` and `normalize.py` never captures `start_ticks` at event time, so `recorded` is always None and every live pid is unconditionally upgraded to CORRELATED with the current occupant's uid. |
| 2 | **critical** | `development/src/annulon/network/tracefs.py:491` | degraded-observation-reads-as-success | **CLOSED (KF-63)** — `attests_completeness` is computed from thread liveness, ring-buffer loss and reader error only — `self._unparsed` is excluded — so events lost to parse failure render as a complete, attested observation epoch with an empty `degraded_reasons`. |
| 3 | **critical** | `development/src/annulon/response/ipc.py:198` | availability-dos | **CLOSED (KF-62)** — The JSON depth limit is applied after json.loads has already recursed, so a deeply nested message raises RecursionError (not a ValueError/IpcError), which escapes read_message and the server's `except ipc.IpcError` at broker.py:541 and terminates the privileged broker's serve loop. |
| 4 | **high** | `development/infra/lab/refhost_release_validation.py:220` | check-cannot-fail | The REF-HOST release validation treats the substring "sensor_available" appearing in the agent self-check output as the pass condition, so a run where the sensor is unavailable still reports COMPLETE. |
| 5 | **high** | `development/src/annulon/cli/agent.py:48` | claim-inflation | **CLOSED (KF-65)** — ADR-057's `ProcessTable` is absent from the shipped entry point — `annulon-agent` wires only the late-`/proc` `WorkloadResolver` and instantiates no process connector — while docs state the mechanism is in production and claim 40/40 attribution for it. |
| 6 | **high** | `development/src/annulon/detect/attribution.py:131` | confidence-inflation | **CLOSED (KF-65)** — The PID-reuse guard (`recorded != facts.start_ticks`) can never fire in the production pipeline because nothing ever populates `start_ticks`, so every still-alive pid is upgraded from PID_ONLY to CORRELATED with no reuse evidence whatsoever. |
| 7 | **high** | `development/src/annulon/detect/egress_policy.py:181` | degraded-observation-reads-as-clean | `DetectionResult.unattributable_violations` can never be incremented (`_violation` has no `return None` path), and unattributable egress violations are instead silently folded into `skipped_uncovered_workload`, so the detector's stated first refusal — "the observation still produces a finding, but the assessment says INCONCLUSIVE" — is not implemented. |
| 8 | **high** | `development/src/annulon/detect/process_table.py:278` | misattribution | `alive_at` applies its 2-second tolerance to *both* ends of a generation's window, so consecutive generations of one pid overlap by up to 4 seconds, and `lookup` breaks the tie toward the newest — the exact misattribution direction the module exists to prevent. |
| 9 | **high** | `development/src/annulon/detect/process_table.py:310` | misattribution | `resolve` cannot distinguish "pid unknown" from "known reuse boundary", so the `/proc` fallback answers with the pid's current occupant immediately after `lookup` has recorded a `generation_mismatch` — undoing the generation check three lines after making it, and labelling the result CORRELATED. |
| 10 | **high** | `development/src/annulon/network/normalize.py:148` | evidence-suppression | A NetworkContractError from the cosmetic `comm` field discards the entire observation (destination, pid and all) and records it only in `NormalizationStats`, which no health path reads, so the drop is invisible even in `unparsed_lines`. |
| 11 | **high** | `development/src/annulon/network/normalize.py:217` | fabricated-field | `tgid=event.pid` asserts the thread-group id from a tracefs pid field that is actually the thread id, fabricating a process identity for any multithreaded workload. |
| 12 | **high** | `development/src/annulon/response/policy.py:252` | authorization-bypass | **CLOSED (KF-64)** — The protected-destination check is skipped entirely when destination_cidr is None, so the broadest possible request (all egress) is allowed while every narrower request that names a protected address is denied. |
| 13 | **high** | `development/src/annulon/response/policy.py:200` | incomplete-fix | **CLOSED (KF-64)** — BrokerPolicy.load's fallback for protected_destinations lists only the two IPv4 entries, silently dropping the three IPv6 protections that the ProtectedScopes dataclass default carries, so a policy file that omits the key reintroduces KF-55. |
| 14 | **high** | `development/src/annulon/supply/manifest.py:256` | fail-open-authorization | **CLOSED (KF-58)** — The rollback-target restriction fails open: when no target is registered for the installed version, `expected is None` and any arbitrarily old genuinely-signed release is accepted under `--allow-rollback`, which is exactly the state `install()` leaves after a first install (state.rollback_to is None, so install.py:107 never registers anything). |
| 15 | **high** | `development/src/annulon/supply/manifest.py:284` | correctness | _compare() puts any non-numeric version segment ABOVE every numeric one, so a prerelease ranks as newer than its final release and the downgrade predicate is inverted in both directions. |
| 16 | **high** | `development/tests/network/test_network_adversarial.py:431` | test-asserts-nothing | `test_control_bytes_in_comm_cannot_reach_an_observation` never injects a control byte: every parameter is double-escaped (`"worker\\nfake"`, `"worker\\x00"`, `"\\u202eworker"`), so all five cases are pure printable ASCII and the assertions can never fail. |
| 17 | **high** | `docs/ASSURANCE_CASE.md:215` | claim-inflation | A3 states six release-substitution attacks were "physically attempted and refused on both profiles", but development/infra/lab/refhost_release_validation.py attempts only the untrusted-key case on REF-HOST. |
| 18 | **high** | `docs/ASSURANCE_CASE.md:54` | claim-inflation | The A1 section scopes its whole "physically attempted and defeated" denial table to REF-HOST, but the only unauthorized-request evidence is REF-DEV and the cited REF-HOST artifact contains no denial cases. |
| 19 | **high** | `docs/ASSURANCE_CASE.md:58` | claim-inflation | The A1 table headed "What was physically attempted, and defeated" lists 13 malicious actions, but only 8 exist in any evidence artifact and no experiment harness in the repository implements the other 5. |
| 20 | **high** | `docs/CURRENT_STATE.md:1009` | claim-inflation | The "Release-grade status for the Ubuntu/x86_64 profile" table marks IPv6 containment, the short-lived attribution gap and signed update/rollback as "closed" on REF-HOST, but every one of those results was produced only on REF-DEV, which ADR-055 forbids promoting. |
| 21 | **high** | `docs/capabilities.json:50` | profile-mismatch | NETWORK_SENSOR_LIVENESS and NETWORK_TELEMETRY_TRACEFS are claimed SUPPORTED on REF-HOST while every artifact they cite records a REF-DEV kernel, and nothing compares a claimed profile against the artifact's recorded platform. |
| 22 | **high** | `tools/context_policy.py:143` | path-screening-bypass | Blocked-path screening uses case-sensitive fnmatch against the caller-supplied path, so on macOS's default case-insensitive filesystem a case-variant spelling of a blocked path is allowed and then successfully opened. |
| 23 | **high** | `tools/memory_store.py:323` | type-coercion | A checkpoint's blockers/decisions entries are never type-checked, so a valid-JSON non-object is appended to the authoritative journal and then crashes rebuild_index with an uncaught AttributeError, permanently bricking every later checkpoint while validate() reports no issues. |
| 24 | **high** | `tools/verify_all.py:368` | correctness | **CLOSED (KF-61)** — check_main_tip_gated returns WARN (not FAIL) both when there is no gate record for main and when the record names a different commit, so verify_all exits 0 for an ungated tip -- contradicting AGENTS.md:229, docs/DECISIONS.md:1119 and docs/CURRENT_STATE.md:1029, which all state it fails. |
| 25 | **high** | `tools/verify_all.py:379` | correctness | **CLOSED (KF-57)** — check_main_tip_gated trusts the record's stored `merge_eligible` boolean instead of re-deriving eligibility from the per-check statuses, and never checks schema_version or the `branch` field -- verify_all does not import merge_gate at all, so Gate.evaluate's re-derivation is bypassed. |
| 26 | **high** | `tools/verify_all.py:335` | gate-bypass | check_capabilities only validates evidence tokens that literally begin with "docs/", so a SUPPORTED capability backed by free prose, or by a second filename in a comma list, passes the gate ADR-056 says refuses a claim whose evidence file does not exist. |
| 27 | **high** | `tools/verify_all.py:164` | degraded-check-reads-as-pass | check_secrets discards every `assigned_secret` finding, which is the only redactor rule that detects a credential assigned to a secret-named variable, so the committed-secrets check can never fail on the commonest committed-credential shape. |
| 28 | medium | `development/infra/lab/refhost_release_validation.py:166` | circular-evidence | The REF-HOST validation extracts the unverified wheel with `python -m zipfile -e` and then runs the installer out of that extraction (PYTHONPATH=.../bootstrap, line 170), so the verifier under test is supplied by the artifact under test — a harness that cannot fail for a malicious artifact, and a direct contradiction of its own docstring (line 12, "verified ... before anything is unpacked") and ADR-058 (docs/DECISIONS.md:1082). |
| 29 | medium | `development/infra/local/fullchain_experiment.py:103` | profile-mismatch | detect_profile is the only measured-profile code in the repository, so every other evidence artifact records no profile at all and capabilities.json assigns profiles by hand -- the condition KF-52's fix was supposed to remove. |
| 30 | medium | `development/src/annulon/cli/agent.py:44` | capability-not-in-delivery-path | The only production entry point instantiates `NetworkLivenessMonitor` but never calls `run()`, so no liveness probe is ever fired in the delivery path and `status()` is permanently NEVER_PROBED. |
| 31 | medium | `development/src/annulon/detect/process_table.py:148` | clock-skew | The table timestamps generations with wall-clock `datetime.now()` while observations are timestamped from a boot time cached once plus an ftrace timestamp, so any drift above the 2-second tolerance makes every lookup miss and silently diverts resolution to the unchecked `/proc` fallback. |
| 32 | medium | `development/src/annulon/detect/process_table.py:300` | crash | `resolve` copies the raw `/proc/<pid>/comm` string into a `ProcessRef`, whose `_COMM` validator rejects anything outside printable ASCII, so an unprivileged process can make attribution raise and silently discard an entire observation batch. |
| 33 | medium | `development/src/annulon/network/normalize.py:228` | false-flow | `_from_state` hard-codes `Direction.OUTBOUND` for the TCP_ESTABLISHED and ex-ESTABLISHED branches, so every inbound connection is recorded as an outbound flow from this host to the remote peer. |
| 34 | medium | `development/src/annulon/network/normalize.py:123` | silent-degradation | `_read_boot_time` silently falls back to `datetime.now()` when /proc/stat has no readable `btime`, fabricating every `observed_at` as now+uptime with no flag, counter or health field to say the timeline is unreconstructed. |
| 35 | medium | `development/src/annulon/response/broker.py:191` | audit-evasion | Target.service_name is never length-bounded, so an oversized value makes the DENIED journal record exceed the journal's 16 KiB per-record cap, and _journal_safely swallows the JournalError, leaving a refused privileged request with no durable audit record. |
| 36 | medium | `development/src/annulon/response/broker.py:259` | error-handling | _release calls self._enforcer.release() without catching EnforcementError, so a release that the backend refuses is answered as MALFORMED_REQUEST and leaves the journal entry in its OS-holding state with no ROLLBACK_REQUIRED transition. |
| 37 | medium | `development/src/annulon/response/contract.py:356` | type-coercion | `destination_cidr=destination or None` coerces an empty-string CIDR to None, silently widening a privileged action from one address to the whole host instead of refusing a malformed value. |
| 38 | medium | `development/src/annulon/response/nftables.py:488` | false-containment-claim | _port_match hardcodes `protocol: "tcp"`, so a port-scoped containment restricts only TCP, while coverage_for ignores the port entirely and the broker reports only address-family coverage. |
| 39 | medium | `development/src/annulon/response/policy.py:119` | config-validation | BrokerPolicy.load never parses protected_destinations entries and covers_destination's try/except guards only the requested CIDR, so one unparseable protected entry turns every scoped request into a broker fault while unscoped requests stay allowed. |
| 40 | medium | `development/src/annulon/supply/install.py:128` | toctou | install() is verify-by-path then use-by-path: the artifact is hashed inside verify_manifest and then re-opened by pip from the same path, with no copy to a private directory, no fd pinning and no re-check, so the verified bytes and the installed bytes need not be the same file. |
| 41 | medium | `development/src/annulon/supply/install.py:142` | claim-inflation | The signed `rollback_to` field is parsed and never enforced: install() records `rollback_to=state.version` (whatever happened to be installed before) instead of `result.manifest.rollback_to`, so the enforced rollback target is local history, not the version the release signed. |
| 42 | medium | `development/src/annulon/supply/install.py:110` | missing-binding | `package` is a signed manifest field that nothing ever compares: install() never checks that the manifest describes annulon, and InstallState records no package, so version state is keyed globally across every artifact the signing key touches. |
| 43 | medium | `development/src/annulon/supply/install.py:51` | fail-open-authorization | **CLOSED (KF-60)** — InstallState.load() maps every unreadable or foreign-shaped state file to an empty state ("No state is a first install, not a failure"), silently disabling the only downgrade control, and the resulting report is byte-identical to a genuine first install. |
| 44 | medium | `docs/ASSURANCE_CASE.md:115` | claim-inflation | Four rows of the A2 "physically attempted, and defeated" table correspond to no key in any evidence artifact and no case in the liveness harness, and one of them is listed elsewhere as explicitly not supported. |
| 45 | medium | `docs/ASSURANCE_CASE.md:185` | unsupported-measurement | Two of the four mutation-testing figures cited as the assurance case's falsifiability evidence appear nowhere else in the repository, and a third contradicts the number recorded in KNOWN_FAILURES. |
| 46 | medium | `docs/CURRENT_STATE.md:71` | doc-contradiction | The "What does NOT exist yet" section of the document every session is required to read states that components which are shipped and tested do not exist. |
| 47 | medium | `docs/CURRENT_STATE.md:178` | stale-claim | **CLOSED (fixed this session)** — The standing OWNER_ACTION_REQUIRED blocker claims publishing is blocked and that the published repository contains no Annulon work, but origin/main already points at the current HEAD. |
| 48 | medium | `docs/capabilities.json:104` | profile-mismatch | SDN_TOPOLOGY_DETECTION is recorded as demonstrated on REF-DEV and "not re-validated on REF-HOST", but CURRENT_STATE records the OVS/OpenFlow verification as having run on Ubuntu 24.04.4 / kernel 7.0.0-1012-aws -- the REF-HOST platform. |
| 49 | medium | `tools/merge_gate.py:222` | correctness | check_checkpoint matches any journal record whose task_id equals the argument anywhere in the whole journal, ignoring the record's `base_commit` and recency, so the memory checkpoint does not bind the task id to the commit being gated -- yet ADR-059 (docs/DECISIONS.md:1138) relies on it as the sole task-identity verification now that branch_matches_task abstains to NOT_APPLICABLE on main. |
| 50 | medium | `tools/redact.py:180` | under-redaction | _NOT_A_LITERAL treats any unquoted value containing a dot as an attribute-chain reference, so a real literal secret with a '.' in it passes through completely unredacted. |
| 51 | medium | `tools/redact.py:204` | over-redaction | The KF-34 prose exemption only applies to whitespace separators, so ordinary prose using a colon after 'auth', 'token', 'secret', 'credential' or 'private_key' is still a HIGH assigned_secret finding and the memory store refuses the whole write. |
| 52 | medium | `tools/safe_exec.py:83` | false-claim-in-code | The comment claims the echoed command line is redacted so a credential like `mysql -pSECRET` cannot leak, but _SECRET_NAME's `(?<![A-Za-z0-9])` lookbehind can never match a short-flag-glued value, so the credential is echoed verbatim with 'redaction: none'. |
| 53 | medium | `tools/safe_exec.py:35` | path-screening-bypass | screen_arguments only screens arguments that exist as filesystem paths, so git revision syntax reaches a blocked path's content through an allowed command. |
| 54 | medium | `tools/verify_all.py:238` | degraded-check-reads-as-pass | check_key_material inspects only the first 8192 bytes of each tracked file, so private key material past that offset is invisible to the check whose stated purpose is that it 'cannot afford a filter'. |
| 55 | low | `development/src/annulon/network/normalize.py:306` | width-assumption | The unsigned-to-signed fold for a connect() return hard-codes a 64-bit width (`value >= 1 << 63`), so on a 32-bit kernel no errno is ever folded and EINPROGRESS is classified OTHER_ERROR. |
| 56 | low | `development/src/annulon/response/broker.py:160` | type-coercion | The envelope schema-version check uses a bare `!=` against the integer 1, so `true` and `1.0` pass as schema version 1 -- the exact bool-as-int defect that contract._require_int was written to eliminate. |
| 57 | low | `development/src/annulon/response/from_finding.py:164` | scope-inflation | _destination parses the destination evidence attribute with rpartition(":"), so a value carrying an address without a port fails to parse and is silently skipped, widening the proposal from one host to all egress. |
| 58 | low | `development/src/annulon/response/nftables.py:472` | canonicalization-asymmetry | _destination_match does not unmap a v4-mapped IPv6 CIDR although policy.covers_destination does, so the two layers disagree about what ::ffff:A.B.C.D means and the installed rule matches no real traffic while the broker reports it as applied. |
| 59 | low | `development/src/annulon/response/policy.py:258` | off-by-one | The rate limit uses `>` against a count of only the prior requests, so max_requests_per_minute+1 requests are permitted per minute, and the boundary test asserts the off-by-one as correct. |
| 60 | low | `development/src/annulon/supply/install.py:170` | error-handling | main() returns the exit status of verification, not of installation: `return 0 if report.get("verified") else 1` reports success when the manifest verified but pip failed and nothing was installed. |
| 61 | low | `development/src/annulon/supply/install.py:11` | claim-inflation | The module's crash-safety claim is false: `pip install --upgrade --target` overwrites the target tree in place, so the state file's "previous version" is not what is on disk after a crash mid-unpack, and no post-install integrity check exists to detect the mixed tree. |
| 62 | low | `development/src/sdnguard/v2/mapping.py:50` | dead-reference | Code and docs cite four ADR numbers that are not defined anywhere in docs/DECISIONS.md, so the decisions the code says it implements cannot be read. |
| 63 | low | `development/tests/adapter/test_contract_and_controller.py:43` | test-double-claim | The adapter contract suite runs only against FakeAdapter; the real OsKenAdapter never runs it, yet SDN_TOPOLOGY_DETECTION is SUPPORTED without recording that gap as a limitation. |
| 64 | low | `docs/ACCEPTANCE_CRITERIA.md:56` | doc-contradiction | ACCEPTANCE_CRITERIA says "A3 is explicitly out of claim" while ASSURANCE_CASE adds a claim named A3, so the two canonical documents state opposite things about A3's status. |
| 65 | low | `docs/ASSURANCE_CASE.md:190` | stale-claim | The defect-history argument states a failure count that does not match KNOWN_FAILURES.md. |
| 66 | low | `tests/tools/test_validation_anchors.py:66` | claim-inflation | The only test mapped to invariant 19 ('A whole-token validation regex never admits a trailing newline') scans re.compile call sites exclusively, so an inline re.match with the exact KF-43 pattern, and any start-anchored pattern with no end anchor, are invisible to it. |

## Closed since this file was written

Twelve of the 66 are now closed as KF-56 through KF-65, each reproduced
by execution with a negative control before being fixed. The three
`critical` candidates listed below as the first things to reproduce have
all been reproduced: two were real and are fixed (KF-62, KF-63), and the
third was real in a way the finder understated — the pid-reuse guard is
not merely unreachable, the capability built on it was claimed SUPPORTED
from a harness the shipped agent does not resemble (KF-65).

That is three for three on the criticals, which is a reason to take the
unverified remainder seriously rather than a reason to trust it: these
were the three the audit rated highest, and no verifier reviewed any of
them.

## Triage order

66 candidates: 3 critical, 24 high, 27 medium, 12 low; 5 already closed.

The three `critical` candidates are the ones to reproduce first,
because each alleges the same failure the project most guards against — an
observation or a guard that is absent while reading as present:

1. `attribution.py` — the pid-reuse guard may be unreachable because nothing
   populates `start_ticks`, which would mean confidence is upgraded from
   PID_ONLY to CORRELATED without evidence. This bears directly on
   `ATTRIBUTION_*` capability claims.
2. `tracefs.py` — `attests_completeness` may exclude `_unparsed`, which would
   let events lost to parse failure render as a complete, attested
   observation. This is the A2 claim's core.
3. `ipc.py` — the JSON depth limit may be applied after `json.loads` has
   already recursed, making `RecursionError` escape as an unhandled error.

Each needs an executed reproduction with a negative control before it is
written up, and each may turn out to be a misreading. Record the outcome
either way: a candidate disproven by execution is worth as much as one
confirmed, and is the cheaper of the two to lose track of.
