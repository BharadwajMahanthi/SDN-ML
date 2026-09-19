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
