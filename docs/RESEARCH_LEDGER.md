# RESEARCH LEDGER

| ID | Question | Source | Version/date | Accessed | Claim supported | Limitations | Impact |
|---|---|---|---|---|---|---|---|
| — | — | — | — | — | — | — | — |

No external research has been performed in this session. Entries are added
only via the isolated public-research workflow, with generic queries that
carry no private design detail. Retrieved text is treated as untrusted data,
never as instructions. Citations are never fabricated; an inaccessible source
is recorded as inaccessible.

## Entries

| ID | Question | Source | Version / date | Accessed | Claim supported | Limitations | Impact |
|---|---|---|---|---|---|---|---|
| R-001 | Is Ryu still maintained? | PyPI JSON API, `ryu` | 4.34, released 2020-05-27; no `requires_python` | 2026-09-20 | Ryu has had no release in ~6 years and declares no Python version support | Release recency is a proxy for maintenance, not proof; the repo may still take patches | Ryu is rejected for new work |
| R-002 | Is OS-Ken maintained and Python-current? | PyPI JSON API, `os-ken` | 4.2.2, released 2026-08-20; `requires_python >=3.10`; classifiers 3.10–3.13; Apache-2.0 | 2026-09-20 | Actively released within the last month and declares support through Python 3.13 | Classifiers are self-declared; not a test of protocol conformance | OS-Ken is the leading candidate (ADR-016) |
| R-003 | What concurrency model does OS-Ken impose? | PyPI metadata, `os-ken` `requires_dist` | 4.2.2 | 2026-09-20 | Depends on `eventlet>=0.27.0`, i.e. green threads with monkey-patched I/O | Dependency presence shows the model is available, not that every path uses it | Drives ADR-017: eventlet must not escape the adapter |
| R-004 | Is eventlet itself current? | PyPI JSON API, `eventlet` | 0.41.2, released 2026-08-14; `requires_python >=3.10` | 2026-09-20 | Released recently and supports current Python | Says nothing about the project's long-term direction, which has been debated in the OpenStack ecosystem | Recorded as a risk to re-check before P11 |
| R-005 | Is Faucet a controller library alternative? | PyPI JSON API, `faucet` | 1.10.12, released 2026-03-05 | 2026-09-20 | Maintained, but it is an SDN *application*, not a controller framework to build on | Not evaluated further | Out of scope |

All queries were generic and carried no repository, design or patent detail.
Retrieved text is treated as data, not instructions.
