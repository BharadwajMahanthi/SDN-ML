# AGENTS.md — canonical instructions for every agent on this repository

Claude Code and Codex share this file. It is guidance, not a security
boundary: the enforcement lives in `tools/context_policy.yaml` and the code
that reads it.

## 0. What this project is, and what it is for

Read this before deciding anything. Sessions that skip it re-derive the
project wrongly and build the wrong thing.

**Annulon is a local-first security agent for ordinary Linux cloud servers.**
It observes what actually happens on a host (processes, and later network and
file activity), turns observations into evidence, turns evidence into
findings with separate severity and confidence, and — only through a
privileged broker that the core cannot command — takes narrow, reversible,
time-bounded containment actions. The end goal is a host that can contain a
compromise itself, within seconds, without an operator present, and without
the security agent ever becoming the more dangerous component.

**SDN is one optional protection pack, not the product.** Software-defined
networking separates the *control plane* (a central controller that decides
where packets may go) from the *data plane* (switches that only forward).
The controller has a global view and programs flow rules into switches over
OpenFlow. That centralisation is the security opportunity — one place can see
and stop a lateral movement across the whole fabric — and the security
problem: the controller believes what switches and hosts tell it, so a lying
host can poison topology (fake links, host hijacking) and redirect traffic.
`development/src/sdnguard` is our controller-side defence against exactly
that, and it plugs into the same evidence and response boundary as the host
agent. If someone runs Annulon on a plain server with no SDN, everything
except that pack must still work.

The privileged-response boundary is the load-bearing safety property:
**compromise, malfunction, hallucination, or bad logic in the Annulon core
must not yield arbitrary privileged execution.** Every design choice that
looks over-strict is defending that sentence.

## 1. Start every session here

```bash
python tools/agent_session.py brief          # bounded current-state briefing
python tools/memory.py validate              # journal integrity
python tools/agent_session.py claim --task <TASK-ID> --agent <you> --path <paths>
```

Read `docs/CURRENT_STATE.md` before proposing anything. Do not reinterpret
the project after a context reset — check `docs/DECISIONS.md` and
`docs/KNOWN_FAILURES.md` first.

## 2. Data minimisation

Hosted models orchestrate, review and decide. Local tools read, search,
test, build and measure. Never dump the repository for convenience.

Read through the gateway, not directly:

```bash
python tools/repo_query.py tree|symbol|signature|callers|references|function|lines|imports
python tools/safe_exec.py -- <approved command>
python tools/safe_test.py [--path P] [--failure NODEID]
python tools/safe_diff.py [--show PATH]
```

Disclosure ladder: structure → interface → bounded source. Limits are in
`tools/context_policy.yaml` (100 source lines, 20 matches, 200 command/diff
lines). Never `printenv`, never print credential files, never return shell
history. If a secret appears in output: stop, redact, report the finding
without the value.

Blocked paths (`.env`, `*.pem`, `*.key`, `secrets/`, `patent/`, `captures/`,
`memory/runtime/`, `datasets/private/`, …) are refused by the tools.

## 3. Memory

```bash
python tools/memory.py checkpoint --session <S> --task <T> --agent <you> \
  --next "<exact next action>" --changed <path> --decision '<json>' --blocker '<json>'
python tools/memory.py status | stats | gc --dry-run | gc --apply
```

Checkpoint after meaningful completed work and before compaction or handoff.
Never store source dumps, transcripts, raw logs, PCAPs, secrets or large
diffs — the store refuses probable secrets and oversized records.

Durable knowledge belongs in `docs/`, not the journal. The journal rotates;
`docs/` does not.

**These obligations are mandatory and survive context compaction.** A new
context window is not a new project. Every session — including one resumed
mid-task after a summary — must run the section 1 commands, honour the claim
it holds, checkpoint before it risks losing context, and release the claim at
the end. An agent that skips the brief and starts editing is operating on a
reconstruction of the project rather than the project.

## 4. Claim status honestly

Use exactly one of: `VERIFIED` (executed evidence), `SUPPORTED_BY_STATIC_ANALYSIS`,
`REPORTED` (inherited), `HYPOTHESIS`, `NOT_RUN`, `BLOCKED`. Never promote
expected/planned/assumed into measured/verified/proven. Never call the system
impenetrable, provably secure, or production-ready without scoped evidence.

## Verification is adversarial, not confirmatory

The full doctrine is in `docs/PROJECT_CONTRACT.md` (ADR-049). The short form:

    DO NOT TEST THAT THE CODE CAN PASS.
    TRY TO MAKE THE SECURITY PROPERTY FAIL.

- **A test count is never a security metric.** Report assurance *classes*
  (unit, property, fuzz, mutation, integration, physical E2E, negative
  control, fault injection, crash/recovery, concurrency, load, soak,
  packaging, supply chain) and say which are `NOT_RUN`. Never render
  `NOT_RUN` as `PASS`.
- **Authorization suites explore denial harder than permission.**
- **Mutation testing covers security-critical predicates.** Any mutation that
  weakens ALLOW/DENY semantics must be killed; survivors are recorded as
  defects or gaps, never averaged into a percentage. Run it with
  `python tools/mutate.py --module <m> --tests <t>` — it rewrites source in
  place and holds a lock, so never run tests alongside it.
- **Security invariants live in `docs/invariants.json`** and each maps to
  tests and evidence.
- **Never lower a requirement to pass.** Work out whether the test, the
  implementation, the architectural assumption or the environment is wrong,
  then fix that layer.
- **A flaky security test blocks its claim** until the nondeterminism is
  understood. Retries are diagnostic, never a way to manufacture a pass.
- **Every KF is generalised to its bug family**, and the family is tested.
- **Capability maturity is per-capability** (L0…L6). The product never
  inherits the level of its strongest component.

## Real systems only — no fakes in the delivery path

We are building real security infrastructure. A simulation is never evidence
about reality, and a test double is never a deliverable.

- A fake or in-memory implementation is permitted **only** as a test double.
  It must never be reachable from a production entry point, and no capability
  may be claimed on the strength of one. `sdnguard/adapter/fake.py` is
  allowed because it is imported solely by tests and because the real OS-Ken
  adapter must pass the *same* conformance suite.
- Every test double has a real counterpart, and both run against one shared
  contract suite. A double without a real counterpart is a stub for work that
  has not been done — say so, in `NOT_RUN` terms.
- Privileged actions are proven against a real kernel: real nftables, real
  netlink, real interfaces, real packet counters. "The unit test passed" is
  `SUPPORTED_BY_STATIC_ANALYSIS`, never `VERIFIED`.
- Every enforcement experiment needs a negative control. An experiment that
  cannot fail has not measured anything.

## Platform parity — macOS is a first-class development platform

The repository must be fully workable on macOS. Two tiers, both real:

- **Tier 1, native macOS.** The full test suite, `tools/verify_all.py`, the
  SDN controller, the domain and evidence layers, and the privileged broker
  with genuine peer-credential authentication (`LOCAL_PEERCRED`/`LOCAL_PEERPID`
  on Darwin, `SO_PEERCRED` on Linux). These run on a Mac with no VM.
- **Tier 2, macOS hosting a real Linux kernel.** Kernel-coupled work —
  netlink process events, nftables containment, OVS datapaths — runs in a
  Linux VM on the Mac (Docker Desktop's VM, Lima or Colima). This is a real
  kernel executing the same code as EC2, not an emulation of one. AWS is a
  deployment target, never a prerequisite for development.

Platform-specific code states its platform and fails loudly where it cannot
work. It never silently degrades to a weaker guarantee — a broker that cannot
identify its callers refuses the connection rather than trusting the payload.
"macOS cannot do X" is not a conclusion; it triggers the ALTERNATIVE_ANALYSIS
in "No artificial dead ends".

## No artificial dead ends

A failed dependency, unavailable tool, disproven legacy assumption,
unsupported framework capability, or missing implementation does not
terminate development. Identify the underlying required capability, evaluate
alternatives, and implement the smallest safe replacement when necessary.
Block only the specific operation that genuinely requires unavailable owner
authority, external access, or irreversible action. Continue all independent
work. Never falsify evidence to preserve an existing design.

In practice:

- A tool name is not a requirement. "Run Mininet on macOS" is not the
  requirement; "a reproducible multi-host environment with isolated
  interfaces, a controllable datapath and observable packet paths" is.
- Before writing `BLOCKED`, perform an **ALTERNATIVE_ANALYSIS**: required
  capability, current approach, why it failed, alternatives with cost, risk
  and testability, recommended path. Then take the strongest safe path.
- Use `TASK_BLOCKED`, `EXTERNAL_ACTION_REQUIRED`, `ALTERNATIVE_SELECTED` or
  `DEFERRED_WITH_SAFE_PATH` rather than a project-wide stop.
- Frameworks are implementation details. OS-Ken is the current adapter, not
  the architecture. If it fails, isolate the missing capability and replace
  the smallest piece, behind the existing boundary.
- Anything we implement ourselves because no suitable library fits carries a
  higher test bar: specification, boundary, property, malformed-input,
  failure and resource-bound tests, plus fuzzing and golden fixtures for
  protocol-facing code. Do not trust custom infrastructure because we wrote it.
- Never reimplement cryptography, TLS, OS networking or a full TCP/IP stack
  without a narrow, documented necessity.
- A disproven research assumption is information, not failure. Record the
  evidence, mark the assumption rejected or conditional, and design something
  stronger. Never change the experiment to preserve the thesis.

## 5. Changing direction

A major architectural change needs an ADR in `docs/DECISIONS.md` (problem,
current approach, proposal, benefits, costs, risks, migration, evidence,
status) recorded before implementation.

## Repository hygiene

`main` is the only long-lived branch, and it holds the product: the Python
platform under `development/`, the governance tooling under `tools/`, and
`docs/`. Nothing else lives there.

Merge through `python tools/merge_gate.py merge <branch>`. It deletes the
branch on success; the merge commit is the history and a leftover ref only
hides what is actually in flight.

- A working branch exists only while its task is in flight. After the merge
  gate passes, it is merged and deleted in the same step.
- The sole permitted exception is `legacy/java-topoguard-research`, the
  archive of the original Java tree. It is published to the remote so the
  history survives, and it is never merged into `main` and never developed on.
  `ARCHIVE_BRANCHES` in `tools/verify_all.py` protects it from deletion.
- No other long-lived branch may be created. If work needs to persist across
  sessions, it belongs on `main` behind a flag or in `docs/`, not on a branch
  nobody merges.

## 6. Session close

Report changed files and symbols, commands actually run with exit statuses,
measurements with units, what was NOT verified, residual risk, the checkpoint
ID, and the exact next task. Then release your task claim.
