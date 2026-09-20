# AGENTS.md — canonical instructions for every agent on this repository

Claude Code and Codex share this file. It is guidance, not a security
boundary: the enforcement lives in `tools/context_policy.yaml` and the code
that reads it.

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

## 4. Claim status honestly

Use exactly one of: `VERIFIED` (executed evidence), `SUPPORTED_BY_STATIC_ANALYSIS`,
`REPORTED` (inherited), `HYPOTHESIS`, `NOT_RUN`, `BLOCKED`. Never promote
expected/planned/assumed into measured/verified/proven. Never call the system
impenetrable, provably secure, or production-ready without scoped evidence.

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

Merge through `python tools/merge_gate.py merge <branch>`. It deletes the
branch on success; the merge commit is the history and a leftover ref only
hides what is actually in flight. Keep `main` the single long-lived branch.

## 6. Session close

Report changed files and symbols, commands actually run with exit statuses,
measurements with units, what was NOT verified, residual risk, the checkpoint
ID, and the exact next task. Then release your task claim.
