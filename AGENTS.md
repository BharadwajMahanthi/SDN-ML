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

## 5. Changing direction

A major architectural change needs an ADR in `docs/DECISIONS.md` (problem,
current approach, proposal, benefits, costs, risks, migration, evidence,
status) recorded before implementation.

## 6. Session close

Report changed files and symbols, commands actually run with exit statuses,
measurements with units, what was NOT verified, residual risk, the checkpoint
ID, and the exact next task. Then release your task claim.
