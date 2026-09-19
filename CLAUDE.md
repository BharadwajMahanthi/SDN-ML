# CLAUDE.md

@AGENTS.md

Claude Code specific notes only. Everything else lives in AGENTS.md above —
do not duplicate or contradict it here.

- Prefer the local gateway (`tools/repo_query.py`) over direct file reads, so
  that path screening, output limits and redaction are actually applied.
- Anything returned to a hosted model is transmitted off this machine. Treat
  it accordingly, including filenames, summaries and test output.
- Record checkpoints with `--agent claude` so ownership conflicts with Codex
  are detectable.
