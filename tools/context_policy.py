"""Loader and enforcement for the context firewall policy.

Every tool in ``tools/`` resolves disclosure questions through this module so
that policy lives in exactly one place (``tools/context_policy.yaml``) and is
enforced by code rather than by agent instructions.

Limitation (deliberate, documented): path screening cannot know that a file
*named* innocuously contains a secret. Content redaction (``tools.redact``)
is the second layer. Neither layer is a proof of data-loss prevention.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path, PurePosixPath

import yaml

POLICY_FILENAME = "context_policy.yaml"


class PolicyViolation(Exception):
    """Raised when a request would disclose material the policy forbids."""


@dataclass(frozen=True)
class Limits:
    max_source_lines: int
    max_search_results: int
    max_command_lines: int
    max_diff_lines: int
    max_tree_entries: int
    max_line_chars: int


@dataclass(frozen=True)
class Policy:
    root: Path
    blocked_paths: tuple[str, ...]
    opaque_paths: tuple[str, ...]
    allowed_commands: frozenset[str]
    denied_commands: frozenset[str]
    limits: Limits
    local_log_dir: str

    # -- path handling ---------------------------------------------------

    def relative(self, path: str | os.PathLike[str]) -> PurePosixPath:
        """Resolve ``path`` and return it relative to the repository root.

        Escaping the root (via ``..`` or a symlink) is itself a violation:
        the firewall's guarantees only hold inside the repository.
        """
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = self.root / candidate
        resolved = candidate.resolve()
        try:
            rel = resolved.relative_to(self.root.resolve())
        except ValueError as exc:
            raise PolicyViolation(
                f"path escapes repository root: {_display(path)}"
            ) from exc
        return PurePosixPath(rel.as_posix())

    def is_blocked(self, path: str | os.PathLike[str]) -> bool:
        return _any_match(self.relative(path), self.blocked_paths)

    def is_opaque(self, path: str | os.PathLike[str]) -> bool:
        return _any_match(self.relative(path), self.opaque_paths)

    def check_readable(self, path: str | os.PathLike[str]) -> PurePosixPath:
        """Return the relative path, or raise if its content must not be read."""
        rel = self.relative(path)
        if _any_match(rel, self.blocked_paths):
            raise PolicyViolation(f"blocked by policy: {rel}")
        if _any_match(rel, self.opaque_paths):
            raise PolicyViolation(
                f"opaque by policy (name may be listed, content may not be "
                f"returned): {rel}"
            )
        return rel

    def check_listable(self, path: str | os.PathLike[str]) -> PurePosixPath:
        """Return the relative path, or raise if even its NAME must not appear."""
        rel = self.relative(path)
        if _any_match(rel, self.blocked_paths):
            raise PolicyViolation(f"blocked by policy: {rel}")
        return rel

    # -- command handling ------------------------------------------------

    def check_command(self, argv: list[str]) -> None:
        if not argv:
            raise PolicyViolation("empty command")
        name = normalize_command(PurePosixPath(argv[0]).name)
        if name in self.denied_commands:
            raise PolicyViolation(f"command denied by policy: {name}")
        if name not in self.allowed_commands:
            raise PolicyViolation(
                f"command not in allowed_commands: {name} "
                f"(add it to {POLICY_FILENAME} if it is genuinely needed)"
            )

    def log_dir(self) -> Path:
        d = self.root / self.local_log_dir
        d.mkdir(parents=True, exist_ok=True)
        return d


_VERSIONED = re.compile(r"\A(?P<stem>python|pypy|pytest|ruff|mypy|java|javac|node)[0-9]*(?:\.[0-9]+)*\Z")


def normalize_command(name: str) -> str:
    """Strip interpreter version suffixes before allowlist matching.

    ``sys.executable`` is commonly ``python3.12``; matching the raw basename
    would reject ordinary local Python invocations. ``python``/``python3.12``
    both normalise to ``python3``.
    """
    name = name.removesuffix(".exe")
    m = _VERSIONED.match(name)
    if not m:
        return name
    stem = m.group("stem")
    return "python3" if stem in {"python", "pypy"} else stem


def _display(path: str | os.PathLike[str]) -> str:
    """Render a rejected path without leaking an absolute filesystem layout."""
    return PurePosixPath(Path(path).name).as_posix()


def _any_match(rel: PurePosixPath, patterns: tuple[str, ...]) -> bool:
    text = rel.as_posix()
    parts = rel.parts
    for pattern in patterns:
        if "/" in pattern:
            if fnmatch.fnmatch(text, pattern):
                return True
            if pattern.endswith("/**"):
                prefix = pattern[:-3]
                if text == prefix or text.startswith(prefix + "/"):
                    return True
                # also match the directory itself appearing at any depth
                if f"/{prefix}/" in f"/{text}/":
                    return True
        else:
            if any(fnmatch.fnmatch(part, pattern) for part in parts):
                return True
    return False


def find_root(start: Path | None = None) -> Path:
    """Walk upward for the directory containing ``tools/context_policy.yaml``."""
    here = (start or Path(__file__).resolve().parent).resolve()
    for candidate in (here, *here.parents):
        if (candidate / "tools" / POLICY_FILENAME).is_file():
            return candidate
    raise PolicyViolation(f"could not locate tools/{POLICY_FILENAME}")


def load_policy(root: Path | None = None) -> Policy:
    base = root or find_root()
    raw = yaml.safe_load((base / "tools" / POLICY_FILENAME).read_text())
    lim = raw["limits"]
    return Policy(
        root=base,
        blocked_paths=tuple(raw.get("blocked_paths", ())),
        opaque_paths=tuple(raw.get("opaque_paths", ())),
        allowed_commands=frozenset(raw.get("allowed_commands", ())),
        denied_commands=frozenset(raw.get("denied_commands", ())),
        limits=Limits(
            max_source_lines=int(lim["max_source_lines"]),
            max_search_results=int(lim["max_search_results"]),
            max_command_lines=int(lim["max_command_lines"]),
            max_diff_lines=int(lim["max_diff_lines"]),
            max_tree_entries=int(lim["max_tree_entries"]),
            max_line_chars=int(lim["max_line_chars"]),
        ),
        local_log_dir=str(raw.get("local_log_dir", "memory/runtime/exec")),
    )


@lru_cache(maxsize=4)
def default_policy() -> Policy:
    return load_policy()
