"""Synthetic fixtures for context-firewall tests.

Every secret here is fabricated and syntactically valid-looking so that the
detectors are exercised realistically. Nothing in this directory is a real
credential, and nothing real is ever committed as a fixture.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

from tests.tools.fixtures import (
    FAKE_API_KEY,
    FAKE_AWS_KEY,
    FAKE_PASSWORD,
    FAKE_PRIVATE_KEY,
)

def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


@pytest.fixture
def fake_repo(tmp_path: Path) -> Path:
    """A miniature repository containing every fixture class §48 calls for."""
    root = tmp_path / "repo"
    (root / "tools").mkdir(parents=True)

    policy = yaml.safe_load(
        (Path(__file__).resolve().parents[2] / "tools" / "context_policy.yaml").read_text()
    )
    (root / "tools" / "context_policy.yaml").write_text(yaml.safe_dump(policy))

    _write(root / "app" / "config.sh", f'SUDO_PASS="{FAKE_PASSWORD}"\nPORT=6653\n')
    _write(root / "app" / "creds.py", f'AWS_ACCESS_KEY_ID = "{FAKE_AWS_KEY}"\napi_key = "{FAKE_API_KEY}"\n')
    _write(root / "secrets" / "service.pem", FAKE_PRIVATE_KEY)
    _write(root / "patent" / "draft_claims.md", "CLAIM-P1 confidential text\n")
    _write(root / "captures" / "run1.pcap", "\x00\x01binary-ish")
    _write(root / ".env", f"DB_PASSWORD={FAKE_PASSWORD}\n")
    _write(root / "memory" / "runtime" / "journal.jsonl", '{"note": "local only"}\n')

    big = "\n".join(f"def sym_{i}():\n    return {i}" for i in range(200))
    _write(root / "app" / "large_module.py", big)
    _write(root / "app" / "small.py", "def alpha(x: int) -> int:\n    return x + 1\n")
    _write(root / "app" / "caller.py", "from app.small import alpha\n\n\ndef beta() -> int:\n    return alpha(1)\n")

    # repo_query enumerates tracked files, so the fixture must be a real index.
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "-A", "-f"], cwd=root, check=True,
                   capture_output=True)
    subprocess.run(
        ["git", "-c", "user.name=fixture", "-c", "user.email=fixture@invalid",
         "commit", "-q", "-m", "fixture"],
        cwd=root, check=True, capture_output=True,
    )
    return root
