"""Verify-then-install, with a rollback that cannot become a downgrade.

The install path is the one place where refusing loudly matters more than
succeeding. A host that declines to update is running a known-good version; a
host that installs an unverified artifact is running whatever an attacker
sent. So every failure here aborts, and nothing is unpacked before the
signature and hash have both been checked.

State is a single JSON file recording what is installed and what it may roll
back to. It is written after a successful install, so a crash mid-install
leaves the previous version recorded — which is true, because the previous
version is what is still on disk.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from annulon.supply.manifest import (
    ReleaseManifest, VerificationResult, register_rollback_target,
    signing_available, verify_manifest,
)

__all__ = ["InstallState", "install", "main", "DEFAULT_STATE_PATH"]

DEFAULT_STATE_PATH = Path("/var/lib/annulon/install-state.json")


@dataclass(frozen=True)
class InstallState:
    """What is installed now, and where a rollback may go."""

    version: str | None = None
    key_id: str = ""
    artifact_sha256: str = ""
    rollback_to: str | None = None

    @staticmethod
    def load(path: Path) -> "InstallState":
        try:
            raw = json.loads(Path(path).read_text())
        except (OSError, json.JSONDecodeError):
            # No state is a first install, not a failure.
            return InstallState()
        if not isinstance(raw, dict):
            return InstallState()
        return InstallState(
            version=raw.get("version"), key_id=str(raw.get("key_id", "")),
            artifact_sha256=str(raw.get("artifact_sha256", "")),
            rollback_to=raw.get("rollback_to"))

    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Written atomically: a torn state file would make the next install
        # believe nothing is installed and accept any version.
        handle = tempfile.NamedTemporaryFile(
            "w", dir=str(path.parent), delete=False, encoding="utf-8")
        with handle:
            json.dump(vars(self), handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)


def load_trusted_keys(path: Path) -> dict[str, bytes]:
    """Trusted public keys, as ``{key_id: base64}``.

    Read from a file the operator controls. Nothing in the release itself can
    add a key -- a manifest naming its own signer would let an attacker
    introduce one.
    """
    try:
        raw = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"trusted key file unreadable: {exc}")
    if not isinstance(raw, dict) or not raw:
        raise SystemExit("trusted key file must be a non-empty object")
    keys: dict[str, bytes] = {}
    for key_id, encoded in raw.items():
        try:
            material = base64.b64decode(str(encoded), validate=True)
        except Exception as exc:                     # noqa: BLE001
            raise SystemExit(f"key {key_id!r} is not valid base64: {exc}")
        if len(material) != 32:
            raise SystemExit(f"key {key_id!r} is not a 32-byte Ed25519 key")
        keys[str(key_id)] = material
    return keys


def install(manifest_path: Path, artifact_path: Path, *,
            trusted_keys: dict[str, bytes], target: Path,
            state_path: Path = DEFAULT_STATE_PATH,
            allow_rollback: bool = False,
            dry_run: bool = False) -> dict:
    """Verify, then install. Returns a report; raises nothing on refusal."""
    state = InstallState.load(state_path)
    if state.version and state.rollback_to:
        register_rollback_target(state.version, state.rollback_to)

    result = verify_manifest(manifest_path, artifact_path, trusted_keys,
                             installed_version=state.version,
                             allow_rollback=allow_rollback)
    report = {"verified": result.ok, "reason": result.reason,
              "installed_before": state.version,
              "candidate": result.manifest.version if result.manifest else None}
    if not result.ok:
        report["installed"] = False
        return report
    if dry_run:
        report["installed"] = False
        report["dry_run"] = True
        return report

    target = Path(target)
    target.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(                      # noqa: S603 - fixed argv
        [sys.executable, "-m", "pip", "install", "--quiet", "--upgrade",
         "--target", str(target), str(artifact_path)],
        capture_output=True, text=True, timeout=900)
    report["install_exit"] = completed.returncode
    if completed.returncode != 0:
        report["installed"] = False
        report["error"] = completed.stderr[-400:]
        # State is deliberately not written: what is on disk is whatever the
        # failed install left, and claiming the new version would be worse
        # than claiming the old one.
        return report

    manifest = result.manifest
    InstallState(version=manifest.version, key_id=manifest.key_id,
                 artifact_sha256=manifest.artifact_sha256,
                 rollback_to=state.version).save(state_path)
    report["installed"] = True
    report["installed_now"] = manifest.version
    report["rollback_available_to"] = state.version
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="annulon-install", description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--trusted-keys", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE_PATH)
    parser.add_argument("--allow-rollback", action="store_true",
                        help="permit the single version this release names")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    if not signing_available():
        raise SystemExit(
            "no signature backend. Install the 'verify' extra; refusing to "
            "install by hash alone.")
    report = install(args.manifest, args.artifact,
                     trusted_keys=load_trusted_keys(args.trusted_keys),
                     target=args.target, state_path=args.state,
                     allow_rollback=args.allow_rollback, dry_run=args.dry_run)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("verified") else 1


if __name__ == "__main__":
    raise SystemExit(main())
