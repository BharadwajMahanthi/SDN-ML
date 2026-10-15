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

That file is the whole of the downgrade defence, and it is not signed. The
threat this module names — "an attacker who cannot forge a signature can
still serve an older signed release" — is only defeated while the file is
intact, so absent and corrupt are treated as refusals rather than as a host
with nothing installed (KF-60). An operator installing onto a genuinely new
host says so explicitly with ``first_install``. Protecting the file itself is
the deployment's job: it belongs to root, and an attacker who can rewrite it
is already inside the boundary this module defends.
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
    ReleaseManifest, VerificationResult, is_valid_version,
    register_rollback_target, signing_available, verify_manifest,
)

__all__ = ["InstallState", "InstallStateError", "install", "main",
           "DEFAULT_STATE_PATH"]


class InstallStateError(Exception):
    """The install state exists but cannot be believed."""

DEFAULT_STATE_PATH = Path("/var/lib/annulon/install-state.json")


@dataclass(frozen=True)
class InstallState:
    """What is installed now, and where a rollback may go."""

    version: str | None = None
    key_id: str = ""
    artifact_sha256: str = ""
    rollback_to: str | None = None

    @staticmethod
    def load(path: Path) -> "InstallState | None":
        """The recorded state, or None when there is no state file.

        Absent and unreadable are different answers and used to be the same
        one. Returning a blank state for both meant `installed_version` was
        None, which skips the downgrade comparison entirely -- so emptying or
        truncating this file disabled downgrade protection without forging
        anything. A file that exists and cannot be parsed is not a clean
        host, and this raises rather than inventing one.
        """
        path = Path(path)
        try:
            text = path.read_text()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise InstallStateError(f"unreadable: {exc}") from exc
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            raise InstallStateError(f"not valid JSON: {exc}") from exc
        if not isinstance(raw, dict):
            raise InstallStateError("must be a JSON object")
        version = raw.get("version")
        if version is None:
            # `install()` only ever saves a concrete version, so a state file
            # recording none was not written by this installer. Accepting it
            # left the same hole as an empty file: present, parseable, and
            # still no version to compare against.
            raise InstallStateError("records no version")
        if not is_valid_version(version):
            # str() would turn 1.5 into "1.5" and True into "True"; _compare
            # would then split a string the signer never wrote. The other
            # fields are coerced because nothing compares them.
            raise InstallStateError(
                f"version {version!r} is not a valid version string")
        rollback = raw.get("rollback_to")
        if rollback is not None and not is_valid_version(rollback):
            raise InstallStateError(
                f"rollback_to {rollback!r} is not a valid version string")
        return InstallState(
            version=version, key_id=str(raw.get("key_id", "")),
            artifact_sha256=str(raw.get("artifact_sha256", "")),
            rollback_to=rollback)

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
            first_install: bool = False,
            dry_run: bool = False) -> dict:
    """Verify, then install. Returns a report; raises nothing on refusal."""
    def refuse(reason: str, before: str | None = None) -> dict:
        return {"verified": False, "installed": False, "reason": reason,
                "installed_before": before, "candidate": None}

    try:
        state = InstallState.load(state_path)
    except InstallStateError as exc:
        return refuse(
            f"install state at {state_path} cannot be believed ({exc}). A "
            "state file that exists and cannot be parsed is not a host with "
            "nothing installed, and treating it as one would accept any "
            "signed release.")

    if state is None:
        # Nothing recorded means nothing to compare against, so the downgrade
        # check cannot run. That is correct on a genuinely new host and is
        # also what deleting this file looks like, so it has to be affirmed
        # rather than inferred.
        if not first_install:
            return refuse(
                f"no install state at {state_path}. Pass first_install to "
                "install onto a host with no recorded version: with no "
                "recorded version there is nothing to compare against, so "
                "accepting this silently would let a deleted state file "
                "disable downgrade protection.")
        state = InstallState()
    elif first_install:
        return refuse(
            f"first_install was requested but {state_path} already records "
            f"version {state.version!r}. Refusing a contradictory "
            "instruction rather than picking one of its two meanings.",
            state.version)

    if state.version and state.rollback_to:
        register_rollback_target(state.version, state.rollback_to)

    result = verify_manifest(manifest_path, artifact_path, trusted_keys,
                             installed_version=state.version,
                             allow_rollback=allow_rollback)
    report = {"verified": result.ok, "reason": result.reason,
              "installed_before": state.version,
              "candidate": result.manifest.version if result.manifest else None}
    if state.version is None:
        # Say so rather than letting a silent pass read as a check that ran.
        report["downgrade_check"] = "not applicable: no version was recorded"
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
    parser.add_argument("--first-install", action="store_true",
                        help="affirm that this host has no installed version; "
                             "required when no state file exists, because a "
                             "deleted one is indistinguishable from a new host")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    if not signing_available():
        raise SystemExit(
            "no signature backend. Install the 'verify' extra; refusing to "
            "install by hash alone.")
    report = install(args.manifest, args.artifact,
                     trusted_keys=load_trusted_keys(args.trusted_keys),
                     target=args.target, state_path=args.state,
                     allow_rollback=args.allow_rollback,
                     first_install=args.first_install, dry_run=args.dry_run)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("verified") else 1


if __name__ == "__main__":
    raise SystemExit(main())
