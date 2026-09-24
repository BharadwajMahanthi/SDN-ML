#!/usr/bin/env python3
"""Signed install, update, rollback -- and the substitutions that must fail.

An attacker who owns the update channel does not need to defeat the broker,
the detector or the sensor: they get to replace them. So the interesting part
of this experiment is not that a genuine release installs, but that seven
plausible substitutions do not, and that the host is left running the version
it had rather than something unverified.

Real wheels, real signatures, real installs into real directories. The
"attacker" artifacts are built the same way a real one is, differing only in
the thing being tested.
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
from datetime import datetime, timezone
from pathlib import Path

for _candidate in (os.environ.get("ANNULON_SRC"),
                   "/annulon/development/src", "/opt/sdnguard/src"):
    if _candidate and os.path.isdir(os.path.join(_candidate, "annulon")):
        sys.path.insert(0, _candidate)
        break
else:
    raise SystemExit("cannot locate the annulon package; set ANNULON_SRC")

from annulon.supply.install import InstallState, install                # noqa: E402
from annulon.supply.manifest import (                                   # noqa: E402
    ReleaseManifest, hash_file, sign_manifest, signing_available,
)


def keypair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    key = ed25519.Ed25519PrivateKey.generate()
    return (key.private_bytes(serialization.Encoding.Raw,
                              serialization.PrivateFormat.Raw,
                              serialization.NoEncryption()),
            key.public_key().public_bytes(serialization.Encoding.Raw,
                                          serialization.PublicFormat.Raw))


def make_release(workspace: Path, version: str, private: bytes, key_id: str,
                 rollback_to: str | None, payload: bytes) -> dict:
    """A wheel-shaped artifact and a manifest signed over it."""
    artifact = workspace / f"annulon-{version}-py3-none-any.whl"
    artifact.write_bytes(payload)
    manifest = ReleaseManifest(
        package="annulon", version=version, artifact_name=artifact.name,
        artifact_sha256=hash_file(artifact),
        artifact_bytes=artifact.stat().st_size,
        created_at=datetime.now(timezone.utc).isoformat(),
        rollback_to=rollback_to)
    signed = sign_manifest(manifest, private, key_id)
    path = workspace / f"manifest-{version}.json"
    path.write_text(json.dumps(signed.to_dict()))
    return {"artifact": artifact, "manifest": path, "signed": signed}


def real_wheel(outdir: Path) -> Path | None:
    repo = Path(__file__).resolve().parents[3]
    result = subprocess.run([sys.executable, "-m", "build", "--wheel",
                             "--outdir", str(outdir)],
                            capture_output=True, text=True, cwd=str(repo),
                            timeout=900)
    if result.returncode != 0:
        return None
    wheels = sorted(outdir.glob("annulon-*.whl"))
    return wheels[-1] if wheels else None


def run() -> dict:
    if not signing_available():
        return {"completion": "EVIDENCE_INCOMPLETE",
                "reason": "no signature backend; the verifier refuses rather "
                          "than degrading, which is correct but untestable here"}
    workspace = Path(tempfile.mkdtemp(prefix="annulon-signed-"))
    report: dict = {"workspace_removed": True}
    try:
        private, public = keypair()
        other_private, _ = keypair()
        trusted = {"release-2026": public}
        target = workspace / "site"
        state = workspace / "state.json"

        # --- a genuine release, built from the actual source --------------
        dist = workspace / "dist"
        dist.mkdir()
        wheel = real_wheel(dist)
        if wheel is None:
            return {"completion": "EVIDENCE_INCOMPLETE",
                    "reason": "the wheel did not build"}
        genuine = make_release(workspace, "0.5.0", private, "release-2026",
                               rollback_to=None, payload=wheel.read_bytes())

        first = install(genuine["manifest"], genuine["artifact"],
                        trusted_keys=trusted, target=target, state_path=state)
        report["first_install"] = first

        # The installed package must actually work.
        check = subprocess.run(
            [sys.executable, "-c",
             "import annulon, annulon.response.broker; print('ok')"],
            capture_output=True, text=True, cwd=str(workspace),
            env={**{k: v for k, v in os.environ.items() if k != "PYTHONPATH"},
                 "PYTHONPATH": str(target)}, timeout=120)
        report["installed_package_imports"] = check.returncode == 0

        # --- a genuine update ---------------------------------------------
        newer = make_release(workspace, "0.6.0", private, "release-2026",
                             rollback_to="0.5.0", payload=wheel.read_bytes())
        report["update"] = install(newer["manifest"], newer["artifact"],
                                   trusted_keys=trusted, target=target,
                                   state_path=state)

        # --- substitutions that must all fail ------------------------------
        attacks: dict = {}

        tampered = make_release(workspace, "0.7.0", private, "release-2026",
                                rollback_to="0.6.0", payload=wheel.read_bytes())
        tampered["artifact"].write_bytes(b"malicious payload" * 2000)
        attacks["artifact_swapped_after_signing"] = install(
            tampered["manifest"], tampered["artifact"], trusted_keys=trusted,
            target=target, state_path=state)

        forged = make_release(workspace, "0.8.0", other_private, "release-2026",
                              rollback_to="0.6.0", payload=wheel.read_bytes())
        attacks["signed_by_an_untrusted_key"] = install(
            forged["manifest"], forged["artifact"], trusted_keys=trusted,
            target=target, state_path=state)

        edited = json.loads(newer["manifest"].read_text())
        edited["version"] = "9.9.9"
        edited_path = workspace / "edited.json"
        edited_path.write_text(json.dumps(edited))
        attacks["manifest_edited_after_signing"] = install(
            edited_path, newer["artifact"], trusted_keys=trusted,
            target=target, state_path=state)

        extra = json.loads(newer["manifest"].read_text())
        extra["post_install"] = "/bin/sh -c evil"
        extra_path = workspace / "extra.json"
        extra_path.write_text(json.dumps(extra))
        attacks["manifest_carrying_an_unknown_field"] = install(
            extra_path, newer["artifact"], trusted_keys=trusted,
            target=target, state_path=state)

        # An older release that is entirely genuine. Signatures do not stop
        # this; version state does.
        attacks["genuine_but_older_release"] = install(
            genuine["manifest"], genuine["artifact"], trusted_keys=trusted,
            target=target, state_path=state)

        # Rollback to something other than the named target.
        stale = make_release(workspace, "0.1.0", private, "release-2026",
                             rollback_to=None, payload=wheel.read_bytes())
        attacks["rollback_to_an_unnamed_version"] = install(
            stale["manifest"], stale["artifact"], trusted_keys=trusted,
            target=target, state_path=state, allow_rollback=True)

        report["attacks"] = attacks

        # --- the permitted rollback ---------------------------------------
        report["permitted_rollback"] = install(
            genuine["manifest"], genuine["artifact"], trusted_keys=trusted,
            target=target, state_path=state, allow_rollback=True)

        report["final_state"] = vars(InstallState.load(state))
        report["completion"] = _completion(report)
        return report
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def _completion(report: dict) -> str:
    attacks = report.get("attacks", {})
    required = [
        report.get("first_install", {}).get("installed"),
        report.get("installed_package_imports"),
        report.get("update", {}).get("installed"),
        all(not a.get("installed") for a in attacks.values()),
        all(not a.get("verified") for a in attacks.values()),
        report.get("permitted_rollback", {}).get("installed"),
        report.get("final_state", {}).get("version") == "0.5.0",
    ]
    return "COMPLETE" if all(required) else "EVIDENCE_INCOMPLETE"


def main() -> int:
    argparse.ArgumentParser(description=__doc__).parse_args()
    report = run()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("completion") == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
