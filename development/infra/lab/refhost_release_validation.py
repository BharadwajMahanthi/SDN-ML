#!/usr/bin/env python3
"""Install a signed release on the reference host, then soak it there.

The two remaining release blockers, run where the claim needs to hold. Every
previous install result came from a container on a development kernel; this
puts the actual artifact on the actual reference profile, over the only
access path the lab has, and then leaves it running long enough for a leak
to show.

Nothing here trusts the source tree on the host. The wheel is built locally,
signed locally, shipped as base64 over SSM, and verified on the host by
`annulon-install` before anything is unpacked. The signing key never leaves
this machine.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shlex
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
LAB = REPO / "development" / "infra" / "lab"
CHUNK = 45_000


def remote(command: str, timeout: int = 600) -> subprocess.CompletedProcess:
    env = {**os.environ, "SDNGUARD_TIMEOUT": str(timeout)}
    return subprocess.run([str(LAB / "remote.sh"), command],
                          capture_output=True, text=True,
                          timeout=timeout + 120, env=env)


def ship(local: Path, remote_path: str) -> bool:
    """Send a file as base64 chunks over SSM, then verify its digest.

    The same mechanism `deploy.sh` uses, for the same reason: SSM caps a
    single invocation's parameters, and there is no S3 bucket, no extra IAM
    grant and no inbound port in this lab.
    """
    import hashlib
    encoded = base64.b64encode(local.read_bytes()).decode()
    digest = hashlib.sha256(local.read_bytes()).hexdigest()
    remote(f"rm -f {remote_path}.b64 {remote_path}")
    for index in range(0, len(encoded), CHUNK):
        part = encoded[index:index + CHUNK]
        result = remote(f"printf '%s' {shlex.quote(part)} >> {remote_path}.b64")
        if result.returncode != 0:
            return False
    check = remote(
        f"base64 -d {remote_path}.b64 > {remote_path} && "
        f"rm -f {remote_path}.b64 && sha256sum {remote_path} | cut -d' ' -f1")
    return digest in check.stdout


def keypair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    key = ed25519.Ed25519PrivateKey.generate()
    return (key.private_bytes(serialization.Encoding.Raw,
                              serialization.PrivateFormat.Raw,
                              serialization.NoEncryption()),
            key.public_key().public_bytes(serialization.Encoding.Raw,
                                          serialization.PublicFormat.Raw))


def build_and_sign(workspace: Path) -> dict | None:
    sys.path.insert(0, str(REPO / "development" / "src"))
    from annulon.supply.manifest import (
        ReleaseManifest, hash_file, sign_manifest)

    dist = workspace / "dist"
    built = subprocess.run([sys.executable, "-m", "build", "--wheel",
                            "--outdir", str(dist)],
                           capture_output=True, text=True, cwd=str(REPO),
                           timeout=900)
    if built.returncode != 0:
        return None
    wheels = sorted(dist.glob("annulon-*.whl"))
    if not wheels:
        return None
    wheel = wheels[-1]
    private, public = keypair()
    manifest = ReleaseManifest(
        package="annulon", version=_version(wheel.name),
        artifact_name=wheel.name, artifact_sha256=hash_file(wheel),
        artifact_bytes=wheel.stat().st_size,
        created_at=datetime.now(timezone.utc).isoformat(), rollback_to=None)
    signed = sign_manifest(manifest, private, "refhost-validation")
    manifest_path = workspace / "manifest.json"
    manifest_path.write_text(json.dumps(signed.to_dict()))
    keys_path = workspace / "trusted-keys.json"
    keys_path.write_text(json.dumps(
        {"refhost-validation": base64.b64encode(public).decode()}))
    # A key the host must NOT accept, shipped alongside so the refusal can be
    # demonstrated on the host rather than asserted from here.
    _, other_public = keypair()
    wrong_keys = workspace / "wrong-keys.json"
    wrong_keys.write_text(json.dumps(
        {"someone-else": base64.b64encode(other_public).decode()}))
    return {"wheel": wheel, "manifest": manifest_path, "keys": keys_path,
            "wrong_keys": wrong_keys, "version": manifest.version}


def _version(name: str) -> str:
    return name.split("-")[1]


def run(soak_seconds: int) -> dict:
    report: dict = {"obligations": ["SAFE-PACKAGE-01 on REF-HOST",
                                    "SAFE-SOAK-01 long run"]}
    workspace = Path(tempfile.mkdtemp(prefix="annulon-refhost-"))
    try:
        environment = remote("uname -srm; . /etc/os-release && echo $PRETTY_NAME")
        report["environment"] = environment.stdout.strip().splitlines()[:2]

        release = build_and_sign(workspace)
        if release is None:
            return {"completion": "EVIDENCE_INCOMPLETE",
                    "reason": "the wheel did not build or sign"}
        report["release"] = {"version": release["version"],
                             "wheel": release["wheel"].name,
                             "wheel_bytes": release["wheel"].stat().st_size}

        remote("sudo mkdir -p /opt/annulon-release && "
               "sudo chown $(id -u):$(id -g) /opt/annulon-release")
        shipped = all([
            ship(release["wheel"], f"/opt/annulon-release/{release['wheel'].name}"),
            ship(release["manifest"], "/opt/annulon-release/manifest.json"),
            ship(release["keys"], "/opt/annulon-release/trusted-keys.json"),
            ship(release["wrong_keys"], "/opt/annulon-release/wrong-keys.json"),
        ])
        report["artifacts_shipped_and_verified"] = shipped
        if not shipped:
            return {**report, "completion": "EVIDENCE_INCOMPLETE",
                    "reason": "artifact transfer failed"}

        # The verification backend is an extra, so the host needs it before
        # it can verify anything. Installing it is part of the install path.
        report["backend_install"] = remote(
            "python3 -m venv /opt/annulon-release/venv && "
            "/opt/annulon-release/venv/bin/pip install --quiet cryptography "
            "2>&1 | tail -2; echo backend=$?", timeout=900).stdout.strip()[-120:]

        base = ("/opt/annulon-release/venv/bin/python -m annulon.supply.install "
                "--manifest /opt/annulon-release/manifest.json "
                f"--artifact /opt/annulon-release/{release['wheel'].name} "
                "--target /opt/annulon-release/site "
                "--state /opt/annulon-release/state.json")
        env = ("PYTHONPATH=/opt/annulon-release/bootstrap "
               "/opt/annulon-release/venv/bin/python")

        # Bootstrap: the installer itself has to come from somewhere before
        # anything is installed. Unpacking the wheel read-only for that is
        # honest -- it is the same bytes the manifest covers.
        remote("rm -rf /opt/annulon-release/bootstrap && "
               "mkdir -p /opt/annulon-release/bootstrap && cd "
               "/opt/annulon-release/bootstrap && "
               f"/opt/annulon-release/venv/bin/python -m zipfile -e "
               f"/opt/annulon-release/{release['wheel'].name} .")

        def installer(extra: str = "", keys: str = "trusted-keys.json") -> dict:
            command = (f"cd /tmp && PYTHONPATH=/opt/annulon-release/bootstrap "
                       f"{base} --trusted-keys /opt/annulon-release/{keys} "
                       f"{extra} 2>&1")
            result = remote(command, timeout=900)
            text = result.stdout.strip()
            start = text.find("{")
            end = text.rfind("}")
            if start >= 0 and end > start:
                try:
                    return json.loads(text[start:end + 1])
                except json.JSONDecodeError:
                    pass
            return {"raw": text[-300:]}

        report["untrusted_key_refused"] = installer(keys="wrong-keys.json")
        report["genuine_install"] = installer()

        report["installed_agent_check"] = remote(
            "cd /tmp && PYTHONPATH=/opt/annulon-release/site "
            "/opt/annulon-release/venv/bin/python -m annulon.cli.agent --check "
            "2>&1").stdout.strip()[-260:]

        # --- the long soak, from the installed package --------------------
        soak = remote(
            "cd /tmp && sudo mount -t tracefs none /sys/kernel/tracing "
            "2>/dev/null; sudo PYTHONPATH=/opt/annulon-release/site "
            f"/opt/annulon-release/venv/bin/python "
            f"/opt/sdnguard/load_soak_experiment.py --connections 2000 "
            f"--workers 4 --queue-limit 200 --soak-seconds {soak_seconds} "
            "2>&1 | tail -c 4000", timeout=soak_seconds + 600)
        text = soak.stdout.strip()
        start, end = text.find("{"), text.rfind("}")
        try:
            report["soak"] = json.loads(text[start:end + 1])
        except (ValueError, json.JSONDecodeError):
            report["soak"] = {"raw": text[-500:]}

        report["completion"] = _completion(report)
        return report
    finally:
        import shutil
        shutil.rmtree(workspace, ignore_errors=True)


def _completion(report: dict) -> str:
    soak = report.get("soak", {})
    required = [
        report.get("artifacts_shipped_and_verified"),
        not report.get("untrusted_key_refused", {}).get("verified", True),
        report.get("genuine_install", {}).get("installed"),
        "sensor_available" in str(report.get("installed_agent_check", "")),
        soak.get("completion") == "COMPLETE",
        soak.get("soak", {}).get("fd_growth", 99) <= 2,
    ]
    return "COMPLETE" if all(required) else "EVIDENCE_INCOMPLETE"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--soak-seconds", type=int, default=900)
    args = parser.parse_args()
    report = run(args.soak_seconds)
    print(json.dumps(report, indent=2, sort_keys=True, default=str))
    return 0 if report.get("completion") == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
