"""Signed release manifests, and the install path that refuses unsigned ones.

An agent that can change a host's firewall is worth compromising through its
update channel: an attacker who can replace the artifact does not need to
defeat any of the controls this project has built, because they get to write
the controls. So the install path verifies before it trusts, and a failure to
verify is a refusal rather than a warning.

Design choices, each rejecting an easier option:

**Ed25519 over the standard library alone.** Python ships `hashlib` and
`hmac` but no public-key signatures. A hash alone proves the artifact matches
*a* manifest, not that the manifest came from the project — an attacker who
replaces both is undetected. HMAC would require the verifying host to hold a
secret that can also *create* valid releases, which is the wrong shape for
something deployed widely. Ed25519 keeps signing keys off the hosts entirely.

**Detached manifest, not an embedded signature.** The artifact stays a plain
wheel that ordinary tooling can read, and the manifest can be re-signed for a
new key without rebuilding.

**The manifest covers a version and a rollback target.** An attacker who
cannot forge a signature can still serve an *old, genuinely signed* release
with a known flaw. Recording the version and refusing a downgrade unless it
is the explicitly named rollback target is what closes that.

If no cryptography backend is available the verifier raises rather than
falling back to a hash comparison. A verification that cannot detect a forged
manifest should not report success.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

__all__ = [
    "ReleaseManifest", "ManifestError", "SignatureError", "VerificationResult",
    "sign_manifest", "verify_manifest", "hash_file", "signing_available",
    "MANIFEST_VERSION",
]

MANIFEST_VERSION = 1
_CHUNK = 1 << 20


class ManifestError(ValueError):
    """The manifest cannot be understood or does not describe the artifact."""


class SignatureError(ManifestError):
    """The manifest is not signed by a key we accept. Never a warning."""


def signing_available() -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: F401
    except ImportError:
        return False
    return True


def _require_backend():
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:                       # pragma: no cover
        raise SignatureError(
            "no signature backend available. Refusing to verify by hash "
            "alone: a hash proves the artifact matches a manifest, not that "
            "the manifest came from the project, and an attacker who "
            "replaces both would be undetected."
        ) from exc
    return ed25519


def hash_file(path: Path) -> str:
    """SHA-256 of a file, streamed so a large artifact is not read at once."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class ReleaseManifest:
    """What a release is, in a form that can be signed.

    ``to_signing_bytes`` is deliberately canonical: sorted keys, no
    whitespace variation, and the signature excluded. Two processes must
    derive byte-identical input from the same manifest or verification
    becomes a coin flip.
    """

    package: str
    version: str
    artifact_name: str
    artifact_sha256: str
    artifact_bytes: int
    created_at: str
    #: The version this release may be rolled back to. An attacker who
    #: cannot forge a signature can still serve an older signed release, so
    #: a downgrade is refused unless it is this one.
    rollback_to: str | None = None
    signature: str = ""
    key_id: str = ""
    schema_version: int = MANIFEST_VERSION

    def to_signing_bytes(self) -> bytes:
        body = {
            "schema_version": self.schema_version,
            "package": self.package,
            "version": self.version,
            "artifact_name": self.artifact_name,
            "artifact_sha256": self.artifact_sha256,
            "artifact_bytes": self.artifact_bytes,
            "created_at": self.created_at,
            "rollback_to": self.rollback_to,
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()

    def to_dict(self) -> dict:
        body = json.loads(self.to_signing_bytes())
        body["signature"] = self.signature
        body["key_id"] = self.key_id
        return body

    @staticmethod
    def from_dict(raw: object) -> "ReleaseManifest":
        if not isinstance(raw, dict):
            raise ManifestError("manifest must be an object")
        if raw.get("schema_version") != MANIFEST_VERSION:
            raise ManifestError(
                f"unsupported manifest schema {raw.get('schema_version')!r}")
        known = {"schema_version", "package", "version", "artifact_name",
                 "artifact_sha256", "artifact_bytes", "created_at",
                 "rollback_to", "signature", "key_id"}
        unknown = set(raw) - known
        if unknown:
            # A field the verifier ignores is a field an attacker can use to
            # carry meaning the signer never agreed to.
            raise ManifestError(f"unknown manifest field(s): {sorted(unknown)}")
        for required in ("package", "version", "artifact_name",
                         "artifact_sha256", "created_at"):
            if not isinstance(raw.get(required), str) or not raw[required]:
                raise ManifestError(f"{required} is required")
        size = raw.get("artifact_bytes")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise ManifestError("artifact_bytes must be a positive integer")
        digest = raw["artifact_sha256"]
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ManifestError("artifact_sha256 must be lowercase hex sha-256")
        rollback = raw.get("rollback_to")
        if rollback is not None and not isinstance(rollback, str):
            raise ManifestError("rollback_to must be a string or null")
        return ReleaseManifest(
            package=raw["package"], version=raw["version"],
            artifact_name=raw["artifact_name"], artifact_sha256=digest,
            artifact_bytes=size, created_at=raw["created_at"],
            rollback_to=rollback,
            signature=str(raw.get("signature", "")),
            key_id=str(raw.get("key_id", "")))


def sign_manifest(manifest: ReleaseManifest, private_key_bytes: bytes,
                  key_id: str) -> ReleaseManifest:
    """Sign a manifest. Used at release time, never on a deployed host."""
    ed25519 = _require_backend()
    key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    unsigned = ReleaseManifest(
        **{**{k: v for k, v in vars(manifest).items()
              if k not in ("signature", "key_id")},
           "signature": "", "key_id": ""})
    signature = key.sign(unsigned.to_signing_bytes())
    return ReleaseManifest(
        **{**{k: v for k, v in vars(manifest).items()
              if k not in ("signature", "key_id")},
           "signature": base64.b64encode(signature).decode(),
           "key_id": key_id})


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    reason: str
    manifest: ReleaseManifest | None = None

    def to_dict(self) -> dict:
        return {"ok": self.ok, "reason": self.reason,
                "version": self.manifest.version if self.manifest else None,
                "key_id": self.manifest.key_id if self.manifest else None}


def verify_manifest(manifest_path: Path, artifact_path: Path,
                    trusted_keys: dict[str, bytes], *,
                    installed_version: str | None = None,
                    allow_rollback: bool = False) -> VerificationResult:
    """Verify a release before anything installs it.

    Every failure is a refusal. The order matters: the signature is checked
    before the artifact hash, so an attacker cannot learn anything by
    submitting artifacts against a manifest they could not have produced.
    """
    ed25519 = _require_backend()
    try:
        raw = json.loads(Path(manifest_path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return VerificationResult(False, f"manifest unreadable: {exc}")
    try:
        manifest = ReleaseManifest.from_dict(raw)
    except ManifestError as exc:
        return VerificationResult(False, f"manifest rejected: {exc}")

    if not manifest.key_id or manifest.key_id not in trusted_keys:
        return VerificationResult(
            False, f"signed by an untrusted key {manifest.key_id!r}", manifest)
    if not manifest.signature:
        return VerificationResult(False, "manifest carries no signature",
                                  manifest)
    try:
        public = ed25519.Ed25519PublicKey.from_public_bytes(
            trusted_keys[manifest.key_id])
        public.verify(base64.b64decode(manifest.signature),
                      manifest.to_signing_bytes())
    except Exception:                                # noqa: BLE001
        # Any failure here is a forged or corrupted manifest. The specific
        # cryptographic reason is not useful to a caller and is not reported.
        return VerificationResult(False, "signature does not verify", manifest)

    artifact = Path(artifact_path)
    if not artifact.is_file():
        return VerificationResult(False, "artifact missing", manifest)
    if artifact.stat().st_size != manifest.artifact_bytes:
        return VerificationResult(False, "artifact size does not match the "
                                         "manifest", manifest)
    if hash_file(artifact) != manifest.artifact_sha256:
        return VerificationResult(False, "artifact hash does not match the "
                                         "manifest", manifest)

    if installed_version is not None:
        comparison = _compare(manifest.version, installed_version)
        if comparison < 0 and not allow_rollback:
            return VerificationResult(
                False,
                f"refusing to downgrade from {installed_version} to "
                f"{manifest.version}: an attacker who cannot forge a "
                "signature can still serve an older signed release",
                manifest)
        if comparison < 0 and allow_rollback:
            expected = _rollback_target(installed_version)
            if expected is not None and manifest.version != expected:
                return VerificationResult(
                    False,
                    f"rollback permitted only to {expected}, not "
                    f"{manifest.version}", manifest)
    return VerificationResult(True, "signature, hash and version accepted",
                              manifest)


#: Set by the installer from the currently installed manifest, so a rollback
#: can only go to the version that release explicitly named.
_ROLLBACK_TARGETS: dict[str, str] = {}


def register_rollback_target(installed_version: str, target: str | None) -> None:
    if target:
        _ROLLBACK_TARGETS[installed_version] = target


def _rollback_target(installed_version: str) -> str | None:
    return _ROLLBACK_TARGETS.get(installed_version)


def _compare(left: str, right: str) -> int:
    """Compare dotted numeric versions. Non-numeric parts compare as text."""
    def parts(value: str):
        out = []
        for piece in value.split("."):
            out.append((0, int(piece)) if piece.isdigit() else (1, piece))
        return out
    a, b = parts(left), parts(right)
    return (a > b) - (a < b)
