"""Release verification, attacked the way an update channel is attacked.

An attacker who can replace the artifact does not need to defeat any control
this project has built, because they get to write the controls. So every test
here is a way of substituting something the project did not sign, and the
required outcome is always a refusal rather than a warning.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from annulon.supply.manifest import (
    ManifestError, ReleaseManifest, SignatureError, hash_file,
    register_rollback_target, sign_manifest, signing_available,
    verify_manifest,
)

pytestmark = pytest.mark.skipif(
    not signing_available(),
    reason="no signature backend; the verifier refuses rather than degrading")


def _keypair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    key = ed25519.Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.Raw,
                                serialization.PrivateFormat.Raw,
                                serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.Raw,
                                           serialization.PublicFormat.Raw)
    return private, public


@pytest.fixture
def release(tmp_path):
    artifact = tmp_path / "annulon-0.5.0-py3-none-any.whl"
    artifact.write_bytes(b"wheel bytes" * 500)
    private, public = _keypair()
    manifest = ReleaseManifest(
        package="annulon", version="0.5.0", artifact_name=artifact.name,
        artifact_sha256=hash_file(artifact),
        artifact_bytes=artifact.stat().st_size,
        created_at=datetime.now(timezone.utc).isoformat(),
        rollback_to="0.4.0")
    signed = sign_manifest(manifest, private, "release-2026")
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(signed.to_dict()))
    return {"artifact": artifact, "manifest": path, "signed": signed,
            "private": private, "trusted": {"release-2026": public},
            "dir": tmp_path}


# --- the positive control --------------------------------------------------

def test_a_genuine_release_verifies(release):
    """A verifier that refuses everything is broken, not safe."""
    result = verify_manifest(release["manifest"], release["artifact"],
                             release["trusted"])
    assert result.ok
    assert result.manifest.version == "0.5.0"


# --- substituting the artifact ---------------------------------------------

def test_a_replaced_artifact_of_a_different_size_is_refused(release):
    release["artifact"].write_bytes(b"malicious" * 500)
    result = verify_manifest(release["manifest"], release["artifact"],
                             release["trusted"])
    assert not result.ok
    assert "size" in result.reason


def test_a_replaced_artifact_of_the_same_size_is_refused(release):
    """Size alone proves nothing; the hash is what catches this."""
    original = release["artifact"].read_bytes()
    release["artifact"].write_bytes(b"x" * len(original))
    result = verify_manifest(release["manifest"], release["artifact"],
                             release["trusted"])
    assert not result.ok
    assert "hash" in result.reason


def test_a_missing_artifact_is_refused(release):
    release["artifact"].unlink()
    assert not verify_manifest(release["manifest"], release["artifact"],
                               release["trusted"]).ok


# --- substituting the manifest ---------------------------------------------

@pytest.mark.parametrize("field,value", [
    ("version", "9.9.9"),
    ("artifact_sha256", "0" * 64),
    ("artifact_bytes", 1),
    ("package", "not-annulon"),
    ("rollback_to", "0.0.1"),
    ("created_at", "2000-01-01T00:00:00+00:00"),
])
def test_editing_any_signed_field_breaks_the_signature(release, field, value):
    """The signature covers the whole body, so there is no field an attacker
    can adjust while keeping it valid."""
    body = json.loads(release["manifest"].read_text())
    body[field] = value
    tampered = release["dir"] / "tampered.json"
    tampered.write_text(json.dumps(body))
    result = verify_manifest(tampered, release["artifact"], release["trusted"])
    assert not result.ok
    assert result.reason == "signature does not verify"


def test_a_manifest_with_no_signature_is_refused(release):
    body = json.loads(release["manifest"].read_text())
    body["signature"] = ""
    path = release["dir"] / "unsigned.json"
    path.write_text(json.dumps(body))
    result = verify_manifest(path, release["artifact"], release["trusted"])
    assert not result.ok
    assert "no signature" in result.reason


def test_a_signature_from_another_key_is_refused(release):
    """Correctly signed, by the wrong signer."""
    other_private, _ = _keypair()
    forged = sign_manifest(release["signed"], other_private, "release-2026")
    path = release["dir"] / "forged.json"
    path.write_text(json.dumps(forged.to_dict()))
    assert not verify_manifest(path, release["artifact"],
                               release["trusted"]).ok


def test_an_unknown_key_id_is_refused(release):
    """An attacker naming their own key must not be able to introduce it."""
    result = verify_manifest(release["manifest"], release["artifact"],
                             {"a-different-key": b"\\x00" * 32})
    assert not result.ok
    assert "untrusted key" in result.reason


def test_an_unknown_manifest_field_is_refused(release):
    """A field the verifier ignores is a field an attacker can use to carry
    meaning the signer never agreed to."""
    body = json.loads(release["manifest"].read_text())
    body["install_hook"] = "/bin/sh -c evil"
    path = release["dir"] / "extra.json"
    path.write_text(json.dumps(body))
    result = verify_manifest(path, release["artifact"], release["trusted"])
    assert not result.ok
    assert "unknown manifest field" in result.reason


@pytest.mark.parametrize("body", [
    "{}", "[]", "null", "not json", '{"schema_version": 99}',
    '{"schema_version": 1}',
])
def test_a_malformed_manifest_is_refused(release, body):
    path = release["dir"] / "malformed.json"
    path.write_text(body)
    assert not verify_manifest(path, release["artifact"],
                               release["trusted"]).ok


@pytest.mark.parametrize("digest", ["", "abc", "Z" * 64, "A" * 64, "0" * 63])
def test_a_malformed_digest_is_refused(release, digest):
    body = json.loads(release["manifest"].read_text())
    body["artifact_sha256"] = digest
    path = release["dir"] / "digest.json"
    path.write_text(json.dumps(body))
    assert not verify_manifest(path, release["artifact"],
                               release["trusted"]).ok


# --- serving an old, genuinely signed release ------------------------------

def test_a_downgrade_is_refused_even_though_it_is_genuinely_signed(release):
    """The attack that signatures alone do not stop.

    An attacker who cannot forge a signature can still serve an older release
    with a known flaw. Every byte of it verifies.
    """
    result = verify_manifest(release["manifest"], release["artifact"],
                             release["trusted"], installed_version="0.6.0")
    assert not result.ok
    assert "downgrade" in result.reason


def test_an_upgrade_is_permitted(release):
    assert verify_manifest(release["manifest"], release["artifact"],
                           release["trusted"], installed_version="0.4.0").ok


def test_reinstalling_the_same_version_is_permitted(release):
    assert verify_manifest(release["manifest"], release["artifact"],
                           release["trusted"], installed_version="0.5.0").ok


def test_a_rollback_is_permitted_only_to_the_named_target(release):
    """Allowing rollback must not become allowing any downgrade."""
    register_rollback_target("0.6.0", "0.5.0")
    assert verify_manifest(release["manifest"], release["artifact"],
                           release["trusted"], installed_version="0.6.0",
                           allow_rollback=True).ok

    register_rollback_target("0.7.0", "0.6.5")
    result = verify_manifest(release["manifest"], release["artifact"],
                             release["trusted"], installed_version="0.7.0",
                             allow_rollback=True)
    assert not result.ok
    assert "rollback permitted only to 0.6.5" in result.reason


@pytest.mark.parametrize("left,right,expected", [
    ("1.0.0", "0.9.9", 1), ("0.9.9", "1.0.0", -1), ("1.0.0", "1.0.0", 0),
    ("1.10.0", "1.9.0", 1), ("1.0.0", "1.0", 1),
])
def test_versions_compare_numerically_not_as_text(left, right, expected):
    """`1.10.0` is newer than `1.9.0`; comparing as text says otherwise and
    would let a downgrade through."""
    from annulon.supply.manifest import _compare
    assert _compare(left, right) == expected


# --- canonical signing input -----------------------------------------------

def test_the_signing_input_is_stable_across_key_order(release):
    """Two processes must derive byte-identical input from one manifest, or
    verification becomes a coin flip."""
    reordered = ReleaseManifest.from_dict(
        json.loads(json.dumps(release["signed"].to_dict(), sort_keys=False)))
    assert reordered.to_signing_bytes() == release["signed"].to_signing_bytes()


def test_the_signature_is_excluded_from_its_own_input(release):
    """Otherwise signing would be impossible and verification circular."""
    assert b"signature" not in release["signed"].to_signing_bytes()


# --- the rollback restriction's default (KF-58) -----------------------------

def test_an_unregistered_rollback_target_refuses_rather_than_permitting_any(
        release):
    """`--allow-rollback` with no recorded target must refuse.

    `test_a_rollback_is_permitted_only_to_the_named_target` registers a
    target before every assertion, so the case where none is registered was
    never exercised -- and that case skipped the restriction entirely:
    `expected is not None and manifest.version != expected` is False when
    `expected` is None, so any validly signed older release was accepted.

    It was reachable rather than theoretical. `_ROLLBACK_TARGETS` is
    in-memory and the installer only populates it when the install state
    carries a `rollback_to`, which a first install does not write -- so a
    freshly installed host was exactly the unrestricted one.
    """
    result = verify_manifest(release["manifest"], release["artifact"],
                             release["trusted"], installed_version="3.3.3",
                             allow_rollback=True)
    assert not result.ok
    assert "no rollback target is recorded" in result.reason


def test_a_downgrade_is_still_refused_without_allow_rollback(release):
    """The negative control for the test above: the refusal must come from
    the missing target, not from downgrades being refused outright."""
    result = verify_manifest(release["manifest"], release["artifact"],
                             release["trusted"], installed_version="3.3.3",
                             allow_rollback=False)
    assert not result.ok
    assert "refusing to downgrade" in result.reason


# --- version strings are ASCII (KF-59) --------------------------------------

@pytest.mark.parametrize("version", [
    "1.٩",       # Arabic-Indic nine: isdigit() and int() both accept it,
                      # so it compared numerically equal to "1.9" while being
                      # a different string -- and the rollback check compares
                      # versions as strings
    "1.²",       # superscript two: isdigit() accepts, int() raises
    "1.⑨",       # circled nine: isdigit() accepts, int() raises
    "1.\U0001d7f9",   # mathematical monospace nine
    "1.9\n",          # KF-43's family, at this boundary
    "../etc/passwd",
    "1.9 ",
])
def test_a_version_outside_ascii_is_refused_at_the_parse_boundary(version):
    """A version reaches two comparisons with different semantics: `_compare`
    reads it numerically, the rollback check compares it as a string. Confine
    it to ASCII at the boundary so those two views cannot disagree."""
    raw = {"schema_version": 1, "package": "annulon", "version": version,
           "artifact_name": "a.whl", "artifact_sha256": "0" * 64,
           "artifact_bytes": 10, "created_at": "2026-10-15T00:00:00+00:00",
           "rollback_to": None}
    with pytest.raises(ManifestError):
        ReleaseManifest.from_dict(raw)


@pytest.mark.parametrize("version", ["1.9", "0.5.0", "1.0-rc1", "2", "1.0+b1"])
def test_ordinary_versions_still_parse(version):
    """The positive control: the ASCII rule must not reject real versions,
    including the non-numeric pre-release forms `_compare` orders as text."""
    raw = {"schema_version": 1, "package": "annulon", "version": version,
           "artifact_name": "a.whl", "artifact_sha256": "0" * 64,
           "artifact_bytes": 10, "created_at": "2026-10-15T00:00:00+00:00",
           "rollback_to": None}
    assert ReleaseManifest.from_dict(raw).version == version


def test_a_rollback_target_outside_ascii_is_refused():
    """`rollback_to` is compared against a version, so it needs the same
    grammar -- otherwise the field that authorises a downgrade is the one
    field not checked."""
    raw = {"schema_version": 1, "package": "annulon", "version": "1.0",
           "artifact_name": "a.whl", "artifact_sha256": "0" * 64,
           "artifact_bytes": 10, "created_at": "2026-10-15T00:00:00+00:00",
           "rollback_to": "0.٩"}
    with pytest.raises(ManifestError):
        ReleaseManifest.from_dict(raw)


@pytest.mark.parametrize("piece", ["²", "⑨", "½", "٩"])
def test_compare_orders_rather_than_raising_on_digit_like_characters(piece):
    """`_compare` is reached from a signature-verified manifest and from the
    local install state, and `str.isdigit()` is true for characters `int()`
    refuses. It raised ValueError instead of ordering the versions, so a
    malformed version crashed the installer rather than being refused."""
    from annulon.supply.manifest import _compare
    assert _compare(f"1.{piece}", "1.9") in (-1, 0, 1)
    assert _compare("1.9", f"1.{piece}") in (-1, 0, 1)
