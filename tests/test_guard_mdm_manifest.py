from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from codex_plugin_scanner.guard.mdm.contracts import RELEASE_MANIFEST_SCHEMA_VERSION
from codex_plugin_scanner.guard.mdm.manifest import verify_release_manifest


def _manifest(runtime: Path) -> dict[str, object]:
    executable = runtime / "bin" / "hol-guard"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"guard-runtime")
    return {
        "schemaVersion": RELEASE_MANIFEST_SCHEMA_VERSION,
        "version": "2.1.0",
        "buildId": "build-1",
        "sourceCommit": "a" * 40,
        "platform": "macos",
        "architecture": "arm64",
        "policySchemaVersion": "hol-guard-mdm-policy.v1",
        "installerIdentity": "org.hol.guard",
        "files": [{"path": "bin/hol-guard", "sha256": hashlib.sha256(executable.read_bytes()).hexdigest()}],
    }


def _write_signed(path: Path, payload: dict[str, object], private_key: Ed25519PrivateKey) -> None:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    signed = dict(payload)
    signed["signature"] = {"keyId": "release-1", "value": base64.b64encode(private_key.sign(canonical)).decode()}
    path.write_text(json.dumps(signed))


def test_verifies_signature_and_runtime_hashes(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    manifest = _manifest(runtime)
    key = Ed25519PrivateKey.generate()
    manifest_path = runtime / "release-manifest.json"
    _write_signed(manifest_path, manifest, key)
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    result = verify_release_manifest(manifest_path, runtime, trusted_keys={"release-1": public})

    assert result.healthy
    assert result.signature_state == "valid"
    assert result.reason_code == "release_manifest_valid"


def test_unsigned_manifest_is_not_healthy(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    manifest = _manifest(runtime)
    manifest_path = runtime / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest))

    result = verify_release_manifest(manifest_path, runtime)

    assert not result.healthy
    assert result.reason_code == "release_manifest_unsigned"


def test_detects_modified_runtime_file(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    manifest = _manifest(runtime)
    manifest_path = runtime / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    (runtime / "bin" / "hol-guard").write_bytes(b"tampered")

    result = verify_release_manifest(manifest_path, runtime, require_signature=False)

    assert result.reason_code == "release_manifest_hash_mismatch"


def test_rejects_manifest_path_traversal(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    manifest = _manifest(runtime)
    manifest["files"] = [{"path": "../outside", "sha256": "0" * 64}]
    manifest_path = runtime / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest))

    result = verify_release_manifest(manifest_path, runtime, require_signature=False)

    assert result.reason_code == "release_manifest_invalid"


def test_rejects_symlink_escape(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    runtime.mkdir()
    (runtime / "link").symlink_to(outside)
    manifest = {
        "schemaVersion": RELEASE_MANIFEST_SCHEMA_VERSION,
        "version": "2.1.0",
        "buildId": "build-1",
        "sourceCommit": "a" * 40,
        "platform": "macos",
        "architecture": "arm64",
        "policySchemaVersion": "hol-guard-mdm-policy.v1",
        "installerIdentity": "org.hol.guard",
        "files": [{"path": "link", "sha256": hashlib.sha256(outside.read_bytes()).hexdigest()}],
    }
    manifest_path = runtime / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest))

    result = verify_release_manifest(manifest_path, runtime, require_signature=False)

    assert result.reason_code == "release_manifest_path_escape"


def test_rejects_wrong_platform_or_architecture(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    manifest = _manifest(runtime)
    manifest_path = runtime / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest))

    platform_result = verify_release_manifest(
        manifest_path, runtime, require_signature=False, expected_platform="windows"
    )
    arch_result = verify_release_manifest(
        manifest_path, runtime, require_signature=False, expected_architecture="x86_64"
    )

    assert platform_result.reason_code == "release_manifest_platform_mismatch"
    assert arch_result.reason_code == "release_manifest_architecture_mismatch"


def test_detects_insecure_machine_file_permissions(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    manifest = _manifest(runtime)
    manifest_path = runtime / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    (runtime / "bin" / "hol-guard").chmod(0o777)

    result = verify_release_manifest(
        manifest_path, runtime, require_signature=False, expected_owner_uid=os.getuid()
    )

    assert result.reason_code == "release_runtime_insecure_permissions"
