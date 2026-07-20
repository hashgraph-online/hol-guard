from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from codex_plugin_scanner.guard.mdm import manifest as manifest_module
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


def test_signed_manifest_without_external_trust_anchor_is_not_healthy(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    manifest = _manifest(runtime)
    manifest_path = runtime / "release-manifest.json"
    _write_signed(manifest_path, manifest, Ed25519PrivateKey.generate())

    result = verify_release_manifest(manifest_path, runtime)

    assert not result.healthy
    assert result.reason_code == "release_manifest_trust_anchor_absent"


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

    result = verify_release_manifest(manifest_path, runtime, require_signature=False, expected_owner_uid=os.getuid())

    assert result.reason_code == "release_runtime_insecure_permissions"


def test_rejects_unlisted_runtime_file(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    manifest = _manifest(runtime)
    (runtime / "unlisted.py").write_text("unexpected")
    manifest_path = runtime / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest))

    result = verify_release_manifest(manifest_path, runtime, require_signature=False)

    assert result.reason_code == "release_manifest_coverage_gap"


def test_distinguishes_missing_manifest_file(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    manifest = _manifest(runtime)
    manifest_path = runtime / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    (runtime / "bin" / "hol-guard").unlink()

    result = verify_release_manifest(manifest_path, runtime, require_signature=False)

    assert result.reason_code == "release_manifest_file_missing"


def test_rejects_duplicate_manifest_path(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    manifest = _manifest(runtime)
    files = manifest["files"]
    assert isinstance(files, list)
    files.append(dict(files[0]))
    manifest_path = runtime / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest))

    result = verify_release_manifest(manifest_path, runtime, require_signature=False)

    assert result.reason_code == "release_manifest_duplicate_path"


def test_binds_manifest_to_expected_installer_identity(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    manifest = _manifest(runtime)
    manifest_path = runtime / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest))

    result = verify_release_manifest(
        manifest_path,
        runtime,
        require_signature=False,
        expected_installer_identity="HOLGuardMachine",
    )

    assert result.reason_code == "release_manifest_installer_identity_mismatch"


def test_rejects_manifest_version_below_managed_minimum(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    manifest = _manifest(runtime)
    manifest_path = runtime / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest))

    result = verify_release_manifest(
        manifest_path,
        runtime,
        require_signature=False,
        minimum_version="2.2.0",
    )

    assert result.reason_code == "release_manifest_version_rollback"


def test_binds_manifest_to_verified_native_version(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    manifest = _manifest(runtime)
    manifest_path = runtime / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest))

    result = verify_release_manifest(
        manifest_path,
        runtime,
        require_signature=False,
        expected_native_version="2.1.1",
    )

    assert result.reason_code == "release_manifest_native_version_mismatch"


def test_rejects_non_pep440_manifest_version_with_stable_reason(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    manifest = _manifest(runtime)
    manifest["version"] = "not-a-version"
    manifest_path = runtime / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest))

    result = verify_release_manifest(manifest_path, runtime, require_signature=False)

    assert result.reason_code == "release_manifest_version_invalid"


def test_rejects_unlisted_runtime_symlink(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    manifest = _manifest(runtime)
    outside = tmp_path / "outside"
    outside.write_text("outside")
    (runtime / "unlisted-link").symlink_to(outside)
    manifest_path = runtime / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest))

    result = verify_release_manifest(manifest_path, runtime, require_signature=False)

    assert result.reason_code == "release_manifest_path_escape"


@pytest.mark.skipif(os.name != "nt", reason="Windows junction regression")
def test_rejects_unlisted_windows_directory_junction(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    manifest = _manifest(runtime)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "payload").write_bytes(b"outside")
    subprocess.run(
        ["cmd.exe", "/c", "mklink", "/J", str(runtime / "junction"), str(outside)],
        check=True,
        capture_output=True,
    )
    manifest_path = runtime / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest))

    result = verify_release_manifest(manifest_path, runtime, require_signature=False)

    assert result.reason_code == "release_manifest_path_escape"


def test_bounds_total_hashed_runtime_size(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = tmp_path / "runtime"
    manifest = _manifest(runtime)
    manifest_path = runtime / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    monkeypatch.setattr(manifest_module, "_MAX_RUNTIME_BYTES", 1)

    result = verify_release_manifest(manifest_path, runtime, require_signature=False)

    assert result.reason_code == "release_manifest_size_limit_exceeded"


def test_dangling_manifest_symlink_is_tamper_not_absence(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    manifest_path = runtime / "release-manifest.json"
    manifest_path.symlink_to(tmp_path / "missing-manifest")

    result = verify_release_manifest(manifest_path, runtime, require_signature=False)

    assert result.reason_code == "release_manifest_path_escape"


def test_bounds_directory_and_entry_traversal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = tmp_path / "runtime"
    manifest = _manifest(runtime)
    manifest_path = runtime / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    monkeypatch.setattr(manifest_module, "_MAX_RUNTIME_ENTRIES", 1)

    result = verify_release_manifest(manifest_path, runtime, require_signature=False)

    assert result.reason_code == "release_manifest_file_limit_exceeded"


def test_hashes_runtime_file_through_bounded_descriptor_reads(tmp_path: Path) -> None:
    runtime_file = tmp_path / "runtime"
    raw = b"guard\r\n-runtime\x1a-after-control-z"
    runtime_file.write_bytes(raw)

    digest, consumed, metadata = manifest_module._hash_regular_file(runtime_file, 1024)

    assert digest == hashlib.sha256(raw).hexdigest()
    assert consumed == len(raw)
    assert metadata.st_size == consumed
