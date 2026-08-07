from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.linux_artifact_ownership import (
    LinuxArtifactMetadata,
    LinuxArtifactOwnershipError,
    verify_linux_artifact_ownership,
)


def _metadata(content: bytes) -> LinuxArtifactMetadata:
    return LinuxArtifactMetadata(
        component_id="linux-network-helper",
        version="1.2.3",
        source="https://example.invalid/releases/1.2.3",
        license_id="Apache-2.0",
        expected_sha256=hashlib.sha256(content).hexdigest(),
    )


def _trusted_uids() -> frozenset[int]:
    return frozenset({0, os.getuid()})


def _artifact(tmp_path: Path, content: bytes = b"verified-linux-helper") -> Path:
    artifact = tmp_path / "helper"
    _ = artifact.write_bytes(content)
    artifact.chmod(0o755)
    return artifact


def test_verifier_returns_descriptor_bound_deterministic_receipt(tmp_path: Path) -> None:
    content = b"verified-linux-helper"
    artifact = _artifact(tmp_path, content)

    receipt = verify_linux_artifact_ownership(
        artifact,
        _metadata(content),
        expected_uid=os.getuid(),
        trusted_ancestor_uids=_trusted_uids(),
    )
    repeated = verify_linux_artifact_ownership(
        artifact,
        _metadata(content),
        expected_uid=os.getuid(),
        trusted_ancestor_uids=_trusted_uids(),
    )

    assert receipt == repeated
    assert receipt.path == str(artifact)
    assert receipt.sha256 == hashlib.sha256(content).hexdigest()
    assert receipt.uid == os.getuid()
    assert receipt.mode == 0o755


@pytest.mark.parametrize("path_text", ["relative/helper", "/tmp//helper", "/tmp/../tmp/helper"])
def test_verifier_rejects_noncanonical_or_relative_path(path_text: str) -> None:
    with pytest.raises(LinuxArtifactOwnershipError, match="path-not"):
        _ = verify_linux_artifact_ownership(
            path_text,
            _metadata(b"x"),
            expected_uid=os.getuid(),
            trusted_ancestor_uids=_trusted_uids(),
        )


def test_verifier_normalizes_embedded_nul_path() -> None:
    with pytest.raises(LinuxArtifactOwnershipError, match="invalid-path"):
        _ = verify_linux_artifact_ownership(
            "/tmp/helper\0suffix",
            _metadata(b"x"),
            expected_uid=os.getuid(),
            trusted_ancestor_uids=_trusted_uids(),
        )


def test_verifier_rejects_symlink_and_nonregular_leaf(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    link = tmp_path / "link"
    link.symlink_to(artifact)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)

    with pytest.raises(LinuxArtifactOwnershipError):
        _ = verify_linux_artifact_ownership(
            link,
            _metadata(artifact.read_bytes()),
            expected_uid=os.getuid(),
            trusted_ancestor_uids=_trusted_uids(),
        )
    with pytest.raises(LinuxArtifactOwnershipError, match="artifact-not-regular"):
        _ = verify_linux_artifact_ownership(
            fifo,
            _metadata(b""),
            expected_uid=os.getuid(),
            trusted_ancestor_uids=_trusted_uids(),
        )


def test_verifier_rejects_hardlinks_wrong_owner_and_unsafe_mode(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    hardlink = tmp_path / "helper-copy"
    os.link(artifact, hardlink)
    with pytest.raises(LinuxArtifactOwnershipError, match="multiple-links"):
        _ = verify_linux_artifact_ownership(
            artifact,
            _metadata(artifact.read_bytes()),
            expected_uid=os.getuid(),
            trusted_ancestor_uids=_trusted_uids(),
        )
    hardlink.unlink()
    with pytest.raises(LinuxArtifactOwnershipError, match="owner-mismatch"):
        _ = verify_linux_artifact_ownership(
            artifact,
            _metadata(artifact.read_bytes()),
            expected_uid=os.getuid() + 1,
            trusted_ancestor_uids=_trusted_uids(),
        )
    artifact.chmod(0o775)
    with pytest.raises(LinuxArtifactOwnershipError, match="writable-by-untrusted"):
        _ = verify_linux_artifact_ownership(
            artifact,
            _metadata(artifact.read_bytes()),
            expected_uid=os.getuid(),
            trusted_ancestor_uids=_trusted_uids(),
        )


def test_verifier_rejects_unsafe_or_untrusted_ancestor(tmp_path: Path) -> None:
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o777)
    unsafe.chmod(0o777)
    artifact = _artifact(unsafe)

    with pytest.raises(LinuxArtifactOwnershipError, match="unsafe-ancestor"):
        _ = verify_linux_artifact_ownership(
            artifact,
            _metadata(artifact.read_bytes()),
            expected_uid=os.getuid(),
            trusted_ancestor_uids=_trusted_uids(),
        )
    unsafe.chmod(0o700)
    with pytest.raises(LinuxArtifactOwnershipError, match="unsafe-ancestor"):
        _ = verify_linux_artifact_ownership(
            artifact,
            _metadata(artifact.read_bytes()),
            expected_uid=os.getuid(),
            trusted_ancestor_uids=frozenset({0}),
        )


def test_verifier_rejects_digest_size_and_metadata_failures(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path, b"abc")
    wrong_digest = LinuxArtifactMetadata("helper", "1", "source", "MIT", "0" * 64)

    with pytest.raises(LinuxArtifactOwnershipError, match="digest-mismatch"):
        _ = verify_linux_artifact_ownership(
            artifact,
            wrong_digest,
            expected_uid=os.getuid(),
            trusted_ancestor_uids=_trusted_uids(),
        )
    with pytest.raises(LinuxArtifactOwnershipError, match="too-large"):
        _ = verify_linux_artifact_ownership(
            artifact,
            _metadata(b"abc"),
            expected_uid=os.getuid(),
            trusted_ancestor_uids=_trusted_uids(),
            max_bytes=2,
        )
    with pytest.raises(LinuxArtifactOwnershipError, match="invalid-metadata"):
        _ = LinuxArtifactMetadata("helper", "1", "source", " ", "0" * 64)
    with pytest.raises(LinuxArtifactOwnershipError, match="invalid-metadata"):
        _ = LinuxArtifactMetadata("helper", "1", "source", "MIT", " " * 64)
