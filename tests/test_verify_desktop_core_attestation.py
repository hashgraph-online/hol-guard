from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.release import verify_desktop_core_attestation as verifier

VERSION = "3.0.1"
SOURCE_COMMIT = "a" * 40
SOURCE_TAG = "v3.0.1"
TARGET = "macos-arm64"


def _write_bundle(root: Path) -> tuple[Path, Path, Path]:
    binary = root / "hol-guard-core-3.0.1-macos-arm64"
    binary.write_bytes(b"signed-core-binary")
    manifest = root / f"{binary.name}.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": "hol-guard-core-update.v1",
                "channel": "stable",
                "version": VERSION,
                "sourceCommit": SOURCE_COMMIT,
                "sourceTag": SOURCE_TAG,
                "target": TARGET,
                "artifact": binary.name,
                "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "size": binary.stat().st_size,
                "bootstrapSchema": "guard-desktop-bootstrap.v1",
                "minimumDesktopVersion": "1.0.0",
                "publishedAt": "2026-09-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    marker = root / f"{binary.name}.attested.json"
    marker.write_text(
        json.dumps(
            {
                "schema": "hol-guard-core-attestation.v3",
                "version": VERSION,
                "sourceCommit": SOURCE_COMMIT,
                "sourceTag": SOURCE_TAG,
                "target": TARGET,
                "appleSigningIdentity": "Developer ID Application: HOL Online LLC (TEAM1234)",
                "appleTeamId": "TEAM1234",
                "binarySha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "manifestSha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
                "workflowRun": "run-123",
                "attestedAt": "2026-09-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    return binary, manifest, marker


def test_verify_binds_post_sign_binary_manifest_and_marker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    binary, manifest, marker = _write_bundle(tmp_path)
    calls: list[tuple[Path, str | None]] = []

    def fake_verify(path: Path, expected_team_id: str | None = None) -> None:
        calls.append((path, expected_team_id))

    monkeypatch.setattr(verifier, "_native_verifier", lambda: SimpleNamespace(verify=fake_verify))

    evidence = verifier.verify(
        binary,
        manifest,
        marker,
        version=VERSION,
        source_commit=SOURCE_COMMIT,
        source_tag=SOURCE_TAG,
        target=TARGET,
        expected_team_id="TEAM1234",
    )

    assert evidence["post_sign_verified"] is True
    assert evidence["binary"]["sha256"] == hashlib.sha256(binary.read_bytes()).hexdigest()
    assert calls == [(binary, "TEAM1234")]


def test_verify_rejects_marker_binary_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    binary, manifest, marker = _write_bundle(tmp_path)
    marker_payload = json.loads(marker.read_text(encoding="utf-8"))
    marker_payload["binarySha256"] = "f" * 64
    marker.write_text(json.dumps(marker_payload), encoding="utf-8")
    monkeypatch.setattr(verifier, "_native_verifier", lambda: SimpleNamespace(verify=lambda *_args, **_kwargs: None))

    with pytest.raises(verifier.DesktopAttestationError, match="attestation mismatch"):
        verifier.verify(
            binary,
            manifest,
            marker,
            version=VERSION,
            source_commit=SOURCE_COMMIT,
            source_tag=SOURCE_TAG,
            target=TARGET,
            expected_team_id="TEAM1234",
        )


def test_verify_rejects_team_identity_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    binary, manifest, marker = _write_bundle(tmp_path)
    monkeypatch.setattr(verifier, "_native_verifier", lambda: SimpleNamespace(verify=lambda *_args, **_kwargs: None))

    with pytest.raises(verifier.DesktopAttestationError, match="team identity"):
        verifier.verify(
            binary,
            manifest,
            marker,
            version=VERSION,
            source_commit=SOURCE_COMMIT,
            source_tag=SOURCE_TAG,
            target=TARGET,
            expected_team_id="OTHERTEAM",
        )
