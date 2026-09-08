#!/usr/bin/env python3
"""Verify a Desktop Core binary, sealed native sidecar, and attestation marker."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import stat
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

_NATIVE_VERIFIER = Path(__file__).with_name("verify_pyinstaller_native_runtime.py")
_MARKER_SCHEMA = "hol-guard-core-attestation.v3"
_MANIFEST_SCHEMA = "hol-guard-core-update.v1"
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_TOKEN = re.compile(r"^[A-Za-z0-9._:-]{1,160}\Z")
_SIGNING_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._():,+-]{0,159}\Z")
_MAX_BINARY_BYTES = 512 * 1024 * 1024
_MAX_SIDECAR_BYTES = 64 * 1024


class DesktopAttestationError(ValueError):
    """Raised when the signed Desktop Core package is not self-consistent."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _regular_file(path: Path, *, label: str, maximum: int) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise DesktopAttestationError(f"{label} is missing") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size <= 0
        or metadata.st_size > maximum
    ):
        raise DesktopAttestationError(f"{label} is not a bounded regular file")


def _json(path: Path, *, label: str) -> dict[str, object]:
    _regular_file(path, label=label, maximum=_MAX_SIDECAR_BYTES)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DesktopAttestationError(f"{label} is not valid JSON") from error
    if not isinstance(value, dict):
        raise DesktopAttestationError(f"{label} must be an object")
    return value


def _native_verifier():
    spec = importlib.util.spec_from_file_location("hol_guard_native_runtime_verifier", _NATIVE_VERIFIER)
    if spec is None or spec.loader is None:
        raise DesktopAttestationError("native runtime verifier is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _require_token(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None:
        raise DesktopAttestationError(f"{label} is not a bounded release token")
    return value


def _require_signing_identity(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SIGNING_IDENTITY.fullmatch(value) is None:
        raise DesktopAttestationError(f"{label} is not a bounded signing identity")
    return value


def verify(
    binary: Path,
    manifest: Path,
    marker: Path,
    *,
    version: str,
    source_commit: str,
    source_tag: str,
    target: str,
    expected_team_id: str,
) -> dict[str, object]:
    """Verify the post-sign bytes and return a privacy-safe evidence record."""

    _regular_file(binary, label="Desktop Core binary", maximum=_MAX_BINARY_BYTES)
    manifest_payload = _json(manifest, label="Desktop Core manifest")
    marker_payload = _json(marker, label="Desktop Core attestation marker")
    _require_token(version, label="release version")
    _require_token(source_tag, label="source tag")
    _require_token(target, label="release target")
    if not _SHA40.fullmatch(source_commit):
        raise DesktopAttestationError("source commit must be a full lowercase Git SHA")
    expected_manifest: Mapping[str, object] = {
        "schema": _MANIFEST_SCHEMA,
        "channel": "stable",
        "version": version,
        "sourceCommit": source_commit,
        "sourceTag": source_tag,
        "target": target,
        "artifact": binary.name,
        "sha256": sha256_file(binary),
        "size": binary.stat().st_size,
        "bootstrapSchema": "guard-desktop-bootstrap.v1",
    }
    for key, expected in expected_manifest.items():
        if manifest_payload.get(key) != expected:
            raise DesktopAttestationError(f"Desktop Core manifest mismatch for {key}")
    expected_marker: Mapping[str, object] = {
        "schema": _MARKER_SCHEMA,
        "version": version,
        "sourceCommit": source_commit,
        "sourceTag": source_tag,
        "target": target,
        "binarySha256": sha256_file(binary),
        "manifestSha256": sha256_file(manifest),
    }
    for key, expected in expected_marker.items():
        if marker_payload.get(key) != expected:
            raise DesktopAttestationError(f"Desktop Core attestation mismatch for {key}")
    _require_signing_identity(marker_payload.get("appleSigningIdentity"), label="attestation appleSigningIdentity")
    for key in ("appleTeamId", "workflowRun", "attestedAt"):
        _require_token(marker_payload.get(key), label=f"attestation {key}")
    _require_token(expected_team_id, label="expected Apple team ID")
    if marker_payload["appleTeamId"] != expected_team_id:
        raise DesktopAttestationError("Desktop Core attestation team identity mismatch")
    verifier = _native_verifier()
    try:
        verifier.verify(binary, expected_team_id=expected_team_id)
    except (OSError, ValueError, SystemExit) as error:
        raise DesktopAttestationError("post-sign native sidecar verification failed") from error
    return {
        "schema": "hol-guard-desktop-core-evidence.v1",
        "version": version,
        "source_commit": source_commit,
        "source_tag": source_tag,
        "target": target,
        "binary": {"name": binary.name, "sha256": expected_marker["binarySha256"], "size": binary.stat().st_size},
        "manifest": {"name": manifest.name, "sha256": expected_marker["manifestSha256"]},
        "attestation": {"name": marker.name, "sha256": sha256_file(marker), "team_id": marker_payload["appleTeamId"]},
        "post_sign_verified": True,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--marker", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tag", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--team-id", required=True)
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        evidence = verify(
            args.binary,
            args.manifest,
            args.marker,
            version=args.version,
            source_commit=args.source_commit,
            source_tag=args.source_tag,
            target=args.target,
            expected_team_id=args.team_id,
        )
    except DesktopAttestationError as error:
        print(f"Desktop Core attestation failed: {error}", file=sys.stderr)
        return 1
    rendered = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    print(rendered, end="")
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
