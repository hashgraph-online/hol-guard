#!/usr/bin/env python3
"""Validate the final privacy-safe Guard release evidence manifest.

This gate proves that all named release checks, artifact evidence, review
state, and platform limitations are accounted for.  It does not mint signing
keys or assert approval-capable release readiness without external authority.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import stat
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

REQUIRED_GATES = (
    "ci",
    "codeql",
    "fuzz",
    "adversarial",
    "parity",
    "mutation",
    "source_race",
    "approval_replay",
    "fault",
    "soak",
    "privacy",
    "independent_review",
)
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_TOKEN = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,159}\Z")
_PLATFORMS = frozenset({"manylinux-x64", "macos-x64", "macos-arm64", "windows-x64"})
_NON_WINDOWS = frozenset(_PLATFORMS - {"windows-x64"})
_MAX_BYTES = 2 * 1024 * 1024


class FinalEvidenceError(ValueError):
    """Raised when final release evidence is incomplete or unsafe."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_bytes(payload: Mapping[str, object]) -> bytes:
    """Serialize the unsigned evidence projection deterministically."""

    unsigned = {key: value for key, value in payload.items() if key not in {"signature", "release_ready"}}
    return (json.dumps(unsigned, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n").encode()


def _token(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None:
        raise FinalEvidenceError(f"{label} is not a bounded release token")
    return value


def _hash(value: object, *, label: str, length: int = 64) -> str:
    if (
        not isinstance(value, str)
        or (length == 40 and _SHA40.fullmatch(value) is None)
        or (length == 64 and _SHA64.fullmatch(value) is None)
    ):
        raise FinalEvidenceError(f"{label} is not a lowercase SHA-256/Git digest")
    return value


def _encoded(value: object, *, label: str, size: int) -> bytes:
    if not isinstance(value, str):
        raise FinalEvidenceError(f"{label} is missing")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise FinalEvidenceError(f"{label} is not valid base64") from error
    if len(decoded) != size:
        raise FinalEvidenceError(f"{label} has an invalid length")
    return decoded


def _safe_strings(value: object) -> None:
    if isinstance(value, str) and (
        any(fragment in value for fragment in ("/Users/", "/home/", "/tmp/", "\\Users\\", "~/."))
        or "-----BEGIN" in value
    ):
        raise FinalEvidenceError("evidence contains a workstation path or private key material")
    if isinstance(value, Mapping):
        for nested in value.values():
            _safe_strings(nested)
    elif isinstance(value, list):
        for nested in value:
            _safe_strings(nested)


def _component(value: object, *, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise FinalEvidenceError(f"{label} evidence must be an object")
    if value.get("status") != "pass":
        raise FinalEvidenceError(f"{label} evidence is not passed")
    _token(value.get("name"), label=f"{label} evidence name")
    _hash(value.get("sha256"), label=f"{label} evidence hash")
    return {"name": value["name"], "sha256": value["sha256"], "status": "pass"}


def _platforms(value: object) -> list[str]:
    if not isinstance(value, list) or not value:
        raise FinalEvidenceError("release platform coverage is missing")
    labels = [_token(item, label="platform") for item in value]
    if len(labels) != len(set(labels)) or not set(labels) <= _PLATFORMS or not set(labels) >= _NON_WINDOWS:
        raise FinalEvidenceError("release platform coverage is incomplete")
    return sorted(labels)


def _validate_release_identity(
    payload: Mapping[str, object],
    *,
    expected_version: str,
    expected_source_sha: str,
    expected_rule_digest: str,
) -> dict[str, object]:
    if payload.get("schema") != "hol-guard-final-release-evidence.v1":
        raise FinalEvidenceError("unsupported final evidence schema")
    release = payload.get("release")
    if not isinstance(release, dict):
        raise FinalEvidenceError("release identity is missing")
    if release.get("version") != expected_version or release.get("source_sha") != expected_source_sha:
        raise FinalEvidenceError("release package identity does not match")
    if release.get("rule_digest") != expected_rule_digest:
        raise FinalEvidenceError("release rule identity does not match")
    _hash(expected_source_sha, label="release source", length=40)
    _hash(expected_rule_digest, label="release rule")
    commit_sha = _hash(release.get("commit_sha"), label="release commit", length=40)
    if commit_sha != expected_source_sha:
        raise FinalEvidenceError("release commit does not match expected source")
    _hash(release.get("base_sha"), label="release base", length=40)
    return {
        "version": expected_version,
        "source_sha": expected_source_sha,
        "rule_digest": expected_rule_digest,
        "commit_sha": commit_sha,
        "base_sha": release["base_sha"],
    }


def _validate_components_and_gates(payload: Mapping[str, object]) -> dict[str, object]:
    components = payload.get("evidence")
    if not isinstance(components, dict):
        raise FinalEvidenceError("component evidence is missing")
    artifacts = _component(components.get("artifacts"), label="artifact")
    desktop_core = _component(components.get("desktop_core"), label="Desktop Core")
    installed_matrix = _component(components.get("installed_matrix"), label="installed matrix")
    gates = payload.get("gates")
    if not isinstance(gates, dict) or set(gates) != set(REQUIRED_GATES):
        raise FinalEvidenceError("final gate set is incomplete")
    if any(value is not True for value in gates.values()):
        raise FinalEvidenceError("one or more final release gates did not pass")
    return {
        "artifacts": artifacts,
        "desktop_core": desktop_core,
        "installed_matrix": installed_matrix,
    }


def _validate_review(payload: Mapping[str, object]) -> dict[str, object]:
    review = payload.get("review")
    if not isinstance(review, dict) or review.get("exact_head") is not True:
        raise FinalEvidenceError("exact-head review evidence is missing")
    if review.get("unresolved_non_outdated") != 0 or review.get("pending_required") != 0:
        raise FinalEvidenceError("actionable review threads or required checks remain")
    ci_run = _token(review.get("ci_run"), label="CI run")
    return {
        "ci_run": ci_run,
        "exact_head": True,
        "unresolved_non_outdated": 0,
        "pending_required": 0,
    }


def _validate_coverage(payload: Mapping[str, object]) -> dict[str, object]:
    coverage = payload.get("coverage")
    if not isinstance(coverage, dict):
        raise FinalEvidenceError("platform coverage is missing")
    platforms = _platforms(coverage.get("platforms"))
    windows_value = coverage.get("windows")
    if windows_value is not None and not isinstance(windows_value, dict):
        raise FinalEvidenceError("Windows coverage entry must be an object")
    windows = cast(dict[str, object] | None, windows_value)
    if "windows-x64" not in platforms:
        if not isinstance(windows, dict) or windows.get("status") != "waived":
            raise FinalEvidenceError("Windows omission requires an explicit waiver")
        reason = _token(windows.get("reason"), label="Windows waiver reason")
        windows_projection: dict[str, object] = {"status": "waived", "reason": reason}
    elif windows is not None and windows.get("status") != "verified":
        raise FinalEvidenceError("Windows evidence must be verified when included")
    else:
        windows_projection = {"status": "verified"} if windows is not None else {}
    projection: dict[str, object] = {"platforms": platforms}
    if windows_projection:
        projection["windows"] = windows_projection
    return projection


def _validate_approval(payload: Mapping[str, object]) -> dict[str, object]:
    approval = payload.get("approval")
    if not isinstance(approval, dict) or type(approval.get("capable")) is not bool:
        raise FinalEvidenceError("approval capability status is missing")
    if bool(approval["capable"]):
        if approval.get("root_configured") is not True or approval.get("signer_ceremony") is not True:
            raise FinalEvidenceError("approval-capable release lacks external root/signer ceremony")
        root_fingerprint = _hash(approval.get("root_fingerprint"), label="approval root fingerprint")
        signer_key_id = _token(approval.get("signer_key_id"), label="approval signer key ID")
        return {
            "capable": True,
            "root_configured": True,
            "signer_ceremony": True,
            "root_fingerprint": root_fingerprint,
            "signer_key_id": signer_key_id,
        }
    elif approval.get("status") != "fail_closed_external_provisioning_required":
        raise FinalEvidenceError("non-capable approval status must state the external blocker")
    return {"capable": False, "status": "fail_closed_external_provisioning_required"}


def _validate_reproducibility(payload: Mapping[str, object]) -> dict[str, object]:
    reproducibility = payload.get("reproducibility")
    if not isinstance(reproducibility, dict) or reproducibility.get("deterministic") is not True:
        raise FinalEvidenceError("reproducibility evidence is missing")
    commands_value = reproducibility.get("commands")
    if (
        not isinstance(commands_value, list)
        or not commands_value
        or any(not isinstance(item, str) for item in commands_value)
    ):
        raise FinalEvidenceError("reproducible command set is missing")
    if any(len(item) > 400 for item in commands_value):
        raise FinalEvidenceError("reproducible command is too long")
    return {"deterministic": True, "commands": list(commands_value)}


def _validate_signature(
    payload: Mapping[str, object],
    *,
    canonical_payload: Mapping[str, object],
    require_signature: bool,
    trusted_public_key: bytes | None,
    trusted_key_id: str | None,
) -> tuple[dict[str, object] | None, bool]:
    signature = payload.get("signature")
    signature_payload = cast(dict[str, object], signature) if isinstance(signature, dict) else None
    signature_verified = signature_payload is not None and signature_payload.get("status") == "verified"
    if signature_verified:
        assert signature_payload is not None
        if set(signature_payload) != {
            "status",
            "algorithm",
            "key_id",
            "public_key",
            "signature",
            "manifest_sha256",
        }:
            raise FinalEvidenceError("evidence signature record is incomplete")
        if signature_payload.get("algorithm") != "ed25519":
            raise FinalEvidenceError("evidence signature algorithm is not approved")
        key_id = _token(signature_payload.get("key_id"), label="evidence signer key ID")
        if trusted_public_key is None:
            raise FinalEvidenceError("trusted evidence signer is not configured")
        if trusted_key_id is not None and key_id != trusted_key_id:
            raise FinalEvidenceError("evidence signer key ID is not trusted")
        signed_bytes = canonical_bytes(canonical_payload)
        _hash(signature_payload.get("manifest_sha256"), label="evidence signed digest")
        if signature_payload["manifest_sha256"] != hashlib.sha256(signed_bytes).hexdigest():
            raise FinalEvidenceError("evidence signature digest does not bind canonical bytes")
        public_key_bytes = _encoded(signature_payload.get("public_key"), label="evidence public key", size=32)
        if public_key_bytes != trusted_public_key:
            raise FinalEvidenceError("evidence signer is not trusted")
        try:
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            public_key.verify(
                _encoded(signature_payload.get("signature"), label="evidence signature", size=64),
                signed_bytes,
            )
        except (InvalidSignature, ValueError) as error:
            raise FinalEvidenceError("evidence signature is invalid") from error
    elif require_signature:
        raise FinalEvidenceError("external evidence signature is required")
    return signature_payload, signature_verified


def validate_final_evidence(
    payload: Mapping[str, object],
    *,
    expected_version: str,
    expected_source_sha: str,
    expected_rule_digest: str,
    require_signature: bool = False,
    trusted_public_key: bytes | None = None,
    trusted_key_id: str | None = None,
) -> dict[str, object]:
    """Validate and normalize a final evidence payload."""

    _safe_strings(payload)
    release = _validate_release_identity(
        payload,
        expected_version=expected_version,
        expected_source_sha=expected_source_sha,
        expected_rule_digest=expected_rule_digest,
    )
    evidence = _validate_components_and_gates(payload)
    review = _validate_review(payload)
    coverage = _validate_coverage(payload)
    approval = _validate_approval(payload)
    reproducibility = _validate_reproducibility(payload)

    normalized: dict[str, object] = {
        "schema": "hol-guard-final-release-evidence.v1",
        "release": release,
        "evidence": evidence,
        "gates": {key: True for key in REQUIRED_GATES},
        "review": review,
        "coverage": coverage,
        "approval": approval,
        "reproducibility": reproducibility,
    }
    signature_payload, signature_verified = _validate_signature(
        payload,
        canonical_payload=normalized,
        require_signature=require_signature,
        trusted_public_key=trusted_public_key,
        trusted_key_id=trusted_key_id,
    )
    normalized["signature"] = signature_payload if signature_verified else {"status": "external-signer-required"}
    normalized["release_ready"] = signature_verified
    return normalized


def _load(path: Path) -> Mapping[str, object]:
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_BYTES:
            raise FinalEvidenceError("evidence file is not a bounded regular file")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FinalEvidenceError("evidence file is not valid JSON") from error
    if not isinstance(value, dict):
        raise FinalEvidenceError("evidence root must be an object")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--rule-digest", required=True)
    parser.add_argument("--require-signature", action="store_true")
    parser.add_argument("--trusted-public-key", help="base64-encoded Ed25519 release signer key")
    parser.add_argument("--trusted-key-id", help="expected purpose-specific release signer key ID")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--digest", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        normalized = validate_final_evidence(
            _load(args.evidence),
            expected_version=args.version,
            expected_source_sha=args.source_sha,
            expected_rule_digest=args.rule_digest,
            require_signature=args.require_signature,
            trusted_public_key=(
                _encoded(args.trusted_public_key, label="trusted evidence public key", size=32)
                if args.trusted_public_key is not None
                else None
            ),
            trusted_key_id=(
                _token(args.trusted_key_id, label="trusted evidence signer key ID")
                if args.trusted_key_id is not None
                else None
            ),
        )
    except FinalEvidenceError as error:
        print(f"Final release evidence failed: {error}", file=sys.stderr)
        return 1
    rendered = json.dumps(normalized, indent=2, sort_keys=True) + "\n"
    print(rendered, end="")
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    if args.digest is not None:
        args.digest.parent.mkdir(parents=True, exist_ok=True)
        digest_name = (args.output or args.evidence).name
        digest = hashlib.sha256(rendered.encode()).hexdigest()
        args.digest.write_text(f"{digest}  {digest_name}\n", encoding="ascii")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
