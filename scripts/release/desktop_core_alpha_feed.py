"""Deterministic helpers for the privileged Desktop Core alpha feed workflow."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

BOOTSTRAP_SCHEMA = "guard-desktop-bootstrap.v1"
MANIFEST_SCHEMA = "hol-guard-core-update.v1"
MARKER_SCHEMA = "hol-guard-core-attestation.v2"
SUPPORTED_TRAINS = frozenset({"3.0"})
_ALPHA_TAG = re.compile(r"^alpha/v(3\.(\d+)\.(\d+)a(\d+))$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _decode_minisign_line(value: str, *, label: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise SystemExit(f"Invalid Minisign {label}") from error


def verify_minisign(file_path: Path, signature_path: Path, public_key_value: str) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    public_key_lines = [line.strip() for line in public_key_value.splitlines() if line.strip()]
    public_key = _decode_minisign_line(public_key_lines[-1] if public_key_lines else "", label="public key")
    if len(public_key) != 42 or public_key[:2] != b"Ed":
        raise SystemExit("Invalid Minisign public key")

    signature_lines = signature_path.read_text(encoding="utf-8").splitlines()
    if len(signature_lines) != 4 or not signature_lines[0].startswith("untrusted comment: "):
        raise SystemExit("Invalid Minisign signature envelope")
    if not signature_lines[2].startswith("trusted comment: "):
        raise SystemExit("Invalid Minisign trusted comment")
    signature = _decode_minisign_line(signature_lines[1], label="signature")
    global_signature = _decode_minisign_line(signature_lines[3], label="global signature")
    if len(signature) != 74 or len(global_signature) != 64 or signature[:2] != b"ED":
        raise SystemExit("Invalid Minisign signature")
    if signature[2:10] != public_key[2:10]:
        raise SystemExit("Minisign signature key ID does not match configured public key")

    message = hashlib.blake2b(file_path.read_bytes(), digest_size=64).digest()
    verifier = Ed25519PublicKey.from_public_bytes(public_key[10:])
    try:
        verifier.verify(signature[10:], message)
        trusted_comment = signature_lines[2].removeprefix("trusted comment: ")
        verifier.verify(global_signature, signature + trusted_comment.encode())
    except InvalidSignature as error:
        raise SystemExit("Minisign signature verification failed") from error


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _emit(key: str, value: str | bool) -> None:
    if isinstance(value, bool):
        value = "true" if value else "false"
    print(f"{key}={value}")


def discover_release(tags_file: Path) -> None:
    candidates: list[tuple[tuple[int, int, int], str, str, str]] = []
    for raw in tags_file.read_text(encoding="utf-8").splitlines():
        tag = raw.strip()
        match = _ALPHA_TAG.fullmatch(tag)
        if match is None:
            continue
        train = f"3.{match.group(2)}"
        if train not in SUPPORTED_TRAINS:
            continue
        order = (int(match.group(2)), int(match.group(3)), int(match.group(4)))
        candidates.append((order, match.group(1), tag, train))
    if not candidates:
        _emit("available", False)
        return
    _, version, tag, train = max(candidates)
    _emit("available", True)
    _emit("version", version)
    _emit("tag", tag)
    _emit("train", train)
    _emit("branch", f"release/{train}")


def inspect_assets(assets_file: Path, base: str) -> None:
    names = set(assets_file.read_text(encoding="utf-8").splitlines())
    expected = {
        "binary": base,
        "manifest": f"{base}.json",
        "signature": f"{base}.json.sig",
        "marker": f"{base}.attested.json",
    }
    present = {key for key, name in expected.items() if name in names}
    for key in expected:
        _emit(f"{key}_present", key in present)
    if not present:
        _emit("mode", "build")
    elif present == {"binary", "manifest", "marker"}:
        _emit("mode", "repair_signature")
    elif present == set(expected):
        _emit("mode", "verify_existing")
    else:
        raise SystemExit(f"Refusing partial or ambiguous Core asset set: {sorted(present)}")


def verify_bootstrap(payload_file: Path, version: str, subject: str) -> None:
    payload = json.loads(payload_file.read_text(encoding="utf-8"))
    if payload.get("schema") != BOOTSTRAP_SCHEMA:
        raise SystemExit(f"{subject} does not expose the Desktop bootstrap contract")
    if payload.get("coreVersion") != version:
        raise SystemExit(f"{subject} returned the wrong version")


def _manifest_expected(
    binary: Path,
    *,
    version: str,
    source_commit: str,
    source_tag: str,
    target: str,
    minimum_desktop_version: str,
) -> dict[str, object]:
    return {
        "schema": MANIFEST_SCHEMA,
        "channel": "alpha",
        "version": version,
        "sourceCommit": source_commit,
        "sourceTag": source_tag,
        "target": target,
        "artifact": binary.name,
        "sha256": _sha256(binary),
        "size": binary.stat().st_size,
        "bootstrapSchema": BOOTSTRAP_SCHEMA,
        "minimumDesktopVersion": minimum_desktop_version,
    }


def create_manifest(
    binary: Path,
    manifest: Path,
    *,
    version: str,
    source_commit: str,
    source_tag: str,
    target: str,
    minimum_desktop_version: str,
) -> None:
    payload = _manifest_expected(
        binary,
        version=version,
        source_commit=source_commit,
        source_tag=source_tag,
        target=target,
        minimum_desktop_version=minimum_desktop_version,
    )
    payload["publishedAt"] = _utc_now()
    _write_json(manifest, payload)


def validate_manifest(
    binary: Path,
    manifest: Path,
    *,
    version: str,
    source_commit: str,
    source_tag: str,
    target: str,
    minimum_desktop_version: str,
) -> None:
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    expected = _manifest_expected(
        binary,
        version=version,
        source_commit=source_commit,
        source_tag=source_tag,
        target=target,
        minimum_desktop_version=minimum_desktop_version,
    )
    for key, value in expected.items():
        if payload.get(key) != value:
            raise SystemExit(f"Manifest mismatch for {key}")
    if not isinstance(payload.get("publishedAt"), str) or not payload["publishedAt"]:
        raise SystemExit("Manifest is missing publishedAt")


def _marker_metadata(
    *,
    version: str,
    source_commit: str,
    source_tag: str,
    target: str,
    apple_signing_identity: str,
    apple_team_id: str,
) -> dict[str, str]:
    # These identity values are public signing metadata, not credentials. Existing
    # marker reuse intentionally requires exact equality, so identity/team rotation or
    # reformatting requires rebuilding rather than silently reusing older assets.
    return {
        "schema": MARKER_SCHEMA,
        "version": version,
        "sourceCommit": source_commit,
        "sourceTag": source_tag,
        "target": target,
        "appleSigningIdentity": apple_signing_identity,
        "appleTeamId": apple_team_id,
    }


def create_marker(
    base: Path,
    marker: Path,
    *,
    version: str,
    source_commit: str,
    source_tag: str,
    target: str,
    apple_signing_identity: str,
    apple_team_id: str,
    workflow_run: str,
) -> None:
    manifest = Path(f"{base}.json")
    signature = Path(f"{base}.json.sig")
    payload: dict[str, object] = _marker_metadata(
        version=version,
        source_commit=source_commit,
        source_tag=source_tag,
        target=target,
        apple_signing_identity=apple_signing_identity,
        apple_team_id=apple_team_id,
    )
    payload.update(
        {
            "binarySha256": _sha256(base),
            "manifestSha256": _sha256(manifest),
            "signatureSha256": _sha256(signature),
            "workflowRun": workflow_run,
            "attestedAt": _utc_now(),
        }
    )
    _write_json(marker, payload)


def validate_marker(
    base: Path,
    marker_path: Path,
    *,
    version: str,
    source_commit: str,
    source_tag: str,
    target: str,
    apple_signing_identity: str,
    apple_team_id: str,
    mode: str,
) -> None:
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    expected = _marker_metadata(
        version=version,
        source_commit=source_commit,
        source_tag=source_tag,
        target=target,
        apple_signing_identity=apple_signing_identity,
        apple_team_id=apple_team_id,
    )
    for key, value in expected.items():
        if marker.get(key) != value:
            if key == "schema":
                raise SystemExit(f"Unsupported marker schema: {marker.get(key)!r}")
            raise SystemExit(f"Marker mismatch for {key}")

    hashes = {
        "binarySha256": _sha256(base),
        "manifestSha256": _sha256(Path(f"{base}.json")),
    }
    if mode == "complete":
        hashes["signatureSha256"] = _sha256(Path(f"{base}.json.sig"))
    elif mode == "repair":
        prior_signature_hash = marker.get("signatureSha256")
        if not isinstance(prior_signature_hash, str) or _SHA256.fullmatch(prior_signature_hash) is None:
            raise SystemExit("Repair marker does not contain a valid prior signatureSha256")
    else:
        raise SystemExit(f"Unsupported marker validation mode: {mode}")

    for key, value in hashes.items():
        if marker.get(key) != value:
            raise SystemExit(f"Marker hash mismatch for {key}")


def _asset_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tag", required=True)
    parser.add_argument("--target", required=True)


def _marker_arguments(parser: argparse.ArgumentParser) -> None:
    _asset_arguments(parser)
    parser.add_argument("--marker", type=Path, required=True)
    parser.add_argument("--apple-signing-identity", required=True)
    parser.add_argument("--apple-team-id", required=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    discover = subparsers.add_parser("discover-release")
    discover.add_argument("--tags", type=Path, required=True)

    inspect = subparsers.add_parser("inspect-assets")
    inspect.add_argument("--assets", type=Path, required=True)
    inspect.add_argument("--base", required=True)

    bootstrap = subparsers.add_parser("verify-bootstrap")
    bootstrap.add_argument("--payload", type=Path, required=True)
    bootstrap.add_argument("--version", required=True)
    bootstrap.add_argument("--subject", required=True)

    verify_signature = subparsers.add_parser("verify-minisign")
    verify_signature.add_argument("--file", type=Path, required=True)
    verify_signature.add_argument("--signature", type=Path, required=True)
    verify_signature.add_argument("--public-key", required=True)

    for name in ("create-manifest", "validate-manifest"):
        command = subparsers.add_parser(name)
        _asset_arguments(command)
        command.add_argument("--manifest", type=Path, required=True)
        command.add_argument("--minimum-desktop-version", required=True)

    create_marker_parser = subparsers.add_parser("create-marker")
    _marker_arguments(create_marker_parser)
    create_marker_parser.add_argument("--workflow-run", required=True)

    validate_marker_parser = subparsers.add_parser("validate-marker")
    _marker_arguments(validate_marker_parser)
    validate_marker_parser.add_argument("--mode", choices=("repair", "complete"), required=True)

    args = parser.parse_args()
    if args.command == "discover-release":
        discover_release(args.tags)
    elif args.command == "inspect-assets":
        inspect_assets(args.assets, args.base)
    elif args.command == "verify-bootstrap":
        verify_bootstrap(args.payload, args.version, args.subject)
    elif args.command == "verify-minisign":
        verify_minisign(args.file, args.signature, args.public_key)
    elif args.command in {"create-manifest", "validate-manifest"}:
        kwargs = {
            "version": args.version,
            "source_commit": args.source_commit,
            "source_tag": args.source_tag,
            "target": args.target,
            "minimum_desktop_version": args.minimum_desktop_version,
        }
        if args.command == "create-manifest":
            create_manifest(args.base, args.manifest, **kwargs)
        else:
            validate_manifest(args.base, args.manifest, **kwargs)
    elif args.command in {"create-marker", "validate-marker"}:
        marker_kwargs = {
            "version": args.version,
            "source_commit": args.source_commit,
            "source_tag": args.source_tag,
            "target": args.target,
            "apple_signing_identity": args.apple_signing_identity,
            "apple_team_id": args.apple_team_id,
        }
        if args.command == "create-marker":
            create_marker(args.base, args.marker, workflow_run=args.workflow_run, **marker_kwargs)
        else:
            validate_marker(args.base, args.marker, mode=args.mode, **marker_kwargs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
