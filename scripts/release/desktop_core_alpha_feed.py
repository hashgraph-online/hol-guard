"""Deterministic helpers for the privileged Desktop Core feed workflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

BOOTSTRAP_SCHEMA = "guard-desktop-bootstrap.v1"
MANIFEST_SCHEMA = "hol-guard-core-update.v1"
ONEDIR_MANIFEST_SCHEMA = "hol-guard-core-update.v2"
ONEDIR_FORMAT = "onedir-zip"
ONEDIR_TREE_ROOT = "hol-guard"
ONEDIR_LAUNCHER = f"{ONEDIR_TREE_ROOT}/hol-guard"
MARKER_SCHEMA = "hol-guard-core-attestation.v3"
_STABLE_TAG = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, payload: Mapping[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _emit(key: str, value: str | bool) -> None:
    if isinstance(value, bool):
        value = "true" if value else "false"
    print(f"{key}={value}")


def discover_release(tags_file: Path, requested_version: str = "") -> None:
    """Select a Release Please stable tag. The version is not pinned."""
    candidates: list[tuple[tuple[int, int, int], str, str, str]] = []
    for raw in tags_file.read_text(encoding="utf-8").splitlines():
        tag = raw.strip()
        match = _STABLE_TAG.fullmatch(tag)
        if match is None:
            continue
        major, minor, patch = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
        version = f"{major}.{minor}.{patch}"
        train = f"{major}.{minor}"
        candidates.append(((major, minor, patch), version, tag, train))
    if requested_version:
        requested = [candidate for candidate in candidates if candidate[1] == requested_version]
        if not requested:
            raise SystemExit(f"Requested stable Core {requested_version} is not an eligible published release")
        candidates = requested
    if not candidates:
        _emit("available", False)
        return
    _, version, tag, train = max(candidates)
    _emit("available", True)
    _emit("version", version)
    _emit("tag", tag)
    _emit("train", train)
    _emit("branch", "main")


def inspect_assets(assets_file: Path, base: str) -> None:
    """Reuse a complete published Core set. Native bundling is build-only.

    Existing GitHub Core assets are immutable. A complete set is verified as-is
    and is not rebuilt, so the native runtime verifier runs only on new builds.
    """
    names = set(assets_file.read_text(encoding="utf-8").splitlines())
    legacy = {base, f"{base}.json", f"{base}.attested.json"}
    onedir = {f"{base}.onedir.zip", f"{base}.onedir.json", f"{base}.onedir.attested.json"}
    present = (legacy | onedir) & names
    if not present:
        _emit("mode", "build")
        _emit("onedir", True)
    elif present == legacy:
        _emit("mode", "verify_existing")
        _emit("onedir", False)
    elif present == legacy | onedir:
        _emit("mode", "verify_existing")
        _emit("onedir", True)
    else:
        raise SystemExit(f"Refusing partial or ambiguous Core asset set: {sorted(present)}")


def verify_bootstrap(payload_file: Path, version: str, subject: str) -> None:
    payload = json.loads(payload_file.read_text(encoding="utf-8"))
    if payload.get("schema") != BOOTSTRAP_SCHEMA:
        raise SystemExit(f"{subject} does not expose the Desktop bootstrap contract")
    if payload.get("coreVersion") != version:
        raise SystemExit(f"{subject} returned the wrong version")


def _manifest_expected(
    binary: Path, *, version: str, source_commit: str, source_tag: str, target: str, minimum_desktop_version: str
) -> dict[str, object]:
    return {
        "schema": MANIFEST_SCHEMA,
        "channel": "stable",
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


def create_manifest(binary: Path, manifest: Path, **kwargs: str) -> None:
    payload = _manifest_expected(binary, **kwargs)
    payload["publishedAt"] = _utc_now()
    _write_json(manifest, payload)


def validate_manifest(binary: Path, manifest: Path, **kwargs: str) -> None:
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    for key, value in _manifest_expected(binary, **kwargs).items():
        if payload.get(key) != value:
            raise SystemExit(f"Manifest mismatch for {key}")
    if not isinstance(payload.get("publishedAt"), str) or not payload["publishedAt"]:
        raise SystemExit("Manifest is missing publishedAt")


def _onedir_launcher_path(tree: Path) -> Path:
    launcher = tree / ONEDIR_LAUNCHER
    if not launcher.is_file():
        raise SystemExit(f"Onedir tree is missing its launcher: {launcher}")
    return launcher


def validate_onedir_zip_members(archive: Path) -> None:
    """Require a sealed, self-contained onedir zip before a manifest may bind it."""
    try:
        with zipfile.ZipFile(archive) as zipped:
            infos = zipped.infolist()
    except (OSError, zipfile.BadZipFile) as error:
        raise SystemExit(f"Onedir archive is not a readable zip: {archive}") from error
    names: set[str] = set()
    for info in infos:
        name = info.filename
        member = PurePosixPath(name)
        if member.is_absolute() or ".." in member.parts:
            raise SystemExit(f"Onedir archive member escapes the tree: {name!r}")
        if name != ONEDIR_TREE_ROOT and not name.startswith(f"{ONEDIR_TREE_ROOT}/"):
            raise SystemExit(f"Onedir archive member is outside {ONEDIR_TREE_ROOT}/: {name!r}")
        if (info.external_attr >> 16) & 0o170000 == 0o120000:
            raise SystemExit(f"Onedir archive member is a symlink: {name!r}")
        if member.name.startswith("._") or "__MACOSX" in member.parts:
            raise SystemExit(f"Onedir archive member is AppleDouble metadata: {name!r}")
        names.add(name)
    required = (
        ONEDIR_LAUNCHER,
        f"{ONEDIR_TREE_ROOT}/Info.plist",
        f"{ONEDIR_TREE_ROOT}/_CodeSignature/CodeResources",
    )
    for entry in required:
        if entry not in names:
            raise SystemExit(f"Onedir archive is missing required member: {entry}")
    if not any(name.startswith(f"{ONEDIR_TREE_ROOT}/_internal/") for name in names):
        raise SystemExit(f"Onedir archive is missing required member: {ONEDIR_TREE_ROOT}/_internal/")


def _onedir_file_count(tree: Path) -> int:
    root = tree / "hol-guard"
    if not root.is_dir():
        raise SystemExit(f"Onedir tree root is missing: {root}")
    return sum(1 for entry in root.rglob("*") if entry.is_file())


def _onedir_manifest_expected(
    archive: Path,
    tree: Path,
    *,
    version: str,
    source_commit: str,
    source_tag: str,
    target: str,
    minimum_desktop_version: str,
) -> dict[str, object]:
    return {
        "schema": ONEDIR_MANIFEST_SCHEMA,
        "channel": "stable",
        "version": version,
        "sourceCommit": source_commit,
        "sourceTag": source_tag,
        "target": target,
        "format": ONEDIR_FORMAT,
        "artifact": archive.name,
        "sha256": _sha256(archive),
        "size": archive.stat().st_size,
        "launcher": ONEDIR_LAUNCHER,
        "launcherSha256": _sha256(_onedir_launcher_path(tree)),
        "fileCount": _onedir_file_count(tree),
        "bootstrapSchema": BOOTSTRAP_SCHEMA,
        "minimumDesktopVersion": minimum_desktop_version,
    }


def create_onedir_manifest(archive: Path, tree: Path, manifest: Path, **kwargs: str) -> None:
    validate_onedir_zip_members(archive)
    payload = _onedir_manifest_expected(archive, tree, **kwargs)
    payload["publishedAt"] = _utc_now()
    _write_json(manifest, payload)


def validate_onedir_manifest(archive: Path, tree: Path, manifest: Path, **kwargs: str) -> None:
    validate_onedir_zip_members(archive)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    for key, value in _onedir_manifest_expected(archive, tree, **kwargs).items():
        if payload.get(key) != value:
            raise SystemExit(f"Onedir manifest mismatch for {key}")
    if not isinstance(payload.get("publishedAt"), str) or not payload["publishedAt"]:
        raise SystemExit("Onedir manifest is missing publishedAt")


_LINUX_SIDECAR_TARGET = "x86_64-unknown-linux-gnu"


def _marker_metadata(
    *, version: str, source_commit: str, source_tag: str, target: str, apple_signing_identity: str, apple_team_id: str
) -> dict[str, str]:
    if target == _LINUX_SIDECAR_TARGET:
        if apple_signing_identity or apple_team_id:
            raise SystemExit("Linux Desktop Core marker must not include Apple identity")
    elif not apple_signing_identity.strip() or not apple_team_id.strip():
        raise SystemExit("Apple identity is required for this Desktop Core target")
    return {
        "schema": MARKER_SCHEMA,
        "version": version,
        "sourceCommit": source_commit,
        "sourceTag": source_tag,
        "target": target,
        "appleSigningIdentity": apple_signing_identity,
        "appleTeamId": apple_team_id,
    }


def _marker_subject_paths(base: Path, base_suffix: str) -> tuple[Path, Path]:
    if base_suffix:
        return Path(f"{base}{base_suffix}.zip"), Path(f"{base}{base_suffix}.json")
    return base, Path(f"{base}.json")


def create_marker(base: Path, marker: Path, *, workflow_run: str, base_suffix: str = "", **kwargs: str) -> None:
    subject, subject_manifest = _marker_subject_paths(base, base_suffix)
    payload = dict(_marker_metadata(**kwargs))
    payload.update(
        {
            "binarySha256": _sha256(subject),
            "manifestSha256": _sha256(subject_manifest),
            "workflowRun": workflow_run,
            "attestedAt": _utc_now(),
        }
    )
    _write_json(marker, payload)


def validate_marker(base: Path, marker_path: Path, *, base_suffix: str = "", **kwargs: str) -> None:
    subject, subject_manifest = _marker_subject_paths(base, base_suffix)
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    for key, value in _marker_metadata(**kwargs).items():
        if marker.get(key) != value:
            if key == "schema":
                raise SystemExit(f"Unsupported marker schema: {marker.get(key)!r}")
            raise SystemExit(f"Marker mismatch for {key}")
    expected_hashes = {"binarySha256": _sha256(subject), "manifestSha256": _sha256(subject_manifest)}
    for key, value in expected_hashes.items():
        if marker.get(key) != value:
            raise SystemExit(f"Marker hash mismatch for {key}")


def _asset_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tag", required=True)
    parser.add_argument("--target", required=True)


def _release_identity_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tag", required=True)
    parser.add_argument("--target", required=True)


def _marker_arguments(parser: argparse.ArgumentParser) -> None:
    _asset_arguments(parser)
    parser.add_argument("--marker", type=Path, required=True)
    parser.add_argument("--apple-signing-identity", required=True)
    parser.add_argument("--apple-team-id", required=True)
    parser.add_argument(
        "--base-suffix",
        default="",
        help="subject suffix: with '.onedir' the marker binds <base>.onedir.zip and <base>.onedir.json",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    discover = subparsers.add_parser("discover-release")
    discover.add_argument("--tags", type=Path, required=True)
    discover.add_argument("--version", default="")
    inspect = subparsers.add_parser("inspect-assets")
    inspect.add_argument("--assets", type=Path, required=True)
    inspect.add_argument("--base", required=True)
    bootstrap = subparsers.add_parser("verify-bootstrap")
    bootstrap.add_argument("--payload", type=Path, required=True)
    bootstrap.add_argument("--version", required=True)
    bootstrap.add_argument("--subject", required=True)
    for name in ("create-manifest", "validate-manifest"):
        command = subparsers.add_parser(name)
        _asset_arguments(command)
        command.add_argument("--manifest", type=Path, required=True)
        command.add_argument("--minimum-desktop-version", required=True)
    for name in ("create-onedir-manifest", "validate-onedir-manifest"):
        command = subparsers.add_parser(name)
        command.add_argument("--archive", type=Path, required=True)
        command.add_argument("--tree", type=Path, required=True)
        _release_identity_arguments(command)
        command.add_argument("--manifest", type=Path, required=True)
        command.add_argument("--minimum-desktop-version", required=True)
    create_marker_parser = subparsers.add_parser("create-marker")
    _marker_arguments(create_marker_parser)
    create_marker_parser.add_argument("--workflow-run", required=True)
    validate_marker_parser = subparsers.add_parser("validate-marker")
    _marker_arguments(validate_marker_parser)
    args = parser.parse_args()
    if args.command == "discover-release":
        discover_release(args.tags, args.version)
    elif args.command == "inspect-assets":
        inspect_assets(args.assets, args.base)
    elif args.command == "verify-bootstrap":
        verify_bootstrap(args.payload, args.version, args.subject)
    elif args.command in {"create-manifest", "validate-manifest"}:
        kwargs = {
            "version": args.version,
            "source_commit": args.source_commit,
            "source_tag": args.source_tag,
            "target": args.target,
            "minimum_desktop_version": args.minimum_desktop_version,
        }
        (create_manifest if args.command == "create-manifest" else validate_manifest)(
            args.base, args.manifest, **kwargs
        )
    elif args.command in {"create-onedir-manifest", "validate-onedir-manifest"}:
        kwargs = {
            "version": args.version,
            "source_commit": args.source_commit,
            "source_tag": args.source_tag,
            "target": args.target,
            "minimum_desktop_version": args.minimum_desktop_version,
        }
        (create_onedir_manifest if args.command == "create-onedir-manifest" else validate_onedir_manifest)(
            args.archive, args.tree, args.manifest, **kwargs
        )
    elif args.command in {"create-marker", "validate-marker"}:
        kwargs = {
            "version": args.version,
            "source_commit": args.source_commit,
            "source_tag": args.source_tag,
            "target": args.target,
            "apple_signing_identity": args.apple_signing_identity,
            "apple_team_id": args.apple_team_id,
        }
        if args.command == "create-marker":
            create_marker(
                args.base, args.marker, workflow_run=args.workflow_run, base_suffix=args.base_suffix, **kwargs
            )
        else:
            validate_marker(args.base, args.marker, base_suffix=args.base_suffix, **kwargs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
