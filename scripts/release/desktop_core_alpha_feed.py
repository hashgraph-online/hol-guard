"""Deterministic helpers for the privileged Desktop Core feed workflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import posixpath
import re
import unicodedata
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
_ALPHA_TAG = re.compile(r"^alpha/v(3\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)a[1-9][0-9]*)$")
ALPHA_VERSION = re.compile(r"^3\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)a[1-9][0-9]*$")
STABLE_VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
CHANNELS = ("stable", "alpha")


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


def _require_channel(channel: str) -> str:
    if channel not in CHANNELS:
        raise SystemExit(f"Unsupported Desktop Core release channel: {channel!r}")
    return channel


def validate_request(
    channel: str, event_name: str, version: str, publication_run_id: str, publication_source_sha: str
) -> None:
    """Gate who may ask for a channel. Alpha is explicit dispatch only, never scheduled or backfilled."""
    if _require_channel(channel) == "stable":
        return
    if event_name != "workflow_dispatch":
        raise SystemExit("Alpha Desktop Core sidecars are published only by explicit dispatch")
    if ALPHA_VERSION.fullmatch(version) is None:
        raise SystemExit(f"Alpha Desktop Core requires an exact alpha version, got {version!r}")
    if re.fullmatch(r"[1-9][0-9]*", publication_run_id) is None:
        raise SystemExit("Alpha Desktop Core requires the publication run id")
    if re.fullmatch(r"[0-9a-f]{40}", publication_source_sha) is None:
        raise SystemExit("Alpha Desktop Core requires the full alpha source commit")


def require_prerelease(release_json: Path, tag: str) -> None:
    """Fail without side effects when the alpha prerelease was retracted or converted."""
    try:
        release = json.loads(release_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"Alpha prerelease {tag} is unavailable; it may have been retracted") from error
    if not isinstance(release, dict) or release.get("tagName") != tag:
        raise SystemExit(f"Alpha prerelease {tag} is unavailable; it may have been retracted")
    if release.get("isDraft") is not False or release.get("isPrerelease") is not True:
        raise SystemExit(f"{tag} is not a published prerelease")


def discover_release(tags_file: Path, requested_version: str = "", channel: str = "stable") -> None:
    """Select a Release Please stable tag, or the one exact requested alpha tag."""
    if _require_channel(channel) == "alpha":
        if ALPHA_VERSION.fullmatch(requested_version) is None:
            raise SystemExit("Alpha Desktop Core discovery requires an exact alpha version")
        tags = [raw.strip() for raw in tags_file.read_text(encoding="utf-8").splitlines()]
        if f"alpha/v{requested_version}" not in tags:
            raise SystemExit(f"Requested alpha Core {requested_version} is not an eligible published prerelease")
        major, minor = requested_version.split(".")[:2]
        _emit("available", True)
        _emit("version", requested_version)
        _emit("tag", f"alpha/v{requested_version}")
        _emit("train", f"{major}.{minor}")
        _emit("branch", "main")
        return
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
    binary: Path,
    *,
    version: str,
    source_commit: str,
    source_tag: str,
    target: str,
    minimum_desktop_version: str,
    channel: str = "stable",
) -> dict[str, object]:
    return {
        "schema": MANIFEST_SCHEMA,
        "channel": _require_channel(channel),
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


_ONEDIR_SYMLINK_TARGET_MAX = 1024


def _fold(name: str) -> list[str]:
    return unicodedata.normalize("NFC", name.rstrip("/")).casefold().split("/")


def _check_onedir_zip_symlink(zipped: zipfile.ZipFile, info: zipfile.ZipInfo) -> None:
    """R2: a symlink member's target must be a short relative path that stays in-tree."""
    name = info.filename
    try:
        raw = zipped.read(info)
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise SystemExit(f"Onedir archive symlink target is unreadable: {name!r}") from error
    if not raw or len(raw) > _ONEDIR_SYMLINK_TARGET_MAX or b"\x00" in raw:
        raise SystemExit(f"Onedir archive symlink target is invalid: {name!r}")
    try:
        target = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SystemExit(f"Onedir archive symlink target is not UTF-8: {name!r}") from error
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
    if PurePosixPath(target).is_absolute() or not resolved.startswith(f"{ONEDIR_TREE_ROOT}/"):
        raise SystemExit(f"Onedir archive symlink escapes the tree: {name!r}")


def validate_onedir_zip_members(archive: Path) -> None:
    """Require a sealed, self-contained onedir zip before a manifest may bind it."""
    try:
        with zipfile.ZipFile(archive) as zipped:
            names: set[str] = set()
            link_names: list[str] = []
            for info in zipped.infolist():
                name = info.filename
                member = PurePosixPath(name)
                if member.is_absolute() or ".." in member.parts:
                    raise SystemExit(f"Onedir archive member escapes the tree: {name!r}")
                # PurePosixPath folds "." and empty components away; check the raw
                # split so a "./" detour cannot dodge the nested-under-link rule.
                raw_parts = name.split("/")
                if "." in raw_parts or "" in raw_parts[:-1]:
                    raise SystemExit(f"Onedir archive member has a malformed path: {name!r}")
                if name != ONEDIR_TREE_ROOT and not name.startswith(f"{ONEDIR_TREE_ROOT}/"):
                    raise SystemExit(f"Onedir archive member is outside {ONEDIR_TREE_ROOT}/: {name!r}")
                if member.name.startswith("._") or "__MACOSX" in member.parts:
                    raise SystemExit(f"Onedir archive member is AppleDouble metadata: {name!r}")
                if (info.external_attr >> 16) & 0o170000 == 0o120000:
                    _check_onedir_zip_symlink(zipped, info)
                    link_names.append(name)
                names.add(name)
    except (OSError, zipfile.BadZipFile) as error:
        raise SystemExit(f"Onedir archive is not a readable zip: {archive}") from error
    folded = [tuple(_fold(name)) for name in names]
    if len(set(folded)) != len(folded):
        raise SystemExit("Onedir archive contains colliding members")
    # R3: nothing may sit beneath a symlink member, so extraction can never
    # write through a link.
    link_parts = [_fold(name) for name in link_names]
    for name in names:
        parts = _fold(name)
        if any(len(link) < len(parts) and parts[: len(link)] == link for link in link_parts):
            raise SystemExit(f"Onedir archive member is nested under a symlink: {name!r}")
    required = (
        ONEDIR_LAUNCHER,
        f"{ONEDIR_TREE_ROOT}/Info.plist",
        f"{ONEDIR_TREE_ROOT}/_CodeSignature/CodeResources",
    )
    # R4: the sealed-bundle anchors must be regular files, never links.
    for entry in required:
        if entry not in names or entry in link_names:
            raise SystemExit(f"Onedir archive is missing required member: {entry}")
    if not any(name.startswith(f"{ONEDIR_TREE_ROOT}/_internal/") for name in names):
        raise SystemExit(f"Onedir archive is missing required member: {ONEDIR_TREE_ROOT}/_internal/")


def _onedir_file_count(tree: Path) -> int:
    """R5: non-directory entries under hol-guard/, counting a link once whatever its target."""
    root = tree / "hol-guard"
    if not root.is_dir():
        raise SystemExit(f"Onedir tree root is missing: {root}")
    return sum(1 for entry in root.rglob("*") if entry.is_symlink() or entry.is_file())


def _onedir_manifest_expected(
    archive: Path,
    tree: Path,
    *,
    version: str,
    source_commit: str,
    source_tag: str,
    target: str,
    minimum_desktop_version: str,
    channel: str = "stable",
) -> dict[str, object]:
    return {
        "schema": ONEDIR_MANIFEST_SCHEMA,
        "channel": _require_channel(channel),
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
    discover.add_argument("--channel", choices=CHANNELS, default="stable")
    request = subparsers.add_parser("validate-request")
    request.add_argument("--channel", required=True)
    request.add_argument("--event-name", required=True)
    request.add_argument("--version", default="")
    request.add_argument("--publication-run-id", default="")
    request.add_argument("--publication-source-sha", default="")
    prerelease = subparsers.add_parser("require-prerelease")
    prerelease.add_argument("--release-json", type=Path, required=True)
    prerelease.add_argument("--tag", required=True)
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
        command.add_argument("--channel", choices=CHANNELS, default="stable")
    for name in ("create-onedir-manifest", "validate-onedir-manifest"):
        command = subparsers.add_parser(name)
        command.add_argument("--archive", type=Path, required=True)
        command.add_argument("--tree", type=Path, required=True)
        _release_identity_arguments(command)
        command.add_argument("--manifest", type=Path, required=True)
        command.add_argument("--minimum-desktop-version", required=True)
        command.add_argument("--channel", choices=CHANNELS, default="stable")
    create_marker_parser = subparsers.add_parser("create-marker")
    _marker_arguments(create_marker_parser)
    create_marker_parser.add_argument("--workflow-run", required=True)
    validate_marker_parser = subparsers.add_parser("validate-marker")
    _marker_arguments(validate_marker_parser)
    args = parser.parse_args()
    if args.command == "discover-release":
        discover_release(args.tags, args.version, args.channel)
    elif args.command == "validate-request":
        validate_request(
            args.channel, args.event_name, args.version, args.publication_run_id, args.publication_source_sha
        )
    elif args.command == "require-prerelease":
        require_prerelease(args.release_json, args.tag)
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
            "channel": args.channel,
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
            "channel": args.channel,
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
