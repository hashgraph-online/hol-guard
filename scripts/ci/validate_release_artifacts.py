#!/usr/bin/env python3
"""Validate package-bound native release artifacts and their provenance.

The validator is intentionally local and offline.  It never discovers a
runtime through ``PATH`` and never downloads an artifact.  It emits only
artifact names, hashes, platform labels, and bounded release metadata.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
import zipfile
from collections.abc import Mapping, Sequence
from pathlib import Path

from packaging.tags import Tag
from packaging.utils import InvalidWheelFilename, parse_wheel_filename
from packaging.version import InvalidVersion, Version

EXPECTED_PLATFORMS: Mapping[str, str] = {
    "manylinux_2_17_x86_64": "x86_64-unknown-linux-musl",
    "macosx_13_0_x86_64": "x86_64-apple-darwin",
    "macosx_11_0_arm64": "aarch64-apple-darwin",
    "win_amd64": "x86_64-pc-windows-msvc",
}
NON_WINDOWS_PLATFORMS = frozenset(set(EXPECTED_PLATFORMS) - {"win_amd64"})
WINDOWS_PLATFORM = "win_amd64"
MANIFEST_PATH = "codex_plugin_scanner/_native/runtime-manifest.json"
RUNTIME_PATH = "codex_plugin_scanner/_native/hol-guard-runtime"
WINDOWS_RUNTIME_PATH = f"{RUNTIME_PATH}.exe"
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_WHEEL_BYTES = 256 * 1024 * 1024
_MAX_RUNTIME_BYTES = 128 * 1024 * 1024
_MAX_MANIFEST_BYTES = 64 * 1024
_MAX_ARCHIVE_ENTRIES = 16_384
_MAX_ARCHIVE_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
_SAFE_WAIVER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,159}\Z")


class ReleaseArtifactError(ValueError):
    """Raised when a release artifact is not safe to publish."""


def sha256_file(path: Path) -> str:
    """Return a file digest without retaining the file in memory."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_version(value: str) -> str:
    try:
        parsed = Version(value)
    except InvalidVersion as error:
        raise ReleaseArtifactError("release version is invalid") from error
    if value != str(parsed) or parsed.local is not None:
        raise ReleaseArtifactError("release version must be canonical")
    return value


def _regular_file(path: Path, *, label: str, maximum: int) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ReleaseArtifactError(f"{label} is missing") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size <= 0
        or metadata.st_size > maximum
    ):
        raise ReleaseArtifactError(f"{label} is not a bounded regular file")


def _parse_wheel(path: Path, version: str) -> tuple[str, Tag]:
    _regular_file(path, label=f"wheel {path.name}", maximum=_MAX_WHEEL_BYTES)
    try:
        name, wheel_version, build, tags = parse_wheel_filename(path.name)
    except InvalidWheelFilename as error:
        raise ReleaseArtifactError(f"invalid wheel filename: {path.name}") from error
    if str(wheel_version) != version or build or len(tags) != 1:
        raise ReleaseArtifactError(f"wheel identity does not match {version}: {path.name}")
    tag = next(iter(tags))
    _validate_wheel_metadata(path, name=name, version=version, tag=tag)
    return name, tag


def _validate_wheel_metadata(path: Path, *, name: str, version: str, tag: Tag) -> None:
    """Bind the wheel filename to its package metadata and wheel tag."""

    try:
        with zipfile.ZipFile(path) as archive:
            _validate_archive(archive)
            metadata_names = [
                item.filename for item in archive.infolist() if item.filename.endswith(".dist-info/METADATA")
            ]
            wheel_names = [item.filename for item in archive.infolist() if item.filename.endswith(".dist-info/WHEEL")]
            if len(metadata_names) != 1 or len(wheel_names) != 1:
                raise ReleaseArtifactError(f"wheel metadata is incomplete: {path.name}")
            metadata = _read_zip_member(archive, metadata_names[0], _MAX_MANIFEST_BYTES).decode("utf-8")
            wheel = _read_zip_member(archive, wheel_names[0], _MAX_MANIFEST_BYTES).decode("utf-8")
    except (OSError, UnicodeDecodeError, zipfile.BadZipFile) as error:
        raise ReleaseArtifactError(f"wheel metadata could not be read: {path.name}") from error
    fields = {line.split(":", 1)[0]: line.split(":", 1)[1].strip() for line in metadata.splitlines() if ":" in line}
    if fields.get("Name", "").replace("-", "_").lower() != name.replace("-", "_").lower():
        raise ReleaseArtifactError(f"wheel metadata package name mismatch: {path.name}")
    if fields.get("Version") != version:
        raise ReleaseArtifactError(f"wheel metadata version mismatch: {path.name}")
    expected_tag = f"Tag: {tag.interpreter}-{tag.abi}-{tag.platform}"
    if expected_tag not in wheel.splitlines():
        raise ReleaseArtifactError(f"wheel metadata tag mismatch: {path.name}")


def _read_zip_member(archive: zipfile.ZipFile, name: str, maximum: int) -> bytes:
    try:
        info = archive.getinfo(name)
    except KeyError as error:
        raise ReleaseArtifactError(f"wheel is missing {name}") from error
    mode = (info.external_attr >> 16) & 0o170000
    if mode == stat.S_IFLNK or info.is_dir() or info.flag_bits & 0x1:
        raise ReleaseArtifactError(f"wheel member is not a regular file: {name}")
    if info.file_size <= 0 or info.file_size > maximum:
        raise ReleaseArtifactError(f"wheel member exceeds its bound: {name}")
    payload = archive.read(info)
    if len(payload) != info.file_size or len(payload) > maximum:
        raise ReleaseArtifactError(f"wheel member is truncated: {name}")
    return payload


def _validate_archive(archive: zipfile.ZipFile) -> None:
    """Reject traversal, duplicate, encrypted, symlink, and zip-bomb entries."""

    infos = archive.infolist()
    if len(infos) > _MAX_ARCHIVE_ENTRIES:
        raise ReleaseArtifactError("wheel contains too many archive entries")
    names: set[str] = set()
    total_size = 0
    for info in infos:
        name = info.filename
        normalized = name.replace("\\", "/")
        parts = normalized.split("/")
        if not name or "\\" in name or "\x00" in name or normalized.startswith("/") or ".." in parts or name in names:
            raise ReleaseArtifactError(f"wheel contains an unsafe archive entry: {name!r}")
        names.add(name)
        if info.is_dir():
            continue
        mode = (info.external_attr >> 16) & 0o170000
        if mode == stat.S_IFLNK or info.flag_bits & 0x1:
            raise ReleaseArtifactError(f"wheel member is not a regular file: {name}")
        if info.file_size < 0 or info.file_size > _MAX_WHEEL_BYTES:
            raise ReleaseArtifactError(f"wheel member exceeds its bound: {name}")
        total_size += info.file_size
        if total_size > _MAX_ARCHIVE_UNCOMPRESSED_BYTES:
            raise ReleaseArtifactError("wheel uncompressed size exceeds its bound")


def _native_manifest(wheel: Path, platform: str, version: str, source_sha: str, rule_digest: str) -> None:
    runtime_name = WINDOWS_RUNTIME_PATH if platform == WINDOWS_PLATFORM else RUNTIME_PATH
    try:
        with zipfile.ZipFile(wheel) as archive:
            _validate_archive(archive)
            manifest_bytes = _read_zip_member(archive, MANIFEST_PATH, _MAX_MANIFEST_BYTES)
            runtime = _read_zip_member(archive, runtime_name, _MAX_RUNTIME_BYTES)
    except (OSError, zipfile.BadZipFile) as error:
        raise ReleaseArtifactError(f"wheel could not be read: {wheel.name}") from error
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseArtifactError("native runtime manifest is invalid JSON") from error
    expected_keys = {
        "schema",
        "protocol_version",
        "package_version",
        "target",
        "platform_tag",
        "source_sha",
        "rule_digest",
        "runtime_sha256",
        "runtime_size",
    }
    if not isinstance(manifest, dict) or set(manifest) != expected_keys:
        raise ReleaseArtifactError("native runtime manifest has an unexpected shape")
    if (
        manifest["schema"] != "hol-guard-native-runtime.v1"
        or manifest["protocol_version"] != 1
        or manifest["package_version"] != version
        or manifest["target"] != EXPECTED_PLATFORMS[platform]
        or manifest["platform_tag"] != platform
        or manifest["source_sha"] != source_sha
        or manifest["rule_digest"] != rule_digest
        or manifest["runtime_size"] != len(runtime)
        or manifest["runtime_sha256"] != hashlib.sha256(runtime).hexdigest()
    ):
        raise ReleaseArtifactError(f"native runtime manifest identity mismatch: {wheel.name}")


def _validate_pure_wheel(path: Path, version: str) -> None:
    name, tag = _parse_wheel(path, version)
    if name.replace("-", "_") != "hol_guard" or tag != Tag("py3", "none", "any"):
        raise ReleaseArtifactError(f"unexpected pure Guard wheel: {path.name}")


def validate_wheel_set(
    dist_dir: Path,
    *,
    version: str,
    source_sha: str,
    rule_digest: str,
    platforms: Sequence[str] = tuple(sorted(NON_WINDOWS_PLATFORMS)),
    windows_waiver: str | None = None,
) -> dict[str, object]:
    """Validate the requested native wheel matrix and return safe evidence."""

    version = _canonical_version(version)
    if _SHA40.fullmatch(source_sha) is None or _SHA64.fullmatch(rule_digest) is None:
        raise ReleaseArtifactError("source SHA and rule digest must be lowercase hexadecimal")
    requested = frozenset(platforms)
    if not requested or not requested <= set(EXPECTED_PLATFORMS):
        raise ReleaseArtifactError("wheel platform set contains an unsupported target")
    if len(platforms) != len(requested):
        raise ReleaseArtifactError("wheel platform set contains duplicate targets")
    if windows_waiver is not None and (
        _SAFE_WAIVER.fullmatch(windows_waiver) is None
        or any(fragment in windows_waiver for fragment in ("/Users/", "/home/", "/tmp/", "\\", "~/", "-----BEGIN"))
    ):
        raise ReleaseArtifactError("Windows waiver is not bounded release text")
    if WINDOWS_PLATFORM not in requested and not windows_waiver:
        raise ReleaseArtifactError("Windows wheel omission requires an explicit waiver")
    if WINDOWS_PLATFORM in requested and windows_waiver:
        raise ReleaseArtifactError("Windows waiver cannot accompany a validated Windows wheel")
    if not requested & NON_WINDOWS_PLATFORMS and WINDOWS_PLATFORM not in requested:
        raise ReleaseArtifactError("at least one non-Windows wheel is required")
    if not dist_dir.is_dir() or dist_dir.is_symlink():
        raise ReleaseArtifactError("distribution directory is not a regular directory")

    pure_name = f"hol_guard-{version.replace('-', '_')}-py3-none-any.whl"
    pure = dist_dir / pure_name
    _validate_pure_wheel(pure, version)
    records: list[dict[str, object]] = [
        {"name": pure.name, "role": "python-wheel", "sha256": sha256_file(pure), "size": pure.stat().st_size}
    ]
    seen: set[str] = set()
    for wheel in sorted(dist_dir.glob("*.whl")):
        if wheel.name == pure_name:
            continue
        name, tag = _parse_wheel(wheel, version)
        if tag.platform == "any":
            raise ReleaseArtifactError(f"unexpected pure wheel: {wheel.name}")
        if name.replace("-", "_") != "hol_guard" or tag.platform not in requested:
            raise ReleaseArtifactError(f"unexpected native wheel: {wheel.name}")
        if tag.platform in seen or tag.interpreter != "py3" or tag.abi != "none":
            raise ReleaseArtifactError(f"duplicate or unsupported native wheel: {wheel.name}")
        _native_manifest(wheel, tag.platform, version, source_sha, rule_digest)
        seen.add(tag.platform)
        records.append(
            {
                "name": wheel.name,
                "role": "native-wheel",
                "platform": tag.platform,
                "target": EXPECTED_PLATFORMS[tag.platform],
                "sha256": sha256_file(wheel),
                "size": wheel.stat().st_size,
            }
        )
    if seen != requested:
        raise ReleaseArtifactError(f"native wheel matrix is incomplete: missing={sorted(requested - seen)}")
    return {
        "schema": "hol-guard-release-artifact-evidence.v1",
        "package_version": version,
        "source_sha": source_sha,
        "rule_digest": rule_digest,
        "platforms": sorted(requested),
        "windows_waiver": windows_waiver,
        "artifacts": records,
    }


def _load_object(path: Path, *, label: str) -> object:
    _regular_file(path, label=label, maximum=16 * 1024 * 1024)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseArtifactError(f"{label} is not valid JSON") from error


def validate_identity(path: Path, *, version: str, source_sha: str, rule_digest: str) -> dict[str, object]:
    value = _load_object(path, label="policy identity")
    if not isinstance(value, dict):
        raise ReleaseArtifactError("policy identity must be an object")
    if any(
        value.get(key) != expected
        for key, expected in {
            "package_version": version,
            "source_sha": source_sha,
            "rule_digest": rule_digest,
        }.items()
    ):
        raise ReleaseArtifactError("policy identity does not match the release")
    policy_digest = value.get("policy_digest")
    if not isinstance(policy_digest, str) or _SHA64.fullmatch(policy_digest) is None:
        raise ReleaseArtifactError("policy identity requires a lowercase policy digest")
    return {"name": path.name, "sha256": sha256_file(path), "policy_digest": policy_digest}


def validate_sbom(path: Path, *, version: str) -> dict[str, object]:
    value = _load_object(path, label="SBOM")
    if not isinstance(value, dict):
        raise ReleaseArtifactError("SBOM must be an object")
    cyclonedx = value.get("bomFormat") == "CycloneDX" and isinstance(value.get("components"), list)
    spdx = isinstance(value.get("spdxVersion"), str) and isinstance(value.get("packages"), list)
    if not (cyclonedx or spdx):
        raise ReleaseArtifactError("SBOM must be CycloneDX or SPDX with a package list")
    metadata = value.get("metadata")
    if cyclonedx and isinstance(metadata, dict):
        component = metadata.get("component")
        if isinstance(component, dict) and component.get("version") not in {None, version}:
            raise ReleaseArtifactError("SBOM component version does not match the release")
    return {"name": path.name, "sha256": sha256_file(path), "format": "CycloneDX" if cyclonedx else "SPDX"}


def validate_provenance(path: Path) -> dict[str, object]:
    _regular_file(path, label="provenance bundle", maximum=64 * 1024 * 1024)
    try:
        rendered = path.read_text(encoding="utf-8")
        try:
            decoded = json.loads(rendered)
        except json.JSONDecodeError:
            lines = [line for line in rendered.splitlines() if line.strip()]
            records = [json.loads(line) for line in lines]
        else:
            records = decoded if isinstance(decoded, list) else [decoded]
    except (OSError, UnicodeDecodeError, IndexError, json.JSONDecodeError) as error:
        raise ReleaseArtifactError("provenance bundle is not valid JSON or JSONL") from error
    if not records or not all(isinstance(record, dict) for record in records):
        raise ReleaseArtifactError("provenance bundle has no attestation records")
    if not any("subject" in record or "predicateType" in record or "predicate" in record for record in records):
        raise ReleaseArtifactError("provenance bundle has no attestation subject")
    return {"name": path.name, "sha256": sha256_file(path), "records": len(records)}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--rule-digest", required=True)
    parser.add_argument("--platform", action="append")
    parser.add_argument("--windows-waiver")
    parser.add_argument("--policy-identity", type=Path)
    parser.add_argument("--sbom", type=Path)
    parser.add_argument("--provenance", type=Path)
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        evidence = validate_wheel_set(
            args.dist_dir,
            version=args.version,
            source_sha=args.source_sha,
            rule_digest=args.rule_digest,
            platforms=args.platform or tuple(sorted(NON_WINDOWS_PLATFORMS)),
            windows_waiver=args.windows_waiver,
        )
        if args.policy_identity is not None:
            evidence["policy_identity"] = validate_identity(
                args.policy_identity,
                version=args.version,
                source_sha=args.source_sha,
                rule_digest=args.rule_digest,
            )
        if args.sbom is not None:
            evidence["sbom"] = validate_sbom(args.sbom, version=args.version)
        if args.provenance is not None:
            evidence["provenance"] = validate_provenance(args.provenance)
    except ReleaseArtifactError as error:
        print(f"Release artifact validation failed: {error}", file=sys.stderr)
        return 1
    rendered = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    print(rendered, end="")
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
