#!/usr/bin/env python3
"""Stage the attested platform-wheel native runtime for Desktop Core PyInstaller."""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import zipfile
from pathlib import Path, PurePosixPath

_NATIVE_DIR = "codex_plugin_scanner/_native"
_RUNTIME_NAMES = ("hol-guard-runtime", "hol-guard-runtime.exe")
_MANIFEST_NAME = "runtime-manifest.json"
_MANIFEST_SCHEMA = "hol-guard-native-runtime.v1"
_PROTOCOL_VERSION = 1
_MAX_WHEEL_BYTES = 256 * 1024 * 1024
_MAX_RUNTIME_BYTES = 128 * 1024 * 1024
_MAX_MANIFEST_BYTES = 16 * 1024
_SHA40 = 40
_SHA64 = 64


class NativeRuntimeStageError(ValueError):
    """Raised when the attested wheel cannot supply a sealed native runtime."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _is_lower_hex(value: object, length: int) -> bool:
    return (
        isinstance(value, str) and len(value) == length and all(character in "0123456789abcdef" for character in value)
    )


def _safe_member_name(name: str) -> PurePosixPath:
    if not name or "\\" in name or "\x00" in name:
        raise NativeRuntimeStageError(f"unsafe native wheel member: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or any(part in {"", "."} for part in path.parts):
        raise NativeRuntimeStageError(f"unsafe native wheel member: {name!r}")
    return path


def _zip_info(archive: zipfile.ZipFile, name: str) -> zipfile.ZipInfo:
    try:
        info = archive.getinfo(name)
    except KeyError as error:
        raise NativeRuntimeStageError(f"native wheel is missing {name}") from error
    unix_mode = (info.external_attr >> 16) & 0o170000
    if unix_mode == 0o120000:
        raise NativeRuntimeStageError(f"native wheel member is a symlink: {name}")
    if info.is_dir():
        raise NativeRuntimeStageError(f"native wheel member is a directory: {name}")
    return info


def _read_member(archive: zipfile.ZipFile, name: str, limit: int) -> bytes:
    info = _zip_info(archive, name)
    if info.file_size <= 0 or info.file_size > limit:
        raise NativeRuntimeStageError(f"native wheel member has an invalid size: {name}")
    payload = archive.read(name)
    if len(payload) != info.file_size:
        raise NativeRuntimeStageError(f"native wheel member was truncated: {name}")
    return payload


def _decode_manifest(payload: bytes) -> dict[str, object]:
    if len(payload) <= 0 or len(payload) > _MAX_MANIFEST_BYTES:
        raise NativeRuntimeStageError("native runtime manifest is the wrong size")
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeRuntimeStageError("native runtime manifest is not valid JSON") from error
    if not isinstance(decoded, dict):
        raise NativeRuntimeStageError("native runtime manifest is not an object")
    schema = decoded.get("schema")
    protocol_version = decoded.get("protocol_version")
    package_version = decoded.get("package_version")
    target = decoded.get("target")
    platform_tag = decoded.get("platform_tag")
    source_sha = decoded.get("source_sha")
    rule_digest = decoded.get("rule_digest")
    runtime_sha256 = decoded.get("runtime_sha256")
    runtime_size = decoded.get("runtime_size")
    if (
        schema != _MANIFEST_SCHEMA
        or protocol_version != _PROTOCOL_VERSION
        or not isinstance(package_version, str)
        or not package_version.strip()
        or not isinstance(target, str)
        or not target.strip()
        or not isinstance(platform_tag, str)
        or not platform_tag.strip()
        or not _is_lower_hex(source_sha, _SHA40)
        or not _is_lower_hex(rule_digest, _SHA64)
        or not _is_lower_hex(runtime_sha256, _SHA64)
        or type(runtime_size) is not int
        or runtime_size <= 0
    ):
        raise NativeRuntimeStageError("native runtime manifest failed identity checks")
    return {
        "schema": schema,
        "protocol_version": protocol_version,
        "package_version": package_version.strip(),
        "target": target.strip(),
        "platform_tag": platform_tag.strip(),
        "source_sha": source_sha,
        "rule_digest": rule_digest,
        "runtime_sha256": runtime_sha256,
        "runtime_size": runtime_size,
    }


def _runtime_member_name(names: set[str]) -> str:
    matches = [f"{_NATIVE_DIR}/{filename}" for filename in _RUNTIME_NAMES if f"{_NATIVE_DIR}/{filename}" in names]
    if len(matches) != 1:
        raise NativeRuntimeStageError("native wheel must contain exactly one hol-guard-runtime binary")
    return matches[0]


def _write_file(path: Path, payload: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(mode)
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise NativeRuntimeStageError(f"staged native path is not a regular file: {path.name}")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise NativeRuntimeStageError(f"staged native path is world-writable: {path.name}")


def stage_from_wheel(
    wheel: Path,
    destination: Path,
    *,
    expected_version: str,
    expected_target: str,
) -> tuple[Path, Path]:
    """Extract and seal the native runtime from one attested platform wheel."""

    if not wheel.is_file():
        raise NativeRuntimeStageError("attested native wheel is missing")
    wheel_size = wheel.stat().st_size
    if wheel_size <= 0 or wheel_size > _MAX_WHEEL_BYTES:
        raise NativeRuntimeStageError("attested native wheel is the wrong size")
    try:
        archive = zipfile.ZipFile(wheel)
    except zipfile.BadZipFile as error:
        raise NativeRuntimeStageError("attested native wheel is not a zip archive") from error
    with archive:
        names = {_safe_member_name(info.filename).as_posix() for info in archive.infolist() if not info.is_dir()}
        runtime_name = _runtime_member_name(names)
        manifest_name = f"{_NATIVE_DIR}/{_MANIFEST_NAME}"
        runtime = _read_member(archive, runtime_name, _MAX_RUNTIME_BYTES)
        manifest_bytes = _read_member(archive, manifest_name, _MAX_MANIFEST_BYTES)
    manifest = _decode_manifest(manifest_bytes)
    if manifest["package_version"] != expected_version:
        raise NativeRuntimeStageError("native runtime package version does not match Core")
    if manifest["target"] != expected_target:
        raise NativeRuntimeStageError("native runtime target does not match Core")
    if manifest["runtime_size"] != len(runtime) or manifest["runtime_sha256"] != _sha256(runtime):
        raise NativeRuntimeStageError("native runtime digest does not match its manifest")
    destination.mkdir(parents=True, exist_ok=True)
    runtime_path = destination / Path(runtime_name).name
    manifest_path = destination / _MANIFEST_NAME
    _write_file(runtime_path, runtime, 0o755)
    _write_file(manifest_path, json.dumps(manifest, indent=2).encode("utf-8") + b"\n", 0o644)
    return runtime_path, manifest_path


def refresh_identity(destination: Path) -> Path:
    """Rewrite manifest size and digest after Apple signing changes the runtime bytes."""

    runtime_matches = [path for path in (destination / name for name in _RUNTIME_NAMES) if path.is_file()]
    if len(runtime_matches) != 1:
        raise NativeRuntimeStageError("staged native runtime must contain exactly one hol-guard-runtime binary")
    runtime_path = runtime_matches[0]
    manifest_path = destination / _MANIFEST_NAME
    if not manifest_path.is_file():
        raise NativeRuntimeStageError("staged native runtime manifest is missing")
    runtime = runtime_path.read_bytes()
    if not runtime or len(runtime) > _MAX_RUNTIME_BYTES:
        raise NativeRuntimeStageError("staged native runtime is the wrong size")
    manifest = _decode_manifest(manifest_path.read_bytes())
    manifest["runtime_sha256"] = _sha256(runtime)
    manifest["runtime_size"] = len(runtime)
    _write_file(manifest_path, json.dumps(manifest, indent=2).encode("utf-8") + b"\n", 0o644)
    metadata = runtime_path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise NativeRuntimeStageError("staged native runtime is not a regular file")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise NativeRuntimeStageError("staged native runtime is world-writable")
    return manifest_path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--expected-version")
    parser.add_argument("--expected-target")
    parser.add_argument("--refresh-identity", action="store_true")
    args = parser.parse_args()
    try:
        if args.refresh_identity:
            path = refresh_identity(args.destination)
            print(path)
            return 0
        if args.wheel is None or not args.expected_version or not args.expected_target:
            raise NativeRuntimeStageError("this command requires --wheel, --expected-version, and --expected-target")
        runtime_path, manifest_path = stage_from_wheel(
            args.wheel,
            args.destination,
            expected_version=args.expected_version,
            expected_target=args.expected_target,
        )
        print(runtime_path)
        print(manifest_path)
        return 0
    except NativeRuntimeStageError as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    raise SystemExit(main())
