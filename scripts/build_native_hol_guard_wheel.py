#!/usr/bin/env python3
"""Build one platform-specific HOL Guard wheel from the verified pure wheel.

The native runtime is injected into ``codex_plugin_scanner/_native``. The
source wheel is never modified in place, and this builder refuses any project
other than ``hol-guard``. It rewrites only wheel metadata required by the
platform artifact plus RECORD hashes.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import unicodedata
import zipfile
from dataclasses import dataclass
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import BinaryIO

_MAX_RUNTIME_BYTES = 128 * 1024 * 1024
_MAX_SOURCE_WHEEL_BYTES = 256 * 1024 * 1024
_MAX_SOURCE_ENTRY_BYTES = 64 * 1024 * 1024
_MAX_SOURCE_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
_MAX_SOURCE_ENTRIES = 16_384
_MAX_CAPABILITIES_BYTES = 64 * 1024
_PLATFORM_TAG_RE = re.compile(r"^[A-Za-z0-9_.]+$")
_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA64_RE = re.compile(r"^[0-9a-f]{64}$")
_NATIVE_DIR = "codex_plugin_scanner/_native"
_RUNTIME_MANIFEST_PATH = f"{_NATIVE_DIR}/runtime-manifest.json"
_DETERMINISTIC_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


class NativeWheelError(ValueError):
    """Raised when a source artifact cannot safely become a native wheel."""


@dataclass(frozen=True, slots=True)
class SourceWheel:
    path: Path
    dist_info: str
    metadata_path: str
    wheel_path: str
    record_path: str
    entries: dict[str, bytes]
    modes: dict[str, int]


@dataclass(frozen=True, slots=True)
class RuntimeCapabilities:
    protocol_version: int
    runtime_version: str
    rule_digest: str
    build_sha: str


def _wheel_version_for_filename(version: str) -> str:
    return version.replace("-", "_")


def _safe_archive_path(name: str) -> bool:
    if (
        not name
        or "\\" in name
        or "\x00" in name
        or any(ord(character) < 0x20 for character in name)
    ):
        return False
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or any(part in {"", "."} for part in path.parts):
        return False
    # Wheel member names are canonical POSIX paths. Reject repeated separators,
    # dot segments, trailing separators, and other spellings that normalize to
    # a different installed path.
    return str(path) == name


def _canonical_archive_key(name: str) -> str:
    """Return a conservative collision key for case/Unicode-normalizing hosts."""
    return unicodedata.normalize("NFC", name).casefold()


def _entry_mode(info: zipfile.ZipInfo) -> int:
    raw = info.external_attr >> 16
    if raw and stat.S_ISLNK(raw):
        raise NativeWheelError(f"source wheel contains a symlink entry: {info.filename}")
    mode = stat.S_IMODE(raw) if raw else 0
    return mode or 0o644


def _open_regular_file(path: Path, *, max_bytes: int, label: str) -> BinaryIO:
    """Open one immutable-by-identity regular file without following POSIX symlinks."""
    lexical = path.expanduser()
    try:
        before = lexical.lstat()
    except OSError as exc:
        raise NativeWheelError(f"{label} must be a regular non-symlink file") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise NativeWheelError(f"{label} must be a regular non-symlink file")
    if before.st_size <= 0 or before.st_size > max_bytes:
        raise NativeWheelError(f"{label} size is outside the accepted release bounds")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(lexical, flags)
    except OSError as exc:
        raise NativeWheelError(f"{label} could not be opened safely") from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size != before.st_size:
            raise NativeWheelError(f"{label} changed while being opened")
        before_identity = (getattr(before, "st_dev", None), getattr(before, "st_ino", None))
        opened_identity = (getattr(opened, "st_dev", None), getattr(opened, "st_ino", None))
        identities_available = all(
            value not in {None, 0}
            for value in (*before_identity, *opened_identity)
        )
        if identities_available and before_identity != opened_identity:
            raise NativeWheelError(f"{label} changed while being opened")
        return os.fdopen(fd, "rb")
    except Exception:
        os.close(fd)
        raise


def _validate_source_archive_bounds(infos: list[zipfile.ZipInfo]) -> None:
    files = [info for info in infos if not info.is_dir()]
    if len(files) > _MAX_SOURCE_ENTRIES:
        raise NativeWheelError("source wheel contains too many entries")
    total_uncompressed = 0
    for info in files:
        if info.flag_bits & 0x1:
            raise NativeWheelError(f"source wheel contains an encrypted entry: {info.filename}")
        if info.file_size < 0 or info.file_size > _MAX_SOURCE_ENTRY_BYTES:
            raise NativeWheelError(f"source wheel entry is too large: {info.filename}")
        total_uncompressed += info.file_size
        if total_uncompressed > _MAX_SOURCE_UNCOMPRESSED_BYTES:
            raise NativeWheelError("source wheel uncompressed size exceeds the accepted release bound")


def _read_zip_entry_bounded(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    content = bytearray()
    try:
        with archive.open(info, "r") as handle:
            while True:
                chunk = handle.read(min(64 * 1024, _MAX_SOURCE_ENTRY_BYTES + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
                if len(content) > _MAX_SOURCE_ENTRY_BYTES or len(content) > info.file_size:
                    raise NativeWheelError(f"source wheel entry expanded past its declared size: {info.filename}")
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise NativeWheelError(f"source wheel entry could not be read safely: {info.filename}") from exc
    if len(content) != info.file_size:
        raise NativeWheelError(f"source wheel entry size changed while reading: {info.filename}")
    return bytes(content)


def _load_source_wheel(path: Path, *, version: str) -> SourceWheel:
    expected_name = f"hol_guard-{_wheel_version_for_filename(version)}-py3-none-any.whl"
    if path.name != expected_name:
        raise NativeWheelError(f"expected pure hol-guard wheel {expected_name}, got {path.name}")

    entries: dict[str, bytes] = {}
    modes: dict[str, int] = {}
    with (
        _open_regular_file(path, max_bytes=_MAX_SOURCE_WHEEL_BYTES, label="source wheel") as source_file,
        zipfile.ZipFile(source_file, "r") as archive,
    ):
        infos = archive.infolist()
        _validate_source_archive_bounds(infos)
        names = [info.filename for info in infos if not info.is_dir()]
        if len(names) != len(set(names)):
            raise NativeWheelError("source wheel contains duplicate entries")
        canonical_names: set[str] = set()
        for info in infos:
            if info.is_dir():
                continue
            if not _safe_archive_path(info.filename):
                raise NativeWheelError(f"source wheel contains an unsafe path: {info.filename}")
            collision_key = _canonical_archive_key(info.filename)
            if collision_key in canonical_names:
                raise NativeWheelError(f"source wheel contains a canonical path collision: {info.filename}")
            canonical_names.add(collision_key)
            entries[info.filename] = _read_zip_entry_bounded(archive, info)
            modes[info.filename] = _entry_mode(info)

    wheel_paths = [name for name in entries if name.endswith(".dist-info/WHEEL")]
    metadata_paths = [name for name in entries if name.endswith(".dist-info/METADATA")]
    record_paths = [name for name in entries if name.endswith(".dist-info/RECORD")]
    if len(wheel_paths) != 1 or len(metadata_paths) != 1 or len(record_paths) != 1:
        raise NativeWheelError("source wheel must contain exactly one WHEEL, METADATA, and RECORD")

    wheel_path = wheel_paths[0]
    metadata_path = metadata_paths[0]
    record_path = record_paths[0]
    dist_info = wheel_path.rsplit("/", 1)[0]
    if metadata_path.rsplit("/", 1)[0] != dist_info or record_path.rsplit("/", 1)[0] != dist_info:
        raise NativeWheelError("source wheel dist-info metadata is inconsistent")

    metadata = BytesParser().parsebytes(entries[metadata_path])
    if metadata.get("Name") != "hol-guard" or metadata.get("Version") != version:
        raise NativeWheelError("source wheel project identity or version does not match")

    wheel_text = entries[wheel_path].decode("utf-8")
    tags = [
        line.removeprefix("Tag:").strip()
        for line in wheel_text.splitlines()
        if line.startswith("Tag:")
    ]
    if tags != ["py3-none-any"]:
        raise NativeWheelError("source wheel must be the canonical py3-none-any artifact")
    if f"{_NATIVE_DIR}/hol-guard-runtime" in entries or f"{_NATIVE_DIR}/hol-guard-runtime.exe" in entries:
        raise NativeWheelError("source wheel already contains a native runtime")
    if _RUNTIME_MANIFEST_PATH in entries:
        raise NativeWheelError("source wheel already contains a native runtime manifest")

    return SourceWheel(
        path=path,
        dist_info=dist_info,
        metadata_path=metadata_path,
        wheel_path=wheel_path,
        record_path=record_path,
        entries=entries,
        modes=modes,
    )


def _load_runtime(path: Path) -> bytes:
    with _open_regular_file(path, max_bytes=_MAX_RUNTIME_BYTES, label="runtime") as handle:
        metadata = os.fstat(handle.fileno())
        if os.name != "nt":
            mode = stat.S_IMODE(metadata.st_mode)
            if mode & 0o022:
                raise NativeWheelError("runtime is group/world writable")
            if not mode & stat.S_IXUSR:
                raise NativeWheelError("runtime is not owner-executable")
        runtime = handle.read(_MAX_RUNTIME_BYTES + 1)
        after = os.fstat(handle.fileno())
        if len(runtime) > _MAX_RUNTIME_BYTES:
            raise NativeWheelError("runtime size is outside the accepted release bounds")
        if (metadata.st_size, metadata.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise NativeWheelError("runtime changed while being read")
        if len(runtime) != metadata.st_size:
            raise NativeWheelError("runtime could not be read completely")
        return runtime


def _runtime_capabilities(path: Path) -> RuntimeCapabilities:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper()
        in {
            "COMSPEC",
            "HOME",
            "LANG",
            "PATHEXT",
            "SYSTEMROOT",
            "TEMP",
            "TMP",
            "TMPDIR",
            "USERPROFILE",
            "WINDIR",
        }
        or key.upper().startswith("LC_")
    }
    try:
        completed = subprocess.run(
            (str(path.resolve(strict=True)), "capabilities", "--json"),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=5.0,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise NativeWheelError("runtime capabilities probe failed") from exc
    if completed.returncode != 0 or len(completed.stdout) > _MAX_CAPABILITIES_BYTES:
        raise NativeWheelError("runtime capabilities probe failed")
    try:
        payload = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NativeWheelError("runtime capabilities response is invalid") from exc
    if not isinstance(payload, dict):
        raise NativeWheelError("runtime capabilities response is invalid")
    protocol_version = payload.get("protocol_version")
    runtime_version = payload.get("runtime_version")
    rule_digest = payload.get("rule_digest")
    build_sha = payload.get("build_sha")
    if (
        not isinstance(protocol_version, int)
        or not isinstance(runtime_version, str)
        or not isinstance(rule_digest, str)
        or not isinstance(build_sha, str)
    ):
        raise NativeWheelError("runtime capabilities response is invalid")
    return RuntimeCapabilities(
        protocol_version=protocol_version,
        runtime_version=runtime_version,
        rule_digest=rule_digest,
        build_sha=build_sha,
    )


def _verify_runtime_provenance(
    path: Path,
    *,
    version: str,
    source_sha: str,
    rule_digest: str,
) -> bytes:
    before = _load_runtime(path)
    capabilities = _runtime_capabilities(path)
    after = _load_runtime(path)
    if not hashlib.sha256(before).digest() == hashlib.sha256(after).digest():
        raise NativeWheelError("runtime changed during capabilities verification")
    if capabilities.protocol_version != 1:
        raise NativeWheelError("runtime protocol version does not match native wheel contract")
    if capabilities.runtime_version != version:
        raise NativeWheelError("runtime package version does not match native wheel version")
    if capabilities.rule_digest != rule_digest:
        raise NativeWheelError("runtime rule digest does not match requested manifest digest")
    if capabilities.build_sha != source_sha:
        raise NativeWheelError("runtime build SHA does not match requested source SHA")
    return before


def _rewrite_wheel_metadata(raw: bytes, *, platform_tag: str) -> bytes:
    lines = raw.decode("utf-8").splitlines()
    rewritten = [
        line
        for line in lines
        if not line.startswith("Root-Is-Purelib:") and not line.startswith("Tag:")
    ]
    rewritten.extend(["Root-Is-Purelib: false", f"Tag: py3-none-{platform_tag}"])
    return ("\n".join(rewritten).rstrip("\n") + "\n").encode("utf-8")


def _record_hash(content: bytes) -> str:
    digest = hashlib.sha256(content).digest()
    encoded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return f"sha256={encoded}"


def _record_content(entries: dict[str, bytes], *, record_path: str) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for name in sorted(entries):
        if name == record_path:
            continue
        content = entries[name]
        writer.writerow([name, _record_hash(content), str(len(content))])
    writer.writerow([record_path, "", ""])
    return output.getvalue().encode("utf-8")


def _zip_info(name: str, *, mode: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=_DETERMINISTIC_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | mode) << 16
    return info


def _prepare_output_dir(output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    metadata = output_dir.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise NativeWheelError("output directory must be a regular non-symlink directory")
    return output_dir


def _write_output_wheel_exclusive(
    output_path: Path,
    entries: dict[str, bytes],
    modes: dict[str, int],
) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(output_path, flags, 0o600)
    except FileExistsError as exc:
        raise NativeWheelError(f"refusing to overwrite existing native wheel: {output_path}") from exc
    with os.fdopen(fd, "w+b") as output_file:
        with zipfile.ZipFile(
            output_file,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as archive:
            for name in sorted(entries):
                if not _safe_archive_path(name):
                    raise NativeWheelError(f"refusing unsafe output path: {name}")
                archive.writestr(_zip_info(name, mode=modes.get(name, 0o644)), entries[name])
        output_file.flush()
        os.fsync(output_file.fileno())


def build_native_wheel(
    *,
    source_wheel: Path,
    runtime: Path,
    output_dir: Path,
    version: str,
    platform_tag: str,
    target: str,
    source_sha: str,
    rule_digest: str,
) -> Path:
    """Return a new native HOL Guard wheel without changing the source wheel."""
    if not version.strip():
        raise NativeWheelError("package version is required")
    if not _PLATFORM_TAG_RE.fullmatch(platform_tag):
        raise NativeWheelError("invalid wheel platform tag")
    if not target or any(character in target for character in "\\/\x00"):
        raise NativeWheelError("invalid runtime target")
    if not _SHA40_RE.fullmatch(source_sha):
        raise NativeWheelError("source SHA must be a lowercase 40-character Git SHA")
    if not _SHA64_RE.fullmatch(rule_digest):
        raise NativeWheelError("rule digest must be a lowercase SHA-256 hex digest")

    source = _load_source_wheel(source_wheel, version=version)
    runtime_bytes = _verify_runtime_provenance(
        runtime,
        version=version,
        source_sha=source_sha,
        rule_digest=rule_digest,
    )
    runtime_name = "hol-guard-runtime.exe" if platform_tag.startswith("win") else "hol-guard-runtime"
    runtime_path = f"{_NATIVE_DIR}/{runtime_name}"

    entries = dict(source.entries)
    modes = dict(source.modes)
    entries[source.wheel_path] = _rewrite_wheel_metadata(
        entries[source.wheel_path],
        platform_tag=platform_tag,
    )
    runtime_sha256 = hashlib.sha256(runtime_bytes).hexdigest()
    manifest = {
        "schema": "hol-guard-native-runtime.v1",
        "protocol_version": 1,
        "package_version": version,
        "target": target,
        "platform_tag": platform_tag,
        "source_sha": source_sha,
        "rule_digest": rule_digest,
        "runtime_sha256": runtime_sha256,
        "runtime_size": len(runtime_bytes),
    }
    entries[runtime_path] = runtime_bytes
    entries[_RUNTIME_MANIFEST_PATH] = (
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    modes[runtime_path] = 0o755
    modes[_RUNTIME_MANIFEST_PATH] = 0o644
    modes[source.wheel_path] = 0o644
    entries[source.record_path] = _record_content(entries, record_path=source.record_path)
    modes[source.record_path] = 0o644

    safe_output_dir = _prepare_output_dir(output_dir)
    output_path = safe_output_dir / (
        f"hol_guard-{_wheel_version_for_filename(version)}-py3-none-{platform_tag}.whl"
    )
    _write_output_wheel_exclusive(output_path, entries, modes)
    return output_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Inject the native runtime into a verified hol-guard wheel")
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--platform-tag", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--rule-digest", required=True)
    args = parser.parse_args()
    output = build_native_wheel(
        source_wheel=args.wheel,
        runtime=args.runtime,
        output_dir=args.output_dir,
        version=args.version,
        platform_tag=args.platform_tag,
        target=args.target,
        source_sha=args.source_sha,
        rule_digest=args.rule_digest,
    )
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
