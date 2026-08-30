from __future__ import annotations

import hashlib
import importlib.util
import json
import struct
import zlib
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
SEALER = ROOT / "scripts" / "release" / "seal_pyinstaller_native_manifest.py"
VERIFIER = ROOT / "scripts" / "release" / "verify_pyinstaller_native_runtime.py"
SIGNING = ROOT / "scripts" / "release" / "verify_pyinstaller_macos_signing.py"


def _load(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _fake_archive(
    path: Path,
    *,
    declared_runtime: str,
    entries: list[tuple[str, bytes, str] | tuple[str, bytes, str, bool]],
    prefix: bytes = b"",
    uncompressed_by_name: dict[str, int] | None = None,
) -> None:
    signing = _load(SIGNING, "verify_pyinstaller_macos_signing")
    payload = bytearray()
    toc = bytearray()
    for item in entries:
        compressed = False
        if len(item) == 4:
            name, data, typecode, compressed = item
        else:
            name, data, typecode = item
        stored = zlib.compress(data) if compressed else data
        offset = len(payload)
        payload.extend(stored)
        raw_name = name.encode("utf-8") + b"\0"
        toc_uncompressed = (
            uncompressed_by_name[name]
            if uncompressed_by_name is not None and name in uncompressed_by_name
            else len(data)
        )
        toc.extend(
            struct.pack(
                signing.TOC_FORMAT,
                signing.TOC_HEADER_LENGTH + len(raw_name),
                offset,
                len(stored),
                toc_uncompressed,
                1 if compressed else 0,
                typecode.encode("ascii"),
            )
        )
        toc.extend(raw_name)

    raw_runtime = declared_runtime.encode("utf-8")
    assert len(raw_runtime) < 64
    cookie = struct.pack(
        signing.COOKIE_FORMAT,
        signing.COOKIE_MAGIC,
        len(payload) + len(toc) + signing.COOKIE_LENGTH,
        len(payload),
        len(toc),
        312,
        raw_runtime + (b"\0" * (64 - len(raw_runtime))),
    )
    path.write_bytes(prefix + bytes(payload) + bytes(toc) + cookie)


def _manifest(*, runtime: bytes, digest: str | None = None) -> dict[str, object]:
    return {
        "schema": "hol-guard-native-runtime.v1",
        "protocol_version": 1,
        "package_version": "3.0.14",
        "target": "aarch64-apple-darwin",
        "platform_tag": "macosx_11_0_arm64",
        "source_sha": "a" * 40,
        "rule_digest": "b" * 64,
        "runtime_sha256": digest if digest is not None else hashlib.sha256(runtime).hexdigest(),
        "runtime_size": len(runtime),
    }


def _native_entries(runtime: bytes, *, digest: str | None, compressed: bool) -> list[tuple[str, bytes, str, bool]]:
    manifest = json.dumps(_manifest(runtime=runtime, digest=digest), indent=2).encode("utf-8")
    return [
        ("Python", b"\xcf\xfa\xed\xfe-runtime", "b", False),
        ("codex_plugin_scanner/_native/hol-guard-runtime", runtime, "x", compressed),
        ("codex_plugin_scanner/_native/runtime-manifest.json", manifest, "x", compressed),
        ("trailing.dat", b"keep-me", "x", compressed),
    ]


def test_sealer_rewrites_stale_manifest_after_packaged_runtime_changes(tmp_path: Path) -> None:
    sealer = _load(SEALER, "seal_pyinstaller_native_manifest")
    verifier = _load(VERIFIER, "verify_pyinstaller_native_runtime")
    runtime = b"re-signed-native-runtime"
    archive = tmp_path / "hol-guard"
    _fake_archive(
        archive,
        declared_runtime="Python",
        entries=_native_entries(runtime, digest="c" * 64, compressed=False),
    )

    with pytest.raises(ValueError, match="digest"):
        verifier.verify(archive)

    sealer.seal(archive)
    verifier.verify(archive)


def test_sealer_is_idempotent_when_manifest_already_matches(tmp_path: Path) -> None:
    sealer = _load(SEALER, "seal_pyinstaller_native_manifest")
    verifier = _load(VERIFIER, "verify_pyinstaller_native_runtime")
    runtime = b"signed-native-runtime"
    archive = tmp_path / "hol-guard"
    _fake_archive(
        archive,
        declared_runtime="Python",
        entries=_native_entries(runtime, digest=None, compressed=False),
    )

    sealer.seal(archive)
    verifier.verify(archive)


def test_sealer_rewrites_compressed_stale_manifest_and_preserves_neighbors(tmp_path: Path) -> None:
    sealer = _load(SEALER, "seal_pyinstaller_native_manifest")
    verifier = _load(VERIFIER, "verify_pyinstaller_native_runtime")
    signing = _load(SIGNING, "verify_pyinstaller_macos_signing")
    runtime = b"re-signed-compressed-runtime"
    archive = tmp_path / "hol-guard"
    prefix = b"BOOTLOADER"
    _fake_archive(
        archive,
        declared_runtime="Python",
        entries=_native_entries(runtime, digest="d" * 64, compressed=True),
        prefix=prefix,
    )

    with pytest.raises(ValueError, match="digest"):
        verifier.verify(archive)

    sealer.seal(archive)
    verifier.verify(archive)
    assert archive.read_bytes().startswith(prefix)
    archive_start, _pylib, entries = signing._archive_layout(archive)
    trailing = next(entry for entry in entries if entry[0] == "trailing.dat")
    with archive.open("rb") as handle:
        assert signing._entry_bytes(handle, archive_start, *trailing[:4]) == b"keep-me"
    manifest = next(entry for entry in entries if entry[0].endswith("runtime-manifest.json"))
    assert manifest[3] is False


def test_sealer_accepts_matching_compressed_manifest_without_rewrite(tmp_path: Path) -> None:
    sealer = _load(SEALER, "seal_pyinstaller_native_manifest")
    verifier = _load(VERIFIER, "verify_pyinstaller_native_runtime")
    signing = _load(SIGNING, "verify_pyinstaller_macos_signing")
    runtime = b"matching-compressed-runtime"
    archive = tmp_path / "hol-guard"
    _fake_archive(
        archive,
        declared_runtime="Python",
        entries=_native_entries(runtime, digest=None, compressed=True),
    )
    before = archive.read_bytes()

    sealer.seal(archive)
    verifier.verify(archive)
    assert archive.read_bytes() == before
    _archive_start, _pylib, entries = signing._archive_layout(archive)
    manifest = next(entry for entry in entries if entry[0].endswith("runtime-manifest.json"))
    assert manifest[3] is True


def test_archive_toc_rejects_entry_that_overlaps_toc(tmp_path: Path) -> None:
    signing = _load(SIGNING, "verify_pyinstaller_macos_signing")
    payload = b"data"
    name = "codex_plugin_scanner/_native/hol-guard-runtime"
    raw_name = name.encode("utf-8") + b"\0"
    toc = struct.pack(
        signing.TOC_FORMAT,
        signing.TOC_HEADER_LENGTH + len(raw_name),
        len(payload),
        4,
        4,
        0,
        b"x",
    )
    toc += raw_name
    raw_runtime = b"Python"
    cookie = struct.pack(
        signing.COOKIE_FORMAT,
        signing.COOKIE_MAGIC,
        len(payload) + len(toc) + signing.COOKIE_LENGTH,
        len(payload),
        len(toc),
        312,
        raw_runtime + (b"\0" * (64 - len(raw_runtime))),
    )
    archive = tmp_path / "hol-guard"
    archive.write_bytes(payload + toc + cookie)

    with pytest.raises(ValueError, match="overlaps the archive TOC"):
        signing._archive_toc(archive)


def test_sealer_rejects_runtime_uncompressed_size_mismatch(tmp_path: Path) -> None:
    sealer = _load(SEALER, "seal_pyinstaller_native_manifest")
    runtime = b"size-mismatch-runtime"
    archive = tmp_path / "hol-guard"
    _fake_archive(
        archive,
        declared_runtime="Python",
        entries=_native_entries(runtime, digest=None, compressed=False),
        uncompressed_by_name={"codex_plugin_scanner/_native/hol-guard-runtime": 999},
    )

    with pytest.raises(ValueError, match="size does not match"):
        sealer.seal(archive)
