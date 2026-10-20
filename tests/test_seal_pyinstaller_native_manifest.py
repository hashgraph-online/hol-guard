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


def _compiler_manifest(*, runtime: bytes, digest: str | None = None, size: int | None = None) -> dict[str, object]:
    return {
        "schema": "hol-guard-native-source-compiler.v2",
        "executable": "hol-guard-runtime",
        "base_program_digest": "c" * 64,
        "compiler_sha256": digest if digest is not None else hashlib.sha256(runtime).hexdigest(),
        "compiler_size": size if size is not None else len(runtime),
    }


def _entries_with_compiler(
    runtime: bytes,
    *,
    runtime_digest: str | None,
    compiler_digest: str | None,
    compiler_size: int | None = None,
    compressed: bool = False,
) -> list[tuple[str, bytes, str, bool]]:
    """A real onefile archive carries both manifests, so most fixtures should too."""
    entries = _native_entries(runtime, digest=runtime_digest, compressed=compressed)
    compiler = json.dumps(
        _compiler_manifest(runtime=runtime, digest=compiler_digest, size=compiler_size),
        indent=2,
    ).encode("utf-8")
    entries.insert(
        3,
        ("codex_plugin_scanner/_native/source-compiler-manifest.json", compiler, "x", compressed),
    )
    return entries


def _read_entry(archive: Path, suffix: str) -> tuple[bytes, bool]:
    signing = _load(SIGNING, "verify_pyinstaller_macos_signing")
    archive_start, _pylib, entries = signing._archive_layout(archive)
    entry = next(item for item in entries if item[0].endswith(suffix))
    with archive.open("rb") as handle:
        return signing._entry_bytes(handle, archive_start, *entry[:4]), entry[3]


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


def _onedir_tree(tmp_path: Path, *, unsigned: bytes, signed: bytes, compiler: bool = True) -> Path:
    """Build a onedir tree whose manifests describe the runtime before signing."""
    tree = tmp_path / "hol-guard"
    native = tree / "_internal" / "codex_plugin_scanner" / "_native"
    native.mkdir(parents=True)
    (native / "hol-guard-runtime").write_bytes(signed)
    (native / "runtime-manifest.json").write_text(
        json.dumps(
            {
                "schema": "hol-guard-native-runtime.v1",
                "protocol_version": 1,
                "package_version": "3.50.0",
                "target": "aarch64-apple-darwin",
                "platform_tag": "macosx_11_0_arm64",
                "source_sha": "a" * 40,
                "rule_digest": "b" * 64,
                "runtime_sha256": hashlib.sha256(unsigned).hexdigest(),
                "runtime_size": len(unsigned),
            }
        )
    )
    if compiler:
        (native / "source-compiler-manifest.json").write_text(
            json.dumps(
                {
                    "schema": "hol-guard-native-source-compiler.v2",
                    "protocol_version": 1,
                    "package_version": "3.50.0",
                    "target": "aarch64-apple-darwin",
                    "platform_tag": "macosx_11_0_arm64",
                    "executable": "hol-guard-runtime",
                    "source_sha": "a" * 40,
                    "base_program_digest": "c" * 64,
                    "implementation_digest": "d" * 64,
                    "compiler_sha256": hashlib.sha256(unsigned).hexdigest(),
                    "compiler_size": len(unsigned),
                }
            )
        )
    return tree


def test_seal_onedir_rebinds_source_compiler_manifest_to_signed_runtime(tmp_path: Path) -> None:
    """Apple signing rewrites the runtime, so both manifests must be resealed.

    Resealing only the runtime manifest leaves the source compiler manifest
    describing the unsigned bytes. The installed bundle then fails to verify for
    the life of the release, and the extensions catalog read model never becomes
    available.
    """
    sealer = _load(SEALER, "seal_pyinstaller_native_manifest")
    unsigned = b"runtime-before-apple-signing"
    signed = unsigned + b"\x00" * 64  # a signature blob grows the Mach-O
    tree = _onedir_tree(tmp_path, unsigned=unsigned, signed=signed)

    sealer.seal_onedir(tree)

    native = tree / "_internal" / "codex_plugin_scanner" / "_native"
    runtime_manifest = json.loads((native / "runtime-manifest.json").read_text())
    compiler_manifest = json.loads((native / "source-compiler-manifest.json").read_text())
    assert runtime_manifest["runtime_size"] == len(signed)
    assert runtime_manifest["runtime_sha256"] == hashlib.sha256(signed).hexdigest()
    assert compiler_manifest["compiler_size"] == len(signed)
    assert compiler_manifest["compiler_sha256"] == hashlib.sha256(signed).hexdigest()
    assert compiler_manifest["base_program_digest"] == "c" * 64


def test_seal_onedir_requires_a_source_compiler_manifest(tmp_path: Path) -> None:
    sealer = _load(SEALER, "seal_pyinstaller_native_manifest")
    runtime = b"runtime-without-a-compiler-manifest"
    tree = _onedir_tree(tmp_path, unsigned=runtime, signed=runtime, compiler=False)

    with pytest.raises(ValueError, match="missing its source compiler manifest"):
        sealer.seal_onedir(tree)


def test_seal_rebinds_source_compiler_entry_in_carchive(tmp_path: Path) -> None:
    """The onefile Core asset is signed the same way the onedir tree is.

    Resealing only the runtime manifest there would ship the same unavailable
    catalog read model the onedir build shipped in 3.50.0.
    """
    sealer = _load(SEALER, "seal_pyinstaller_native_manifest")
    verifier = _load(VERIFIER, "verify_pyinstaller_native_runtime")
    runtime = b"re-signed-onefile-runtime"
    archive = tmp_path / "hol-guard"
    _fake_archive(
        archive,
        declared_runtime="Python",
        entries=_entries_with_compiler(
            runtime,
            runtime_digest="c" * 64,
            compiler_digest="d" * 64,
            compiler_size=1,
        ),
    )

    sealer.seal(archive)
    verifier.verify(archive)

    raw, compressed = _read_entry(archive, "source-compiler-manifest.json")
    compiler = json.loads(raw.decode("utf-8"))
    assert compiler["compiler_sha256"] == hashlib.sha256(runtime).hexdigest()
    assert compiler["compiler_size"] == len(runtime)
    assert compiler["base_program_digest"] == "c" * 64
    assert compressed is False
    assert _read_entry(archive, "trailing.dat")[0] == b"keep-me"


def test_seal_leaves_a_matching_compiler_entry_alone(tmp_path: Path) -> None:
    sealer = _load(SEALER, "seal_pyinstaller_native_manifest")
    verifier = _load(VERIFIER, "verify_pyinstaller_native_runtime")
    runtime = b"half-stale-onefile-runtime"
    archive = tmp_path / "hol-guard"
    _fake_archive(
        archive,
        declared_runtime="Python",
        entries=_entries_with_compiler(
            runtime,
            runtime_digest="c" * 64,
            compiler_digest=None,
        ),
    )
    compiler_before = _read_entry(archive, "source-compiler-manifest.json")[0]

    sealer.seal(archive)
    verifier.verify(archive)

    assert _read_entry(archive, "source-compiler-manifest.json")[0] == compiler_before


def test_seal_tolerates_an_archive_without_a_compiler_entry(tmp_path: Path) -> None:
    """Onefile stays tolerant: not every archive the sealer sees carries one."""
    sealer = _load(SEALER, "seal_pyinstaller_native_manifest")
    verifier = _load(VERIFIER, "verify_pyinstaller_native_runtime")
    runtime = b"compiler-less-onefile-runtime"
    archive = tmp_path / "hol-guard"
    _fake_archive(
        archive,
        declared_runtime="Python",
        entries=_native_entries(runtime, digest="c" * 64, compressed=False),
    )

    sealer.seal(archive)
    verifier.verify(archive)


def test_seal_rebinds_a_stale_compiler_entry_when_the_runtime_manifest_matches(tmp_path: Path) -> None:
    """Only the compiler manifest is stale, so the old early return would skip it."""
    sealer = _load(SEALER, "seal_pyinstaller_native_manifest")
    verifier = _load(VERIFIER, "verify_pyinstaller_native_runtime")
    runtime = b"compiler-only-stale-runtime"
    archive = tmp_path / "hol-guard"
    _fake_archive(
        archive,
        declared_runtime="Python",
        entries=_entries_with_compiler(
            runtime,
            runtime_digest=None,
            compiler_digest="d" * 64,
            compiler_size=1,
        ),
    )

    sealer.seal(archive)
    verifier.verify(archive)

    compiler = json.loads(_read_entry(archive, "source-compiler-manifest.json")[0].decode("utf-8"))
    assert compiler["compiler_sha256"] == hashlib.sha256(runtime).hexdigest()
    assert compiler["compiler_size"] == len(runtime)
