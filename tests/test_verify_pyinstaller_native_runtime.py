from __future__ import annotations

import hashlib
import importlib.util
import json
import struct
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
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
    entries: list[tuple[str, bytes, str]],
) -> None:
    signing = _load(SIGNING, "verify_pyinstaller_macos_signing")
    payload = bytearray()
    toc = bytearray()
    for name, data, typecode in entries:
        offset = len(payload)
        payload.extend(data)
        raw_name = name.encode("utf-8") + b"\0"
        entry_length = signing.TOC_HEADER_LENGTH + len(raw_name)
        toc.extend(
            struct.pack(
                signing.TOC_FORMAT,
                entry_length,
                offset,
                len(data),
                len(data),
                0,
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
    path.write_bytes(bytes(payload) + bytes(toc) + cookie)


def test_verifier_accepts_sealed_native_data_entry(tmp_path: Path) -> None:
    module = _load(VERIFIER, "verify_pyinstaller_native_runtime")
    runtime = b"signed-native-runtime"
    manifest = {
        "schema": "hol-guard-native-runtime.v1",
        "protocol_version": 1,
        "package_version": "3.0.12",
        "target": "aarch64-apple-darwin",
        "platform_tag": "macosx_11_0_arm64",
        "source_sha": "a" * 40,
        "rule_digest": "b" * 64,
        "runtime_sha256": hashlib.sha256(runtime).hexdigest(),
        "runtime_size": len(runtime),
    }
    archive = tmp_path / "hol-guard"
    _fake_archive(
        archive,
        declared_runtime="Python",
        entries=[
            ("Python", b"\xcf\xfa\xed\xfe-runtime", "b"),
            ("codex_plugin_scanner/_native/hol-guard-runtime", runtime, "x"),
            (
                "codex_plugin_scanner/_native/runtime-manifest.json",
                json.dumps(manifest).encode("utf-8"),
                "x",
            ),
        ],
    )

    module.verify(archive)


def test_verifier_rejects_missing_native_runtime(tmp_path: Path) -> None:
    module = _load(VERIFIER, "verify_pyinstaller_native_runtime")
    archive = tmp_path / "hol-guard"
    _fake_archive(
        archive,
        declared_runtime="Python",
        entries=[("Python", b"\xcf\xfa\xed\xfe-runtime", "b")],
    )

    with pytest.raises(ValueError, match="exactly one native runtime"):
        module.verify(archive)


def test_verifier_rejects_manifest_digest_mismatch(tmp_path: Path) -> None:
    module = _load(VERIFIER, "verify_pyinstaller_native_runtime")
    runtime = b"signed-native-runtime"
    manifest = {
        "schema": "hol-guard-native-runtime.v1",
        "protocol_version": 1,
        "package_version": "3.0.12",
        "target": "aarch64-apple-darwin",
        "platform_tag": "macosx_11_0_arm64",
        "source_sha": "a" * 40,
        "rule_digest": "b" * 64,
        "runtime_sha256": "c" * 64,
        "runtime_size": len(runtime),
    }
    archive = tmp_path / "hol-guard"
    _fake_archive(
        archive,
        declared_runtime="Python",
        entries=[
            ("Python", b"\xcf\xfa\xed\xfe-runtime", "b"),
            ("codex_plugin_scanner/_native/hol-guard-runtime", runtime, "x"),
            (
                "codex_plugin_scanner/_native/runtime-manifest.json",
                json.dumps(manifest).encode("utf-8"),
                "x",
            ),
        ],
    )

    with pytest.raises(ValueError, match="digest"):
        module.verify(archive)
