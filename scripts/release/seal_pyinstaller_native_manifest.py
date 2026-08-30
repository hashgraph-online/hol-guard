#!/usr/bin/env python3
"""Rewrite the bundled native manifest to match PyInstaller-packaged runtime bytes."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import struct
import zlib
from pathlib import Path

_NATIVE_VERIFIER_PATH = Path(__file__).with_name("verify_pyinstaller_native_runtime.py")
_MANIFEST_SCHEMA = "hol-guard-native-runtime.v1"


class NativeManifestSealError(ValueError):
    """Raised when the packaged native manifest cannot be resealed."""


def _load_native_verifier():
    spec = importlib.util.spec_from_file_location("verify_pyinstaller_native_runtime", _NATIVE_VERIFIER_PATH)
    if spec is None or spec.loader is None:
        raise SystemExit("PyInstaller native runtime verifier is missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _encode_manifest(payload: dict[str, object]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _rebuild_carchive(
    signing,
    *,
    prefix: bytes,
    suffix: bytes,
    pyvers: int,
    pylib_name: str,
    entries: list[tuple[str, bytes, int, bool, str]],
) -> bytes:
    raw_runtime = pylib_name.encode("utf-8")
    if not raw_runtime or len(raw_runtime) >= 64:
        raise NativeManifestSealError("PyInstaller CArchive Python runtime name cannot be resealed")
    payload = bytearray()
    toc = bytearray()
    for name, stored, uncompressed, compressed, typecode in entries:
        offset = len(payload)
        payload.extend(stored)
        raw_name = name.encode("utf-8") + b"\0"
        toc.extend(
            struct.pack(
                signing.TOC_FORMAT,
                signing.TOC_HEADER_LENGTH + len(raw_name),
                offset,
                len(stored),
                uncompressed,
                1 if compressed else 0,
                typecode.encode("ascii"),
            )
        )
        toc.extend(raw_name)
    cookie = struct.pack(
        signing.COOKIE_FORMAT,
        signing.COOKIE_MAGIC,
        len(payload) + len(toc) + signing.COOKIE_LENGTH,
        len(payload),
        len(toc),
        pyvers,
        raw_runtime + (b"\0" * (64 - len(raw_runtime))),
    )
    return prefix + bytes(payload) + bytes(toc) + cookie + suffix


def seal(binary: Path) -> None:
    native = _load_native_verifier()
    signing = native._load_signing_module()
    archive_start, cookie_offset, pyvers, pylib_name, entries = signing._archive_toc(binary)
    runtime_entries = [entry for entry in entries if native._is_native_runtime_entry(entry[0])]
    manifest_entries = [entry for entry in entries if native._is_native_manifest_entry(entry[0])]
    if len(runtime_entries) != 1:
        raise NativeManifestSealError(
            f"Core archive must contain exactly one native runtime; found {len(runtime_entries)}"
        )
    if len(manifest_entries) != 1:
        raise NativeManifestSealError(
            f"Core archive must contain exactly one native manifest; found {len(manifest_entries)}"
        )
    data = binary.read_bytes()
    rebuilt: list[tuple[str, bytes, int, bool, str]] = []
    runtime: bytes | None = None
    payload: dict[str, object] | None = None
    with binary.open("rb") as handle:
        for name, offset, stored_length, uncompressed, compressed, typecode in entries:
            stored = data[archive_start + offset : archive_start + offset + stored_length]
            if len(stored) != stored_length:
                raise NativeManifestSealError(f"Truncated PyInstaller archive entry: {name}")
            rebuilt.append((name, stored, uncompressed, compressed, typecode))
            if native._is_native_runtime_entry(name):
                try:
                    runtime = signing._entry_bytes(handle, archive_start, name, offset, stored_length, compressed)
                except (OSError, ValueError, zlib.error) as error:
                    raise NativeManifestSealError(f"Bundled native runtime is not readable: {name}") from error
                if len(runtime) != uncompressed:
                    raise NativeManifestSealError("Bundled native runtime size does not match its TOC entry")
            if native._is_native_manifest_entry(name):
                try:
                    decoded = signing._entry_bytes(handle, archive_start, name, offset, stored_length, compressed)
                    parsed = json.loads(decoded.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError, OSError, zlib.error) as error:
                    raise NativeManifestSealError("Bundled native manifest is not valid JSON") from error
                if len(decoded) != uncompressed:
                    raise NativeManifestSealError("Bundled native manifest size does not match its TOC entry")
                if not isinstance(parsed, dict) or parsed.get("schema") != _MANIFEST_SCHEMA:
                    raise NativeManifestSealError("Bundled native manifest failed identity checks")
                payload = parsed
    if runtime is None or payload is None:
        raise NativeManifestSealError("Core archive native runtime or manifest could not be read")
    digest = hashlib.sha256(runtime).hexdigest()
    if payload.get("runtime_sha256") == digest and payload.get("runtime_size") == len(runtime):
        print(f"native manifest already matches packaged runtime {runtime_entries[0][0]!r}")
        return
    payload["runtime_sha256"] = digest
    payload["runtime_size"] = len(runtime)
    encoded = _encode_manifest(payload)
    sealed: list[tuple[str, bytes, int, bool, str]] = []
    for name, stored, uncompressed, compressed, typecode in rebuilt:
        if native._is_native_manifest_entry(name):
            sealed.append((name, encoded, len(encoded), False, typecode))
            continue
        sealed.append((name, stored, uncompressed, compressed, typecode))
    binary.write_bytes(
        _rebuild_carchive(
            signing,
            prefix=data[:archive_start],
            suffix=data[cookie_offset + signing.COOKIE_LENGTH :],
            pyvers=pyvers,
            pylib_name=pylib_name,
            entries=sealed,
        )
    )
    print(f"resealed native manifest for {runtime_entries[0][0]!r} ({len(runtime)} bytes)")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    if not args.binary.is_file():
        raise SystemExit(f"Binary does not exist: {args.binary}")
    try:
        seal(args.binary)
    except (OSError, ValueError, zlib.error) as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    main()
