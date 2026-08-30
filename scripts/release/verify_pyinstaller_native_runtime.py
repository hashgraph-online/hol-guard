#!/usr/bin/env python3
"""Prove a Desktop Core onefile archive contains a sealed native runtime."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

_SIGNING_PATH = Path(__file__).with_name("verify_pyinstaller_macos_signing.py")
_RUNTIME_NAMES = {"hol-guard-runtime", "hol-guard-runtime.exe"}
_MANIFEST_NAME = "runtime-manifest.json"
_NATIVE_PARENT = "_native"
_MANIFEST_SCHEMA = "hol-guard-native-runtime.v1"


def _load_signing_module():
    spec = importlib.util.spec_from_file_location("verify_pyinstaller_macos_signing", _SIGNING_PATH)
    if spec is None or spec.loader is None:
        raise SystemExit("PyInstaller signing verifier is missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _posix_name(name: str) -> str:
    return name.replace("\\", "/")


def _is_native_runtime_entry(name: str) -> bool:
    parts = Path(_posix_name(name)).parts
    return len(parts) >= 2 and parts[-1] in _RUNTIME_NAMES and parts[-2] == _NATIVE_PARENT


def _is_native_manifest_entry(name: str) -> bool:
    parts = Path(_posix_name(name)).parts
    return len(parts) >= 2 and parts[-1] == _MANIFEST_NAME and parts[-2] == _NATIVE_PARENT


def verify(binary: Path, expected_team_id: str | None = None) -> None:
    signing = _load_signing_module()
    archive_start, _declared_runtime, entries = signing._archive_layout(binary)
    runtime_entries = [entry for entry in entries if _is_native_runtime_entry(entry[0])]
    manifest_entries = [entry for entry in entries if _is_native_manifest_entry(entry[0])]
    if len(runtime_entries) != 1:
        raise ValueError(f"Core archive must contain exactly one native runtime; found {len(runtime_entries)}")
    if len(manifest_entries) != 1:
        raise ValueError(f"Core archive must contain exactly one native manifest; found {len(manifest_entries)}")
    with binary.open("rb") as handle:
        runtime_name, runtime_offset, runtime_length, runtime_compressed, _typecode = runtime_entries[0]
        manifest_name, manifest_offset, manifest_length, manifest_compressed, _manifest_type = manifest_entries[0]
        runtime = signing._entry_bytes(
            handle,
            archive_start,
            runtime_name,
            runtime_offset,
            runtime_length,
            runtime_compressed,
        )
        manifest_bytes = signing._entry_bytes(
            handle,
            archive_start,
            manifest_name,
            manifest_offset,
            manifest_length,
            manifest_compressed,
        )
    try:
        payload = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Bundled native manifest is not valid JSON") from error
    if not isinstance(payload, dict) or payload.get("schema") != _MANIFEST_SCHEMA:
        raise ValueError("Bundled native manifest failed identity checks")
    digest = hashlib.sha256(runtime).hexdigest()
    if payload.get("runtime_sha256") != digest or payload.get("runtime_size") != len(runtime):
        raise ValueError("Bundled native runtime digest does not match its manifest")
    if expected_team_id:
        import tempfile

        with tempfile.TemporaryDirectory(prefix="hol-guard-native-runtime-") as tmp:
            extracted = Path(tmp) / Path(runtime_name).name
            extracted.write_bytes(runtime)
            actual_team_id = signing._team_id(extracted)
            if actual_team_id != expected_team_id:
                raise ValueError(
                    f"Bundled native runtime has TeamIdentifier={actual_team_id!r}; expected {expected_team_id!r}"
                )
    print(f"verified bundled native runtime {runtime_name!r} ({len(runtime)} bytes)")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--team-id")
    args = parser.parse_args()
    if not args.binary.is_file():
        raise SystemExit(f"Binary does not exist: {args.binary}")
    try:
        verify(args.binary, args.team_id)
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    main()
