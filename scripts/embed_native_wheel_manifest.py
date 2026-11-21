#!/usr/bin/env python3
"""Embed the native wheel digest manifest in the pure hol-guard wheel.

Native wheels for some platforms ship on the GitHub release only. A client that
installed the pure wheel from the registry downloads its platform wheel from the
release and verifies it against this manifest, which the registry served inside
the pure wheel it already trusts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

from packaging.utils import InvalidWheelFilename, parse_wheel_filename

if __package__:
    from .build_native_hol_guard_wheel import (
        NativeWheelError,
        _load_source_wheel,
        _record_content,
        _wheel_version_for_filename,
        _write_output_wheel_exclusive,
    )
else:
    from build_native_hol_guard_wheel import (  # pyright: ignore[reportImplicitRelativeImport]
        NativeWheelError,
        _load_source_wheel,
        _record_content,
        _wheel_version_for_filename,
        _write_output_wheel_exclusive,
    )

MANIFEST_SCHEMA = "hol-guard-native-wheels.v1"
MANIFEST_MEMBER = "codex_plugin_scanner/native-wheels.json"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def native_wheel_digests(dist_dir: Path, *, version: str) -> dict[str, str]:
    """Return ``{native wheel name: sha256}`` for every hol-guard platform wheel in ``dist_dir``."""

    digests: dict[str, str] = {}
    for path in sorted(dist_dir.glob("hol_guard-*.whl")):
        try:
            name, wheel_version, _build, tags = parse_wheel_filename(path.name)
        except InvalidWheelFilename as exc:
            raise NativeWheelError(f"invalid wheel filename: {path.name}") from exc
        if name != "hol-guard" or str(wheel_version) != version:
            raise NativeWheelError(f"unexpected wheel in distribution directory: {path.name}")
        if all(tag.platform == "any" for tag in tags):
            continue
        if path.is_symlink() or not path.is_file():
            raise NativeWheelError(f"native wheel must be a regular file: {path.name}")
        digests[path.name] = _sha256_file(path)
    if not digests:
        raise NativeWheelError("distribution directory has no native wheels")
    return digests


def manifest_bytes(version: str, digests: dict[str, str]) -> bytes:
    document = {"schema": MANIFEST_SCHEMA, "version": version, "wheels": dict(sorted(digests.items()))}
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def embed_manifest(dist_dir: Path, *, version: str) -> Path:
    """Rewrite the pure wheel in ``dist_dir`` with the manifest of its sibling native wheels."""

    pure = dist_dir / f"hol_guard-{_wheel_version_for_filename(version)}-py3-none-any.whl"
    source = _load_source_wheel(pure, version=version)
    if MANIFEST_MEMBER in source.entries:
        raise NativeWheelError("pure wheel already contains a native wheel manifest")
    entries = dict(source.entries)
    modes = dict(source.modes)
    entries[MANIFEST_MEMBER] = manifest_bytes(version, native_wheel_digests(dist_dir, version=version))
    modes[MANIFEST_MEMBER] = 0o644
    entries[source.record_path] = _record_content(entries, record_path=source.record_path)
    staged = pure.with_name(f".{pure.name}.manifest")
    staged.unlink(missing_ok=True)
    try:
        _write_output_wheel_exclusive(staged, entries, modes)
        os.replace(staged, pure)
    finally:
        staged.unlink(missing_ok=True)
    return pure


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir", type=Path, required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args(argv)
    try:
        pure = embed_manifest(args.dist_dir, version=args.version)
    except (NativeWheelError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"status": "embedded", "wheel": pure.name, "sha256": _sha256_file(pure)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
