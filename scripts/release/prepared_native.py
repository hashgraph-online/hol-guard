"""Bind exact-run native compiler/runtime artifacts to their source and version."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def transfer(directory: Path, *, install: bool) -> None:
    expected = {"source_sha": os.environ["SOURCE_SHA"], "version": os.environ["VERSION"]}
    paths = {key: Path(os.environ[key]) for key in ("RUNTIME", "SOURCE_COMPILER")}
    manifest = directory / "identity.json"
    if install:
        recorded = json.loads(manifest.read_text())
        if any(recorded.get(key) != value for key, value in expected.items()):
            raise ValueError("prepared native source/version mismatch")
        for key, destination in paths.items():
            source = directory / destination.name
            if source.is_symlink() or digest(source) != recorded["sha256"][key]:
                raise ValueError("prepared native binary hash mismatch")
        for destination in paths.values():
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(directory / destination.name, destination)
            destination.chmod(0o755)
    else:
        directory.mkdir(parents=True, exist_ok=False)
        hashes = {}
        for key, source in paths.items():
            shutil.copyfile(source, directory / source.name)
            hashes[key] = digest(source)
        manifest.write_text(json.dumps({**expected, "sha256": hashes}, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("pack", "install"))
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    transfer(args.directory, install=args.action == "install")
