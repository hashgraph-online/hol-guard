"""Create immutable extension directory snapshots without changing Git history."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

SCHEMA = "guard.extension-artifacts.v1"
ARCHIVE = "extension-artifacts.zip"
MANIFEST = "extension-artifacts.v1.json"
MAX_FILES = 2048
MAX_BYTES = 32 * 1024 * 1024
FILES = (
    "contracts/extensions/command-catalog.v1.json",
    "contracts/extensions/native-command-program.v1.json",
    "contracts/extensions/trust-class-map.v1.json",
    "docs/guard/extensions/catalog.v1.json",
    "docs/guard/extensions/catalog.v2.json",
    "docs/guard/extensions/README.md",
)
DIRECTORIES = (
    "contributions/command-sources",
    "contributions/extensions",
    "contributions/mcp-servers",
    "contributions/extension-listings",
    "contracts/extensions/trust",
)


def source_sha(value: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise ValueError("snapshot source must be a full commit SHA")
    return value


def selected_files(root: Path) -> list[Path]:
    paths = [root / name for name in FILES if name != "contracts/extensions/trust-class-map.v1.json"]
    for name in DIRECTORIES:
        directory = root / name
        if directory.is_symlink():
            raise ValueError("snapshot input directory cannot be a symlink")
        paths.extend(sorted(directory.glob("*.json")))
    if len(paths) > MAX_FILES or len(paths) != len(set(paths)):
        raise ValueError("snapshot file inventory is invalid")
    for path in paths:
        if any(parent.is_symlink() for parent in (path, *path.parents) if parent != root):
            raise ValueError("snapshot input cannot traverse a symlink")
        if not path.is_file():
            raise ValueError("snapshot input is missing")
    if sum(path.stat().st_size for path in paths) > MAX_BYTES:
        raise ValueError("snapshot exceeds byte limit")
    return sorted(paths)


def create_bundle(root: Path, output: Path, expected_sha: str) -> dict:
    expected_sha = source_sha(expected_sha)
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True, timeout=15).strip()
    if actual != expected_sha:
        raise ValueError("snapshot checkout does not match the requested source")
    files = {path.relative_to(root).as_posix(): path.read_bytes() for path in selected_files(root)}
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from extension_trust_projection import repository_trust_map

    files["contracts/extensions/trust-class-map.v1.json"] = (
        json.dumps(repository_trust_map(root), sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    if len(files) > MAX_FILES or sum(map(len, files.values())) > MAX_BYTES:
        raise ValueError("snapshot exceeds inventory or byte limit")
    catalog = json.loads(files[FILES[0]])
    manifest = {
        "schema": SCHEMA,
        "source_sha": actual,
        "catalog_digest": catalog["catalog_digest"],
        "program_digest": catalog["program_digest"],
        "implementation_digest": catalog["implementation_digest"],
        "files": {
            name: {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)} for name, data in files.items()
        },
    }
    output.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output / ARCHIVE, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            info = zipfile.ZipInfo(name)
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    manifest["archive_sha256"] = hashlib.sha256((output / ARCHIVE).read_bytes()).hexdigest()
    (output / MANIFEST).write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    verify_bundle(output, expected_sha)
    return manifest


def verify_bundle(directory: Path, expected_sha: str) -> dict:
    manifest_path = directory / MANIFEST
    archive_path = directory / ARCHIVE
    if any(path.is_symlink() for path in (directory, manifest_path, archive_path)):
        raise ValueError("snapshot assets cannot be symlinks")
    if manifest_path.stat().st_size > 1024 * 1024 or archive_path.stat().st_size > MAX_BYTES:
        raise ValueError("snapshot assets exceed byte limit")
    manifest = json.loads(manifest_path.read_bytes())
    if manifest.get("schema") != SCHEMA or manifest.get("source_sha") != source_sha(expected_sha):
        raise ValueError("snapshot identity does not match")
    files = manifest["files"]
    if not isinstance(files, dict) or not files or len(files) > MAX_FILES:
        raise ValueError("snapshot inventory is invalid")
    if hashlib.sha256(archive_path.read_bytes()).hexdigest() != manifest["archive_sha256"]:
        raise ValueError("snapshot archive digest does not match")
    with zipfile.ZipFile(archive_path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or set(names) != set(files):
            raise ValueError("snapshot archive inventory does not match")
        if sum(info.file_size for info in archive.infolist()) > MAX_BYTES:
            raise ValueError("snapshot expanded size exceeds byte limit")
        for name in names:
            path = Path(name)
            mode = archive.getinfo(name).external_attr >> 16
            if path.is_absolute() or ".." in path.parts or "\\" in name or not stat.S_ISREG(mode):
                raise ValueError("snapshot archive path is invalid")
            data = archive.read(name)
            if files[name] != {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}:
                raise ValueError("snapshot file digest does not match")
        if not set(FILES).issubset(files):
            raise ValueError("snapshot is missing required artifacts")
        catalog = json.loads(archive.read(FILES[0]))
        for key in ("catalog_digest", "program_digest", "implementation_digest"):
            if not isinstance(manifest.get(key), str) or not re.fullmatch(r"[0-9a-f]{64}", manifest[key]):
                raise ValueError("snapshot native identity is invalid")
            if catalog.get(key) != manifest[key]:
                raise ValueError("snapshot native identity does not match")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    result = (
        verify_bundle(args.output, args.source_sha)
        if args.verify
        else create_bundle(root, args.output, args.source_sha)
    )
    print(json.dumps({"ok": True, "source_sha": result["source_sha"], "files": len(result["files"])}))


if __name__ == "__main__":
    main()
