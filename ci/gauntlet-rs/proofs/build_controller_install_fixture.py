"""Build an inert, exact-source controller tree fixture for the Rust verifier.

This proof helper reads the pinned source maps and current regular files. It
does not install, import, or execute controller code.
"""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile


WORKSPACE = Path(__file__).resolve().parents[3]
MAP_DIR = WORKSPACE / "ci/gauntlet-rs"
CONTROL_PLANE = {
    "__init__.py", "vm_worker.py", "vm_live.py", "vm_features.py",
    "feature_entry.py", "stage_candidate.py", "artifacts.py", "vm_build.py",
    "vm_network.py", "Builder.Dockerfile", "Builder.apparmor",
    "builder_entry.py", "build_artifact.py", "stage_outcome.py",
    "executor_image.py", "bootstrap_guest.py", "Executor.Dockerfile",
    "malloc_policy.c", "malloc.preload",
}


def source_hashes() -> dict[str, str]:
    baseline = json.loads((MAP_DIR / "parity-manifest.v1.json").read_bytes())
    delta = json.loads((MAP_DIR / "integration-source-delta.v1.json").read_bytes())
    if delta["base_source_commit"] != baseline["source_commit"]:
        raise ValueError("source-map base differs")
    values = {row["path"]: row["sha256"] for row in baseline["files"]}
    for row in delta["changed"]:
        if values.get(row["path"]) != row["base_sha256"]:
            raise ValueError("changed source-map base differs")
        values[row["path"]] = row["sha256"]
    for row in delta["added"]:
        if row["path"] in values:
            raise ValueError("duplicate source-map addition")
        values[row["path"]] = row["sha256"]
    if len(values) != delta["source_file_count"] or (WORKSPACE / "ci/__init__.py").exists():
        raise ValueError("unexpected source-map shape")
    return values


def selected(path: str) -> bool:
    parts = path.split("/")
    return (
        path.startswith("ci/gauntlet/")
        and "__pycache__" not in parts
        and not path.endswith(".pyc")
        and ("control_plane" not in parts or parts[-1] in CONTROL_PLANE)
    )


def info(name: str, mode: int, size: int, *, directory: bool = False) -> tarfile.TarInfo:
    item = tarfile.TarInfo(name + ("/" if directory else ""))
    item.uid = item.gid = item.mtime = 0
    item.uname = item.gname = ""
    item.mode = mode
    item.size = size
    item.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    return item


def main(destination: Path) -> None:
    if destination.exists() or destination.is_symlink():
        raise ValueError("fixture destination already exists")
    files = {path: digest for path, digest in source_hashes().items() if selected(path)}
    if len(files) != 396:
        raise ValueError("current controller selection changed")
    directories = set()
    for name in files:
        parts = name.split("/")
        directories.update("/".join(parts[:depth]) for depth in range(1, len(parts)))
    total = 0
    contents = {}
    for name, expected in sorted(files.items()):
        path = WORKSPACE / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"source is not an ordinary file: {name}")
        raw = path.read_bytes()
        if len(raw) > 8 * 1024**2 or hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError(f"source differs from pinned map or byte limit: {name}")
        contents[name] = raw
        total += len(raw)
    if total > 64 * 1024**2:
        raise ValueError("controller fixture exceeds bootstrap byte limit")
    with tarfile.open(destination, "x:") as archive:
        for name in sorted(directories):
            archive.addfile(info(name, 0o755, 0, directory=True))
        for name, raw in sorted(contents.items()):
            archive.addfile(info(name, 0o444, len(raw)), io.BytesIO(raw))
    print(json.dumps({
        "archive_sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
        "files": len(files), "directories": len(directories), "bytes": total,
    }, sort_keys=True))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: build_controller_install_fixture.py EXACT_OUTPUT_TAR")
    main(Path(sys.argv[1]))
