"""Maintainer core selection and separate complete pack descriptor projection."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def core_entries(root, read_object) -> list[dict]:
    """Maintainer selection, never inferred from the growing optional inventory."""
    manifest = read_object(root / "contracts/extensions/core-defaults.v1.json")
    entries = manifest.get("entries")
    if (
        manifest.get("schema") != "guard.core-defaults.v1"
        or not isinstance(entries, list)
        or not 0 < len(entries) <= 512
    ):
        raise ValueError("invalid core/default manifest")
    seen = set()
    for entry in entries:
        identity = entry.get("extension_id")
        if (
            not isinstance(identity, str)
            or not identity.startswith("command.")
            or any(c in identity for c in "/\\")
            or identity in seen
        ):
            raise ValueError("invalid/duplicate core identity")
        seen.add(identity)
        source = (
            f"contributions/mcp-servers/mcp.{identity.removeprefix('command.mcp-')}.json"
            if identity.startswith("command.mcp-")
            else f"contributions/command-sources/{identity}.json"
        )
        if entry != {
            "extension_id": identity,
            "source": source,
            "trust": f"contracts/extensions/trust/{identity}.v1.json",
        }:
            raise ValueError("invalid core input paths")
        binding = read_object(root / entry["trust"])
        if binding.get("extension") != identity or binding.get("trustClass") not in {"first-party", "trusted-library"}:
            raise ValueError("core inputs must have reviewed nonexternal trust")
    return entries


def core_trust(root, read_object):
    classes = {name: [] for name in ("first-party", "trusted-library", "external")}
    for entry in core_entries(root, read_object):
        binding = read_object(root / entry["trust"])
        if binding.get("schemaVersion") != "guard.extension-trust-binding.v1":
            raise ValueError("invalid core trust schema")
        classes[binding["trustClass"]].append(entry["extension_id"])
    return {
        "schemaVersion": "guard.extension-trust-class-map.v1",
        "publishers": {
            "hol": {"id": "hol", "displayName": "HOL"},
            "hol-curated": {"id": "hol-curated", "displayName": "HOL curated library"},
        },
        "classes": {name: sorted(ids) for name, ids in classes.items()},
    }


def pack_descriptors(root, compiler: Path | None, read_object, *, inventory=None) -> list[dict]:
    """Public descriptors come from the complete pack stream, never an aggregate program."""
    if compiler is None:
        metadata = subprocess.run(
            [
                "cargo",
                "+1.88.0",
                "metadata",
                "--no-deps",
                "--format-version",
                "1",
                "--manifest-path",
                str(root / "rust/Cargo.toml"),
            ],
            capture_output=True,
            check=True,
            cwd=root,
            timeout=60,
        )
        import os

        compiler = (
            Path(json.loads(metadata.stdout)["target_directory"])
            / "debug"
            / ("guard-command-source.exe" if os.name == "nt" else "guard-command-source")
        )
    sys.path.insert(0, str(root / "scripts"))
    try:
        from build_native_command_packs import stage
        from command_pack_store import PackReader
        from extension_delivery_objects import entries
    finally:
        # Leaving scripts/ first lets scripts/ci shadow the ci namespace package.
        sys.path.remove(str(root / "scripts"))

    def descriptors(directory):
        release = read_object(directory / "release.json", root=directory)
        reader = PackReader(directory / "objects")
        result = []
        for _, reference in entries(reader, release["index"], release["extensions"]):
            manifest = reader.json(reference)
            result.extend(reader.json(manifest["descriptors"]))
        return result

    if inventory is not None:
        with inventory.open(compiler, root=root) as (directory, _, _):
            return descriptors(directory)
    with tempfile.TemporaryDirectory(prefix="hol-guard-descriptors-") as scratch:
        directory = Path(scratch).resolve(strict=True)
        stage(compiler.resolve(strict=True), directory, source_root=root)
        return descriptors(directory)


def _implementation_files(directory: Path) -> set[Path]:
    """Match the native walk: reject links before selecting regular sources."""
    if directory.is_symlink():
        raise ValueError("invalid native implementation input")
    selected = set()
    for path in directory.rglob("*"):
        if path.is_symlink():
            raise ValueError("invalid native implementation input")
        if path.is_file() and path.suffix in (".rs", ".json"):
            selected.add(path)
    return selected


def implementation_digest(root) -> str:
    """Mirror the Rust build fingerprint, not its compilation or admission logic."""
    workspace = root / "rust"
    manifest_path = workspace / "build_support/command_source_inputs.v2.json"
    if manifest_path.is_symlink():
        raise ValueError("invalid native implementation input")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != "guard.command-source-inputs.v2":
        raise ValueError("invalid command source inputs manifest")
    domain = manifest.get("identity_domain")
    if not isinstance(domain, str) or not domain:
        raise ValueError("invalid command source inputs identity domain")
    paths = {workspace / "Cargo.lock", workspace / "Cargo.toml"}
    for relative in manifest.get("files", ()):
        if (
            not isinstance(relative, str)
            or not relative
            or relative.startswith(("/", "\\"))
            or any(part in ("", ".", "..") for part in relative.split("/"))
        ):
            raise ValueError("invalid command source inputs file")
        path = workspace / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError("invalid native implementation input")
        paths.add(path)
    for name in manifest.get("crates", ()):
        if not isinstance(name, str) or not name.replace("-", "").replace("_", "").isalnum():
            raise ValueError("invalid command source inputs crate")
        crate = workspace / "crates" / name
        if crate.is_symlink():
            raise ValueError("invalid native implementation input")
        manifest_file = crate / "Cargo.toml"
        if manifest_file.is_symlink() or not manifest_file.is_file():
            raise ValueError("invalid native implementation input")
        paths.add(manifest_file)
        if (crate / "build.rs").is_file():
            paths.add(crate / "build.rs")
        if (crate / "src").is_dir():
            paths.update(_implementation_files(crate / "src"))
    for name, entries in manifest.get("crate_files", {}).items():
        if not isinstance(name, str) or not name.replace("-", "").replace("_", "").isalnum():
            raise ValueError("invalid command source inputs crate")
        if not isinstance(entries, list):
            raise ValueError("invalid command source inputs crate_files")
        crate = workspace / "crates" / name
        # The listed sources are only part of what builds this crate: its own
        # manifest and build script decide what the producer compiles to, so
        # they belong in the identity as they do for a whole-crate entry.
        manifest_file = crate / "Cargo.toml"
        if manifest_file.is_symlink() or not manifest_file.is_file():
            raise ValueError("invalid native implementation input")
        paths.add(manifest_file)
        if (crate / "build.rs").is_file():
            paths.add(crate / "build.rs")
        for relative in entries:
            if (
                not isinstance(relative, str)
                or not relative
                or relative.startswith(("/", "\\"))
                or any(part in ("", ".", "..") for part in relative.split("/"))
            ):
                raise ValueError("invalid command source inputs crate_files path")
            path = crate / relative
            if path.is_symlink() or not path.is_file():
                raise ValueError("invalid native implementation input")
            paths.add(path)
    digest = hashlib.sha256(domain.encode() + b"\0")
    for path in sorted(paths, key=lambda item: item.relative_to(workspace).as_posix()):
        if path.is_symlink() or not path.is_file():
            raise ValueError("invalid native implementation input")
        name = path.relative_to(workspace).as_posix().encode()
        content = path.read_bytes().replace(b"\r\n", b"\n")
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()
