"""Bind frozen source-distribution projections to every native build input."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

NAMES = ("command-catalog.v1.json", "native-command-program.v1.json", "trust-class-map.v1.json")
MANIFEST = "contracts/extensions/command-projection-build.v1.json"


def _binding_fingerprint(root: Path) -> str:
    """Fingerprint authored trust bindings byte-for-byte so any edit invalidates the archive."""
    directory = root / "contracts/extensions/trust"
    digest = hashlib.sha256(b"hol-guard.extension-trust-bindings.v1\0")
    for path in sorted(directory.glob("*.v1.json")):
        if path.is_symlink() or not path.is_file():
            raise ValueError("invalid trust binding input")
        name = path.name.encode()
        content = path.read_bytes()
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _generator(root: Path):
    """Load the archived generator so fingerprints use the same canonical input rules."""
    spec = importlib.util.spec_from_file_location(
        "command_projection_generator", root / "scripts/build_native_command_program.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _trust_artifact(root: Path) -> Path:
    """Use the archive resource only inside a source distribution."""
    name = "trust-class-map.v1.json" if (root / "PKG-INFO").is_file() else "build-trust-class-map.v1.json"
    return root / "contracts/extensions" / name


def projection_manifest(root: Path, *, descriptors: Path | None = None, trust_map: Path | None = None) -> dict:
    """Fingerprint canonical sources, native implementation, and packaged outputs."""
    generator = _generator(root)
    trust_map = trust_map or _trust_artifact(root)
    paths = {
        name: trust_map if name == "trust-class-map.v1.json" else root / "contracts/extensions" / name for name in NAMES
    }
    for name in NAMES:
        generator.read_object(paths[name])
    request = generator.build_request()
    if generator.read_object(trust_map) != generator.packaged_trust_map(request):
        raise ValueError("source-distribution trust map does not match authored bindings")
    result = {
        "schema": "guard.command-projection-build.v1",
        "request_sha256": hashlib.sha256(generator.canonical_bytes(request)).hexdigest(),
        "bindings_sha256": _binding_fingerprint(root),
        "implementation_digest": generator.implementation_digest(),
        "artifacts": {name: hashlib.sha256(paths[name].read_bytes()).hexdigest() for name in NAMES},
    }
    if descriptors is not None:
        if descriptors.is_symlink():
            raise ValueError("descriptor directory cannot be a symlink")
        result["descriptors"] = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(descriptors.glob("command.*.json"))
            if not path.is_symlink() and path.is_file()
        }
        if any(path.is_symlink() for path in descriptors.glob("*.json")):
            raise ValueError("descriptor cannot be a symlink")
    if trust_map is not None:
        generator.read_object(trust_map)
        result["trust_map_sha256"] = hashlib.sha256(trust_map.read_bytes()).hexdigest()
    return result


def write_projection_manifest(root: Path, *, descriptors: Path | None = None, trust_map: Path | None = None) -> None:
    """Record the source and output fingerprints shipped in the source archive."""
    generator = _generator(root)
    destination = root / MANIFEST
    if destination.is_symlink():
        raise ValueError("source-distribution projection manifest cannot be a symlink")
    destination.write_bytes(
        generator.canonical_bytes(projection_manifest(root, descriptors=descriptors, trust_map=trust_map))
    )


def verify_projection_manifest(root: Path) -> None:
    """Never accept archive projections after any bound input has changed."""
    generator = _generator(root)
    saved = generator.read_object(root / MANIFEST)
    descriptors = root / "contributions/extensions" if "descriptors" in saved else None
    trust_map = _trust_artifact(root) if "trust_map_sha256" in saved else None
    if saved != projection_manifest(root, descriptors=descriptors, trust_map=trust_map):
        raise ValueError("source-distribution command projections do not match their build inputs")
