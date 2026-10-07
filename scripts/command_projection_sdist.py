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


def projection_manifest(root: Path) -> dict:
    """Fingerprint canonical sources, native implementation, and packaged outputs."""
    generator = _generator(root)
    for name in NAMES:
        generator.read_object(root / "contracts/extensions" / name)
    request = generator.build_request()
    if generator.read_object(root / "contracts/extensions/trust-class-map.v1.json") != request["trust"]:
        raise ValueError("source-distribution trust map does not match authored bindings")
    return {
        "schema": "guard.command-projection-build.v1",
        "request_sha256": hashlib.sha256(generator.canonical_bytes(request)).hexdigest(),
        "bindings_sha256": _binding_fingerprint(root),
        "implementation_digest": generator.implementation_digest(),
        "artifacts": {
            name: hashlib.sha256((root / "contracts/extensions" / name).read_bytes()).hexdigest() for name in NAMES
        },
    }


def write_projection_manifest(root: Path) -> None:
    """Record the source and output fingerprints shipped in the source archive."""
    generator = _generator(root)
    destination = root / MANIFEST
    if destination.is_symlink():
        raise ValueError("source-distribution projection manifest cannot be a symlink")
    destination.write_bytes(generator.canonical_bytes(projection_manifest(root)))


def verify_projection_manifest(root: Path) -> None:
    """Never accept archive projections after any bound input has changed."""
    generator = _generator(root)
    if generator.read_object(root / MANIFEST) != projection_manifest(root):
        raise ValueError("source-distribution command projections do not match their build inputs")
