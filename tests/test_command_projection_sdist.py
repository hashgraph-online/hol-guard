"""Source archives can reuse projections only while every bound input matches."""

from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path

import pytest


@pytest.fixture
def archive(tmp_path):
    """Create a minimal source archive with fingerprints for authored inputs and outputs."""
    (tmp_path / "PKG-INFO").write_text("Metadata-Version: 2.1\n")
    root = Path(__file__).parents[1]
    spec = importlib.util.spec_from_file_location(
        "command_projection_sdist_test", root / "scripts/command_projection_sdist.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    files = {
        "contributions/command-sources/command.example.json": {"extension": {"extension_id": "command.example"}},
        "contracts/extensions/trust/command.example.v1.json": {
            "schemaVersion": "guard.extension-trust-binding.v1",
            "extension": "command.example",
            "trustClass": "external",
        },
        "contracts/extensions/command-catalog.v1.json": {"catalog": []},
        "contracts/extensions/native-command-program.v1.json": {"rules": []},
        "contracts/extensions/trust-class-map.v1.json": {
            "schemaVersion": "guard.extension-trust-class-map.v1",
            "publishers": {
                "hol": {"id": "hol", "displayName": "Hashgraph Online"},
                "hol-curated": {"id": "hol-curated", "displayName": "HOL curated library"},
            },
            "classes": {"first-party": [], "trusted-library": [], "external": ["command.example"]},
        },
        "rust/Cargo.toml": "[workspace]\n",
        "rust/Cargo.lock": "version = 4\n",
        "rust/crates/example/src/lib.rs": "// implementation\n",
    }
    for relative, value in files.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value) if isinstance(value, dict) else value)
    (tmp_path / "contributions/mcp-servers").mkdir()
    (tmp_path / "rust/build_support").mkdir()
    (tmp_path / "scripts").mkdir()
    shutil.copyfile(
        root / "scripts/build_native_command_program.py", tmp_path / "scripts/build_native_command_program.py"
    )
    module.write_projection_manifest(tmp_path)
    return module, tmp_path


def test_frozen_archive_inputs_verify_without_invoking_rust(archive):
    """Unmodified archive fingerprints verify using Python alone."""
    module, root = archive
    module.verify_projection_manifest(root)


@pytest.mark.parametrize(
    "relative",
    [
        "contributions/command-sources/command.example.json",
        "contracts/extensions/trust/command.example.v1.json",
        "rust/crates/example/src/lib.rs",
        "rust/Cargo.lock",
        "contracts/extensions/command-catalog.v1.json",
        "contracts/extensions/native-command-program.v1.json",
        "contracts/extensions/trust-class-map.v1.json",
    ],
)
def test_changed_archive_input_or_output_is_rejected(archive, relative):
    """Changes to any bound source, implementation, or projection invalidate the archive."""
    module, root = archive
    path = root / relative
    if path.suffix == ".json":
        value = json.loads(path.read_text())
        value["changed"] = True
        path.write_text(json.dumps(value))
    else:
        path.write_text(path.read_text() + "changed\n")
    with pytest.raises(ValueError, match=r"do not match|does not match"):
        module.verify_projection_manifest(root)


def test_archive_manifest_cannot_rebind_a_promoted_trust_projection(archive):
    """An output cannot promote an external extension even with a refreshed manifest."""
    module, root = archive
    path = root / "contracts/extensions/trust-class-map.v1.json"
    payload = json.loads(path.read_text())
    payload["classes"] = {"first-party": ["command.example"], "trusted-library": [], "external": []}
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="trust map does not match authored bindings"):
        module.write_projection_manifest(root)


def test_new_canonical_source_is_rejected(archive):
    """Adding an authored source must invalidate the existing archive fingerprint."""
    module, root = archive
    (root / "contributions/command-sources/command.added.json").write_text(
        json.dumps({"extension": {"extension_id": "command.added"}})
    )
    with pytest.raises(ValueError, match="not match"):
        module.verify_projection_manifest(root)


def test_descriptor_projection_is_bound_in_new_archives(archive):
    module, root = archive
    descriptors = root / "contributions/extensions"
    descriptors.mkdir()
    descriptor = descriptors / "command.example.json"
    descriptor.write_text('{"id":"command.example"}')
    module.write_projection_manifest(root, descriptors=descriptors)
    module.verify_projection_manifest(root)
    descriptor.write_text('{"id":"command.changed"}')
    with pytest.raises(ValueError, match="do not match"):
        module.verify_projection_manifest(root)


def test_generated_trust_map_is_bound_in_new_archives(archive):
    module, root = archive
    trust_map = root / "contracts/extensions/trust-class-map.v1.json"
    module.write_projection_manifest(root, trust_map=trust_map)
    module.verify_projection_manifest(root)
    trust_map.write_text('{"classes":{"first-party":["command.example"]}}')
    with pytest.raises(ValueError, match="not match"):
        module.verify_projection_manifest(root)


def test_unbound_canonical_contributions_default_to_external(archive):
    module, root = archive
    generator = module._generator(root)
    request = generator.build_request()
    request["sources"].append({"extension": {"extension_id": "command.new"}})
    request["mcp_sources"].append({"id": "mcp.new-server"})
    trust = generator.packaged_trust_map(request)
    assert set(trust["classes"]["external"]) == {"command.example", "command.new", "command.mcp-new-server"}
    assert request["trust"]["classes"]["external"] == ["command.example"]
