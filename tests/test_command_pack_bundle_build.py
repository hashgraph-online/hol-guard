"""Bundle archives preserve independent read sets and frozen source inputs."""

from __future__ import annotations

import importlib
import io
import json
import zipfile
from pathlib import Path

import pytest


@pytest.fixture
def modules(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    return tuple(
        importlib.import_module(name)
        for name in (
            "command_pack_bundle_build",
            "extension_policy_delivery",
            "extension_delivery_assets",
            "extension_delivery_located_store",
            "extension_delivery_objects",
        )
    )


def test_each_pack_archive_contains_only_its_own_complete_read_set(modules, tmp_path, monkeypatch):
    _, policy, assets, located, objects = modules
    compiled = tmp_path / "compiled"
    store = objects.ObjectStore(compiled / "objects")
    shared = store.put_json({"shared": "matcher"})
    manifests = {}
    expected = {}
    for identity in ("command.first", "command.second"):
        catalog = store.put_json(
            [
                {
                    "extension_id": identity,
                    "enabled": False,
                    "dependencies": [],
                    "required": False,
                    "activation": "opt-in",
                    "trust_class": "external",
                }
            ]
        )
        program = store.put_json({"nodes": {"shared": shared}})
        descriptors = store.put_json({"identity": identity})
        manifest = store.put_json(
            {
                "schema": "guard.command-policy-pack.v1",
                "extension_id": identity,
                "program": program,
                "catalog": catalog,
                "descriptors": descriptors,
                "related_interfaces": [],
            }
        )
        manifests[identity] = manifest
        expected[identity] = {row["sha256"] + ".json" for row in (shared, catalog, program, descriptors, manifest)}
    native = {"extensions": 2, "index": store.index(manifests)}
    plan = assets.AssetPlan(tmp_path / "assets", "a" * 40)
    delivered = located.LocatedStore(tmp_path / "metadata", publisher=plan)
    requests = []

    def select(operation, request, *, compiler):
        requests.append((operation, request, compiler))
        return {"selected_ids": ["command.second"]}

    monkeypatch.setattr(policy, "run_source_compiler", select)
    compiler = tmp_path / "compiler"
    core = {"schema": "guard.core-defaults.v1", "entries": []}
    result = policy.build_policy(compiled, native, plan, delivered, compiler=compiler, core_defaults=core)
    assert requests == [
        (
            "bundle-metadata",
            {
                "operation": "release-defaults",
                "catalogs": [
                    {"extension_id": identity, "enabled": False, "trust_class": "external"}
                    for identity in ("command.first", "command.second")
                ],
                "core_defaults": core,
            },
            compiler,
        )
    ]
    assert result["defaults"]["count"] == 1
    selected = [identity for identity, _ in objects.entries(delivered, result["defaults"]["index"], 1)]
    assert selected == ["command.second"]
    plan.finish()
    records = delivered.json(result["transport"])["records"]
    from codex_plugin_scanner.guard.catalog_delivery.containers import member

    for identity, reference in records:
        record = delivered.json(reference)
        assert len(record["archives"]) == 1
        archive = record["archives"][0]
        target = archive["location"]
        container = (plan.directory / target["tag"] / target["asset"]).read_bytes()
        data = member(container, target["asset"], target["member"], archive["length"])
        with zipfile.ZipFile(io.BytesIO(data)) as part:
            assert set(part.namelist()) == expected[identity]


@pytest.fixture
def frozen(modules, tmp_path):
    build = modules[0]
    for relative in (
        "rust/Cargo.toml",
        "rust/Cargo.lock",
        "pyproject.toml",
        "scripts/tool.py",
        "contributions/command-sources/command.example.json",
        "contracts/catalog-delivery/security.v1.json",
        "rust/crates/example/src/lib.rs",
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("original")
    directory = tmp_path / build.DIRECTORY
    directory.mkdir(parents=True)
    (directory / "command-pack-bundle.v1.json").write_text("{}")
    manifest = tmp_path / build.MANIFEST
    manifest.write_text(json.dumps(build.frozen_manifest(tmp_path, directory)))
    return build, tmp_path, directory, manifest


def test_frozen_bundle_verifies_without_compiler_or_git(frozen, monkeypatch):
    build, root, directory, manifest = frozen
    monkeypatch.setattr(build.subprocess, "run", lambda *args, **kwargs: pytest.fail("compiler-free archive"))
    assert build.prepare(root, source_archive=True) == (directory, manifest, None)


@pytest.mark.parametrize(
    "relative",
    [
        "contributions/command-sources/command.example.json",
        "contracts/catalog-delivery/security.v1.json",
        "rust/crates/example/src/lib.rs",
        "scripts/tool.py",
        "contracts/extensions/command-pack-bundle/command-pack-bundle.v1.json",
    ],
)
def test_frozen_bundle_rejects_changed_source_native_or_output(frozen, relative):
    build, root, _, _ = frozen
    (root / relative).write_text("changed")
    with pytest.raises(ValueError, match="build inputs"):
        build.prepare(root, source_archive=True)


def test_frozen_bundle_rejects_added_inputs_and_symlinks(frozen):
    build, root, directory, _ = frozen
    extra = root / "contributions/command-sources/command.added.json"
    extra.write_text("{}")
    with pytest.raises(ValueError, match="build inputs"):
        build.prepare(root, source_archive=True)
    extra.unlink()
    (directory / "linked").symlink_to(root / "pyproject.toml")
    with pytest.raises(ValueError, match="symlink"):
        build.prepare(root, source_archive=True)
