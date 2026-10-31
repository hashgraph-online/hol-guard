"""Installed release authority is fixed-path, bounded, and distinct from remote updates."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import subprocess
import zipfile
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.catalog_delivery import installed_bundle as installed
from codex_plugin_scanner.guard.catalog_delivery.installed_bundle import MANIFEST, descriptor, validate
from codex_plugin_scanner.guard.extension_builder import native_source_compiler
from tests.installed_bundle_layout import installed_layout

SOURCE = "a" * 40
ENGINE = "b" * 64


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def root():
    reference = {"sha256": "c" * 64, "length": 2, "expanded_length": 2, "kind": "data"}
    located = {
        **reference,
        "location": {"tag": f"extension-data-{SOURCE}-0.0-000000", "asset": "object-" + "c" * 64 + ".json"},
    }
    return {
        "schema": "guard.command-pack-bundle.v1",
        "source_sha": SOURCE,
        "engine": ENGINE,
        "authority_epoch": 1,
        "publication_id": "0.0",
        "policy": {
            "root": {
                "schema": "guard.command-pack-release.v1",
                "kind": "root",
                "authority": "requires-authenticated-release-binding",
                "engine": ENGINE,
                "extensions": 1,
                "index": reference,
                "index_fanout": 64,
                "objects": 1,
                "object_bytes": 2,
                "object_bytes_limit": 65536,
            },
            "transport": located,
            "defaults": {"count": 0, "index": None},
            "revocations": {"epoch": 0, "count": 0, "index": None},
        },
    }


def _use_native_metadata_compiler(monkeypatch):
    # Synthetic release bytes remain fixture IO; the candidate native validator
    # authenticates their manifests, executable digest and complete Root.
    binary_path = Path(
        os.environ.get("HOL_GUARD_BUILD_SOURCE_COMPILER")
        or Path(__file__).resolve().parents[1] / "rust/target/debug/guard-command-source"
    )
    monkeypatch.setattr(
        installed,
        "run_source_compiler",
        lambda operation, request, **options: native_source_compiler.run_source_compiler(
            operation, request, **{"compiler": binary_path, **options}
        ),
    )


@pytest.fixture
def package(tmp_path, monkeypatch):
    _use_native_metadata_compiler(monkeypatch)
    monkeypatch.setattr(installed, "_package", lambda: tmp_path)
    directory = tmp_path / "guard/contracts/data/extensions/command-pack-bundle"
    directory.mkdir(parents=True)
    data = encoded(root())
    (directory / MANIFEST).write_bytes(data)
    native = tmp_path / "_native"
    native.mkdir()
    binary = b"release executable"
    (native / "hol-guard-runtime").write_bytes(binary)
    digest = hashlib.sha256(binary).hexdigest()
    common = {
        "protocol_version": 1,
        "package_version": "1.0",
        "source_sha": SOURCE,
        "target": "test",
        "platform_tag": "test",
        "command_pack_bundle": descriptor(data, source_sha=SOURCE, engine=ENGINE),
    }
    runtime = {**common, "schema": "hol-guard-native-runtime.v1", "runtime_size": len(binary), "runtime_sha256": digest}
    compiler = {
        **common,
        "schema": "hol-guard-native-source-compiler.v2",
        "compiler_size": len(binary),
        "compiler_sha256": digest,
        "implementation_digest": ENGINE,
        "executable": "hol-guard-runtime",
    }
    (native / "runtime-manifest.json").write_bytes(encoded(runtime))
    (native / "source-compiler-manifest.json").write_bytes(encoded(compiler))
    return directory, native


def test_factory_only_immutable_release_profile(package):
    with pytest.raises(TypeError):
        installed.VerifiedInstalledBundle()
    bundle = installed.load_installed_bundle()
    assert bundle.kind == "installed-release-bundle"
    assert bundle.engine == ENGINE and bundle.source_sha == SOURCE
    assert bundle.digest == hashlib.sha256(bundle.data).hexdigest()
    copy = bundle.manifest()
    copy["policy"].clear()
    assert bundle.manifest()["policy"]
    assert "expires_at" not in bundle.manifest()
    with pytest.raises(AttributeError):
        bundle.engine = "d" * 64


@pytest.mark.parametrize("fault", ["root", "executable", "source", "engine", "binding", "path", "size"])
def test_native_root_and_executable_tampering_is_rejected(package, fault):
    directory, native = package
    if fault == "root":
        (directory / MANIFEST).write_bytes(encoded({**root(), "authority_epoch": 2}))
    elif fault == "executable":
        (native / "hol-guard-runtime").write_bytes(b"changed executable")
    else:
        path = native / "source-compiler-manifest.json"
        compiler = json.loads(path.read_bytes())
        key, value = {
            "source": ("source_sha", "d" * 40),
            "engine": ("implementation_digest", "d" * 64),
            "binding": ("command_pack_bundle", {}),
            "path": ("executable", "../runtime"),
            "size": ("compiler_size", True),
        }[fault]
        compiler[key] = value
        path.write_bytes(encoded(compiler))
    with pytest.raises(ValueError):
        installed.load_installed_bundle()


@pytest.mark.parametrize(
    "fault",
    [
        "policy",
        "native-extra",
        "native-index",
        "defaults",
        "epoch",
        "location",
        "source",
        "engine",
        "expiry",
        "duplicate",
        "bytes",
    ],
)
def test_complete_root_shape_is_strict(fault):
    value = root()
    if fault == "policy":
        value["policy"] = {}
    elif fault == "native-extra":
        value["policy"]["root"]["unknown"] = 1
    elif fault == "native-index":
        value["policy"]["root"]["index"]["length"] = 65537
    elif fault == "defaults":
        value["policy"]["defaults"]["count"] = 2
    elif fault == "epoch":
        value["authority_epoch"] = True
    elif fault == "location":
        value["policy"]["transport"]["location"]["tag"] = f"extension-data-{'d' * 40}-0.0-000000"
    elif fault in {"source", "engine"}:
        value["source_sha" if fault == "source" else "engine"] = "d" * (40 if fault == "source" else 64)
    elif fault == "expiry":
        value["expires_at"] = 9999999999
    data = encoded(value)
    if fault == "duplicate":
        data = data[:-1] + b',"policy":{}}'
    elif fault == "bytes":
        data = b" " * 65537
    with pytest.raises(ValueError):
        validate(data, source_sha=SOURCE, engine=ENGINE)


def test_installed_asset_paths_fit_a_stock_windows_install(monkeypatch):
    # A default pipx or uv install puts site-packages about 90 characters deep;
    # Windows refuses longer paths than 259 unless long paths are enabled.
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    from installed_bundle_assets import tag_directory

    longest = (
        installed.PREFIX
        + "assets/"
        + tag_directory(f"extension-data-{SOURCE}-0.0-000000", source_sha=SOURCE)
        + f"/pack-{'a' * 64}.zip"
    )
    installed.asset_path(longest.removeprefix(installed.PREFIX))
    assert len(longest) <= 160
    with pytest.raises(ValueError):
        installed.asset_path(f"assets/extension-data-{SOURCE}-0.0-000000/pack-{'a' * 64}.zip")
    for tag in (
        f"extension-data-{'d' * 40}-0.0-000000",
        f"extension-data-{SOURCE}-1.0-000000",
        f"extension-data-{SOURCE}-0.0-../000",
    ):
        with pytest.raises(ValueError):
            tag_directory(tag, source_sha=SOURCE)


@pytest.mark.parametrize("fault", ["files", "bytes", "path", "orphan"])
def test_native_bundle_inventory_bounds_and_paths(monkeypatch, fault):
    from scripts import native_wheel_metadata as metadata

    entries = {metadata.ROOT: encoded(root())}
    if fault == "files":
        monkeypatch.setattr(metadata, "MAX_FILES", 0)
        entries[metadata.PREFIX + "assets/000000/objects-000000.zip"] = b"asset"
    elif fault == "bytes":
        monkeypatch.setattr(metadata, "MAX_BYTES", len(entries[metadata.ROOT]) - 1)
    elif fault == "path":
        entries[metadata.PREFIX + "assets/../escape"] = b"asset"
    else:
        entries.pop(metadata.ROOT)
        entries[metadata.PREFIX + "orphan"] = b"asset"
    with pytest.raises(ValueError):
        metadata.binding(entries, source_sha=SOURCE, engine=ENGINE)


def test_fetch_checks_containers_digest_paths_and_symlinks(package, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    assets = importlib.import_module("extension_delivery_assets")
    directory, _ = package
    plan = assets.AssetPlan(directory / "assets", SOURCE)
    content = b'{"policy":true}'
    target = plan.asset(content, "object")
    plan.finish()
    installed_layout(directory / "assets")
    bundle = installed.load_installed_bundle()
    assert bundle.fetch(target, len(content)) == content
    for bad in ({**target, "asset": "../escape"}, {**target, "tag": f"extension-data-{'d' * 40}-0.0-000000"}):
        with pytest.raises(ValueError):
            bundle.fetch(bad, len(content))
    with pytest.raises(ValueError):
        bundle.fetch(target, 65537)
    with pytest.raises(ValueError):
        bundle.fetch(target, len(content) - 1)
    path = directory / "assets" / target["tag"].rsplit("-", 1)[1] / target["asset"]
    original = path.read_bytes()
    path.write_bytes(original.replace(content, b'{"policy":fals}'))
    with pytest.raises(ValueError):
        bundle.fetch(target, len(content))
    path.unlink()
    destination = path.parent / "other"
    destination.write_bytes(original)
    path.symlink_to(destination)
    with pytest.raises(ValueError):
        bundle.fetch(target, len(content))


def test_preparation_io_reuses_one_container_and_still_checks_each_member(package, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    assets = importlib.import_module("extension_delivery_assets")
    directory, _ = package
    plan = assets.AssetPlan(directory / "assets", SOURCE)
    first, second = b'{"first":true}', b'{"second":true}'
    targets = [plan.asset(value, "object") for value in (first, second)]
    plan.finish()
    installed_layout(directory / "assets")
    assert targets[0]["asset"] == targets[1]["asset"]
    bundle = installed.load_installed_bundle()
    reads = []
    original = installed.read_bytes

    def reader(path, **kwargs):
        reads.append(path)
        return original(path, **kwargs)

    monkeypatch.setattr(installed, "read_bytes", reader)
    fetch = bundle.preparation_fetch()
    assert fetch(targets[0], len(first)) == first
    assert fetch(targets[1], len(second)) == second
    # The runtime opens the one container and checks each member; Python never
    # loads the container bytes.
    assert reads == []
    with pytest.raises(ValueError):
        fetch(targets[1], len(second) - 1)
    assert reads == []
    assert bundle.preparation_fetch()(targets[0], len(first)) == first
    assert reads == []


@pytest.mark.parametrize("fault", [None, "engine", "source", "executable-engine"])
def test_native_wheel_binds_both_manifests_and_executable(tmp_path, monkeypatch, fault):
    _use_native_metadata_compiler(monkeypatch)
    from scripts import build_native_hol_guard_wheel as builder
    from scripts.native_wheel_metadata import ROOT

    value = root()
    if fault in {"engine", "source"}:
        value["engine" if fault == "engine" else "source_sha"] = "d" * (64 if fault == "engine" else 40)
    raw = encoded(value)
    source = tmp_path / "hol_guard-1.0-py3-none-any.whl"
    with zipfile.ZipFile(source, "w") as wheel:
        for name, data in {
            "hol_guard-1.0.dist-info/METADATA": b"Metadata-Version: 2.4\nName: hol-guard\nVersion: 1.0\n",
            "hol_guard-1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
            "hol_guard-1.0.dist-info/RECORD": b"",
            "codex_plugin_scanner/guard/contracts/data/extensions/native-command-program.v1.json": encoded(
                {"program_digest": "c" * 64}
            ),
            ROOT: raw,
        }.items():
            wheel.writestr(name, data)
    runtime = tmp_path / "runtime"
    runtime.write_bytes(b"verified executable")
    runtime.chmod(0o755)

    def probe(arguments, **kwargs):
        info = (
            {
                "schema": "guard.source-compiler-capabilities.v1",
                "embedded_catalog": False,
                "implementation_digest": "d" * 64 if fault == "executable-engine" else ENGINE,
            }
            if arguments[1] == "compiler-info"
            else {"protocol_version": 1, "runtime_version": "1.0", "rule_digest": "c" * 64, "build_sha": SOURCE}
        )
        return subprocess.CompletedProcess(arguments, 0, stdout=encoded(info))

    monkeypatch.setattr(builder.subprocess, "run", probe)

    def build():
        return builder.build_native_wheel(
            source_wheel=source,
            runtime=runtime,
            output_dir=tmp_path / "output",
            version="1.0",
            platform_tag="test",
            target="test",
            source_sha=SOURCE,
            rule_digest="c" * 64,
            implementation_digest=ENGINE,
            base_program_digest="c" * 64,
        )

    if fault:
        with pytest.raises(ValueError):
            build()
        return
    with zipfile.ZipFile(build()) as wheel:
        first = json.loads(wheel.read("codex_plugin_scanner/_native/runtime-manifest.json"))
        second = json.loads(wheel.read("codex_plugin_scanner/_native/source-compiler-manifest.json"))
        assert (
            first["command_pack_bundle"]
            == second["command_pack_bundle"]
            == descriptor(raw, source_sha=SOURCE, engine=ENGINE)
        )
        assert first["runtime_sha256"] == second["compiler_sha256"] == hashlib.sha256(runtime.read_bytes()).hexdigest()
        wheel.extractall(tmp_path / "installed")
    monkeypatch.setattr(installed, "_package", lambda: tmp_path / "installed/codex_plugin_scanner")
    assert installed.load_installed_bundle().manifest() == root()
