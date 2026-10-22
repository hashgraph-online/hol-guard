"""Actual native compiler, installed factory and production bridge qualification."""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import zipfile
from contextlib import contextmanager
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.catalog_delivery import (
    activation_record,
    cache_io,
    installed_bundle,
    lifecycle,
    offline,
    preparation,
    transport,
)
from codex_plugin_scanner.guard.catalog_delivery.installed_bundle import MANIFEST, descriptor
from codex_plugin_scanner.guard.catalog_delivery.metadata_objects import encoded
from codex_plugin_scanner.guard.extension_builder import native_source_compiler as bridge
from tests.extension_builder_support import use_installed_native_source_compiler

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("HOL_GUARD_NATIVE_BINARY", ROOT / "rust/target/debug/hol-guard-runtime"))


@pytest.fixture(scope="module")
def packaged(tmp_path_factory):
    base = tmp_path_factory.mktemp("native-offline-public").resolve()
    source = base / "sources"
    for name in ("contributions", "contracts"):
        shutil.copytree(ROOT / name, source / name)
    template = (source / "contributions/command-sources/command.noodle.json").read_text()
    for number in range(440):
        name = f"offlinefixture{number:04}"
        (source / f"contributions/command-sources/command.{name}.json").write_text(template.replace("noodle", name))
        (source / f"contracts/extensions/trust/command.{name}.v1.json").write_bytes(
            encoded(
                {
                    "schemaVersion": "guard.extension-trust-binding.v1",
                    "extension": "command." + name,
                    "trustClass": "external",
                }
            )
        )
    with pytest.MonkeyPatch.context() as patch:
        patch.syspath_prepend(str(ROOT / "scripts"))
        import build_command_pack_bundle as builder

        package = base / "package"
        native = package / "_native"
        native.mkdir(parents=True)
        raw = BINARY.read_bytes()
        assert len(raw) <= 128 * 1024 * 1024
        executable = native / "hol-guard-runtime"
        executable.write_bytes(raw)
        executable.chmod(0o700)
        info = json.loads(subprocess.check_output([str(BINARY), "compiler-info"]))
        engine = info["implementation_digest"]
        bundle = package / "guard/contracts/data/extensions/command-pack-bundle"
        bundle.parent.mkdir(parents=True)
        published = base / "published"
        report = builder.build(BINARY, bundle, "a" * 40, source_root=source, assets_output=published)
        assert report["extensions"] > 512
        assert report["installed_asset_bytes"] < report["asset_bytes"]

        class Response(io.BytesIO):
            def __init__(self, data):
                super().__init__(data)
                self.headers = {"Content-Encoding": "identity"}

        def mirror(request, **kwargs):
            prefix = "https://github.com/hashgraph-online/hol-guard/releases/download/"
            assert request.full_url.startswith(prefix)
            tag, asset = request.full_url.removeprefix(prefix).split("/")
            assert asset.startswith("pack-") and asset.endswith(".zip")
            return Response((published / tag / asset).read_bytes())

        patch.setattr(transport, "managed_urlopen", mirror)
        exported = json.loads(subprocess.check_output([str(BINARY), "export-built"]))
        program = package / "native-command-program.v1.json"
        program.write_bytes(encoded(exported["program"]))
        data = (bundle / MANIFEST).read_bytes()
        common = dict(
            protocol_version=1,
            package_version="3.50.0",
            source_sha="a" * 40,
            target="test",
            platform_tag="test",
            command_pack_bundle=descriptor(data, source_sha="a" * 40, engine=engine),
        )
        digest = hashlib.sha256(raw).hexdigest()
        (native / "runtime-manifest.json").write_bytes(
            encoded(dict(common, schema="hol-guard-native-runtime.v1", runtime_size=len(raw), runtime_sha256=digest))
        )
        (native / "source-compiler-manifest.json").write_bytes(
            encoded(
                dict(
                    common,
                    schema="hol-guard-native-source-compiler.v2",
                    compiler_size=len(raw),
                    compiler_sha256=digest,
                    executable="hol-guard-runtime",
                    implementation_digest=engine,
                    base_program_digest=exported["program"]["program_digest"],
                )
            )
        )
        original = bridge.metadata.version
        patch.setattr(bridge.metadata, "version", lambda name: "3.50.0" if name == "hol-guard" else original(name))
        use_installed_native_source_compiler(patch, native)
        patch.setattr(bridge, "_PACKAGED_PROGRAM", program)
        patch.setattr(installed_bundle, "_package", lambda: package)
        authority = installed_bundle.load_installed_bundle()
        print(
            json.dumps(
                {
                    "fixture_extensions": report["extensions"],
                    "engine": engine,
                    "runtime_sha256": digest,
                    "root": authority.digest,
                    "build": report,
                }
            )
        )
        yield authority, base, report


@pytest.fixture(scope="module")
def complete(packaged):
    authority, base, report = packaged
    directory = base / "cache"
    batch_sizes = []
    run_bounded = bridge._run_bounded

    def count_batches(arguments, payload, **kwargs):
        result = run_bounded(arguments, payload, **kwargs)
        if arguments[1:] == ["pack-lifecycle", "--stdin"]:
            request = json.loads(payload)
            if request.get("kind") == "object" and request.get("operation") == "installed-batch":
                batch_sizes.append(len(request["items"]))
        return result

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(bridge, "_run_bounded", count_batches)
        plan = offline.prefetch(authority, directory)
    assert plan["complete"] and plan["extensions"] == report["extensions"]
    assert len(plan["archives"]) > 512
    assert batch_sizes and len(batch_sizes) < sum(batch_sizes)
    print(json.dumps({"native_object_batches": len(batch_sizes), "native_object_reads": sum(batch_sizes)}))
    print(json.dumps({"offline_plan": {k: v if k not in {"objects", "archives"} else len(v) for k, v in plan.items()}}))
    return authority, directory, plan


@pytest.fixture(scope="module")
def exported(complete, tmp_path_factory):
    from types import SimpleNamespace

    from codex_plugin_scanner.guard.catalog_delivery import activation_store, preparation_authority
    from codex_plugin_scanner.guard.cli.extension_offline_commands import run

    _authority, directory, _plan = complete
    (directory / "private-controls.json").write_text("private inventory and credential sentinel")
    destination = tmp_path_factory.mktemp("public-export").resolve() / "export"
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(preparation_authority, "load_installed_bundle", installed_bundle.load_installed_bundle)
        patch.setattr(activation_store, "prepare_directory_for_store", lambda store: directory)
        assert run(
            SimpleNamespace(controls_command="export-offline", remote=False, path=destination), SimpleNamespace()
        )["complete"]
    return destination


def test_complete_export_import_and_cached_vs_uncached_enable(complete, exported, tmp_path, monkeypatch):
    authority, _directory, plan = complete
    destination = exported
    assert sorted(p.name for p in destination.iterdir()) == ["archives", "objects", "root.json"]
    assert len(list((destination / "archives").iterdir())) == len(plan["archives"])

    def disconnected(*args, **kwargs):
        raise OSError("offline fixture transport")

    monkeypatch.setattr(installed_bundle.VerifiedInstalledBundle, "fetch", disconnected)
    imported = tmp_path / "imported"
    assert offline.import_release(authority, destination, imported)["complete"]
    prepared = preparation.prepare(authority, ["command.offlinefixture0439"], imported, engine=authority.engine)
    assert "command.offlinefixture0439" in prepared.selected
    # Preparation grants no controls or floors. A failure cannot replace them.
    with pytest.raises(OSError, match="offline fixture"):
        preparation.prepare(authority, ["command.offlinefixture0439"], tmp_path / "uncached", engine=authority.engine)
    assert prepared.metadata.program_digest
    assert not (imported / "controls.json").exists()


@pytest.mark.parametrize("fault", ["corrupt-object", "missing-object", "wrong-root", "symlink"])
def test_import_rejects_corruption_missing_wrong_release_and_traversal(complete, exported, tmp_path, fault):
    authority, _directory, plan = complete
    damaged = tmp_path / "export"
    shutil.copytree(exported, damaged)
    target = damaged / "objects" / (plan["objects"][0] + ".json")
    if fault == "corrupt-object":
        target.write_bytes(b"corrupt")
    elif fault == "missing-object":
        target.unlink()
    elif fault == "wrong-root":
        (damaged / "root.json").write_bytes(authority.data.replace(b'"0.0"', b'"0.1"'))
    else:
        original = tmp_path / "outside"
        target.rename(original)
        target.symlink_to(original)
    with pytest.raises(ValueError):
        offline.import_release(authority, damaged, tmp_path / "reject-cache")
    assert not (tmp_path / "reject-cache/objects").exists()


@pytest.mark.parametrize("fault", ["traversal", "duplicate", "symlink", "compressed", "digest"])
def test_native_archive_admissibility_rejects_malicious_zip(tmp_path, fault):
    content = b"{}"
    identity = hashlib.sha256(content).hexdigest()
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        name = "../escape.json" if fault == "traversal" else identity + ".json"
        info = zipfile.ZipInfo(name)
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK if fault == "symlink" else stat.S_IFREG | 0o644) << 16
        info.compress_type = zipfile.ZIP_DEFLATED if fault == "compressed" else zipfile.ZIP_STORED
        archive.writestr(info, b"bad" if fault == "digest" else content)
        if fault == "duplicate":
            archive.writestr(info, content)
    path = tmp_path / "malicious.zip"
    path.write_bytes(stream.getvalue())
    result = subprocess.run(
        [str(BINARY), "pack-lifecycle", "--stdin"],
        input=encoded(
            {
                "kind": "offline",
                "operation": "archive",
                "path": str(path),
                "length": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        ),
        capture_output=True,
        timeout=60,
    )
    assert result.returncode != 0


def test_active_pending_and_inflight_pins_and_inactive_eviction(complete, tmp_path):
    authority, directory, _plan = complete
    # Separate device cache avoids mutating the shared complete fixture.
    cache = tmp_path / "device"
    shutil.copytree(directory, cache)
    key = b"k" * 32
    active = preparation.prepare(authority, ["command.offlinefixture0001"], cache, engine=authority.engine)
    pending = preparation.prepare(authority, ["command.offlinefixture0439"], cache, engine=authority.engine)

    def header(prepared, revision):
        data, digest, mac = activation_record.seal(prepared, key=key, revision=revision)
        return dict(activation=data, activation_digest=digest, activation_mac=mac)

    activations = [header(active, 1), header(pending, 2)]

    def collect():
        return lifecycle.invoke(
            "offline",
            operation="cleanup",
            directory=str(cache),
            key=key.hex(),
            control_authority={"phase": "committed", "pack_program_digest": active.metadata.program_digest},
            activations=activations,
            maximum_bytes=0,
        )

    assert collect()["busy"]
    active._cache_lease.close()
    pending._cache_lease.close()
    # An unrelated in-flight transfer also fences native cleanup.
    lease = cache_io.Lease(cache)
    assert collect()["busy"]
    lease.close()
    # Crash a real isolated transfer process without running its destructors.
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import os,sys; from pathlib import Path; "
            "from codex_plugin_scanner.guard.catalog_delivery.cache_io import Lease; "
            "lease=Lease(Path(sys.argv[1])); print('leased',flush=True); sys.stdin.buffer.read(1); os._exit(7)",
            str(cache),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )
    try:
        assert child.stdout.readline() == b"leased\n"
        assert collect()["busy"]
        child.stdin.write(b"x")
        child.stdin.flush()
        assert child.wait(timeout=30) == 7
    finally:
        child.stdin.close()
        child.stdout.close()
    result = collect()
    assert result["evicted"] > 512 and result["pinned_sets"] == 2 and result["over_budget"]
    assert len(list((cache / "archives").iterdir())) == 0
    for prepared, row in zip((active, pending), activations, strict=True):
        reopened = activation_record.open_record(
            row["activation"], row["activation_digest"], row["activation_mac"], key=key, directory=cache
        )
        assert reopened.selected == prepared.selected
        assert (
            bridge.check_pack_cache(cache, prepared.metadata.program_digest)["program_digest"]
            == prepared.metadata.program_digest
        )
    # Idempotent collection leaves every surviving protection object intact.
    assert collect()["evicted"] == 0
    with pytest.raises(ValueError, match="active_record_missing"):
        lifecycle.invoke(
            "offline",
            operation="cleanup",
            directory=str(cache),
            key=key.hex(),
            control_authority={"phase": "committed", "pack_program_digest": "0" * 64},
            activations=activations,
            maximum_bytes=0,
        )
    bad = dict(activations[0], activation_mac="0" * 64)
    with pytest.raises(ValueError):
        lifecycle.invoke(
            "offline", operation="cleanup", directory=str(cache), key=key.hex(), activations=[bad], maximum_bytes=0
        )


def test_prefetch_rejects_unsigned_authority(packaged, tmp_path):
    authority, _base, _report = packaged
    with pytest.raises(ValueError, match="verified publication"):
        offline.prefetch(authority.manifest(), tmp_path / "cache")


@pytest.mark.parametrize("fault", ["expired", "future", "engine"])
def test_native_remote_prefetch_rejects_expiry_freeze_and_engine_substitution(packaged, tmp_path, fault):
    authority, _base, _report = packaged
    value = authority.manifest()
    value.update(schema="guard.extension-distribution.v2", publication_id="1.1", issued_at=100, expires_at=200)
    if fault == "future":
        value.update(issued_at=300, expires_at=400)
    if fault == "engine":
        value["engine"] = "0" * 64
    result = subprocess.run(
        [str(BINARY), "pack-lifecycle", "--stdin"],
        input=encoded(
            dict(
                kind="offline",
                operation="plan",
                profile="remote",
                directory=str(tmp_path),
                release_data=encoded(value).decode(),
                now=201 if fault == "expired" else 150,
            )
        ),
        capture_output=True,
        timeout=60,
    )
    assert result.returncode != 0 and b"fresh_authority_required" in result.stderr


def test_production_cli_prefetch_and_import(complete, exported, tmp_path, monkeypatch):
    from types import SimpleNamespace

    from codex_plugin_scanner.guard.catalog_delivery import preparation_authority
    from codex_plugin_scanner.guard.cli.extension_offline_commands import run

    _authority, directory, _plan = complete
    monkeypatch.setattr(preparation_authority, "load_installed_bundle", installed_bundle.load_installed_bundle)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.catalog_delivery.activation_store.prepare_directory_for_store",
        lambda store: directory,
    )
    assert run(SimpleNamespace(controls_command="prefetch", remote=False), SimpleNamespace())["complete"]
    assert run(SimpleNamespace(controls_command="import-offline", remote=False, path=exported), SimpleNamespace())[
        "complete"
    ]


def test_production_cleanup_captures_sql_pins_and_rejects_sql_loss(complete, tmp_path):
    from types import SimpleNamespace

    from codex_plugin_scanner.guard.catalog_delivery import activation_store
    from codex_plugin_scanner.guard.native_command_control_authority import encode_authority
    from codex_plugin_scanner.guard.native_command_control_authority_io import write_private_state
    from codex_plugin_scanner.guard.native_command_control_authority_store import _key
    from codex_plugin_scanner.guard.store_extension_control_authority_schema import (
        ensure_extension_control_authority_schema,
    )

    authority, source, _plan = complete
    home = tmp_path / "isolated-home"
    home.mkdir(mode=0o700)
    database = home / "fixture.sqlite"

    @contextmanager
    def connect():
        with sqlite3.connect(database) as connection:
            connection.row_factory = sqlite3.Row
            yield connection

    store = SimpleNamespace(
        guard_home=home, _connect=connect, _policy_integrity_secret_material=lambda **kwargs: (b"m" * 32, "fixture")
    )
    cache = activation_store.prepare_directory_for_store(store)
    shutil.copytree(source, cache)
    key = _key(store)
    prepared = preparation.prepare(authority, ["command.offlinefixture0001"], cache, engine=authority.engine)
    sealed = activation_record.seal(prepared, key=key, revision=1)
    with connect() as connection:
        ensure_extension_control_authority_schema(connection, activate_packs=True, activation_format_v2=True)
        connection.execute("insert into extension_command_pack_activation values(1,1,?,?,?,'fixture')", sealed)
        connection.execute("insert into extension_command_pack_pending values(2,?,?,?,'link','digest','mac')", sealed)
        connection.execute("create table saved_approvals(value text)")
        connection.execute("insert into saved_approvals values('always-allow fixture sentinel')")
    marker = encode_authority(
        dict(
            schema="guard.native-command-control-authority.v2",
            epoch=1,
            mutation_revision=1,
            authority_key_id="0" * 64,
            phase="committed",
            effective_digest="e" * 64,
            recovery=None,
            pack_program_digest=prepared.metadata.program_digest,
        ),
        key,
    )
    write_private_state(home, "command-control-authority.v1.json", marker, 4096)
    prepared._cache_lease.close()
    before = database.read_bytes()
    result = cache_io.cleanup(store, maximum_bytes=0)
    assert result["pinned_sets"] == 1 and result["evicted"] > 512
    assert database.read_bytes() == before
    with connect() as connection:
        connection.execute("delete from extension_command_pack_activation")
    remaining = sorted(path.name for path in (cache / "objects").iterdir())
    with pytest.raises(RuntimeError, match="activation_missing"):
        cache_io.cleanup(store, maximum_bytes=0)
    assert sorted(path.name for path in (cache / "objects").iterdir()) == remaining
