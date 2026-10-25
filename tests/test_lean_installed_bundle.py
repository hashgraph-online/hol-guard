"""Real compiler/factory/admission proof with synthetic public-equivalent IO."""

# ruff: noqa: E402

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import urllib.error
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

try:
    import build_command_pack_bundle as builder
    import publish_installed_bundle_assets as publisher
    from extension_delivery_policy_lookup import lookup, read_transport_page
finally:
    sys.path.remove(str(ROOT / "scripts"))

from codex_plugin_scanner.guard.catalog_delivery import installed_bundle, preparation, transport
from codex_plugin_scanner.guard.catalog_delivery.installed_bundle import MANIFEST, descriptor
from codex_plugin_scanner.guard.catalog_delivery.installed_bundle import ROOT as ROOT_MEMBER
from codex_plugin_scanner.guard.catalog_delivery.located_store import LocatedStore
from codex_plugin_scanner.guard.catalog_delivery.metadata_objects import encoded
from codex_plugin_scanner.guard.extension_builder import native_source_compiler as native
from tests.extension_builder_support import use_installed_native_source_compiler


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    binary = Path(os.environ.get("HOL_GUARD_BUILD_SOURCE_COMPILER") or ROOT / "rust/target/debug/guard-command-source")
    if not binary.is_file():
        pytest.skip("build the exact-source native compiler first")
    directory = tmp_path_factory.mktemp("lean-installed")
    output, assets = directory / "normal", directory / "public"
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    report = builder.build(binary, output, source, source_root=ROOT, assets_output=assets)
    data = (output / MANIFEST).read_bytes()
    root = json.loads(data)
    wheel = directory / "normal.whl"
    with zipfile.ZipFile(wheel, "x") as archive:
        for path in output.rglob("*"):
            if path.is_file():
                archive.write(path, ROOT_MEMBER.removesuffix(MANIFEST) + path.relative_to(output).as_posix())
    return directory, binary, output, assets, report, root, data, wheel


def install(built, tmp_path, monkeypatch, *, require_runtime=True):
    _, binary, output, _, _, root, data, _ = built
    if require_runtime:
        binary = Path(os.environ.get("HOL_GUARD_LEAN_TEST_RUNTIME", str(ROOT / "rust/target/debug/hol-guard-runtime")))
        if not binary.is_file():
            pytest.skip("exact seeded runtime prerequisites must compile before fixed-factory proof")
    package = tmp_path / "package"
    destination = package / "guard/contracts/data/extensions/command-pack-bundle"
    shutil.copytree(output, destination)
    native_directory = package / "_native"
    native_directory.mkdir()
    executable = native_directory / "hol-guard-runtime"
    shutil.copyfile(binary, executable)
    executable.chmod(0o700)
    raw = executable.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    common = dict(
        protocol_version=1,
        package_version=native.metadata.version("hol-guard"),
        source_sha=root["source_sha"],
        target="test",
        platform_tag="test",
        command_pack_bundle=descriptor(data, source_sha=root["source_sha"], engine=root["engine"]),
    )
    runtime = dict(common, schema="hol-guard-native-runtime.v1", runtime_size=len(raw), runtime_sha256=digest)
    compiler = dict(
        common,
        schema="hol-guard-native-source-compiler.v2",
        compiler_size=len(raw),
        compiler_sha256=digest,
        executable="hol-guard-runtime",
        implementation_digest=root["engine"],
        base_program_digest="1" * 64,
    )
    for name, value in (("runtime-manifest.json", runtime), ("source-compiler-manifest.json", compiler)):
        (native_directory / name).write_bytes(encoded(value))
    # Fixed installed resource IO only; production URL checks, release binding,
    # executable hashing, dependency selection and native admission are real.
    program = package / "base-program.json"
    program.write_bytes(encoded({"program_digest": "1" * 64}))
    use_installed_native_source_compiler(monkeypatch, native_directory)
    monkeypatch.setattr(native, "_PACKAGED_PROGRAM", program)
    monkeypatch.setattr(installed_bundle, "_package", lambda: package)
    return installed_bundle.load_installed_bundle()


def selected_record(built, identity=None):
    directory, _, output, _, _, root, _, _ = built

    # Build-time/test IO adapter; no network and no caller URL authority.
    def fetch(location, length):
        from codex_plugin_scanner.guard.catalog_delivery.containers import member

        path = output / "assets" / location["tag"].rsplit("-", 1)[1] / location["asset"]
        return member(path.read_bytes(), location["asset"], location["member"], length)

    store = LocatedStore(directory / "inspection", fetch=fetch)
    if identity is None:

        def walk(reference, expected, count, prefix=""):
            wrapper, page = read_transport_page(store, reference, expected, count, prefix)
            if page["kind"] == "leaf":
                for name, _ in page["entries"]:
                    record = lookup(store, root["policy"]["root"], root["policy"]["transport"], name)
                    if record["trust_class"] == "external":
                        return name
                return None
            for index, (key, size, target) in enumerate(page["children"]):
                if result := walk(wrapper["children"][index][2], target, size, key):
                    return result
            return None

        identity = walk(
            root["policy"]["transport"], root["policy"]["root"]["index"], root["policy"]["root"]["extensions"]
        )
    return identity, lookup(store, root["policy"]["root"], root["policy"]["transport"], identity)


def test_normal_inventory_and_exact_publication(built):
    _, _, output, assets, report, root, _, wheel = built
    identity, record = selected_record(built)
    assert identity and all("member" not in row["location"] for row in record["archives"])
    assert all(
        not (output / "assets" / row["location"]["tag"].rsplit("-", 1)[1] / row["location"]["asset"]).exists()
        for row in record["archives"]
    )
    assert report["installed_asset_bytes"] < report["asset_bytes"]
    assert report["installed_assets"] < report["assets"]
    assert publisher.publish(assets, wheel, root["source_sha"], verify_only=True)["assets"] == report["assets"]


def test_fixed_factory_selected_fetch_and_offline_native_admission(built, tmp_path, monkeypatch):
    authority = install(built, tmp_path, monkeypatch)
    _, _, _, assets, report, root, _, _ = built
    identity, _ = selected_record(built)
    fetched = []

    class Response:
        def __init__(self, data):
            self.data = data
            self.headers = {"Content-Encoding": "identity"}

        def read(self, maximum):
            return self.data[:maximum]

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    def mirror(request, **kwargs):
        url = request.full_url
        prefix = "https://github.com/hashgraph-online/hol-guard/releases/download/"
        assert url.startswith(prefix)
        tag, name = url.removeprefix(prefix).split("/")
        assert name.startswith("pack-") and name.endswith(".zip")
        fetched.append((tag, name))
        return Response((assets / tag / name).read_bytes())

    monkeypatch.setattr(transport, "managed_urlopen", mirror)
    cache = tmp_path / "cache"
    defaults = preparation.prepare(authority, [], cache, engine=root["engine"])
    assert not fetched and len(defaults.selected) == root["policy"]["defaults"]["count"]
    prepared = preparation.prepare(authority, [identity], cache, engine=root["engine"])
    expected = set()
    for selected in prepared.selected - defaults.selected:
        _, record = selected_record(built, selected)
        expected.update((row["location"]["tag"], row["location"]["asset"]) for row in record["archives"])
    assert set(fetched) == expected and len(fetched) == len(expected)
    assert len(fetched) < report["assets"]
    monkeypatch.setattr(
        transport, "managed_urlopen", lambda *a, **k: (_ for _ in ()).throw(urllib.error.URLError("offline"))
    )
    admitted = native.check_pack_cache(cache, prepared.metadata.program_digest)
    assert admitted["extensions"] == len(prepared.selected)
    with pytest.raises(ValueError, match="unavailable"):
        preparation.prepare(authority, [identity], tmp_path / "uncached", engine=root["engine"])
    assert native.check_pack_cache(cache, prepared.metadata.program_digest) == admitted


@pytest.mark.parametrize("failure", ["substituted", "missing"])
def test_missing_or_malicious_optional_data_fails_closed(built, tmp_path, monkeypatch, failure):
    authority = install(built, tmp_path, monkeypatch)
    identity, _record = selected_record(built)
    if failure == "substituted":
        monkeypatch.setattr(transport, "download", lambda url, maximum: b"x" * maximum)
    else:
        monkeypatch.setattr(
            transport, "download", lambda *args: (_ for _ in ()).throw(urllib.error.URLError("missing"))
        )
    with pytest.raises(ValueError, match=r"integrity|unavailable"):
        preparation.prepare(authority, [identity], tmp_path / "cache", engine=built[5]["engine"])
    assert not tuple((tmp_path / "cache/sets").glob("*.json"))


def test_public_legacy_records_use_metadata_without_policy_archives(built, tmp_path, monkeypatch):
    install(built, tmp_path, monkeypatch, require_runtime=False)
    original = installed_bundle.read_bytes

    def metadata_only(path, *, limit, anchor=None):
        assert not path.name.startswith("pack-"), "legacy metadata must not read executable policy"
        return original(path, limit=limit, anchor=anchor)

    monkeypatch.setattr(installed_bundle, "read_bytes", metadata_only)
    for family in ("commands", "mcp"):
        rows = installed_bundle.compatibility_payloads(family)
        assert len(rows) == built[5]["compatibility"][family]["count"]
        assert len({row["id"] for row in rows}) == len(rows)


def test_publication_rejects_unbound_asset_before_any_upload(built, tmp_path):
    _, _, _, assets, _, root, _, wheel = built
    directory = tmp_path / "public"
    shutil.copytree(assets, directory)
    plan_path = directory / "installed-bundle-assets.v1.json"
    plan = json.loads(plan_path.read_bytes())
    rows = list(publisher.plan_rows(directory, plan["asset_count"]))
    extra = b"not-root-bound"
    digest = hashlib.sha256(extra).hexdigest()
    tag = rows[0]["location"]["tag"]
    name = f"pack-{digest}.zip"
    (directory / tag / name).write_bytes(extra)
    rows.append({"location": {"tag": tag, "asset": name}, "sha256": digest, "length": len(extra)})
    plan["asset_count"] += 1
    plan_path.write_bytes(encoded(plan))
    (directory / "asset-plan.jsonl").write_bytes(b"".join(encoded(row) + b"\n" for row in rows))
    with pytest.raises(ValueError, match="Root reachability"):
        publisher.publish(directory, wheel, root["source_sha"], verify_only=True)
