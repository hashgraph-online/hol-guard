"""Production authoring operations with native planning and normal Builder IO."""

from __future__ import annotations

import copy
import json

import pytest

from codex_plugin_scanner.guard.catalog_delivery.metadata_objects import ObjectStore, encoded
from codex_plugin_scanner.guard.extension_builder.metadata_index import exchange
from codex_plugin_scanner.guard.extension_builder.native_source_compiler import NativeSourceCompilerError
from tests import extension_builder_support as builder_support

ROOT = builder_support.REPOSITORY
native = builder_support.native_authoring_index
inventory = builder_support.authoring_index_inventory
invoke = builder_support.invoke_source_cli


def release_for(native, directory, count, *, change=None):
    _compiler, built, selected, request = native
    catalog = inventory(native, count)
    if change:
        change(catalog)
    store = ObjectStore(directory)
    # Only the selected pack has IR. Inactive records cannot accidentally be
    # read as policy: their program references are intentionally absent.
    program = copy.deepcopy(selected["program"])
    program["nodes"] = {key: store.put_json(value) for key, value in program["nodes"].items()}
    program_ref = store.put_json(program)
    manifests = {}
    for entry in catalog:
        identity = entry["extension_id"]
        manifests[identity] = store.put_json(
            {
                "extension_id": identity,
                "catalog": store.put_json([entry]),
                "program": program_ref if identity == "command.dependency" else None,
            }
        )
    root = {
        "schema": "guard.command-pack-release.v1",
        "engine": built["implementation_digest"],
        "extensions": count,
        "index": store.index(manifests),
    }
    return store, {"mode": "development", "root": root, "source_context": "a" * 64, "request": request}


def plan(native, tmp_path, count, *, change=None, damage=None, admission=None):
    store, request = release_for(native, tmp_path / "release", count, change=change)
    if damage:
        damage(store, request)
    if admission is not None:
        request["admission"] = admission
    fetched = []

    def fetch(reference):
        fetched.append(reference["sha256"])
        return (store.directory / (reference["sha256"] + ".json")).read_bytes()

    result = exchange(native[0], "authoring-context", [request], tmp_path / "index", fetch=fetch)
    return result, fetched


@pytest.mark.parametrize("count", [166, 1660, 16600])
def test_native_global_planner_selects_only_dependency_ir(native, tmp_path, count):
    result, fetched = plan(native, tmp_path, count)
    assert result["selected"] == ["command.dependency"]
    assert result["programs"] == [native[2]["program"]]
    request = copy.deepcopy(native[3])
    request["validation_base"] = {key: result[key] for key in ("metadata_index", "programs")}
    response = invoke(native[0], request)
    assert response.returncode == 0, response.stdout
    output = json.loads(response.stdout)
    assert len(output["program"]["extensions"]) == len(native[1]["program"]["extensions"]) + 2
    print(
        json.dumps(
            {
                "native_authoring_inventory": count,
                "fetches": len(fetched),
                "selected": result["selected"],
                "request_bytes": len(encoded(request)),
                "program_digest": output["program"]["program_digest"],
            }
        )
    )


@pytest.mark.parametrize("fault", ["last-alias", "core", "missing", "corrupt", "engine", "version"])
def test_native_planner_rejects_global_and_transport_faults(native, tmp_path, fault):
    def change(catalog):
        if fault == "last-alias":
            catalog[-1]["aliases"] = ["command.example-cli"]
        if fault == "core":
            catalog[0]["description"] += " substituted"

    def damage(store, request):
        if fault in {"engine", "version"}:
            request["root"]["engine" if fault == "engine" else "schema"] = "forged"
        if fault in {"missing", "corrupt"}:
            path = store.directory / (request["root"]["index"]["sha256"] + ".json")
            if fault == "missing":
                path.unlink()
            else:
                path.write_bytes(b"corrupt")

    with pytest.raises((NativeSourceCompilerError, FileNotFoundError)):
        plan(native, tmp_path, 1660, change=change, damage=damage)


def test_native_admission_checks_last_inactive_global_executable(native, tmp_path):
    (tmp_path / "contributions/extensions").mkdir(parents=True)

    def change(catalog):
        catalog[-1]["executables"] = ["last-owned"]

    admission = {
        "root": str(tmp_path),
        "kind": "cli",
        "contribution_id": "new",
        "catalog_id": "command.new",
        "executable": "last-owned",
        "package": "",
    }
    with pytest.raises(NativeSourceCompilerError, match="authoring_installed_executable_collision"):
        plan(native, tmp_path, 1660, change=change, admission=admission)


@pytest.mark.parametrize("corrupt", [False, True])
def test_fixed_installed_bundle_uses_native_traversal_and_selected_archive(native, tmp_path, monkeypatch, corrupt):
    import hashlib
    from types import SimpleNamespace

    from codex_plugin_scanner.guard.catalog_delivery import installed_bundle
    from codex_plugin_scanner.guard.catalog_delivery.located_store import LocatedStore
    from codex_plugin_scanner.guard.catalog_delivery.metadata_objects import lookup_entry
    from codex_plugin_scanner.guard.catalog_delivery.pack_archives import archive_bytes
    from codex_plugin_scanner.guard.catalog_delivery.pack_store import PackReader
    from codex_plugin_scanner.guard.extension_builder.bundle_baseline import validation_base

    store, request = release_for(native, tmp_path / "release", 1660)
    assets, fetched = {}, []

    def asset(data, kind):
        identity = hashlib.sha256(data).hexdigest()
        name = f"{kind}-{identity}." + ("zip" if kind == "pack" else "json")
        assets[name] = data
        return {"tag": "extension-data-" + "0" * 40 + "-0.0-000000", "asset": name}

    located = LocatedStore(tmp_path / "located", publisher=SimpleNamespace(asset=asset))
    # One real archive contains the selected IR. Inactive programs are absent.
    reader = PackReader(store.directory)
    manifest_ref = lookup_entry(store, request["root"]["index"], 1660, "command.dependency")
    manifest = reader.json(manifest_ref)
    reader.json(manifest["catalog"])
    program = reader.json(manifest["program"])
    for reference in program["nodes"].values():
        reader.json(reference)
    data = archive_bytes(store.directory, sorted(reader.reads))
    archive = {"sha256": hashlib.sha256(data).hexdigest(), "length": len(data), "location": asset(data, "pack")}
    if corrupt:
        assets[archive["location"]["asset"]] = b"x" + data[1:]

    def wrap(reference):
        page = store.json(reference)
        wrapper = {
            "schema": "guard.policy-transport.v2",
            "kind": page["kind"],
            "native": {**reference, "location": asset(store.blob(reference), "object")},
        }
        if page["kind"] == "leaf":
            records = []
            for identity, manifest_ref in page["entries"]:
                manifest = store.json(manifest_ref)
                catalog = store.json(manifest["catalog"])
                record = {
                    "schema": "guard.policy-delivery.v2",
                    "extension_id": identity,
                    "manifest": manifest_ref,
                    "catalog_metadata": located.put_json(catalog),
                    "archives": [archive],
                    "dependencies": catalog[0]["dependencies"],
                    "related_interfaces": [],
                    "required": False,
                    "activation": "opt-in",
                    "trust_class": "external",
                }
                records.append([identity, located.put_json(record)])
            wrapper["records"] = records
        else:
            wrapper["children"] = [[prefix, count, wrap(child)] for prefix, count, child in page["children"]]
        return located.put_json(wrapper)

    policy = {"root": request["root"], "transport": wrap(request["root"]["index"])}

    def fetch(location, maximum):
        fetched.append(location["asset"])
        data = assets[location["asset"]]
        assert len(data) == maximum
        return data

    bundle = SimpleNamespace(manifest=lambda: {"policy": policy}, digest="a" * 64, fetch=fetch)
    monkeypatch.setattr(installed_bundle, "load_installed_bundle", lambda: bundle)
    if corrupt:
        with pytest.raises(ValueError, match="integrity"):
            validation_base(request["request"], native[0], installed=True, directory=tmp_path / "consumer")
    else:
        result = validation_base(request["request"], native[0], installed=True, directory=tmp_path / "consumer")
        assert result["programs"] == [native[2]["program"]]
        assert fetched.count(archive["location"]["asset"]) == 1


@pytest.mark.parametrize("kind", ["cli", "mcp"])
def test_normal_builder_apply_above_512_preserves_core_profile(tmp_path, monkeypatch, capsys, kind):
    import sys

    from codex_plugin_scanner import cli
    from codex_plugin_scanner.guard.extension_builder.kit import load_kit
    from codex_plugin_scanner.guard.extension_builder.repository_edits import trust_binding_path
    from codex_plugin_scanner.guard.extension_builder.repository_write import apply_kit
    from tests.extension_builder_support import make_discovery, repository_fixture, use_built_native_source_compiler

    monkeypatch.setattr(sys, "argv", ["hol-guard"])
    # Destination admission is not routed through the kit; it reads the override
    # from the environment, so expose the compiler this job actually built.
    if (compiler := use_built_native_source_compiler(monkeypatch)) is not None:
        monkeypatch.setenv("HOL_GUARD_NATIVE_SOURCE_COMPILER", str(compiler))
    discovery = make_discovery(tmp_path, kind)
    identity = discovery.metadata
    arguments = [
        "extensions",
        "generate",
        "--from",
        kind,
        "--input",
        str(tmp_path / f"{kind}-source.json"),
        "--output",
        str(tmp_path / "kit"),
        "--slug",
        identity.slug,
        "--publisher",
        identity.publisher_id,
        "--homepage",
        identity.homepage,
        "--json",
    ]
    arguments += (
        ["--executable", identity.executable]
        if kind == "cli"
        else ["--launcher", identity.launcher, "--package", identity.package]
    )
    assert cli.main(arguments) == 0
    assert json.loads(capsys.readouterr().out)["generated"]
    kit = load_kit(tmp_path / "kit")
    root = repository_fixture(tmp_path)
    core = "contracts/extensions/core-defaults.v1.json"
    (root / core).write_bytes((ROOT / core).read_bytes())
    core_inputs = [
        entry[field] for entry in json.loads((root / core).read_bytes())["entries"] for field in ("source", "trust")
    ]
    for path in core_inputs:
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_bytes((ROOT / path).read_bytes())
    resident = "src/codex_plugin_scanner/guard/contracts/data/extensions/native-command-program.v1.json"
    (root / resident).parent.mkdir(parents=True, exist_ok=True)
    (root / resident).write_bytes((ROOT / resident).read_bytes())
    protected = {path: (root / path).read_bytes() for path in (core, resident, "pyproject.toml", *core_inputs)}
    family = "extensions" if kind == "cli" else "mcp-servers"
    directory = root / "contributions" / family
    for index in range(600):
        payload = {
            "id": f"synthetic{index}",
            "executables": [f"synthetic{index}"],
            "launch": {"package": f"@synthetic/{index}"},
        }
        (directory / f"zzsynthetic{index:05d}.json").write_bytes(encoded(payload))

    def cli_apply(*extra):
        status = cli.main(["extensions", "apply", str(tmp_path / "kit"), "--repo", str(root), "--json", *extra])
        payload = json.loads(capsys.readouterr().out)
        assert status == 0, payload
        return payload

    preview = cli_apply()
    assert not preview["written"]
    result = cli_apply("--write", "--expected-plan", preview["planDigest"])
    assert result["written"]
    repeated = cli_apply("--write")
    assert all(row["action"] == "unchanged" for row in repeated["files"])
    assert {path: (root / path).read_bytes() for path in protected} == protected
    binding = json.loads((root / trust_binding_path(kit.discovery.metadata)).read_bytes())
    assert binding["trustClass"] == "external"
    # A collision in the final entry must still be seen on the normal path.
    last = directory / "zzsynthetic99999.json"
    last.write_bytes(
        encoded(
            {
                "id": "someone-else",
                "executables": [kit.discovery.metadata.executable],
                "launch": {"package": kit.discovery.metadata.package},
            }
        )
    )
    from codex_plugin_scanner.guard.extension_builder.errors import BuilderError

    with pytest.raises(BuilderError, match="already"):
        apply_kit(kit, root)
