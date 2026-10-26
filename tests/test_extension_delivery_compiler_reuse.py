"""Authenticated build reuse transports bytes without granting activation."""

from __future__ import annotations

import hashlib
import importlib
import io
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.catalog_delivery import authority
from tests.test_extension_delivery_authority import SOURCE, root_value


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    reuse = importlib.import_module("extension_delivery_compiler_reuse")
    from command_pack_store import PackReader
    from extension_delivery_assets import AssetPlan
    from extension_delivery_located_store import LocatedStore
    from extension_delivery_objects import ObjectStore, encoded
    from extension_pack_archives import parts

    from codex_plugin_scanner.guard.catalog_delivery.containers import member

    policy = ObjectStore(tmp_path / "policy")
    manifest = policy.put_json({"schema": "guard.command-policy-pack.v1", "extension_id": "command.one"})
    index = policy.index({"command.one": manifest})
    plan = AssetPlan(tmp_path / "assets", SOURCE)
    metadata = LocatedStore(tmp_path / "metadata", publisher=plan)
    archive = next(parts(policy.directory, {manifest["sha256"]}))
    record = metadata.put_json(
        {
            "schema": "guard.policy-delivery.v2",
            "extension_id": "command.one",
            "manifest": manifest,
            "catalog_metadata": metadata.put_json([]),
            "archives": [
                {
                    "sha256": hashlib.sha256(archive).hexdigest(),
                    "length": len(archive),
                    "location": plan.asset(archive, "pack"),
                }
            ],
            "dependencies": [],
            "related_interfaces": [],
            "required": False,
            "activation": "opt-in",
            "trust_class": "external",
        }
    )
    native = metadata.put(PackReader(policy.directory).blob(index))
    transport = metadata.put_json(
        {"schema": "guard.policy-transport.v2", "native": native, "kind": "leaf", "records": [["command.one", record]]}
    )
    value = root_value()
    value["policy"]["root"]["index"] = index
    value["policy"]["transport"] = transport
    value["directory"]["index"] = metadata.put_json([])
    plan.finish()
    calls = []

    def fetch(target, maximum):
        calls.append(target)
        data = (plan.directory / target["tag"] / target["asset"]).read_bytes()
        return member(data, target["asset"], target["member"], maximum)

    monkeypatch.setattr(reuse, "cached_fetcher", lambda _: fetch)
    # Unit transport fixture only. Production crypto is separately exercised by
    # the real Sigstore vectors; this patch never exists in shipped code.
    monkeypatch.setattr(authority, "_verify_attested_artifact", lambda *args, **kwargs: None)
    verified = authority.verify_distribution(encoded(value), b"unit proof", expected_source_sha=SOURCE, now=1500)
    return reuse, verified, tmp_path / "cache", manifest, index, calls, fetch


def test_only_verified_compatible_publications_can_seed_compiler_reuse(prepared):
    reuse, verified, cache, _, _, calls, _ = prepared
    with pytest.raises(ValueError, match="authenticated"):
        reuse.prepare(verified.manifest(), cache, "1" * 64)
    assert reuse.prepare(verified, cache, "2" * 64) is None
    assert calls == []
    assert not cache.exists()


def test_materialized_merkle_inputs_and_separate_digest_are_repeatable(prepared):
    reuse, verified, cache, manifest, index, _, _ = prepared
    from command_pack_store import PackReader

    result = reuse.prepare(verified, cache, "1" * 64)
    assert result.arguments() == ["compile-packs-reuse", str(result.directory), result.root_digest]
    root = (result.directory / "release.json").read_bytes()
    assert hashlib.sha256(root).hexdigest() == result.root_digest
    assert json.loads(root) == verified.manifest()["policy"]["root"]
    reader = PackReader(result.directory / "objects")
    assert reader.json(manifest)["extension_id"] == "command.one"
    assert reader.json(index)["entries"] == [["command.one", manifest]]
    assert reuse.prepare(verified, cache, "1" * 64) == result
    with pytest.raises(AttributeError):
        result.root_digest = "0" * 64


def test_poisoned_cache_objects_and_roots_never_receive_a_reuse_token(prepared):
    reuse, verified, cache, manifest, _, _, _ = prepared
    result = reuse.prepare(verified, cache, "1" * 64)
    path = result.directory / "objects" / (manifest["sha256"] + ".json")
    path.write_bytes(b"poison")
    with pytest.raises(ValueError, match="integrity"):
        reuse.prepare(verified, cache, "1" * 64)


def test_substituted_root_and_policy_transfer_fail_closed(prepared, monkeypatch):
    reuse, verified, cache, _, _, _, fetch = prepared
    result = reuse.prepare(verified, cache, "1" * 64)
    (result.directory / "release.json").write_bytes(b"{}")
    with pytest.raises(ValueError, match=r"integrity|authenticated"):
        reuse.prepare(verified, cache, "1" * 64)

    def corrupt(target, maximum):
        return b"corrupt archive" if target["member"].startswith("pack-") else fetch(target, maximum)

    monkeypatch.setattr(reuse, "cached_fetcher", lambda _: corrupt)
    with pytest.raises(ValueError, match="integrity"):
        reuse.prepare(verified, cache.parent / "second-cache", "1" * 64)


def test_build_stage_rejects_bare_cache_paths(prepared):
    _, _, cache, _, _, _, _ = prepared
    from build_native_command_packs import stage

    with pytest.raises(ValueError, match="verified"):
        stage(Path("unused-compiler"), cache, reuse=cache)
    assert not cache.exists()


def test_failed_reuse_compiler_preserves_exit_status_and_stderr(prepared, monkeypatch):
    reuse, verified, cache, _, _, _, _ = prepared
    import build_native_command_packs as packs

    token = reuse.prepare(verified, cache, "1" * 64)
    monkeypatch.setattr(packs, "input_stream", lambda *args: 1)

    class Process:
        stdout = io.BytesIO(b"")

        def wait(self):
            return 2

        def poll(self):
            return 2

    def failed(*args, **kwargs):
        kwargs["stderr"].write(b"unit compiler panic diagnostic")
        return Process()

    monkeypatch.setattr(packs.subprocess, "Popen", failed)
    with pytest.raises(ValueError, match=r"failed \(2\).*unit compiler panic diagnostic"):
        packs.stage(Path("unit-test-compiler"), cache.parent / "failed-output", reuse=token)


def test_failed_distribution_does_not_leave_a_premature_compilation_report(prepared, monkeypatch):
    _, _, cache, _, _, _, _ = prepared
    import build_extension_delivery as delivery

    monkeypatch.setattr(delivery, "verify_sources", lambda *args, **kwargs: None)

    def stage(compiler, output, **kwargs):
        output.mkdir(parents=True)
        (output / "release.json").write_text("{}")
        return {"schema": "guard.pack-build-report.v1", "extensions": 1}

    monkeypatch.setattr(delivery.packs, "stage", stage)

    def interrupted(*args, **kwargs):
        raise ValueError("unit interrupted distribution")

    monkeypatch.setattr(delivery, "build_from_packs", interrupted)
    with pytest.raises(ValueError, match="unit interrupted"):
        delivery.create_distribution(Path("unit-test-compiler"), cache, "1" * 40)
    assert not (cache / "compilation-report.json").exists()
    assert not (cache / delivery.MANIFEST).exists()
