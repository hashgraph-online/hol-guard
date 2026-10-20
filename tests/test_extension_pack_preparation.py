"""Preparation integrity/selection tests; native executable admission is separate."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.catalog_delivery import authority, preparation
from codex_plugin_scanner.guard.catalog_delivery.containers import member
from codex_plugin_scanner.guard.catalog_delivery.located_store import LocatedStore
from codex_plugin_scanner.guard.catalog_delivery.metadata_objects import ObjectStore, encoded, entries
from codex_plugin_scanner.guard.catalog_delivery.pack_archives import pack_objects, parts
from codex_plugin_scanner.guard.catalog_delivery.pack_store import PackReader
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from tests.native_activation_support import compiled_lifecycle as compiled_lifecycle
from tests.test_extension_delivery_authority import SOURCE, root_value


@pytest.fixture
def delivery(tmp_path, monkeypatch):
    # Existing activation/security adapter tests need deliberately synthetic IR
    # and historical snapshots. Freeze that constructor here, never in runtime.
    # Candidate preparation is qualified with real IR and the verified native
    # bridge in test_native_pack_preparation.py, without this fixture.
    namespace = {"__package__": preparation.__package__}
    fixture = Path(__file__).parent / "fixtures/extension-preparation-legacy.py.txt"
    exec(compile(fixture.read_text(), str(fixture), "exec"), namespace)
    namespace["PreparedCommandPacks"] = preparation.PreparedCommandPacks
    namespace["UnavailablePackError"] = preparation.UnavailablePackError
    namespace["cached_fetcher"] = lambda directory: preparation.cached_fetcher(directory)
    from codex_plugin_scanner.guard.catalog_delivery.cache_io import stage_archive
    from tests.native_activation_support import native

    namespace["stage_archive"] = lambda directory, reference, fetch: stage_archive(
        directory, reference, fetch, invoke=native
    )

    def legacy_snapshot(*args, **kwargs):
        result = namespace["_prepare"](*args, **kwargs)
        object.__setattr__(result, "_cache_lease", namespace["Lease"](args[2]))
        return result

    monkeypatch.setattr(preparation, "prepare", legacy_snapshot)
    monkeypatch.setattr(preparation, "lookup", namespace["lookup"], raising=False)
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    from extension_delivery_assets import AssetPlan

    policy = ObjectStore(tmp_path / "policy")
    plan = AssetPlan(tmp_path / "assets", SOURCE)
    metadata = LocatedStore(tmp_path / "metadata", publisher=plan)
    manifests, records, defaults, archive_digests = {}, {}, {}, {}
    for suffix in ["core", "external", "dependency", "unused"]:
        identity = "command." + suffix
        permission = identity + ".permission.read"
        permission_template = BUILT_IN_COMMAND_EXTENSION_REGISTRY.permissions[0].to_dict()
        catalog = {
            **BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions[0].to_dict(),
            "extension_id": identity,
            "action_classes": [],
            "aliases": [],
            "rules": [],
            "rule_count": 0,
            "permission_count": 1,
            "dependencies": [],
            "required": suffix == "core",
            "activation": "default-on" if suffix == "core" else "opt-in",
            "trust_class": "first-party" if suffix == "core" else "external",
            "permissions": [
                {
                    **permission_template,
                    "permission_id": permission,
                    "extension_id": identity,
                    "rule_ids": [],
                    "configurable": True,
                    "fixed_reason": None,
                    "dependencies": ["command.dependency.permission.read"] if suffix == "external" else [],
                    "implied_permissions": [],
                }
            ],
        }
        catalog_ref = policy.put_json([catalog])
        program = {"catalog_digest": hashlib.sha256(encoded([catalog])).hexdigest(), "nodes": {}}
        trust = hashlib.sha256(("trust:" + identity).encode()).hexdigest()
        manifest = {
            "schema": "guard.command-policy-pack.v1",
            "extension_id": identity,
            "program_digest": hashlib.sha256(identity.encode()).hexdigest(),
            "trust_digest": trust,
            "program": policy.put_json(program),
            "catalog": catalog_ref,
            "descriptors": policy.put_json([]),
        }
        reference = policy.put_json(manifest)
        manifests[identity] = reference
        _, objects = pack_objects(PackReader(policy.directory), reference)
        archives = []
        for archive in parts(policy.directory, objects):
            digest = hashlib.sha256(archive).hexdigest()
            archive_digests[identity] = digest
            archives.append({"sha256": digest, "length": len(archive), "location": plan.asset(archive, "pack")})
        record = metadata.put_json(
            {
                "schema": "guard.policy-delivery.v2",
                "extension_id": identity,
                "manifest": reference,
                "catalog_metadata": metadata.put_json([catalog]),
                "archives": archives,
                "dependencies": [],
                "related_interfaces": ["command.dependency", "command.unused"] if suffix == "external" else [],
                "required": catalog["required"],
                "activation": catalog["activation"],
                "trust_class": catalog["trust_class"],
            }
        )
        records[identity] = record
        if suffix == "core":
            defaults[identity] = record
    native_index = policy.index(manifests)
    native_ref = metadata.put(PackReader(policy.directory).blob(native_index))
    transport = metadata.put_json(
        {
            "schema": "guard.policy-transport.v2",
            "kind": "leaf",
            "native": native_ref,
            "records": [[identity, records[identity]] for identity in sorted(records)],
        }
    )
    value = root_value()
    value["policy"]["root"].update(index=native_index, extensions=len(manifests))
    value["directory"]["count"] = len(manifests)
    value["policy"]["transport"] = transport
    value["policy"]["defaults"] = {"count": len(defaults), "index": metadata.index(defaults)}
    plan.finish()
    calls, native_calls = [], []

    def fetch(target, maximum):
        calls.append(target)
        raw = (plan.directory / target["tag"] / target["asset"]).read_bytes()
        return member(raw, target["asset"], target["member"], maximum)

    def check(directory, expected):
        # Test transport/selection without pretending this synthetic IR is a
        # qualified executable. Rust tests separately admit actual compiler IR.
        native_calls.append(expected)
        reader = PackReader(directory / "objects")
        cache = json.loads((directory / "sets" / (expected + ".json")).read_bytes())
        root = reader.json(cache["release"])
        references = dict(entries(reader, root["index"], root["extensions"]))
        chosen, page = [], cache["selection"]
        while page:
            body = reader.json(page)
            chosen.extend(body["ids"])
            page = body["next"]
        identities = []
        for identity in chosen:
            manifest = reader.json(references[identity])
            identities.append(
                {
                    "extension": identity,
                    "program": manifest["program_digest"],
                    "catalog": reader.json(manifest["program"])["catalog_digest"],
                    "trust": manifest["trust_digest"],
                }
            )
        identities = namespace["_identity"]("1" * 64, identities)
        assert identities.program_digest == expected
        return {
            "engine": "1" * 64,
            "extensions": len(chosen),
            "program_digest": identities.program_digest,
            "catalog_digest": identities.catalog_digest,
            "trust_digest": identities.trust_digest,
        }

    monkeypatch.setattr(preparation, "check_pack_cache", check, raising=False)
    namespace["check_pack_cache"] = lambda directory, expected: preparation.check_pack_cache(directory, expected)
    monkeypatch.setattr(authority, "_verify_attested_artifact", lambda *args, **kwargs: None)

    def verified(root=value):
        return authority.verify_distribution(
            encoded(root), b"unit transport proof", expected_source_sha=SOURCE, now=1500
        )

    return SimpleNamespace(
        verified=verified,
        value=value,
        fetch=fetch,
        calls=calls,
        native_calls=native_calls,
        cache=(tmp_path / "cache").resolve(),
        archives=archive_digests,
        store=metadata,
        plan=plan,
        manifests=manifests,
    )


def test_preparation_is_inert_until_explicit_selection_and_includes_permission_closure(delivery):
    result = preparation.prepare(
        delivery.verified(), [], delivery.cache, engine="1" * 64, now=1500, fetch=delivery.fetch
    )
    assert result.selected == {"command.core"}
    assert not any(delivery.archives["command.external"] in target["member"] for target in delivery.calls)

    assert not any(delivery.archives["command.unused"] in target["member"] for target in delivery.calls)
    expanded = preparation.prepare(
        delivery.verified(), ["command.external"], delivery.cache, engine="1" * 64, now=1500, fetch=delivery.fetch
    )
    assert expanded.selected == {"command.core", "command.external", "command.dependency"}
    assert len(list(expanded.catalogs())) == 3
    assert not any(delivery.archives["command.unused"] in target["member"] for target in delivery.calls)
    assert len(delivery.native_calls) == 2
    assert not hasattr(expanded, "active")
    with pytest.raises(AttributeError):
        expanded.source_sha = "0" * 40


@pytest.mark.parametrize("forged_copy", [False, True])
def test_defaults_cannot_disguise_an_external_transport_record(delivery, forged_copy):
    policy = delivery.value["policy"]
    record = preparation.lookup(delivery.store, policy["root"], policy["transport"], "command.external")
    if forged_copy:
        record = {**record, "trust_class": "first-party"}
    reference = delivery.store.put_json(record)
    policy["defaults"] = {"count": 1, "index": delivery.store.index({"command.external": reference})}
    delivery.plan.finish()
    with pytest.raises(ValueError, match=r"external policy|default policy reference"):
        preparation.prepare(delivery.verified(), [], delivery.cache, engine="1" * 64, now=1500, fetch=delivery.fetch)
    assert delivery.native_calls == []
    assert not any(delivery.archives["command.external"] in target["member"] for target in delivery.calls)


def test_unverified_expired_and_incompatible_roots_do_no_preparation(delivery):
    for root, engine, now, message in [
        (delivery.value, "1" * 64, 1500, "authenticated"),
        (delivery.verified(), "2" * 64, 1500, "different native engine"),
        (delivery.verified(), "1" * 64, 2500, "fresh"),
    ]:
        with pytest.raises(ValueError, match=message):
            preparation.prepare(root, [], delivery.cache, engine=engine, now=now, fetch=delivery.fetch)
    assert not delivery.cache.exists()
    assert delivery.calls == []


def test_retained_inactive_control_targets_load_metadata_without_policy(delivery):
    result = preparation.prepare(
        delivery.verified(),
        [],
        delivery.cache,
        engine="1" * 64,
        retained_extension_ids=["command.external"],
        now=1500,
        fetch=delivery.fetch,
    )
    assert result.selected == {"command.core"}
    assert "command.external" in result.registry_ids
    assert "command.dependency" in result.registry_ids
    assert len(list(result.registry_catalogs())) == len(result.registry_ids)
    assert not any(delivery.archives["command.external"] in target["member"] for target in delivery.calls)
    assert not any(delivery.archives["command.dependency"] in target["member"] for target in delivery.calls)


def test_new_discovery_publication_keeps_the_same_enforcement_representation(delivery):
    first = preparation.prepare(
        delivery.verified(), [], delivery.cache, engine="1" * 64, now=1500, fetch=delivery.fetch
    )
    path = delivery.cache / "sets" / (first.metadata.program_digest + ".json")
    before = path.read_bytes()
    delivery.value["publication_id"] = "2.1"
    second = preparation.prepare(
        delivery.verified(), [], delivery.cache, engine="1" * 64, now=1500, fetch=delivery.fetch
    )
    assert first.metadata == second.metadata
    assert first.root_digest != second.root_digest
    assert path.read_bytes() == before


@pytest.mark.parametrize("kind", ["extension", "pack"])
def test_revoked_selected_policy_never_reaches_native_preparation(delivery, kind):
    from codex_plugin_scanner.guard.catalog_delivery.revocations import RevokedPackError, revocation_key

    identity = "command.core"
    manifest = delivery.manifests[identity]["sha256"] if kind == "pack" else None
    record = {
        "schema": "guard.extension-revocation.v1",
        "extension_id": identity,
        "kind": kind,
        "epoch": 1,
        "state": "revoked",
        "reason": "Withdrawn reviewed policy.",
    }
    if manifest is not None:
        record["manifest_sha256"] = manifest
    reference = delivery.store.put_json(record)
    delivery.value["policy"]["revocations"] = {
        "epoch": 1,
        "count": 1,
        "index": delivery.store.index({revocation_key(identity, kind, manifest): reference}),
    }
    delivery.plan.finish()
    with pytest.raises(RevokedPackError):
        preparation.prepare(delivery.verified(), [], delivery.cache, engine="1" * 64, now=1500, fetch=delivery.fetch)
    assert delivery.native_calls == []
