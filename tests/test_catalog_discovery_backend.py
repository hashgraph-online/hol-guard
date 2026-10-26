"""Authenticated preparation is separate from the native semantic read path."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_catalog_read as native
from codex_plugin_scanner.guard.catalog_delivery import discovery
from codex_plugin_scanner.guard.catalog_delivery.authority import VerifiedDistribution
from codex_plugin_scanner.guard.catalog_delivery.metadata_objects import ObjectStore, encoded
from codex_plugin_scanner.guard.catalog_delivery.pack_store import PackReader


def prepared_fixture(tmp_path, monkeypatch, count=130, metadata_template=None, catalog_entries=None):
    """Build both halves of real native-index/transport metadata proofs."""
    origin = ObjectStore(tmp_path / "origin")
    records = {}
    manifests = {}
    if metadata_template is None:
        path = Path(__file__).parents[1] / "contracts/extensions/command-catalog.v1.json"
        metadata_template = json.loads(path.read_bytes())["catalog"][0]

    def located(reference):
        return {
            **reference,
            "location": {
                "tag": "extension-data-" + "a" * 40 + "-1.0-000001",
                "asset": "object-" + reference["sha256"] + ".json",
            },
        }

    if catalog_entries is not None:
        count = len(catalog_entries)
    for index in range(count):
        identity = (
            catalog_entries[index]["extension_id"] if catalog_entries is not None else f"command.synthetic-{index:05}"
        )
        value = {
            **(metadata_template or {}),
            "extension_id": identity,
            "permissions": [],
            "rules": [],
            "permission_count": 0,
            "rule_count": 0,
        }
        value["description"] = "lastunloadedneedle" if index + 1 == count else "synthetic metadata"
        if catalog_entries is not None:
            value = catalog_entries[index]
        catalog = origin.put_json([value])
        manifest = origin.put_json({"test": index})
        manifests[identity] = manifest
        record = {
            "schema": "guard.policy-delivery.v2",
            "extension_id": identity,
            "manifest": manifest,
            "catalog_metadata": located(catalog),
            "archives": [
                {
                    "sha256": "f" * 64,
                    "length": 1,
                    "location": {
                        "tag": "extension-data-" + "a" * 40 + "-1.0-000001",
                        "asset": "pack-" + "f" * 64 + ".zip",
                    },
                }
            ],
            "dependencies": [],
            "related_interfaces": [],
            "required": False,
            "activation": "opt-in",
            "trust_class": "external",
        }
        records[identity] = located(origin.put_json(record))
    index = origin.index(manifests)

    def wrap(reference):
        value = origin.json(reference)
        wrapper = {"schema": "guard.policy-transport.v2", "kind": value["kind"], "native": located(reference)}
        if value["kind"] == "leaf":
            wrapper["records"] = [[identity, records[identity]] for identity, _ in value["entries"]]
        else:
            wrapper["children"] = [[key, n, wrap(child)] for key, n, child in value["children"]]
        return located(origin.put_json(wrapper))

    root = {
        "schema": "guard.extension-distribution.v2",
        "source_sha": "a" * 40,
        "engine": "e" * 64,
        "expires_at": 9_999_999_999,
        "policy": {
            "root": {
                "schema": "guard.command-pack-release.v1",
                "engine": "e" * 64,
                "extensions": count,
                "index": index,
            },
            "transport": wrap(index),
        },
    }
    authority = object.__new__(VerifiedDistribution)
    data = encoded(root)
    object.__setattr__(authority, "data", data)
    object.__setattr__(authority, "digest", hashlib.sha256(data).hexdigest())
    object.__setattr__(authority, "source_sha", "a" * 40)
    object.__setattr__(authority, "expires_at", 9_999_999_999)
    requests = []

    def fetch(target, maximum):
        requests.append(target["asset"])
        assert target["asset"].startswith("object-")  # never policy archives
        data = (origin.directory / (target["asset"][7:])).read_bytes()
        assert len(data) <= maximum
        return data

    monkeypatch.setattr(discovery, "_cached", None)
    return authority, fetch, requests, root


def provision(home):
    from codex_plugin_scanner.guard.native_policy_snapshot_publisher import provision_native_verifier_key_for_store
    from codex_plugin_scanner.guard.store import GuardStore

    provision_native_verifier_key_for_store(GuardStore(home))


def test_factory_preparation_has_complete_sorted_pages_and_no_archive_reads(tmp_path, monkeypatch, native_hook_force):
    request = discovery.native_resident_client_request

    def checked_request(**kwargs):
        response = request(**kwargs)
        if response is not None:
            decoded = json.loads(response)
            assert decoded.get("schema") == "guard.catalog-prepare-result.v1", decoded
        return response

    monkeypatch.setattr(discovery, "native_resident_client_request", checked_request)
    authority, fetch, requests, _ = prepared_fixture(tmp_path, monkeypatch)
    home = tmp_path / "home"
    provision(home)
    handle = discovery.prepare_discovery(home, authority, fetch=fetch)
    objects = PackReader(home / "native-runtime/catalog-discovery/objects")
    root = json.loads((objects.directory / (handle.root + ".json")).read_bytes())
    assert root["authority"] == authority.digest and root["count"] == 130
    reference = root["first"]
    ids = []
    while reference is not None:
        page = objects.json(reference)
        assert reference["length"] <= 65536 and len(page["entries"]) <= 64
        for identity, metadata in page["entries"]:
            assert objects.json(metadata)["extension_id"] == identity
            ids.append(identity)
        reference = page["next"]
    assert ids == sorted(set(ids)) and len(ids) == 130
    assert requests and all(name.startswith("object-") for name in requests)
    before = len(requests)
    assert discovery.prepare_discovery(home, authority, fetch=fetch) is handle
    assert len(requests) == before
    # A cache holds one immutable handle, never all payloads or index rows.
    assert discovery._cached == (home, authority.digest, handle)
    assert discovery.require_handle(handle, home) is handle
    provision(tmp_path / "other")
    with pytest.raises(ValueError, match="handle_invalid"):
        discovery.require_handle(handle, tmp_path / "other")
    with pytest.raises(ValueError, match="unverified"):
        discovery.require_handle(SimpleNamespace(root=handle.root), home)
    handle.native["expires_at"] = 1
    with pytest.raises(ValueError, match="expired"):
        discovery.require_handle(handle, home)


def test_missing_metadata_never_publishes_handle_and_unverified_input_rejected(
    tmp_path, monkeypatch, native_hook_force
):
    authority, fetch, _, _ = prepared_fixture(tmp_path, monkeypatch, count=2)
    provision(tmp_path / "failed")
    with pytest.raises(FileNotFoundError):
        discovery.prepare_discovery(
            tmp_path / "failed", authority, fetch=lambda *_: (_ for _ in ()).throw(FileNotFoundError())
        )
    assert discovery._cached is None
    monkeypatch.setattr(discovery, "_installed_type", lambda: type("Installed", (), {}))
    with pytest.raises(ValueError, match="factory-authenticated"):
        discovery.prepare_discovery(tmp_path / "failed", SimpleNamespace(manifest=authority.manifest), fetch=fetch)
    object.__setattr__(authority, "expires_at", 1)
    with pytest.raises(ValueError, match="expired"):
        discovery.prepare_discovery(tmp_path / "failed", authority, fetch=fetch)


def test_missing_new_capability_fails_explicitly(tmp_path, monkeypatch):
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=tmp_path / "native"),
        capabilities=SimpleNamespace(features=[native.CATALOG_READ_FEATURE]),
    )
    monkeypatch.setattr(discovery, "native_runtime_status", lambda: status)
    with pytest.raises(ValueError, match="preparation unavailable"):
        discovery._native(tmp_path, {"kind": "begin"})


@pytest.mark.parametrize("failure", [False, True])
def test_transport_uses_authenticated_root_or_fails_503_without_legacy(tmp_path, monkeypatch, failure):
    status = SimpleNamespace(
        identity=SimpleNamespace(path=tmp_path / "native"),
        capabilities=SimpleNamespace(features=[native.CATALOG_READ_FEATURE, native.CATALOG_DISCOVERY_FEATURE]),
    )
    monkeypatch.setattr(native, "native_runtime_status", lambda **_: status)
    monkeypatch.setattr(native, "_supports_catalog_read", lambda _: True)
    payloads = []

    def installed(home):
        assert home == tmp_path
        if failure:
            raise ValueError("installed descriptor mismatch")
        return SimpleNamespace(root="c" * 64)

    def request(**kwargs):
        payloads.append(json.loads(kwargs["payload"]))
        return json.dumps(
            {
                "schema": "guard-catalog-read-result.v1",
                "outcome": "ok",
                "http_status": 200,
                "etag": '"cr1-' + "d" * 32 + '"',
                "body": '{"verbatim":true}',
                "error_code": None,
            }
        ).encode()

    monkeypatch.setattr(discovery, "installed_discovery", installed)
    monkeypatch.setattr(native, "native_resident_client_request", request)
    result = native.native_catalog_read(
        guard_home=tmp_path, route="index", query="q=anything", if_none_match=None, expected_catalog_digest="b" * 64
    )
    if failure:
        assert result.status == 503 and not payloads
    else:
        assert result.body == b'{"verbatim":true}'
        envelope = payloads[0]
        assert envelope["operation"] == "catalog_read_v2"
        assert envelope["request"]["discovery_root"] == "c" * 64
        assert envelope["request"]["read"]["query"] == "q=anything"


def test_real_native_factory_metadata_search_and_revalidation(tmp_path, monkeypatch, native_hook_force):
    from codex_plugin_scanner.guard.native_policy_snapshot_publisher import provision_native_verifier_key_for_store
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents
    from codex_plugin_scanner.guard.store import GuardStore

    # Test publication capability and CAS are separate from embedded active
    # policy: the last synthetic entry is never compiled into this executable.
    path = Path(__file__).parents[1] / "contracts/extensions/command-catalog.v1.json"
    metadata = json.loads(path.read_bytes())["catalog"][0]
    authority, fetch, _, _ = prepared_fixture(tmp_path, monkeypatch, metadata_template=metadata)
    home = tmp_path / "native-home"
    provision_native_verifier_key_for_store(GuardStore(home))
    handle = discovery.prepare_discovery(home, authority, fetch=fetch)
    status = native.native_runtime_status()
    assert native.CATALOG_DISCOVERY_FEATURE in status.capabilities.features
    arguments = dict(
        guard_home=home,
        route="index",
        query="q=lastunloadedneedle&limit=1",
        if_none_match=None,
        expected_catalog_digest="b" * 64,
        timeout_seconds=60,
        discovery_handle=handle,
    )
    try:
        result = native.native_catalog_read(**arguments)
        assert result is not None and result.status == 200, result
        body = json.loads(result.body)
        assert body["total_count"] == 1
        assert body["items"][0]["extension_id"] == "command.synthetic-00129"
        assert body["native_catalog_digest"] == "b" * 64
        arguments["if_none_match"] = result.etag
        assert native.native_catalog_read(**arguments).status == 304
    finally:
        close_native_residents(guard_home=home)
