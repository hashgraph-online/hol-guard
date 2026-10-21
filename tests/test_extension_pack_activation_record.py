"""Local authority records bind complete bounded metadata, not cache flags."""

from __future__ import annotations

import json

import pytest

from codex_plugin_scanner.guard.catalog_delivery import activation_record, preparation
from codex_plugin_scanner.guard.runtime.extension_control_authority import ExtensionControlAuthorityError
from tests.native_activation_support import compiled_lifecycle as compiled_lifecycle
from tests.test_extension_pack_preparation import delivery as delivery


def test_authenticated_record_reopens_offline_without_rechecking_expired_publication(delivery, monkeypatch):
    prepared = preparation.prepare(
        delivery.verified(), ["command.external"], delivery.cache, engine="1" * 64, now=1500, fetch=delivery.fetch
    )
    key = b"local activation record fixture".ljust(32, b"x")
    sealed = activation_record.seal(prepared, key=key, revision=1, now=1500)
    calls = len(delivery.calls)
    monkeypatch.setattr(preparation.time, "time", lambda: 10000)
    reopened = activation_record.open_record(*sealed, key=key, directory=delivery.cache)
    assert reopened.metadata == prepared.metadata
    assert reopened.selected == prepared.selected
    assert reopened.registry_ids == prepared.registry_ids
    assert list(reopened.registry_catalogs()) == list(prepared.registry_catalogs())
    assert len(delivery.calls) == calls
    with pytest.raises(ValueError, match="expired"):
        activation_record.seal(prepared, key=key, revision=2)
    with pytest.raises(ValueError, match="prepared"):
        activation_record.seal(reopened, key=key, revision=2)


def test_record_tampering_wrong_key_and_incomplete_metadata_never_reopen(delivery):
    prepared = preparation.prepare(
        delivery.verified(), [], delivery.cache, engine="1" * 64, now=1500, fetch=delivery.fetch
    )
    key = b"local activation record fixture".ljust(32, b"x")
    data, digest, mac = activation_record.seal(prepared, key=key, revision=1, now=1500)
    with pytest.raises(ExtensionControlAuthorityError):
        activation_record.open_record(data, digest, mac, key=b"z" * 32, directory=delivery.cache)
    value = json.loads(data)
    value["selected_count"] += 1
    with pytest.raises(ExtensionControlAuthorityError):
        activation_record.open_record(json.dumps(value), digest, mac, key=key, directory=delivery.cache)
    value = json.loads(data)
    path = delivery.cache / "objects" / (value["registry"]["sha256"] + ".json")
    path.write_bytes(b"{}")
    with pytest.raises(ValueError):
        activation_record.open_record(data, digest, mac, key=key, directory=delivery.cache)
