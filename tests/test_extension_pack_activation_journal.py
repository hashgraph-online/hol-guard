"""Staging a pack draft against the protected floor, and durable pack objects.

The resident reserves and installs the draft with the control transition;
``pack_reserve_tests`` and ``pack_finish_tests`` in the native runtime pin it.
"""

from __future__ import annotations

import sqlite3
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.catalog_delivery import (
    activation_store,
    activation_transition,
    preparation,
)
from codex_plugin_scanner.guard.native_command_control_authority_store import _key
from codex_plugin_scanner.guard.store_extension_control_authority_schema import (
    ensure_extension_control_authority_schema,
)
from tests.extension_control_records import TRANSITION_PURPOSE, authenticated_record
from tests.native_activation_support import compiled_lifecycle as compiled_lifecycle
from tests.native_activation_support import seed
from tests.test_extension_pack_preparation import delivery as delivery


@pytest.fixture
def journal(delivery):
    home = delivery.cache.parent / "journal-device"
    home.mkdir(mode=0o700)
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    anchor = SimpleNamespace(current=None)
    store = SimpleNamespace(
        guard_home=home,
        _connect=lambda: connection,
        _policy_integrity_secret_material=lambda *, create: (b"k" * 32, "test"),
        _authority_key=lambda *, required: b"a" * 32,
        _read_anchor=lambda *, key: anchor.current,
    )
    ensure_extension_control_authority_schema(connection)
    connection.commit()
    seed(store)
    prepared = preparation.prepare(
        delivery.verified(),
        [],
        activation_store.prepare_directory_for_store(store),
        engine="1" * 64,
        now=1500,
        fetch=delivery.fetch,
    )
    draft = activation_transition.stage(None, prepared, verifier_key=_key(store), store=store, now=1500)
    payload = {"command_pack_record_digest": draft.digest}
    data, digest, mac = authenticated_record(payload, key=b"a" * 32, purpose=TRANSITION_PURPOSE)
    transition = {
        "revision": 1,
        "snapshot_digest": "e" * 64,
        "catalog_digest": prepared.metadata.catalog_digest,
        "created_at": "unit",
        "transition_json": data,
        "transition_digest": digest,
        "transition_mac": mac,
    }
    return SimpleNamespace(
        store=store,
        connection=connection,
        anchor=anchor,
        prepared=prepared,
        draft=draft,
        transition=transition,
        pack=draft.digest,
    )


def test_first_activation_cannot_omit_the_protected_floor(journal):
    journal.store._policy_integrity_secret_store.values.clear()
    with pytest.raises(ValueError, match="protected_floor_missing"):
        activation_transition.stage(
            None, journal.prepared, verifier_key=_key(journal.store), store=journal.store, now=1500
        )


def test_published_object_entry_is_durable_for_both_new_and_competing_writers(tmp_path, monkeypatch):
    import hashlib

    from codex_plugin_scanner.guard.catalog_delivery import pack_store

    directory = tmp_path / "objects"
    directory.mkdir()
    data = b'{"fixture":true}\n'
    digest = hashlib.sha256(data).hexdigest()
    synchronized = []
    monkeypatch.setattr(pack_store, "durable_directory", lambda path: synchronized.append(path))
    assert pack_store.publish_object(directory, digest, data) is True
    assert pack_store.publish_object(directory, digest, data) is False
    assert synchronized == [directory, directory]
