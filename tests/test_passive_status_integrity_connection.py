"""Connection-aware integrity reads preserve the passive store boundary."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.passive_status_store import PassiveStatusStore
from codex_plugin_scanner.guard.runtime.exact_cloud_review import enable_exact_cloud_review
from tests.guard_exact_cloud_review_support import connected_exact_review_store
from tests.test_cloud_review_status_storage import _snapshot


@pytest.mark.parametrize("cached", [False, True])
def test_passive_integrity_reads_its_owned_snapshot_without_mutation(tmp_path: Path, cached: bool) -> None:
    store = connected_exact_review_store(tmp_path)
    enable_exact_cloud_review(store)
    expected = store._policy_integrity_secret_material(create=False)
    assert expected[0] is not None and expected[1] is not None
    if not cached:
        store._clear_policy_integrity_cache()
    before = _snapshot(store)

    with closing(PassiveStatusStore(store)) as reader, reader._connect() as connection:
        assert connection.in_transaction
        assert reader._policy_integrity_secret_material(create=False, connection=connection) == expected
        assert reader._policy_integrity_secret_material(create=False) == expected
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            connection.execute("delete from guard_devices")

    assert _snapshot(store) == before


def test_passive_integrity_missing_material_is_not_created_with_connection(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    assert store._policy_integrity_secret_store is not None
    store._policy_integrity_secret_store.delete_secret(store._policy_integrity_key_ref)
    store._clear_policy_integrity_cache()
    before = _snapshot(store)

    with closing(PassiveStatusStore(store)) as reader, reader._connect() as connection:
        assert reader._policy_integrity_secret_material(create=False, connection=connection) == (None, None)
        with pytest.raises(RuntimeError, match="cannot create an integrity key"):
            reader._policy_integrity_secret_material(create=True, connection=connection)

    assert _snapshot(store) == before


def test_passive_integrity_refuses_a_foreign_connection(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    before = _snapshot(store)

    with (
        closing(PassiveStatusStore(store)) as reader,
        closing(sqlite3.connect(":memory:")) as foreign,
        pytest.raises(RuntimeError, match="requires its existing snapshot connection"),
    ):
        reader._policy_integrity_secret_material(create=False, connection=foreign)

    assert _snapshot(store) == before
