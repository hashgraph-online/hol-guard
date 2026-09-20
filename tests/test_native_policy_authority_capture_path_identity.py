"""Connection reuse never turns a replaced database path into current authority."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Literal

import pytest

from codex_plugin_scanner.guard import native_policy_authority_read as reader
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.runtime.command_extensions import CommandSafetyExtensionRegistry
from codex_plugin_scanner.guard.runtime.extension_control_authority import ExtensionControlAuthorityView
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_canonical_policy_row_authority import _NOW, _activated_store
from tests.test_native_policy_authority_read import _TIME


def _replacement_database(store: GuardStore, destination: Path) -> None:
    with closing(sqlite3.connect(store.path)) as original, closing(sqlite3.connect(destination)) as replacement:
        original.backup(replacement)
    destination.chmod(store.path.stat().st_mode & 0o777)


@pytest.mark.parametrize("phase", ["before-begin", "captured-view", "final-integrity"])
def test_replaced_database_with_unchanged_integrity_refuses_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    phase: Literal["before-begin", "captured-view", "final-integrity"],
) -> None:
    store = _activated_store(tmp_path)
    replacement = tmp_path / "synthetic-replacement.db"
    _replacement_database(store, replacement)
    original_identity = store.path.stat().st_dev, store.path.stat().st_ino
    replacement_identity = replacement.stat().st_dev, replacement.stat().st_ino
    assert replacement_identity != original_identity
    original_control = store._load_policy_integrity_control_state
    original_managed = store._read_captured_extension_control_authority
    observed: list[sqlite3.Connection] = []
    replaced: list[bool] = []

    def replace_database() -> None:
        # A byte-equivalent, legitimately backed-up database keeps the same
        # key/control state. Only its path identity changed during capture.
        replacement.replace(store.path)
        assert (store.path.stat().st_dev, store.path.stat().st_ino) == replacement_identity
        replaced.append(True)

    def replace_after_control(
        *, create: bool, connection: sqlite3.Connection | None = None
    ) -> dict[str, object] | None:
        control = original_control(create=create, connection=connection)
        assert not create and connection is not None and not connection.in_transaction
        observed.append(connection)
        if (phase == "before-begin" and len(observed) == 1) or (phase == "final-integrity" and len(observed) == 2):
            replace_database()
        return control

    def replace_after_captured_read(
        connection: sqlite3.Connection,
        registry: CommandSafetyExtensionRegistry,
    ) -> ExtensionControlAuthorityView:
        result = original_managed(connection, registry)
        if phase == "captured-view":
            assert connection.in_transaction
            replace_database()
        return result

    monkeypatch.setattr(store, "_load_policy_integrity_control_state", replace_after_control)
    monkeypatch.setattr(store, "_read_captured_extension_control_authority", replace_after_captured_read)
    with pytest.raises(NativePolicySnapshotError, match="changed_during_read"):
        reader.read_native_policy_authority_inputs(store, now=_TIME)
    assert replaced == [True]
    assert len(observed) == (2 if phase == "final-integrity" else 1)


def test_same_database_external_commit_before_begin_is_visible_and_allowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _activated_store(tmp_path)
    other = GuardStore(store.guard_home)
    expected = reader.read_native_policy_authority_inputs(store, now=_TIME)
    original_identity = store.path.stat().st_dev, store.path.stat().st_ino
    original_control = store._load_policy_integrity_control_state
    original_managed = store._read_captured_extension_control_authority
    observed: list[sqlite3.Connection] = []
    captured: list[bool] = []
    marker = "synthetic-pre-capture-runtime"

    def commit_after_control(*, create: bool, connection: sqlite3.Connection | None = None) -> dict[str, object] | None:
        control = original_control(create=create, connection=connection)
        if not observed:
            assert not create and connection is not None and not connection.in_transaction
            observed.append(connection)
            other.set_sync_payload(marker, {"observed": True}, _NOW)
            assert (store.path.stat().st_dev, store.path.stat().st_ino) == original_identity
        return control

    def observe_captured_transaction(
        connection: sqlite3.Connection,
        registry: CommandSafetyExtensionRegistry,
    ) -> ExtensionControlAuthorityView:
        assert connection.in_transaction
        assert connection.execute("pragma query_only").fetchone()[0] == 1
        row = connection.execute("select payload_json from sync_state where state_key = ?", (marker,)).fetchone()
        assert row is not None and json.loads(row["payload_json"]) == {"observed": True}
        captured.append(True)
        return original_managed(connection, registry)

    monkeypatch.setattr(store, "_load_policy_integrity_control_state", commit_after_control)
    monkeypatch.setattr(store, "_read_captured_extension_control_authority", observe_captured_transaction)
    assert reader.read_native_policy_authority_inputs(store, now=_TIME) == expected
    assert len(observed) == 1 and captured == [True]
