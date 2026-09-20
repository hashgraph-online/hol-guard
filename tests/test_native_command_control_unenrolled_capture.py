"""A never-enrolled observer uses one coherent, read-only authority view."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.managed_controls_policy_bundle import (
    MANAGED_CONTROLS_ACTIVE_STATE_KEY,
    MANAGED_CONTROLS_LAST_GOOD_STATE_KEY,
    MANAGED_CONTROLS_REVISION_STATE_KEY,
)
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_extension_control_authority import MemorySecretStore


def test_never_enrolled_read_uses_one_read_only_sql_snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path)
    store._extension_control_authority_secret_store = MemorySecretStore()
    original = store._connect
    captures: list[tuple[bool, int, int]] = []

    @contextmanager
    def observed_connection() -> Iterator[sqlite3.Connection]:
        with original() as connection:
            yield connection
            captures.append(
                (
                    connection.in_transaction,
                    connection.execute("pragma query_only").fetchone()[0],
                    connection.total_changes,
                )
            )

    monkeypatch.setattr(store, "_connect", observed_connection)
    view = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY, read_only=True)

    assert view.health is AuthorityHealth.UNENROLLED
    assert view.revision == 0 and view.managed_revision == 0 and view.layers == ()
    # Connection setup dominates cold observer work. More importantly, the
    # schema, absence and managed-state reads must describe the same SQL view.
    assert captures == [(True, 1, 0)]


@pytest.mark.parametrize(
    "state_key",
    [MANAGED_CONTROLS_ACTIVE_STATE_KEY, MANAGED_CONTROLS_REVISION_STATE_KEY, MANAGED_CONTROLS_LAST_GOOD_STATE_KEY],
)
def test_retained_managed_state_cannot_become_never_enrolled(tmp_path: Path, state_key: str) -> None:
    store = GuardStore(tmp_path)
    store._extension_control_authority_secret_store = MemorySecretStore()
    with store._connect() as connection:
        connection.execute(
            "insert into sync_state(state_key, payload_json, updated_at) values (?, ?, ?)",
            (state_key, '{"unverified":true}', "2026-01-01T00:00:00Z"),
        )

    view = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY, read_only=True)

    assert view.health is AuthorityHealth.TAMPERED


def test_retained_anchor_cannot_become_never_enrolled(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    secrets = MemorySecretStore()
    store._extension_control_authority_secret_store = secrets
    secrets.set_secret(store._anchor_ref(), "unverified-anchor")

    view = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY, read_only=True)

    assert view.health is AuthorityHealth.TAMPERED


def test_unknown_schema_is_not_an_empty_authority(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store._extension_control_authority_secret_store = MemorySecretStore()
    with store._connect() as connection:
        connection.execute("update extension_control_schema_migration set version = 999 where singleton = 1")

    view = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY, read_only=True)

    assert view.health is not AuthorityHealth.UNENROLLED


def test_missing_table_retains_existing_schema_preparation(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store._extension_control_authority_secret_store = MemorySecretStore()
    with store._connect() as connection:
        connection.execute("drop table extension_control_authority_snapshot")

    view = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY, read_only=True)

    assert view.health is AuthorityHealth.UNENROLLED
    with store._connect() as connection:
        assert connection.execute("select count(*) from extension_control_authority_snapshot").fetchone()[0] == 0
