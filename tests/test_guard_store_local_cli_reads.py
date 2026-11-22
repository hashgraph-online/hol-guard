"""The native store answers the single-value local CLI reads."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_local_cli_schema import local_cli_schema_marker


def test_a_fresh_store_reads_no_local_cli_authority(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")

    assert store.read_local_cli_revision() == 0
    assert store.read_local_cli_surface("local-cli.tool") is None
    assert store.has_local_cli_block_rules() is False
    assert store.read_local_cli_capabilities("local-cli.tool") == {
        "loopback-network": "off",
        "state-dir-read": "off",
        "state-dir-write": "off",
    }


def test_a_cause_for_an_unobserved_cli_changes_nothing(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")

    changed = store.note_local_cli_capability_cause(
        cli_id="local-cli.tool", identity_hash="hash", cause="connect_loopback"
    )

    assert changed == 0


def test_an_older_local_cli_marker_makes_the_schema_stale(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    assert store._schema_is_current() is True
    version, _checksum = local_cli_schema_marker()

    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "update local_cli_schema_migration set version = ?, checksum = ? where singleton = 1",
            (version - 1, "older"),
        )

    assert store._schema_is_current() is False


def test_a_missing_local_cli_marker_makes_the_schema_stale(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")

    with sqlite3.connect(store.path) as connection:
        connection.execute("delete from local_cli_schema_migration")

    assert store._schema_is_current() is False


def test_a_non_boolean_block_rules_answer_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    monkeypatch.setattr(store, "_native_store_call", lambda _method, _args: 1)

    with pytest.raises(sqlite3.DatabaseError, match="native_local_cli_block_rules_invalid"):
        store.has_local_cli_block_rules()
