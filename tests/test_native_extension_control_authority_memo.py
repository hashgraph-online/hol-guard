"""The authority memo serves a settled reply only while the authority's inputs are unchanged."""

from __future__ import annotations

import re
import sqlite3
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_extension_control_authority_memo as memo
from codex_plugin_scanner.guard.store_extension_control_authority_epoch import AUTHORITY_INPUT_TABLES
from codex_plugin_scanner.guard.store_extension_control_authority_schema import (
    ensure_extension_control_authority_schema,
)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="the memo keeps nothing on Windows")


def _store(directory: Path, *, activate_packs: bool = True) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "guard.db"
    with sqlite3.connect(path) as connection:
        connection.execute("create table t (v integer)")
        connection.execute(
            "create table guard_events (event_id integer primary key autoincrement, event_name text not null, "
            "payload_json text not null, occurred_at text not null)"
        )
        connection.execute(
            "create table sync_state (state_key text primary key, payload_json text not null, updated_at text not null)"
        )
        ensure_extension_control_authority_schema(connection, activate_packs=activate_packs)
    return path


def _commit(store: Path, statement: str, *values: object) -> None:
    with sqlite3.connect(store) as connection:
        connection.execute(statement, values)


_RUST_OPS = Path(__file__).resolve().parents[1] / "rust/crates/guard-runtime/src/extension_control_authority_op"


def _wire(store: Path, *, op: str = "read", allow_migration: bool = False, request_id: str = "r1") -> dict[str, object]:
    return {
        "store_path": str(store),
        "op": op,
        "request_id": request_id,
        "allow_migration": allow_migration,
        "catalog_digest": "c" * 64,
    }


def _keep(wire: dict[str, object], payload: dict[str, object]) -> None:
    key, kept = memo.lookup(wire)
    assert kept is None
    memo.keep(key, payload)


def test_settled_reply_outlives_unrelated_commits_but_not_an_authority_write(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _keep(_wire(store), {"view": {"health": "protected"}})

    _key, kept = memo.lookup(_wire(store, request_id="r2"))
    assert kept == {"view": {"health": "protected"}}
    kept["view"]["health"] = "mutated"
    assert memo.lookup(_wire(store))[1] == {"view": {"health": "protected"}}

    # A hook's receipts, evidence and other state commit on every request.
    _commit(store, "insert into t values (1)")
    _commit(store, "insert into guard_events (event_name, payload_json, occurred_at) values ('hook', '{}', 't')")
    _commit(store, "insert into sync_state values ('other', '{}', 't')")
    assert memo.lookup(_wire(store))[1] == {"view": {"health": "protected"}}

    _commit(store, "update extension_control_schema_migration set checksum = checksum")
    assert memo.lookup(_wire(store))[1] is None


def test_legacy_schema_memo_stops_serving_when_pack_schema_activates(tmp_path: Path) -> None:
    store = _store(tmp_path, activate_packs=False)
    reply = {"view": {"health": "protected"}}
    _keep(_wire(store), reply)
    assert memo.lookup(_wire(store))[1] == reply
    with sqlite3.connect(store) as connection:
        epoch = connection.execute("select epoch from extension_control_authority_epoch").fetchone()[0]
        ensure_extension_control_authority_schema(connection, activate_packs=True)
        # The schema identity itself must invalidate the token, independently
        # of the migration's writes to the authority epoch.
        connection.execute("update extension_control_authority_epoch set epoch=?", (epoch,))
    assert memo.lookup(_wire(store))[1] is None
    _keep(_wire(store), reply)
    _commit(store, "insert into extension_command_pack_activation values (1, 0, '{}', 'd', 'm', 't')")
    assert memo.lookup(_wire(store))[1] is None


def test_pack_schema_with_missing_activation_table_never_memoizes(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _keep(_wire(store), {"view": {"health": "protected"}})
    _commit(store, "drop table extension_command_pack_activation")
    assert memo.lookup(_wire(store)) == (None, None)


@pytest.mark.parametrize(
    "statement",
    [
        "insert into extension_control_catalog_manifest values ('d', '{}', '{}', 'r', 'm', 't')",
        "insert into extension_command_pack_activation values (1, 0, '{}', 'd', 'm', 't')",
        "insert into guard_events (event_name, payload_json, occurred_at) "
        "values ('extension_control_authority_catalog_migrated', '{}', 't')",
        "insert into sync_state values ('managed_controls_active', '{}', 't')",
        "update sync_state set state_key = 'managed_controls_revision' where state_key = 'other'",
    ],
)
def test_any_write_to_an_authority_input_drops_the_reply(tmp_path: Path, statement: str) -> None:
    store = _store(tmp_path)
    _commit(store, "insert into sync_state values ('other', '{}', 't')")
    _keep(_wire(store), {"view": {"health": "protected"}})
    _commit(store, statement)
    assert memo.lookup(_wire(store))[1] is None


@pytest.mark.parametrize(
    "statement",
    [
        "drop trigger trg_extension_control_epoch_extension_control_authority_transition_update",
        "create trigger trg_extension_control_epoch_extra after insert on t begin select 1; end",
    ],
)
def test_a_missing_or_foreign_epoch_trigger_turns_the_memo_off(tmp_path: Path, statement: str) -> None:
    store = _store(tmp_path)
    _keep(_wire(store), {"view": {"health": "protected"}})
    _commit(store, statement)
    key, kept = memo.lookup(_wire(store))
    assert key is None
    assert kept is None


def test_replaced_database_is_not_served_from_the_memo(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _keep(_wire(store), {"view": {"health": "protected"}})
    _store(tmp_path / "next").replace(store)
    assert memo.lookup(_wire(store))[1] is None


@pytest.mark.parametrize(
    "payload",
    [
        {"fault": "tampered"},
        {"view": {}, "action": {"kind": "rollback"}},
        {"need": "manifest"},
        {"view": {}, "events": [{"kind": "migrated"}]},
        {"view": {}, "manifest_write": {"sha256": "m"}},
    ],
)
def test_unsettled_replies_always_go_back_to_the_resident(tmp_path: Path, payload: dict[str, object]) -> None:
    store = _store(tmp_path)
    _keep(_wire(store), payload)
    assert memo.lookup(_wire(store))[1] is None


@pytest.mark.parametrize("op", ["commit_plan", "resume_plan", "rollback_plan", "unknown"])
def test_a_writer_plan_is_never_kept(tmp_path: Path, op: str) -> None:
    store = _store(tmp_path)
    _keep(_wire(store, op=op), {"plan": {"outcome": "prepare"}})
    key, kept = memo.lookup(_wire(store, op=op))
    assert key is None
    assert kept is None


def test_migrating_reply_serves_a_read_only_caller_but_not_the_converse(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _keep(_wire(store, allow_migration=True), {"view": {"health": "protected"}})
    assert memo.lookup(_wire(store, allow_migration=False))[1] == {"view": {"health": "protected"}}

    other = _store(tmp_path / "other")
    _keep(_wire(other, allow_migration=False), {"view": {"health": "protected"}})
    assert memo.lookup(_wire(other, allow_migration=True))[1] is None


def test_missing_database_is_never_memoized(tmp_path: Path) -> None:
    key, kept = memo.lookup(_wire(tmp_path / "absent.db"))
    assert key is None
    assert kept is None


def test_epoch_watches_every_table_the_resident_authority_ops_read() -> None:
    """A table the resident starts reading without a trigger would serve stale replies."""

    read: set[str] = set()
    for source in sorted(_RUST_OPS.glob("*.rs")):
        if source.name.endswith("tests.rs"):
            continue
        for literal in re.findall(r'"((?:[^"\\]|\\.)*)"', source.read_text(encoding="utf-8")):
            read.update(re.findall(r"(?i)\b(?:from|join)\s+([a-z_][a-z0-9_]*)", literal))
    assert read, "no SQL was found in the resident authority ops"
    assert read <= {table for table, _rows in AUTHORITY_INPUT_TABLES}, read
    # The two shared tables are watched only on the rows the resident reads.
    filters = " ".join(rows for _table, rows in AUTHORITY_INPUT_TABLES if rows is not None)
    sources = "".join(source.read_text(encoding="utf-8") for source in _RUST_OPS.glob("*.rs"))
    for name in ("MIGRATED_EVENT", "ACTIVE_STATE_KEY", "REVISION_STATE_KEY"):
        (value,) = re.findall(rf'const {name}: &str = "([^"]+)";', sources)
        assert f"'{value}'" in filters, name
