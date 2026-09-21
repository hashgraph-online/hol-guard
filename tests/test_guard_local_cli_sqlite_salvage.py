from __future__ import annotations

import sqlite3
from pathlib import Path

from codex_plugin_scanner.guard import sqlite_recovery
from codex_plugin_scanner.guard.local_cli_trust import utc_now
from codex_plugin_scanner.guard.runtime.local_cli_commands import LocalCliCommand
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.sqlite_recovery import _copy_allowlisted_table, salvage_local_cli_state
from codex_plugin_scanner.guard.store import GuardStore


def _identity() -> UnlistedCliIdentity:
    return UnlistedCliIdentity(
        cli_id="local-cli.mcp-abcdef12",
        name="chrome-devtools",
        kind="executable",
        identity_hash="a" * 64,
        example_label="npx -y chrome-devtools-mcp@latest",
    )


def _commands() -> tuple[LocalCliCommand, ...]:
    return (
        LocalCliCommand("root", "chrome-devtools", "npx chrome-devtools", "root"),
        LocalCliCommand("navigate", "navigate", "navigate", "Open a page", parent_id="root"),
        LocalCliCommand("other", "Other commands", "npx chrome-devtools …", "other"),
    )


def _grant_store(home: Path, *, with_commands: bool = False) -> GuardStore:
    store = GuardStore(home, prime_policy_integrity=False)
    identity = _identity()
    store.record_local_cli_observation(
        identity,
        seen_at=utc_now(),
        help_status="ok",
        surface="mcp",
    )
    store.upsert_local_cli_grant(
        identity=identity,
        state="allowed",
        expected_revision=0,
        updated_at=utc_now(),
    )
    if with_commands:
        store.replace_local_cli_commands(identity.cli_id, _commands())
        store.upsert_local_cli_command_states(identity.cli_id, {"navigate": "block"})
    return store


def test_salvage_copies_custom_extension_grant(tmp_path: Path) -> None:
    source = _grant_store(tmp_path / "src")
    destination_home = tmp_path / "dst"
    destination = GuardStore(destination_home, prime_policy_integrity=False)
    assert destination.read_local_cli_grant(_identity().cli_id) is None
    assert salvage_local_cli_state(source=source.path, destination=destination.path) is True
    granted = destination.read_local_cli_grant(_identity().cli_id)
    assert granted is not None
    assert granted["state"] == "allowed"
    listed = destination.list_local_cli_items()
    assert any(item.get("cli_id") == _identity().cli_id and item.get("state") == "allowed" for item in listed)


def test_salvage_keeps_destination_schema_marker(tmp_path: Path) -> None:
    source = _grant_store(tmp_path / "src")
    with sqlite3.connect(source.path) as connection:
        connection.execute("update local_cli_schema_migration set version = 1, checksum = 'stale' where singleton = 1")
        connection.commit()
    destination = GuardStore(tmp_path / "dst", prime_policy_integrity=False)
    assert salvage_local_cli_state(source=source.path, destination=destination.path) is True
    granted = destination.read_local_cli_grant(_identity().cli_id)
    assert granted is not None
    with sqlite3.connect(destination.path) as connection:
        version, checksum = connection.execute(
            "select version, checksum from local_cli_schema_migration where singleton = 1"
        ).fetchone()
    assert version != 1
    assert checksum != "stale"


def test_salvage_rolls_back_when_grants_unreadable(tmp_path: Path) -> None:
    source = _grant_store(tmp_path / "src")
    with sqlite3.connect(source.path) as connection:
        connection.execute("drop table local_cli_grant")
        connection.commit()
    destination = GuardStore(tmp_path / "dst", prime_policy_integrity=False)
    assert salvage_local_cli_state(source=source.path, destination=destination.path) is False
    assert destination.read_local_cli_grant(_identity().cli_id) is None
    listed = destination.list_local_cli_items()
    assert listed == []


def test_salvage_rolls_back_when_commands_unreadable(tmp_path: Path) -> None:
    source = _grant_store(tmp_path / "src", with_commands=True)
    with sqlite3.connect(source.path) as connection:
        connection.execute("drop table local_cli_command")
        connection.commit()
    destination = GuardStore(tmp_path / "dst", prime_policy_integrity=False)
    assert salvage_local_cli_state(source=source.path, destination=destination.path) is False
    assert destination.read_local_cli_grant(_identity().cli_id) is None
    assert destination.read_local_cli_command_catalog(_identity().cli_id) == []
    listed = destination.list_local_cli_items()
    assert listed == []


def test_salvage_rolls_back_when_command_grants_unreadable(tmp_path: Path) -> None:
    source = _grant_store(tmp_path / "src", with_commands=True)
    with sqlite3.connect(source.path) as connection:
        connection.execute("drop table local_cli_command_grant")
        connection.commit()
    destination = GuardStore(tmp_path / "dst", prime_policy_integrity=False)
    assert salvage_local_cli_state(source=source.path, destination=destination.path) is False
    assert destination.read_local_cli_grant(_identity().cli_id) is None
    assert destination.read_local_cli_command_catalog(_identity().cli_id) == []
    assert destination.read_local_cli_command_states(_identity().cli_id) == {}
    listed = destination.list_local_cli_items()
    assert listed == []


def test_salvage_copies_command_catalog_and_states(tmp_path: Path) -> None:
    source = _grant_store(tmp_path / "src", with_commands=True)
    destination = GuardStore(tmp_path / "dst", prime_policy_integrity=False)
    assert salvage_local_cli_state(source=source.path, destination=destination.path) is True
    granted = destination.read_local_cli_grant(_identity().cli_id)
    assert granted is not None
    assert granted["state"] == "allowed"
    catalog = destination.read_local_cli_command_catalog(_identity().cli_id)
    assert [item.command_id for item in catalog] == ["root", "navigate", "other"]
    assert destination.read_local_cli_command_states(_identity().cli_id) == {"navigate": "block"}


def _source_that_fails_after_first_select_row(connection: sqlite3.Connection) -> object:
    original = connection.execute

    class _Source:
        def execute(self, sql: str, parameters: object = ()) -> object:
            cursor = original(sql, parameters)
            if not sql.strip().lower().startswith("select "):
                return cursor
            rows = list(cursor)
            if not rows:
                return cursor

            class _Cursor:
                def __iter__(self) -> object:
                    yield rows[0]
                    raise sqlite3.DatabaseError("btreeInitPage")

            return _Cursor()

    return _Source()


def test_copy_keeps_rows_read_before_source_failure(tmp_path: Path) -> None:
    source = _grant_store(tmp_path / "src")
    destination = GuardStore(tmp_path / "dst", prime_policy_integrity=False)
    with sqlite3.connect(source.path) as src, sqlite3.connect(destination.path) as dst:
        assert _copy_allowlisted_table(_source_that_fails_after_first_select_row(src), dst, "local_cli_grant") is True
        dst.commit()
    granted = destination.read_local_cli_grant(_identity().cli_id)
    assert granted is not None
    assert granted["state"] == "allowed"


def test_copy_rejects_command_grant_insert_error(tmp_path: Path) -> None:
    source = _grant_store(tmp_path / "src", with_commands=True)
    source.upsert_local_cli_command_states(_identity().cli_id, {"navigate": "block", "other": "block"})
    destination = GuardStore(tmp_path / "dst", prime_policy_integrity=False)
    with sqlite3.connect(source.path) as src, sqlite3.connect(destination.path) as dst:
        original = dst.execute
        inserts = {"count": 0}

        class _Destination:
            def execute(self, sql: str, parameters: object = ()) -> object:
                if sql.strip().lower().startswith("insert"):
                    inserts["count"] += 1
                    if inserts["count"] >= 2:
                        raise sqlite3.DatabaseError("constraint")
                return original(sql, parameters)

        assert _copy_allowlisted_table(src, _Destination(), "local_cli_command_grant") is False


def test_copy_rejects_partial_command_grant_scan(tmp_path: Path) -> None:
    source = _grant_store(tmp_path / "src", with_commands=True)
    source.upsert_local_cli_command_states(_identity().cli_id, {"navigate": "block", "other": "block"})
    destination = GuardStore(tmp_path / "dst", prime_policy_integrity=False)
    with sqlite3.connect(source.path) as src, sqlite3.connect(destination.path) as dst:
        assert (
            _copy_allowlisted_table(
                _source_that_fails_after_first_select_row(src),
                dst,
                "local_cli_command_grant",
            )
            is False
        )


def test_salvage_rolls_back_after_partial_command_grant_scan(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source = _grant_store(tmp_path / "src", with_commands=True)
    destination = GuardStore(tmp_path / "dst", prime_policy_integrity=False)
    original = sqlite_recovery._copy_allowlisted_table

    def wrapped(src: sqlite3.Connection, dst: sqlite3.Connection, table: str) -> bool:
        copied = original(src, dst, table)
        if table != "local_cli_command_grant":
            return copied
        assert copied is True
        return False

    monkeypatch.setattr(sqlite_recovery, "_copy_allowlisted_table", wrapped)
    assert salvage_local_cli_state(source=source.path, destination=destination.path) is False
    assert destination.read_local_cli_grant(_identity().cli_id) is None
    assert destination.read_local_cli_command_states(_identity().cli_id) == {}
    listed = destination.list_local_cli_items()
    assert listed == []


def test_salvage_ignores_unreadable_quarantine(tmp_path: Path) -> None:
    destination = GuardStore(tmp_path / "dst", prime_policy_integrity=False)
    junk = tmp_path / "junk.db"
    junk.write_bytes(b"not-a-sqlite-database")
    assert salvage_local_cli_state(source=junk, destination=destination.path) is False
    assert destination.read_local_cli_grant(_identity().cli_id) is None


def test_fatal_recovery_salvages_grants_when_full_restore_fails(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store = _grant_store(tmp_path / "guard")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.store_connection_schema.restore_readable_sqlite_store",
        lambda **_kwargs: False,
    )
    monkeypatch.setattr(store, "_store_is_proven_unusable", lambda _error: True)
    recovered = store._recover_fatal_sqlite_store(  # pyright: ignore[reportPrivateUsage]
        sqlite3.DatabaseError("database disk image is malformed")
    )
    assert recovered is True
    assert store._last_sqlite_recovery == "reinitialized_salvaged"
    granted = store.read_local_cli_grant(_identity().cli_id)
    assert granted is not None
    assert granted["state"] == "allowed"
