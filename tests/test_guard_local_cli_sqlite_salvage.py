from __future__ import annotations

import sqlite3
from pathlib import Path

from codex_plugin_scanner.guard.local_cli_trust import utc_now
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.sqlite_recovery import salvage_local_cli_state
from codex_plugin_scanner.guard.store import GuardStore


def _identity() -> UnlistedCliIdentity:
    return UnlistedCliIdentity(
        cli_id="local-cli.mcp-abcdef12",
        name="chrome-devtools",
        kind="executable",
        identity_hash="a" * 64,
        example_label="npx -y chrome-devtools-mcp@latest",
    )


def _grant_store(home: Path) -> GuardStore:
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
        connection.execute(
            "update local_cli_schema_migration set version = 1, checksum = 'stale' where singleton = 1"
        )
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
