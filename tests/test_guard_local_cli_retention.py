from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiError, LocalCliApiService
from codex_plugin_scanner.guard.runtime.local_cli_commands import LocalCliCommand
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_local_cli_retention import LocalCliForgetError

NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)


def _stamp(days_ago: int) -> str:
    return (NOW - timedelta(days=days_ago)).isoformat()


def _cli(name: str, digit: str) -> UnlistedCliIdentity:
    return UnlistedCliIdentity(
        cli_id=f"local-cli.{name}",
        name=name,
        kind="executable",
        identity_hash=digit * 64,
        example_label=name,
    )


def _observe(store: GuardStore, identity: UnlistedCliIdentity, *, days_ago: int) -> None:
    store.record_local_cli_observation(identity, seen_at=_stamp(days_ago), surface="cli")
    store.replace_local_cli_commands(
        identity.cli_id,
        (LocalCliCommand("other", "Other commands", f"{identity.name} …", "other"),),
    )


def _observe_mcp(store: GuardStore, cli_id: str, args: tuple[str, ...], *, days_ago: int) -> UnlistedCliIdentity:
    label = " ".join(("node", *args))
    identity = UnlistedCliIdentity(
        cli_id=cli_id,
        name="observed-mcp",
        kind="executable",
        identity_hash=sha256(label.encode()).hexdigest(),
        example_label=label,
    )
    store.ensure_local_mcp_observation(
        identity,
        seen_at=_stamp(days_ago),
        server_identity_hash=identity.identity_hash,
        server_command="node",
        server_args_hash=sha256(" ".join(args).encode()).hexdigest(),
    )
    return identity


def _enroll(store: GuardStore, identity: UnlistedCliIdentity) -> None:
    store.upsert_local_cli_grant(
        identity=identity,
        state="allowed",
        expected_revision=store.read_local_cli_revision(),
        updated_at=_stamp(0),
        command_states={},
    )


def _ids(store: GuardStore) -> set[str]:
    return {str(item["cli_id"]) for item in store.list_local_cli_items()}


def _command_rows(store: GuardStore, cli_id: str) -> int:
    with sqlite3.connect(store.path) as connection:
        row = connection.execute("select count(*) from local_cli_command where cli_id = ?", (cli_id,)).fetchone()
    return int(row[0])


def test_forget_removes_an_unenrolled_observation_and_its_commands(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    stale = _cli("stale-tool", "a")
    _observe(store, stale, days_ago=1)

    store.forget_local_cli_observation(stale.cli_id, identity_hash=stale.identity_hash)

    assert stale.cli_id not in _ids(store)
    assert _command_rows(store, stale.cli_id) == 0


def test_forget_refuses_enrolled_records_and_changed_identities(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    enrolled = _cli("enrolled-tool", "b")
    _observe(store, enrolled, days_ago=1)
    _enroll(store, enrolled)

    with pytest.raises(LocalCliForgetError, match="local_cli_enrolled"):
        store.forget_local_cli_observation(enrolled.cli_id, identity_hash=enrolled.identity_hash)
    with pytest.raises(LocalCliForgetError, match="identity_changed"):
        store.forget_local_cli_observation(enrolled.cli_id, identity_hash="c" * 64)
    with pytest.raises(LocalCliForgetError, match="local_cli_not_found"):
        store.forget_local_cli_observation("local-cli.missing", identity_hash="c" * 64)
    assert enrolled.cli_id in _ids(store)


def test_removed_extension_can_then_be_forgotten(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    removed = _cli("removed-tool", "d")
    _observe(store, removed, days_ago=1)
    _enroll(store, removed)
    store.upsert_local_cli_grant(
        identity=removed,
        state="unset",
        expected_revision=store.read_local_cli_revision(),
        updated_at=_stamp(0),
        command_states={},
    )

    store.forget_local_cli_observation(removed.cli_id, identity_hash=removed.identity_hash)

    assert removed.cli_id not in _ids(store)


def test_new_observation_prunes_only_unenrolled_records_past_retention(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    expired = _cli("expired-tool", "e")
    recent = _cli("recent-tool", "f")
    enrolled_old = _cli("enrolled-old-tool", "1")
    _observe(store, expired, days_ago=45)
    _observe(store, recent, days_ago=10)
    _observe(store, enrolled_old, days_ago=90)
    _enroll(store, enrolled_old)

    _observe(store, _cli("fresh-tool", "2"), days_ago=0)

    assert _ids(store) == {recent.cli_id, enrolled_old.cli_id, "local-cli.fresh-tool"}
    assert _command_rows(store, expired.cli_id) == 0


def test_mcp_observation_insert_prunes_expired_near_duplicates(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    old = _observe_mcp(store, "local-cli.mcp-old", ("--experimental-strip-types", "server.ts"), days_ago=40)

    current = _observe_mcp(store, "local-cli.mcp-current", ("server.ts",), days_ago=0)

    assert _ids(store) == {current.cli_id}
    assert old.cli_id not in _ids(store)


def test_prune_keeps_connections_sharing_an_enrolled_server(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    enrolled = _observe_mcp(store, "local-cli.mcp-enrolled", ("server.ts",), days_ago=60)
    _enroll(store, enrolled)
    with sqlite3.connect(store.path) as connection:
        server_hash = connection.execute(
            "select server_identity_hash from local_cli_observation where cli_id = ?", (enrolled.cli_id,)
        ).fetchone()[0]
        connection.execute(
            """insert into local_cli_observation (
                   cli_id, identity_hash, kind, name, interpreter_name, example_label, observed_count,
                   last_seen_at, surface, server_identity_hash, server_command, server_args_hash
               ) values (
                   'local-cli.mcp-sibling', ?, 'executable', 'sibling', null, 'sibling', 1,
                   ?, 'mcp', ?, 'node', 'x'
               )""",
            ("3" * 64, _stamp(60), server_hash),
        )

    assert store.prune_inactive_local_cli_observations(now=NOW) == []
    with pytest.raises(LocalCliForgetError, match="local_cli_shared_server_enrolled"):
        store.forget_local_cli_observation("local-cli.mcp-sibling", identity_hash="3" * 64)


def test_daemon_forget_maps_store_refusals_to_http_errors(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    detected = _cli("detected-tool", "4")
    enrolled = _cli("granted-tool", "5")
    _observe(store, detected, days_ago=1)
    _observe(store, enrolled, days_ago=1)
    _enroll(store, enrolled)
    service = LocalCliApiService(store=store)

    response = service.forget({"cli_id": detected.cli_id, "identity_hash": detected.identity_hash})

    assert response["status"] == "forgotten"
    assert detected.cli_id not in _ids(store)
    with pytest.raises(LocalCliApiError) as refused:
        service.forget({"cli_id": enrolled.cli_id, "identity_hash": enrolled.identity_hash})
    assert (refused.value.status, refused.value.code) == (409, "local_cli_enrolled")
    with pytest.raises(LocalCliApiError) as missing:
        service.forget({"cli_id": detected.cli_id, "identity_hash": detected.identity_hash})
    assert (missing.value.status, missing.value.code) == (404, "local_cli_not_found")
