from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiError, LocalCliApiService
from codex_plugin_scanner.guard.runtime.local_cli_commands import LocalCliCommand
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.runtime.observed_local_clis import _latest_request_times
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_local_cli_retention import LocalCliForgetError, LocalCliReplaySkippedError

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


@pytest.mark.parametrize("legacy_server_wide", [False, True], ids=["connection", "legacy-server-wide"])
def test_prune_keeps_connections_sharing_an_enrolled_server(tmp_path: Path, legacy_server_wide: bool) -> None:
    store = GuardStore(tmp_path / "guard-home")
    enrolled = _observe_mcp(store, "local-cli.mcp-enrolled", ("server.ts",), days_ago=60)
    _enroll(store, enrolled)
    with sqlite3.connect(store.path) as connection:
        server_hash = connection.execute(
            "select server_identity_hash from local_cli_observation where cli_id = ?", (enrolled.cli_id,)
        ).fetchone()[0]
        if legacy_server_wide:
            # Older server-wide grants stored the server hash only as identity_hash.
            connection.execute(
                "update local_cli_observation set server_identity_hash = null where cli_id = ?", (enrolled.cli_id,)
            )
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
    listed = {str(item["cli_id"]): item for item in store.list_local_cli_items()}
    assert listed["local-cli.mcp-sibling"].get("shares_enrolled_server") is True


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


def _authority_rows(store: GuardStore, cli_id: str) -> int:
    with sqlite3.connect(store.path) as connection:
        tool = connection.execute("select count(*) from local_mcp_tool_authority where cli_id = ?", (cli_id,))
        provider = connection.execute("select count(*) from local_mcp_provider_authority where cli_id = ?", (cli_id,))
        return int(tool.fetchone()[0]) + int(provider.fetchone()[0])


def test_forget_clears_derived_authority_digests(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    connection_identity = _observe_mcp(store, "local-cli.mcp-forget", ("server.ts",), days_ago=1)
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "insert into local_mcp_tool_authority values (?, ?, ?, ?, ?)",
            (connection_identity.cli_id, connection_identity.identity_hash, "read", 1, "d" * 64),
        )
        connection.execute(
            "insert into local_mcp_provider_authority values (?, ?, ?)",
            (connection_identity.cli_id, connection_identity.identity_hash, "e" * 64),
        )

    store.forget_local_cli_observation(connection_identity.cli_id, identity_hash=connection_identity.identity_hash)

    assert _authority_rows(store, connection_identity.cli_id) == 0


def test_history_replay_skips_forgotten_and_expired_identities(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    forgotten = _cli("forgotten-tool", "6")
    _observe(store, forgotten, days_ago=1)
    store.forget_local_cli_observation(forgotten.cli_id, identity_hash=forgotten.identity_hash)
    recent = datetime.now(timezone.utc) - timedelta(days=2)
    expired = datetime.now(timezone.utc) - timedelta(days=45)

    assert store.local_cli_replay_allowed(forgotten.identity_hash, recent.isoformat()) is False
    assert store.local_cli_replay_allowed("7" * 64, expired.isoformat()) is False
    # The cutoff is relative to the replaying discovery's own time.
    replay_time = (expired + timedelta(days=1)).isoformat()
    assert store.local_cli_replay_allowed("7" * 64, expired.isoformat(), now=replay_time) is True
    assert store.local_cli_replay_allowed("7" * 64, recent.isoformat()) is True
    store.record_local_cli_observation(forgotten, seen_at=recent.isoformat(), surface="cli", only_if_missing=True)
    assert forgotten.cli_id not in _ids(store)

    later = datetime.now(timezone.utc) + timedelta(minutes=1)
    assert store.local_cli_replay_allowed(forgotten.identity_hash, later.isoformat()) is True
    store.record_local_cli_observation(forgotten, seen_at=later.isoformat(), surface="cli")
    assert forgotten.cli_id in _ids(store)


def test_replayed_mcp_history_never_moves_last_seen_backward(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    current = _observe_mcp(store, "local-cli.mcp-replayed", ("server.ts",), days_ago=1)
    with sqlite3.connect(store.path) as connection:
        server_hash, command, args_hash = connection.execute(
            "select server_identity_hash, server_command, server_args_hash from local_cli_observation where cli_id = ?",
            (current.cli_id,),
        ).fetchone()

    store.ensure_local_mcp_observation(
        current,
        seen_at=_stamp(20),
        server_identity_hash=server_hash,
        server_command=command,
        server_args_hash=args_hash,
        replayed=True,
    )

    listed = {str(item["cli_id"]): item for item in store.list_local_cli_items()}
    assert listed[current.cli_id]["last_seen_at"] == _stamp(1)


def test_pruned_record_returns_from_recent_history_but_forgotten_one_does_not(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    pruned = _cli("pruned-tool", "a")
    forgotten = _cli("forgotten-again-tool", "b")
    _observe(store, pruned, days_ago=40)
    # Inserting a new record runs the daily prune, which drops the idle one.
    _observe(store, forgotten, days_ago=1)
    assert pruned.cli_id not in _ids(store)
    store.forget_local_cli_observation(forgotten.cli_id, identity_hash=forgotten.identity_hash)

    # Expiry is not a Forget: a receipt newer than the stale last_seen_at
    # restores the record on the next history replay.
    assert store.local_cli_replay_allowed(pruned.identity_hash, _stamp(2), now=_stamp(0)) is True
    store.record_local_cli_observation(
        pruned, seen_at=_stamp(2), surface="cli", only_if_missing=True, replayed_at=_stamp(0)
    )
    assert pruned.cli_id in _ids(store)


def test_replayed_mcp_entry_is_checked_inside_the_write_transaction(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    current = _observe_mcp(store, "local-cli.mcp-forget-race", ("server.ts",), days_ago=0)
    with sqlite3.connect(store.path) as connection:
        server_hash, command, args_hash = connection.execute(
            "select server_identity_hash, server_command, server_args_hash from local_cli_observation where cli_id = ?",
            (current.cli_id,),
        ).fetchone()
    store.forget_local_cli_observation(current.cli_id, identity_hash=current.identity_hash)
    history_seen_at = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()

    with pytest.raises(LocalCliReplaySkippedError):
        store.ensure_local_mcp_observation(
            current,
            seen_at=history_seen_at,
            server_identity_hash=server_hash,
            server_command=command,
            server_args_hash=args_hash,
            replayed=True,
        )

    assert current.cli_id not in _ids(store)


def test_history_times_use_the_latest_retry_of_a_request(tmp_path: Path) -> None:
    workspace = str(tmp_path)
    records = [
        {"raw_command_text": "tool run", "workspace": workspace, "created_at": _stamp(40), "last_seen_at": _stamp(2)},
        {"raw_command_text": "other run", "workspace": workspace, "created_at": _stamp(5)},
    ]

    latest = _latest_request_times(records)

    assert latest[("tool run", workspace)] == _stamp(2)
    assert latest[("other run", workspace)] == _stamp(5)


def test_refreshing_an_existing_record_prunes_at_most_once_a_day(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    expired = _cli("idle-tool", "8")
    active = _cli("active-tool", "9")
    _observe(store, expired, days_ago=40)
    _observe(store, active, days_ago=40)

    store.record_local_cli_observation(active, seen_at=_stamp(0), surface="cli")

    assert _ids(store) == {active.cli_id}
    stale_again = _cli("idle-again-tool", "0")
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            """insert into local_cli_observation (
                   cli_id, identity_hash, kind, name, example_label, observed_count, last_seen_at, surface
               ) values (?, ?, 'executable', 'idle', 'idle', 1, ?, 'cli')""",
            (stale_again.cli_id, stale_again.identity_hash, _stamp(60)),
        )
    store.record_local_cli_observation(active, seen_at=(NOW + timedelta(hours=1)).isoformat(), surface="cli")
    assert stale_again.cli_id in _ids(store)
    store.record_local_cli_observation(active, seen_at=(NOW + timedelta(days=2)).isoformat(), surface="cli")
    assert stale_again.cli_id not in _ids(store)


def test_list_flags_siblings_kept_for_an_enrolled_server(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    enrolled = _observe_mcp(store, "local-cli.mcp-flag-enrolled", ("server.ts",), days_ago=1)
    _enroll(store, enrolled)
    with sqlite3.connect(store.path) as connection:
        server_hash = connection.execute(
            "select server_identity_hash from local_cli_observation where cli_id = ?", (enrolled.cli_id,)
        ).fetchone()[0]
        connection.execute(
            """insert into local_cli_observation (
                   cli_id, identity_hash, kind, name, example_label, observed_count, last_seen_at, surface,
                   server_identity_hash, server_command, server_args_hash
               ) values (
                   'local-cli.mcp-flag-sibling', ?, 'executable', 'sibling', 'sibling', 1, ?, 'mcp', ?, 'node', 'x'
               )""",
            ("a1" * 32, _stamp(1), server_hash),
        )

    listed = {str(item["cli_id"]): item for item in store.list_local_cli_items()}

    assert listed["local-cli.mcp-flag-sibling"].get("shares_enrolled_server") is True
    assert "shares_enrolled_server" not in listed[enrolled.cli_id]
