"""Regression tests for local Guard policy integrity enforcement."""

from __future__ import annotations

import base64
import json
import sqlite3
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.store import GuardStore, SystemKeyringSecretStore


@pytest.fixture(autouse=True)
def _fake_policy_integrity_keyring(install_fake_system_keyring) -> None:
    install_fake_system_keyring()


def _store(tmp_path: Path) -> GuardStore:
    return GuardStore(tmp_path / "guard-home")


def _decision(
    *,
    artifact_id: str = "codex:project:workspace-skill",
    artifact_hash: str = "hash-123",
    action: str = "allow",
    source: str = "local",
) -> PolicyDecision:
    return PolicyDecision(
        harness="codex",
        scope="artifact",
        action=action,
        artifact_id=artifact_id,
        artifact_hash=artifact_hash,
        reason="reviewed",
        source=source,
    )


def _policy_row(home_dir: Path, *, artifact_id: str) -> sqlite3.Row:
    with sqlite3.connect(home_dir / "guard.db") as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "select * from policy_decisions where artifact_id = ?",
            (artifact_id,),
        ).fetchone()
    assert row is not None
    return row


def _policy_integrity_state_payload(home_dir: Path) -> dict[str, object]:
    with sqlite3.connect(home_dir / "guard.db") as connection:
        row = connection.execute("select payload_json from sync_state where state_key = 'policy_integrity'").fetchone()
    assert row is not None
    return json.loads(str(row[0]))


def _strip_policy_integrity(home_dir: Path, *, artifact_id: str) -> None:
    with sqlite3.connect(home_dir / "guard.db") as connection:
        connection.execute(
            """
            update policy_decisions
            set integrity_version = null,
                payload_hash = null,
                payload_mac = null,
                integrity_key_id = null,
                signed_at = null
            where artifact_id = ?
            """,
            (artifact_id,),
        )


def _set_policy_integrity_state(
    home_dir: Path,
    *,
    backend: str,
    mode: str,
    enforcement: str,
    key_id: str | None,
    degraded_reasons: list[str] | None = None,
) -> None:
    payload = {
        "backend": backend,
        "degraded_reasons": degraded_reasons or [],
        "enforcement": enforcement,
        "key_id": key_id,
        "mode": mode,
    }
    with sqlite3.connect(home_dir / "guard.db") as connection:
        connection.execute(
            """
            insert into sync_state (state_key, payload_json, updated_at)
            values ('policy_integrity', ?, ?)
            on conflict(state_key) do update set
              payload_json = excluded.payload_json,
              updated_at = excluded.updated_at
            """,
            (json.dumps(payload, sort_keys=True, separators=(",", ":")), "2026-06-14T00:00:00Z"),
        )


def _rotate_policy_integrity_key(store: GuardStore, *, raw_key: bytes) -> None:
    secret_store = store._policy_integrity_secret_store
    assert secret_store is not None
    secret_store.set_secret(
        store._policy_integrity_key_ref,
        base64.urlsafe_b64encode(raw_key).decode("ascii"),
    )


def test_upsert_policy_signs_local_row_and_resolve_honors_it(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.upsert_policy(_decision(), "2026-06-14T00:00:00Z")

    row = _policy_row(store.guard_home, artifact_id="codex:project:workspace-skill")
    resolved = store.resolve_policy_decision(
        "codex",
        "codex:project:workspace-skill",
        "hash-123",
        now="2026-06-14T00:01:00Z",
    )

    assert row["integrity_version"] == 1
    assert isinstance(row["payload_hash"], str) and row["payload_hash"]
    assert isinstance(row["payload_mac"], str) and row["payload_mac"]
    assert isinstance(row["integrity_key_id"], str) and row["integrity_key_id"]
    assert resolved is not None
    assert resolved["action"] == "allow"
    assert resolved["integrity_status"] == "valid"


def test_direct_sqlite_insert_is_ignored_in_enforce_mode(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        connection.execute(
            """
            insert into policy_decisions (
              harness, scope, artifact_id, artifact_hash, workspace, publisher, action, reason, owner, source,
              expires_at, updated_at
            )
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "codex",
                "artifact",
                "codex:project:forged",
                "hash-forged",
                None,
                None,
                "allow",
                "forged",
                None,
                "local",
                None,
                "2026-06-14T00:00:00Z",
            ),
        )

    resolved = store.resolve_policy(
        "codex",
        "codex:project:forged",
        "hash-forged",
        now="2026-06-14T00:01:00Z",
    )
    verify = store.verify_policy_integrity()

    assert resolved is None
    assert verify["enforcement"] == "enforce"
    assert verify["counts"]["missing_integrity"] == 1


def test_upsert_policy_uses_single_integrity_key_lookup_per_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    original_lookup = store._policy_integrity_secret_material
    lookup_calls = 0

    def _flaky_lookup(*, create: bool) -> tuple[bytes | None, str | None]:
        nonlocal lookup_calls
        lookup_calls += 1
        if lookup_calls == 1:
            return None, None
        return original_lookup(create=create)

    monkeypatch.setattr(store, "_policy_integrity_secret_material", _flaky_lookup)

    store.upsert_policy(
        _decision(artifact_id="codex:project:transient", artifact_hash="hash-transient"),
        "2026-06-14T00:00:00Z",
    )

    row = _policy_row(store.guard_home, artifact_id="codex:project:transient")
    state = _policy_integrity_state_payload(store.guard_home)

    assert lookup_calls == 1
    assert row["integrity_version"] is None
    assert state["mode"] == "degraded"
    assert state["key_id"] is None


def test_tampered_signed_row_is_ignored_and_event_emitted(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:tampered", artifact_hash="hash-tampered"),
        "2026-06-14T00:00:00Z",
    )
    with sqlite3.connect(store.guard_home / "guard.db") as connection:
        connection.execute(
            "update policy_decisions set payload_mac = ? where artifact_id = ?",
            ("deadbeef", "codex:project:tampered"),
        )

    resolved = store.resolve_policy(
        "codex",
        "codex:project:tampered",
        "hash-tampered",
        now="2026-06-14T00:01:00Z",
    )
    events = store.list_events(limit=100, event_name="policy_integrity_violation")

    assert resolved is None
    assert any(event.get("payload", {}).get("artifact_id") == "codex:project:tampered" for event in events)


def test_remote_policy_row_is_honored_without_local_mac(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.replace_remote_policies(
        [_decision(artifact_id="codex:project:remote", artifact_hash="hash-remote", source="cloud-sync")],
        "2026-06-14T00:00:00Z",
    )

    resolved = store.resolve_policy(
        "codex",
        "codex:project:remote",
        "hash-remote",
        now="2026-06-14T00:01:00Z",
    )

    assert resolved == "allow"


def test_legacy_unsigned_row_warn_mode_then_enforce_mode(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:legacy", artifact_hash="hash-legacy"),
        "2026-06-14T00:00:00Z",
    )
    status = store.get_policy_integrity_status()
    _strip_policy_integrity(store.guard_home, artifact_id="codex:project:legacy")
    _set_policy_integrity_state(
        store.guard_home,
        backend=str(status["backend"]),
        mode="protected",
        enforcement="warn",
        key_id=status["key_id"] if isinstance(status["key_id"], str) else None,
    )

    warned = store.resolve_policy_decision(
        "codex",
        "codex:project:legacy",
        "hash-legacy",
        now="2026-06-14T00:01:00Z",
    )
    _set_policy_integrity_state(
        store.guard_home,
        backend=str(status["backend"]),
        mode="protected",
        enforcement="enforce",
        key_id=status["key_id"] if isinstance(status["key_id"], str) else None,
    )
    enforced = store.resolve_policy(
        "codex",
        "codex:project:legacy",
        "hash-legacy",
        now="2026-06-14T00:02:00Z",
    )

    assert warned is not None
    assert warned["integrity_status"] == "missing_integrity"
    assert enforced is None


def test_migrate_local_policy_integrity_preserves_selected_rows_only(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:legacy-one", artifact_hash="hash-one"),
        "2026-06-14T00:00:00Z",
    )
    store.upsert_policy(
        _decision(artifact_id="codex:project:legacy-two", artifact_hash="hash-two"),
        "2026-06-14T00:00:00Z",
    )
    status = store.get_policy_integrity_status()
    _strip_policy_integrity(store.guard_home, artifact_id="codex:project:legacy-one")
    _strip_policy_integrity(store.guard_home, artifact_id="codex:project:legacy-two")
    _set_policy_integrity_state(
        store.guard_home,
        backend=str(status["backend"]),
        mode="protected",
        enforcement="warn",
        key_id=status["key_id"] if isinstance(status["key_id"], str) else None,
    )

    items = store.verify_policy_integrity()["items"]
    preserve_id = next(
        int(item["decision_id"]) for item in items if item.get("artifact_id") == "codex:project:legacy-one"
    )
    payload = store.migrate_local_policy_integrity(
        preserve_decision_ids={preserve_id},
        clear_unselected=False,
        now="2026-06-14T00:05:00Z",
    )

    first = store.resolve_policy("codex", "codex:project:legacy-one", "hash-one", now="2026-06-14T00:06:00Z")
    second = store.resolve_policy("codex", "codex:project:legacy-two", "hash-two", now="2026-06-14T00:06:00Z")

    assert Path(str(payload["backup_path"])).exists()
    assert payload["enforcement"] == "enforce"
    assert payload["counts"]["valid"] == 1
    assert payload["counts"]["missing_integrity"] == 1
    assert first == "allow"
    assert second is None


def test_migrate_local_policy_integrity_re_signs_unknown_key_rows(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:rotated", artifact_hash="hash-rotated"),
        "2026-06-14T00:00:00Z",
    )
    _rotate_policy_integrity_key(store, raw_key=b"2" * 32)

    verify_payload = store.verify_policy_integrity()
    preserve_id = next(
        int(item["decision_id"])
        for item in verify_payload["items"]
        if item.get("artifact_id") == "codex:project:rotated"
    )
    payload = store.migrate_local_policy_integrity(
        preserve_decision_ids={preserve_id},
        clear_unselected=False,
        now="2026-06-14T00:05:00Z",
    )

    resolved = store.resolve_policy("codex", "codex:project:rotated", "hash-rotated", now="2026-06-14T00:06:00Z")

    assert verify_payload["counts"]["unknown_key"] == 1
    assert payload["unknown_key_row_ids"] == [preserve_id]
    assert payload["counts"]["valid"] == 1
    assert resolved == "allow"


def test_policies_cli_verify_status_migrate_and_repair(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "home"
    store = GuardStore(home_dir)
    store.upsert_policy(_decision(artifact_id="codex:project:cli", artifact_hash="hash-cli"), "2026-06-14T00:00:00Z")
    status = store.get_policy_integrity_status()
    _strip_policy_integrity(home_dir, artifact_id="codex:project:cli")
    _set_policy_integrity_state(
        home_dir,
        backend=str(status["backend"]),
        mode="protected",
        enforcement="warn",
        key_id=status["key_id"] if isinstance(status["key_id"], str) else None,
    )

    verify_rc = main(["guard", "policies", "verify", "--home", str(home_dir), "--json"])
    verify_payload = json.loads(capsys.readouterr().out)
    assert verify_rc == 0
    assert verify_payload["counts"]["missing_integrity"] == 1

    status_rc = main(["guard", "policies", "integrity-status", "--home", str(home_dir), "--json"])
    status_payload = json.loads(capsys.readouterr().out)
    assert status_rc == 0
    assert status_payload["enforcement"] == "warn"

    migrate_rc = main(
        [
            "guard",
            "policies",
            "migrate-local-integrity",
            "--home",
            str(home_dir),
            "--preserve-all-local",
            "--json",
        ]
    )
    migrate_payload = json.loads(capsys.readouterr().out)
    assert migrate_rc == 0
    assert migrate_payload["preserved"] == 1
    assert migrate_payload["enforcement"] == "enforce"

    _strip_policy_integrity(home_dir, artifact_id="codex:project:cli")
    _set_policy_integrity_state(
        home_dir,
        backend=str(status["backend"]),
        mode="protected",
        enforcement="enforce",
        key_id=status["key_id"] if isinstance(status["key_id"], str) else None,
    )
    repair_rc = main(
        [
            "guard",
            "policies",
            "repair",
            "--home",
            str(home_dir),
            "--clear-invalid",
            "--json",
        ]
    )
    repair_payload = json.loads(capsys.readouterr().out)
    assert repair_rc == 0
    assert repair_payload["cleared"] == 1
    assert GuardStore(home_dir).list_policy_decisions() == []


def test_policies_cli_migrate_preserve_all_local_re_signs_unknown_key_rows(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "home"
    store = GuardStore(home_dir)
    store.upsert_policy(
        _decision(artifact_id="codex:project:cli-rotated", artifact_hash="hash-cli-rotated"),
        "2026-06-14T00:00:00Z",
    )
    _rotate_policy_integrity_key(store, raw_key=b"3" * 32)
    assert store.verify_policy_integrity()["counts"]["unknown_key"] == 1

    migrate_rc = main(
        [
            "guard",
            "policies",
            "migrate-local-integrity",
            "--home",
            str(home_dir),
            "--preserve-all-local",
            "--json",
        ]
    )
    migrate_payload = json.loads(capsys.readouterr().out)

    assert migrate_rc == 0
    assert migrate_payload["preserved"] == 1
    assert migrate_payload["counts"]["valid"] == 1


def test_backup_policy_database_sets_private_mode_when_backup_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    calls: list[tuple[Path, int]] = []

    def _fake_set_private_mode(path: Path, mode: int) -> None:
        calls.append((Path(path), mode))

    class _BrokenBackupConnection:
        def backup(self, backup_connection: sqlite3.Connection) -> None:
            raise sqlite3.OperationalError("boom")

    monkeypatch.setattr("codex_plugin_scanner.guard.store._set_private_mode", _fake_set_private_mode)

    with pytest.raises(sqlite3.OperationalError, match="boom"):
        store._backup_policy_database(
            cast(sqlite3.Connection, _BrokenBackupConnection()),
            now="2026-06-14T00:05:00Z",
        )

    assert calls
    assert calls[-1][0].exists()
    assert calls[-1][0].name.startswith("guard.db.pre-integrity-")
    assert calls[-1][1] == 0o600


def test_degraded_mode_persistent_local_allow_is_not_authoritative(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(SystemKeyringSecretStore, "_is_available", classmethod(lambda cls: False))
    store = _store(tmp_path)
    store.upsert_policy(
        _decision(artifact_id="codex:project:degraded", artifact_hash="hash-degraded"),
        "2026-06-14T00:00:00Z",
    )

    resolved = store.resolve_policy(
        "codex",
        "codex:project:degraded",
        "hash-degraded",
        now="2026-06-14T00:01:00Z",
    )
    verify = store.verify_policy_integrity()

    assert resolved is None
    assert verify["mode"] == "degraded"
    assert verify["counts"]["degraded_mode"] == 1
