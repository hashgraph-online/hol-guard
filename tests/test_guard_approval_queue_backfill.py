"""Approval-queue backfill keeps going when one row is rejected and fails closed otherwise."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator, Sequence
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_execution, native_store_policy, store_approvals
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.native_approval_queue_identity import (
    APPROVAL_QUEUE_IDENTITY_FEATURE,
    ApprovalQueueIdentityUnavailableError,
    bind_connection_guard_home,
)
from codex_plugin_scanner.guard.native_context import _canonical_request_sha256
from codex_plugin_scanner.guard.store_approvals import (
    add_approval_request,
    approval_schema_statement,
    backfill_approval_queue_columns,
    backfill_queue_identities_once,
)

_FEATURES = ("resident-protocol-v2", APPROVAL_QUEUE_IDENTITY_FEATURE)
_RESULT_SCHEMA = "guard-approval-queue-identity-result.v1"


@pytest.fixture(autouse=True)
def _isolated_backfill_cache() -> Iterator[None]:
    store_approvals._QUEUE_BACKFILLED_HOMES.clear()
    yield
    store_approvals._QUEUE_BACKFILLED_HOMES.clear()


def _home(tmp_path: Path) -> Path:
    home = tmp_path / "guard-home"
    key = home / "native-runtime" / "policy-verifier.key"
    key.parent.mkdir(parents=True)
    key.write_bytes(b"verifier")
    return home


def _connection(*, home: Path | None = None) -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(approval_schema_statement())
    if home is not None:
        bind_connection_guard_home(connection, home)
    return connection


def _insert_legacy(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    created_at: str,
    artifact_id: str,
) -> None:
    connection.execute(
        """
        insert into approval_requests (
            request_id, harness, artifact_id, artifact_name, artifact_type, artifact_hash,
            policy_action, recommended_scope, changed_fields_json, source_scope, config_path,
            review_command, approval_url, status, created_at, launch_target, action_envelope_json
        ) values (
            ?, 'codex', ?, 'tool', 'artifact', 'hash',
            'require-reapproval', 'session', '[]', 'project', 'config.toml',
            'hol-guard review', 'http://127.0.0.1/approve', 'pending', ?, 'git status', ?
        )
        """,
        (request_id, artifact_id, created_at, json.dumps({"command": artifact_id})),
    )


def _request(request_id: str, artifact_id: str) -> GuardApprovalRequest:
    return GuardApprovalRequest(
        request_id=request_id,
        harness="codex",
        artifact_id=artifact_id,
        artifact_name="tool",
        artifact_hash="hash",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("command",),
        source_scope="project",
        config_path="config.toml",
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1:4455/requests/{request_id}",
        launch_target="git status --short",
    )


def _install(monkeypatch: pytest.MonkeyPatch, answer) -> list[int]:
    calls = [0]
    status = SimpleNamespace(
        mode="force",
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=Path("/native"), sha256="sha"),
        capabilities=SimpleNamespace(features=_FEATURES),
    )
    monkeypatch.setattr(native_execution, "native_runtime_status", lambda: status)
    monkeypatch.setattr(native_store_policy, "native_runtime_status", lambda: status)

    def respond(**kwargs: object) -> bytes | None:
        calls[0] += 1
        body = kwargs["payload"]
        assert isinstance(body, bytes)
        request = json.loads(body)["request"]
        assert isinstance(request, dict)
        return answer(request)

    monkeypatch.setattr(native_execution, "native_resident_client_request", respond)
    for module in (native_execution, native_store_policy):
        monkeypatch.setattr(module, "native_record_resident_failure", lambda *_args, **_kwargs: None)
        monkeypatch.setattr(module, "native_record_resident_success", lambda *_args, **_kwargs: None)
    return calls


def _bound(request: dict[str, object], items: object) -> bytes:
    return json.dumps(
        {
            "schema": _RESULT_SCHEMA,
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + _canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": {"items": items},
        }
    ).encode()


def _identities_for(request: dict[str, object]) -> bytes:
    raw_items = request["items"]
    assert isinstance(raw_items, list)
    if any(isinstance(item, dict) and item.get("artifact_id") == "poison" for item in raw_items):
        return json.dumps(
            {
                "schema": _RESULT_SCHEMA,
                "request_id": request["request_id"],
                "request_sha256": "sha256:" + _canonical_request_sha256(request),
                "status": "error",
                "code": "rejected",
                "payload": {},
            }
        ).encode()
    payload = []
    for item in raw_items:
        assert isinstance(item, dict)
        artifact_id = str(item["artifact_id"])
        payload.append(
            {
                "identity_key": "",
                "action_identity": f"action-{artifact_id}",
                "queue_group_id": f"queue-{artifact_id}",
            }
        )
    return _bound(request, payload)


def _identity_of(connection: sqlite3.Connection, request_id: str) -> str | None:
    row = connection.execute(
        "select action_identity from approval_requests where request_id = ?",
        (request_id,),
    ).fetchone()
    assert row is not None
    value = row["action_identity"]
    return value if isinstance(value, str) else None


def test_unbound_memory_connection_fails_before_insert(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[object] = []

    def identity(*args: object, **kwargs: object) -> list[object]:
        calls.append(args)
        del kwargs
        return []

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.store_approval_writes.native_approval_queue_identities",
        identity,
    )
    connection = _connection()

    with pytest.raises(ApprovalQueueIdentityUnavailableError) as caught:
        add_approval_request(connection, _request("req-1", "artifact-1"), "2026-05-08T10:00:00Z")

    assert caught.value.reason == "unavailable"
    assert calls == []
    assert connection.execute("select count(*) from approval_requests").fetchone()[0] == 0


def test_bound_memory_connection_inserts_the_resident_identity(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls = _install(monkeypatch, _identities_for)
    home = _home(tmp_path)
    connection = _connection(home=home)

    stored_id = add_approval_request(connection, _request("req-1", "artifact-1"), "2026-05-08T10:00:00Z")

    assert stored_id == "req-1"
    assert calls[0] == 1
    assert _identity_of(connection, "req-1") == "action-artifact-1"


def test_rejected_row_does_not_stop_later_rows(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls = _install(monkeypatch, _identities_for)
    monkeypatch.setattr(store_approvals, "APPROVAL_QUEUE_BACKFILL_BATCH_SIZE", 2)
    home = _home(tmp_path)
    connection = _connection(home=home)
    _insert_legacy(connection, request_id="poison", created_at="2026-05-08T10:00:00Z", artifact_id="poison")
    _insert_legacy(connection, request_id="good", created_at="2026-05-08T10:01:00Z", artifact_id="good")
    _insert_legacy(connection, request_id="later", created_at="2026-05-08T10:02:00Z", artifact_id="later")
    connection.commit()

    complete = backfill_approval_queue_columns(connection, guard_home=home, commit_batches=True)

    assert complete is False
    assert _identity_of(connection, "poison") is None
    assert _identity_of(connection, "good") == "action-good"
    assert _identity_of(connection, "later") == "action-later"
    assert calls[0] > 1


def test_unavailable_resident_does_not_split_or_mark_the_home_complete(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def answer(request: dict[str, object]) -> None:
        del request
        return None

    calls = _install(monkeypatch, answer)
    monkeypatch.setattr(store_approvals, "APPROVAL_QUEUE_BACKFILL_BATCH_SIZE", 1)
    home = _home(tmp_path)
    connection = _connection(home=home)
    for index in range(3):
        _insert_legacy(
            connection,
            request_id=f"row-{index}",
            created_at=f"2026-05-08T10:0{index}:00Z",
            artifact_id=f"artifact-{index}",
        )
    connection.commit()

    backfill_queue_identities_once(connection, home)
    backfill_queue_identities_once(connection, home)

    assert calls[0] == 2
    assert _identity_of(connection, "row-0") is None
    assert _identity_of(connection, "row-2") is None
    row = connection.execute(
        "select last_seen_at, created_at from approval_requests where request_id = 'row-2'"
    ).fetchone()
    assert row is not None
    assert row["last_seen_at"] == row["created_at"]


def test_complete_backfill_runs_once_per_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls = _install(monkeypatch, _identities_for)
    home = _home(tmp_path)
    connection = _connection(home=home)
    _insert_legacy(connection, request_id="row-a", created_at="2026-05-08T10:00:00Z", artifact_id="row-a")
    connection.commit()

    backfill_queue_identities_once(connection, home)
    backfill_queue_identities_once(connection, home)

    assert calls[0] == 1
    assert _identity_of(connection, "row-a") == "action-row-a"


def _record_transactions(
    monkeypatch: pytest.MonkeyPatch, connection: sqlite3.Connection
) -> list[tuple[bool, str | None]]:
    original = store_approvals.native_approval_queue_identities
    observed: list[tuple[bool, str | None]] = []

    def wrapped(items: Sequence[object], *, guard_home: Path, provision: bool = True) -> object:
        artifact_ids = [str(item.get("artifact_id")) for item in items if isinstance(item, dict)]
        previous = None
        if artifact_ids == ["row-b"]:
            row = connection.execute(
                "select action_identity from approval_requests where artifact_id = 'row-a'"
            ).fetchone()
            value = None if row is None else row["action_identity"]
            previous = value if isinstance(value, str) else None
        observed.append((connection.in_transaction, previous))
        return original(items, guard_home=guard_home, provision=provision)

    monkeypatch.setattr(store_approvals, "native_approval_queue_identities", wrapped)
    return observed


def test_backfill_commits_each_batch_before_the_next_identity_lookup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _install(monkeypatch, _identities_for)
    monkeypatch.setattr(store_approvals, "APPROVAL_QUEUE_BACKFILL_BATCH_SIZE", 1)
    home = _home(tmp_path)
    connection = _connection(home=home)
    _insert_legacy(connection, request_id="row-a", created_at="2026-05-08T10:00:00Z", artifact_id="row-a")
    _insert_legacy(connection, request_id="row-b", created_at="2026-05-08T10:01:00Z", artifact_id="row-b")
    connection.commit()
    observed = _record_transactions(monkeypatch, connection)

    backfill_queue_identities_once(connection, home)

    assert observed == [(False, None), (False, "action-row-a")]
    assert connection.in_transaction is False
    assert _identity_of(connection, "row-b") == "action-row-b"


def test_migration_backfill_does_not_commit_between_batches(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _install(monkeypatch, _identities_for)
    monkeypatch.setattr(store_approvals, "APPROVAL_QUEUE_BACKFILL_BATCH_SIZE", 1)
    home = _home(tmp_path)
    connection = _connection(home=home)
    _insert_legacy(connection, request_id="row-a", created_at="2026-05-08T10:00:00Z", artifact_id="row-a")
    _insert_legacy(connection, request_id="row-b", created_at="2026-05-08T10:01:00Z", artifact_id="row-b")
    connection.commit()
    observed = _record_transactions(monkeypatch, connection)

    complete = backfill_approval_queue_columns(connection)

    assert complete is True
    assert observed == [(False, None), (True, "action-row-a")]
    assert connection.in_transaction is True


def test_sqlite_error_during_backfill_is_rolled_back_and_a_later_write_proceeds(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _install(monkeypatch, _identities_for)
    home = _home(tmp_path)
    connection = _connection(home=home)
    _insert_legacy(connection, request_id="legacy", created_at="2026-05-08T10:00:00Z", artifact_id="legacy")
    connection.commit()
    connection.execute(
        """
        create trigger approval_backfill_fail_update
        before update on approval_requests
        begin
            select raise(abort, 'backfill failed');
        end
        """
    )

    backfill_queue_identities_once(connection, home)

    assert _identity_of(connection, "legacy") is None
    assert str(home) not in store_approvals._QUEUE_BACKFILLED_HOMES
    connection.execute("drop trigger approval_backfill_fail_update")

    stored_id = add_approval_request(connection, _request("req-new", "fresh"), "2026-05-08T10:05:00Z")

    assert stored_id == "req-new"
    assert _identity_of(connection, "legacy") == "action-legacy"
    assert _identity_of(connection, "req-new") == "action-fresh"


def test_backfill_without_a_home_fills_counters_without_calling_the_resident(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[object] = []
    monkeypatch.setattr(store_approvals, "native_approval_queue_identities", lambda *args, **kwargs: calls.append(args))
    connection = _connection()
    _insert_legacy(connection, request_id="legacy", created_at="2026-05-08T10:00:00Z", artifact_id="legacy")
    connection.commit()

    assert backfill_approval_queue_columns(connection) is False

    row = connection.execute(
        "select action_identity, last_seen_at, created_at from approval_requests where request_id = 'legacy'"
    ).fetchone()
    assert row is not None
    assert row["action_identity"] is None
    assert row["last_seen_at"] == row["created_at"]
    assert calls == []
