from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_command_envelope import CommandEnvelopeUnavailableError
from codex_plugin_scanner.guard.native_command_state import CommandStateUnavailableError
from codex_plugin_scanner.guard.runtime import command_capability as command_capability_module
from codex_plugin_scanner.guard.runtime import command_queue
from codex_plugin_scanner.guard.runtime.command_capability import (
    COMMAND_LOCAL_APPROVALS_STATE_KEY,
    COMMAND_REPLAY_STATE_KEY,
    CommandCapabilityError,
    approve_pending_command,
    authorize_command_job,
    command_capability_status,
    consume_local_command_approval,
    pending_command_approvals,
    register_pending_command,
)
from codex_plugin_scanner.guard.runtime.command_executors import COMMAND_OPERATION_SCHEMA_VERSIONS
from tests.test_guard_command_capability import _connected_store, _context, _issue, _job


@pytest.fixture(autouse=True)
def _capability_runtime(native_command_capability_runtime: Path) -> None:
    """Every local approval asserted here goes through the compiled ledger."""


def test_state_change_requires_exact_single_use_local_approval(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    operation = "guard.app.update"
    _issue(store, operation)
    job = _job(store, operation, payload={"channel": "stable"})
    authorized = authorize_command_job(
        store,
        job,
        schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS,
    )

    assert authorized.requires_local_approval is True
    assert consume_local_command_approval(store, authorized) is False
    pending = register_pending_command(store, authorized, job)
    assert pending["id"] == "job-1"
    assert pending_command_approvals(store)[0]["operation"] == operation

    result = approve_pending_command(store, "job-1")
    assert result["approved"] is True

    changed_job = {**job, "payload": {"channel": "preview"}}
    changed_authorization = authorize_command_job(
        store,
        changed_job,
        schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS,
    )
    assert consume_local_command_approval(store, changed_authorization) is False
    assert consume_local_command_approval(store, authorized) is True
    assert consume_local_command_approval(store, authorized) is False


def test_only_the_grant_operations_ship_the_signing_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _connected_store(tmp_path)
    operation = "guard.app.update"
    _issue(store, operation)
    job = _job(store, operation, payload={"channel": "stable"})
    authorized = authorize_command_job(store, job, schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS)
    real = command_capability_module.native_command_state
    calls: list[tuple[str, bool]] = []

    def recorded(guard_home: Path, op: str, **kwargs: object) -> object:
        calls.append((op, kwargs.get("integrity_key_b64") is not None))
        return real(guard_home, op, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(command_capability_module, "native_command_state", recorded)

    register_pending_command(store, authorized, job)
    assert approve_pending_command(store, "job-1")["approved"] is True
    assert consume_local_command_approval(store, authorized, record_replay=True) is True

    # The replay row rides on the consume call, in the transaction that
    # spends the grant.
    assert calls == [
        ("register_pending", False),
        ("approve", True),
        ("consume", True),
    ]
    replay = store.get_sync_payload(COMMAND_REPLAY_STATE_KEY)
    assert isinstance(replay, dict)
    assert [item["jobId"] for item in replay["items"]] == ["job-1"]


def test_an_unanswered_runtime_refuses_an_approval_as_a_capability_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _connected_store(tmp_path)
    operation = "guard.app.update"
    _issue(store, operation)
    job = _job(store, operation, payload={"channel": "stable"})
    authorized = authorize_command_job(store, job, schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS)
    register_pending_command(store, authorized, job)

    def unavailable(*_args: object, **_kwargs: object) -> object:
        raise CommandStateUnavailableError

    monkeypatch.setattr(command_capability_module, "native_command_state", unavailable)

    with pytest.raises(CommandCapabilityError, match=CommandEnvelopeUnavailableError.reason):
        approve_pending_command(store, "job-1")


def test_an_unanswered_runtime_never_reads_a_grant_as_unmatched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _connected_store(tmp_path)
    operation = "guard.app.update"
    _issue(store, operation)
    job = _job(store, operation, payload={"channel": "stable"})
    authorized = authorize_command_job(store, job, schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS)
    register_pending_command(store, authorized, job)
    assert approve_pending_command(store, "job-1")["approved"] is True
    real = command_capability_module.native_command_state

    answering = [False]

    def unavailable_for_consume(guard_home: Path, op: str, **kwargs: object) -> object:
        if not answering[0] and op == "consume":
            raise CommandStateUnavailableError
        return real(guard_home, op, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(command_capability_module, "native_command_state", unavailable_for_consume)

    # Walking past the unanswered grant would read as "no approval on file"
    # and spend the user's approval without running the job.
    with pytest.raises(CommandCapabilityError, match=CommandEnvelopeUnavailableError.reason):
        consume_local_command_approval(store, authorized)

    answering[0] = True
    assert consume_local_command_approval(store, authorized) is True


def test_pending_approval_rejects_nonportable_cloud_job_id(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    operation = "guard.app.update"
    _issue(store, operation)
    job_id = "job-$(touch /opt/guard-test/unsafe)"
    job = _job(store, operation, job_id=job_id, payload={"channel": "stable"})
    with pytest.raises(CommandCapabilityError, match="command_id_invalid"):
        authorize_command_job(store, job, schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS)


def test_status_still_answers_while_the_ledger_does_not(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _connected_store(tmp_path)
    _issue(store, "guard.app.update")

    def unavailable(*_args: object, **_kwargs: object) -> object:
        raise CommandStateUnavailableError

    monkeypatch.setattr(command_capability_module, "native_command_state", unavailable)

    # Revocation reads status first, so status must not depend on the ledger.
    status = command_capability_status(store)
    assert status["pending_commands"] == []


def test_an_approval_is_never_spent_against_a_digest_the_runtime_has_not_given(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One digest serves both the grant match and the replay row.

    The poll used to ask for it twice: once to find the grant it deletes, and
    again to write the replay row. A resident that stopped answering between
    the two failed the job with the user's approval already gone, so the next
    attempt asked them to approve it a second time.
    """

    store = _connected_store(tmp_path)
    operation = "guard.app.update"
    _issue(store, operation)
    leased = _job(store, operation, payload={"channel": "stable"})
    authorized = authorize_command_job(store, leased, schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS)
    register_pending_command(store, authorized, leased)
    assert approve_pending_command(store, "job-1")["approved"] is True

    real = command_capability_module.native_command_envelope
    digests = [0]

    def one_digest_only(**kwargs: object) -> dict[str, object]:
        if kwargs.get("action") == "digest":
            digests[0] += 1
            if digests[0] > 1:
                raise CommandEnvelopeUnavailableError
        return real(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(command_capability_module, "native_command_envelope", one_digest_only)
    calls: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(
        command_queue,
        "_resolve_command_queue_auth_context",
        lambda _store, **_kwargs: {"sync_url": "https://hol.test/sync"},
    )

    def request(
        _auth: dict[str, object],
        *,
        method: str,
        path: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        calls.append((path, payload))
        return {"item": leased} if path == "/lease" else {"ok": True}

    monkeypatch.setattr(command_queue, "_json_request", request)
    monkeypatch.setattr(command_queue, "_execute_job", lambda *_args, **_kwargs: {"data": {"ok": True}})

    command_queue.poll_command_queue_once(store, _context(tmp_path))

    result = next(payload for path, payload in calls if path.endswith("/result"))
    assert result["status"] == "succeeded"
    assert digests[0] == 1
    grants = store.get_sync_payload(COMMAND_LOCAL_APPROVALS_STATE_KEY)
    assert isinstance(grants, dict) and grants["items"] == []
    replay = store.get_sync_payload(COMMAND_REPLAY_STATE_KEY)
    assert isinstance(replay, dict)
    assert [item["jobId"] for item in replay["items"]] == ["job-1"]
