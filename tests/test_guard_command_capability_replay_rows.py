from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import command_capability as command_capability_module
from codex_plugin_scanner.guard.runtime import command_queue
from codex_plugin_scanner.guard.runtime.command_capability import (
    COMMAND_REPLAY_STATE_KEY,
    CommandCapabilityError,
    authorize_command_job,
    mark_command_job_consumed,
)
from codex_plugin_scanner.guard.runtime.command_executors import COMMAND_OPERATION_SCHEMA_VERSIONS
from tests.test_guard_command_capability import _connected_store, _issue, _job


@pytest.fixture(autouse=True)
def _capability_runtime(native_command_capability_runtime: Path) -> None:
    """Every capability verdict asserted here comes from the compiled runtime."""


def test_only_job_and_replay_questions_ship_the_replay_rows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _connected_store(tmp_path)
    _issue(store, "guard.packageShims.status")
    job = _job(store)
    authorized = authorize_command_job(store, job, schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS)
    mark_command_job_consumed(store, authorized)
    real = command_capability_module.native_command_capability
    shipped: list[tuple[bool, int]] = []

    def recorded(**kwargs: object) -> dict[str, object]:
        shipped.append((kwargs["job"] is not None, len(kwargs["replay_items"])))  # type: ignore[arg-type]
        return real(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(command_capability_module, "native_command_capability", recorded)

    assert command_queue.command_capability_operations(store) == ("guard.packageShims.status",)
    with pytest.raises(CommandCapabilityError, match="command_replayed"):
        authorize_command_job(store, job, schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS)

    assert shipped == [(False, 0), (True, 1)]


def test_a_job_question_ships_only_the_rows_naming_that_job(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _connected_store(tmp_path)
    _issue(store, "guard.packageShims.status")
    for job_id in ("job-1", "job-2", "job-3"):
        job = _job(store, job_id=job_id)
        mark_command_job_consumed(
            store, authorize_command_job(store, job, schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS)
        )
    real = command_capability_module.native_command_capability
    shipped: list[list[object]] = []

    def recorded(**kwargs: object) -> dict[str, object]:
        shipped.append([item["jobId"] for item in kwargs["replay_items"]])  # type: ignore[attr-defined,index]
        return real(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(command_capability_module, "native_command_capability", recorded)

    with pytest.raises(CommandCapabilityError, match="command_replayed"):
        authorize_command_job(store, _job(store, job_id="job-2"), schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS)
    same_key = {**_job(store, job_id="job-9"), "idempotencyKey": "idempotency-job-3"}
    with pytest.raises(CommandCapabilityError, match="command_replayed"):
        authorize_command_job(store, same_key, schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS)
    authorize_command_job(store, _job(store, job_id="job-4"), schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS)

    assert shipped == [["job-2"], ["job-3"], []]


def test_a_malformed_job_keeps_every_row_for_the_runtime_to_refuse(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    rows: list[dict[str, object]] = [{"jobId": "job-1", "idempotencyKey": "key-1"}, {"identityDigest": "sha256:x"}]
    store.set_sync_payload(COMMAND_REPLAY_STATE_KEY, {"version": 1, "items": rows}, "2026-09-27T12:00:00+00:00")

    def naming(subject: object) -> object:
        return command_capability_module._ledger(store, "replay_rows", now="2026-09-27T12:00:00+00:00", subject=subject)

    assert naming(["job-1"]) == rows
    assert naming({"id": " job-1 ", "idempotencyKey": 7}) == rows
    assert naming({"id": "job-2", "idempotencyKey": "key-2"}) == [rows[1]]


def test_the_replay_lookup_receives_only_the_fields_it_filters_on() -> None:
    job = {"id": "job-1", "idempotencyKey": "key-1", "payload": {"blob": "x" * 2_000_000}}

    assert command_capability_module._replay_subject(job) == {"id": "job-1", "idempotencyKey": "key-1"}
    assert command_capability_module._replay_subject({"payload": {}}) == {}
    assert command_capability_module._replay_subject("not-a-job") == "not-a-job"
