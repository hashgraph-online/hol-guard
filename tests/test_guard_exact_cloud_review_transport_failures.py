# pyright: reportPrivateUsage=false

from __future__ import annotations

import io
import urllib.error
from datetime import datetime, timezone
from email.message import Message
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.contracts.guard_cloud_review import validate_exact_command_result
from codex_plugin_scanner.guard.runtime import command_queue
from codex_plugin_scanner.guard.runtime.command_capability import CommandCapabilityError
from codex_plugin_scanner.guard.runtime.exact_cloud_review import enable_exact_cloud_review
from codex_plugin_scanner.guard.runtime.exact_cloud_review_transport import exact_result, exact_transport_job
from tests.guard_exact_cloud_review_support import (
    add_review_request,
    connected_exact_review_store,
    exact_review_job,
    remote_approval,
    review_request,
)


def _exact_job(tmp_path: Path):
    store = connected_exact_review_store(tmp_path)
    request = review_request("exact-transport")
    add_review_request(store, request)
    enable_exact_cloud_review(store)
    job = exact_review_job(
        store,
        remote_approval(store, request.request_id, receipt_id="exact-transport-receipt"),
    )
    job.update(
        {
            "resultContractVersion": "guard-cloud-review-command-result-v2",
            "serverResolvedBinding": {"localRequestId": request.request_id},
        }
    )
    return store, job


def test_exact_transport_rejects_cross_queue_operations_and_fails_closed_when_route_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, exact_job = _exact_job(tmp_path)
    generic_job = {
        **exact_job,
        "operation": "guard.packageShims.status",
        "schemaVersion": 1,
        "payload": {},
    }
    with pytest.raises(CommandCapabilityError, match="remote_exact_job_operation_invalid"):
        command_queue.authorize_command_queue_job(
            store,
            exact_transport_job(generic_job),
            schema_versions=command_queue.COMMAND_OPERATION_SCHEMA_VERSIONS,
        )
    with pytest.raises(CommandCapabilityError, match="remote_exact_transport_required"):
        command_queue.authorize_command_queue_job(
            store,
            exact_job,
            schema_versions=command_queue.COMMAND_OPERATION_SCHEMA_VERSIONS,
        )
    with pytest.raises(CommandCapabilityError, match="remote_exact_job_invalid"):
        command_queue.authorize_command_queue_job(
            store,
            exact_transport_job({**exact_job, "schemaVersion": 1}),
            schema_versions=command_queue.COMMAND_OPERATION_SCHEMA_VERSIONS,
        )
    with pytest.raises(CommandCapabilityError, match="cloud_review_protocol_upgrade_required"):
        command_queue.authorize_command_queue_job(
            store,
            exact_transport_job({**exact_job, "protocolVersion": 1}),
            schema_versions=command_queue.COMMAND_OPERATION_SCHEMA_VERSIONS,
        )

    def unavailable(*args: object, **kwargs: object) -> dict[str, object]:
        del args, kwargs
        raise urllib.error.HTTPError(
            "https://guard.example/api/guard/review/v2/commands/lease",
            404,
            "Not Found",
            Message(),
            io.BytesIO(),
        )

    monkeypatch.setattr(command_queue, "_exact_json_request", unavailable)
    monkeypatch.setattr(
        command_queue,
        "_json_request",
        lambda *_args, **_kwargs: pytest.fail("missing exact route must not reach the generic queue"),
    )
    with pytest.raises(urllib.error.HTTPError, match="Not Found"):
        command_queue._lease_next_job(store, {"sync_url": "https://guard.example", "access_token": "token"})


def test_pending_exact_result_retries_on_versioned_result_route(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, job = _exact_job(tmp_path)
    tagged = exact_transport_job(job)
    payload = {
        "leaseId": tagged["leaseId"],
        "idempotencyKey": "retry-result",
        "protocolVersion": 2,
        "status": "succeeded",
        "result": exact_result(
            tagged,
            {
                "generatedAt": "2026-08-24T00:03:00+00:00",
                "data": {
                    "applicationReason": None,
                    "applicationStatus": "applied",
                    "applicationUpdatedAt": "2026-08-24T00:03:00+00:00",
                    "localRequestId": "exact-transport",
                    "receiptId": "exact-transport-receipt",
                    "continuationReason": None,
                    "continuationStatus": "resumed",
                    "continuationUpdatedAt": "2026-08-24T00:03:00+00:00",
                },
            },
        ),
    }
    state: dict[str, object] = {
        "state": "result_pending",
        "pending_result": {"job": tagged, "payload": payload},
        "active_job": tagged,
    }
    store.set_sync_payload(command_queue.COMMAND_QUEUE_STATE_KEY, state, datetime.now(timezone.utc).isoformat())
    calls: list[str] = []
    monkeypatch.setattr(
        command_queue,
        "_exact_json_request",
        lambda _auth, *, method, path, payload: calls.append(path) or {"ok": True},
    )
    monkeypatch.setattr(
        command_queue,
        "_json_request",
        lambda *args, **kwargs: pytest.fail("pending exact result must not use the generic queue"),
    )

    assert command_queue._retry_pending_result(
        store,
        {"sync_url": "https://guard.example", "access_token": "token"},
        state,
    )
    assert calls == [f"/{job['id']}/result"]


def test_exact_result_validates_unsupported_continuation_status(tmp_path: Path) -> None:
    _store, job = _exact_job(tmp_path)

    result = exact_result(
        job,
        {
            "generatedAt": "2026-08-24T00:03:00+00:00",
            "data": {
                "applicationReason": None,
                "applicationStatus": "applied",
                "applicationUpdatedAt": "2026-08-24T00:03:00+00:00",
                "localRequestId": "exact-transport",
                "receiptId": "exact-transport-receipt",
                "continuationReason": "no_resume_transport",
                "continuationStatus": "unsupported",
                "continuationUpdatedAt": "2026-08-24T00:03:00+00:00",
            },
        },
    )

    assert result["continuationStatus"] == "unsupported"
    validate_exact_command_result(result)
