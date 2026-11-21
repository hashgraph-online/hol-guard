from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.native_command_result import CommandResultUnavailableError
from codex_plugin_scanner.guard.runtime import command_queue_protocol
from codex_plugin_scanner.guard.runtime.exact_cloud_review_transport import exact_transport_job


def _unavailable(job: object, execution: object) -> dict[str, object]:
    raise CommandResultUnavailableError("native_command_result_unavailable")


def test_unanswered_runtime_still_closes_the_lease(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(command_queue_protocol, "native_command_result", _unavailable)

    payload = command_queue_protocol.result_payload({"id": "job-1", "leaseId": "lease-1"}, {"ok": True})

    assert payload == {
        "leaseId": "lease-1",
        "idempotencyKey": "job-1:lease-1:failed",
        "status": "failed",
        "failureCode": "native_command_result_unavailable",
        "failureMessage": "Guard could not build this job's result (native_command_result_unavailable).",
    }


def test_unanswered_exact_job_keeps_its_protocol_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(command_queue_protocol, "native_command_result", _unavailable)

    job = exact_transport_job({"id": "job-1", "leaseId": "lease-1"})
    payload = command_queue_protocol.result_payload(job, {})

    assert payload["protocolVersion"] == 2
    assert payload["status"] == "failed"


@pytest.mark.parametrize(
    ("job", "message"),
    [
        ({}, "Guard command job is missing a lease id."),
        ({"id": "job-1"}, "Guard command job is missing a lease id."),
        ({"leaseId": "lease-1"}, "Guard command job is missing an id."),
    ],
)
def test_missing_job_fields_are_refused_before_the_runtime_is_asked(
    monkeypatch: pytest.MonkeyPatch, job: dict[str, object], message: str
) -> None:
    monkeypatch.setattr(command_queue_protocol, "native_command_result", _unavailable)

    with pytest.raises(RuntimeError, match=message):
        command_queue_protocol.result_payload(job, {})
