"""The Python side of the native Guard command report: what it sends and how it reads the answer."""

from __future__ import annotations

import json
import os
import urllib.error
from collections.abc import Mapping

import pytest

from codex_plugin_scanner.guard.runtime import cloud_bundle_sync, cloud_command_lease

pytestmark = [pytest.mark.native_command_report]

_URL = "https://guard.example/api/guard/commands/job-1/result"


def _answer(monkeypatch: pytest.MonkeyPatch, answer: object) -> list[dict[str, object]]:
    seen: list[dict[str, object]] = []

    def native(
        command: str,
        feature: str,
        guard_home: object,
        action: str,
        *,
        auth_context: object,
        subject: str,
        extra: Mapping[str, object],
    ) -> object:
        call = dict(extra["commandReport"])  # type: ignore[arg-type]
        body_file = call.get("bodyFile")
        if isinstance(body_file, str):
            with open(body_file, "rb") as handle:
                call["bodyFileBytes"] = len(handle.read())
        seen.append({"feature": feature, "action": action, "call": call})
        return answer

    monkeypatch.setattr(cloud_command_lease, "run_native_cloud_sync", native)
    return seen


def test_an_ack_names_the_job_route_and_lease(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _answer(monkeypatch, {"url": _URL, "reply": {"response": {"ok": True}}})

    answer = cloud_command_lease.cloud_command_report({}, job_id="job-1", exact=True, kind="ack", lease_id="lease-1")

    assert answer == {"ok": True}
    assert seen == [
        {
            "feature": "cloud-command-report-v1",
            "action": "command_report",
            "call": {"jobId": "job-1", "exact": True, "kind": "ack", "leaseId": "lease-1"},
        }
    ]


def test_a_large_result_crosses_in_a_private_file_removed_afterwards(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _answer(monkeypatch, {"url": _URL, "reply": {"response": {}}})
    body = json.dumps({"output": "x" * (cloud_bundle_sync._INLINE_BODY_LIMIT_BYTES + 1)}).encode("utf-8")

    cloud_command_lease.cloud_command_report({}, job_id="job-1", exact=False, kind="result", body=body)

    call = seen[0]["call"]
    assert isinstance(call, dict)
    assert "body" not in call
    assert call["bodyFileBytes"] == len(body)
    assert not os.path.exists(str(call["bodyFile"]))


def test_a_small_result_crosses_inline(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _answer(monkeypatch, {"url": _URL, "reply": {"response": {}}})

    cloud_command_lease.cloud_command_report({}, job_id="job-1", exact=False, kind="result", body=b'{"a":1}')

    assert seen[0]["call"] == {"jobId": "job-1", "exact": False, "kind": "result", "body": '{"a":1}'}


def test_a_refusal_is_raised_against_the_url_the_report_reached(monkeypatch: pytest.MonkeyPatch) -> None:
    _answer(monkeypatch, {"url": _URL, "reply": {"refusal": {"status": 410, "headers": {}, "body": ""}}})

    with pytest.raises(urllib.error.HTTPError) as raised:
        cloud_command_lease.cloud_command_report({}, job_id="job-1", exact=False, kind="result", body=b"{}")

    assert raised.value.code == 410
    assert raised.value.url == _URL


@pytest.mark.parametrize("answer", [None, {}, {"url": ""}, {"url": 7, "reply": {"response": {}}}])
def test_an_answer_without_its_url_is_not_an_answer(monkeypatch: pytest.MonkeyPatch, answer: object) -> None:
    _answer(monkeypatch, answer)

    with pytest.raises(RuntimeError, match="did not answer the Guard command report"):
        cloud_command_lease.cloud_command_report({}, job_id="job-1", exact=False, kind="ack", lease_id="lease-1")
