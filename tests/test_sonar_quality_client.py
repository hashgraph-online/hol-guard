"""Reject foreign task metadata, incomplete scans, oversized responses and redirects."""

from __future__ import annotations

import io
from pathlib import Path
from unittest.mock import Mock
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit

import pytest

from scripts.ci import sonar_quality_client as client_module
from scripts.ci.sonar_quality_client import MAX_BYTES, ORIGIN, PROJECT, NoRedirect, SonarClient, metadata_task


def metadata(tmp_path: Path, **changes: str) -> Path:
    values = {
        "projectKey": PROJECT,
        "serverUrl": ORIGIN,
        "ceTaskId": "task_123",
        "ceTaskUrl": "https://untrusted.invalid/not-followed",
    }
    values.update(changes)
    path = tmp_path / "report-task.txt"
    path.write_text("\n".join(f"{key}={value}" for key, value in values.items()))
    return path


def test_only_fixed_origin_and_current_task_id_are_used(tmp_path):
    assert metadata_task(metadata(tmp_path)) == "task_123"
    client = SonarClient("test-only-token")
    client.opener = Mock()
    client.opener.open.return_value = io.BytesIO(b'{"projectStatus":{"status":"OK"}}')
    assert client.gate("analysis-id") == {"status": "OK"}
    request = client.opener.open.call_args.args[0]
    parsed = urlsplit(request.full_url)
    assert parsed.scheme == "https" and parsed.netloc == "sonarcloud.io"
    assert parsed.path == "/api/qualitygates/project_status"
    assert parse_qs(parsed.query) == {"analysisId": ["analysis-id"]}
    assert request.get_header("Authorization") == "Bearer test-only-token"


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("serverUrl", "https://sonarcloud.io.evil.invalid"),
        ("serverUrl", "http://sonarcloud.io"),
        ("serverUrl", "https://sonarcloud.io@evil.invalid"),
        ("projectKey", "other-project"),
        ("ceTaskId", "https://elsewhere.invalid/task"),
        ("ceTaskId", "a&projectKey=other"),
    ],
)
def test_foreign_or_malformed_metadata_is_rejected(tmp_path, key, value):
    with pytest.raises(ValueError):
        metadata_task(metadata(tmp_path, **{key: value}))


def test_duplicate_and_oversized_metadata_is_rejected(tmp_path):
    path = metadata(tmp_path)
    with path.open("a") as stream:
        stream.write("\nceTaskId=another")
    with pytest.raises(ValueError, match="duplicate"):
        metadata_task(path)
    path.write_bytes(b"x" * 65_537)
    with pytest.raises(ValueError, match="byte limit"):
        metadata_task(path)


def test_redirects_never_receive_scanner_credentials():
    assert NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://evil.invalid") is None


@pytest.mark.parametrize("body", [b"[]", b"malformed", b"x" * (MAX_BYTES + 1)])
def test_bad_responses_fail_closed(body):
    client = SonarClient("test-only-token")
    client.opener = Mock()
    client.opener.open.return_value = io.BytesIO(body)
    with pytest.raises(ValueError):
        client.gate("analysis-id")


def test_expired_budget_and_unapproved_endpoint_do_not_make_requests():
    client = SonarClient("test-only-token", timeout=-1)
    client.opener = Mock()
    with pytest.raises(TimeoutError):
        client.gate("analysis-id")
    with pytest.raises(ValueError):
        client.read("/api/user_tokens/search")
    client.opener.open.assert_not_called()


def test_authentication_failure_is_not_converted_to_a_passing_gate():
    client = SonarClient("test-only-token")
    client.opener = Mock()
    client.opener.open.side_effect = HTTPError(ORIGIN, 401, "Unauthorized", {}, None)
    with pytest.raises(HTTPError):
        client.gate("analysis-id")


def test_completed_scan_is_bound_to_the_exact_task_and_project(monkeypatch):
    client = SonarClient("test-only-token")
    client.read = Mock(
        side_effect=[
            {"task": {"id": "task-id", "componentKey": PROJECT, "status": "IN_PROGRESS"}},
            {"task": {"id": "task-id", "componentKey": PROJECT, "status": "SUCCESS", "analysisId": "analysis-id"}},
        ]
    )
    monkeypatch.setattr(client_module.time, "sleep", Mock())
    assert client.analysis("task-id") == "analysis-id"
    assert all(call.kwargs == {"id": "task-id"} for call in client.read.call_args_list)


@pytest.mark.parametrize("change", ["foreign-project", "foreign-task", "failed", "cancelled", "missing-analysis"])
def test_bad_task_cannot_produce_gate_evidence(change):
    task = {"id": "task-id", "componentKey": PROJECT, "status": "SUCCESS", "analysisId": "analysis-id"}
    if change == "foreign-project":
        task["componentKey"] = "another"
    elif change == "foreign-task":
        task["id"] = "another"
    elif change == "missing-analysis":
        task.pop("analysisId")
    else:
        task["status"] = change.upper()
    client = SonarClient("test-only-token")
    client.read = Mock(return_value={"task": task})
    with pytest.raises(ValueError):
        client.analysis("task-id")


def test_malformed_json_metadata_does_not_use_a_default_gate():
    client = SonarClient("test-only-token")
    client.read = Mock(return_value={"projectStatus": None})
    with pytest.raises(ValueError, match="missing"):
        client.gate("analysis-id")
