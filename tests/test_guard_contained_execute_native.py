"""The contained-execute client forwards payloads verbatim and never decides in Python."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_execution

_REQUEST: dict[str, object] = {
    "schema_version": "containment-contract-v1",
    "kind": "probe-case",
    "argv": ["/bin/sh", "-c", "true"],
    "cwd": "/workspace",
    "env_allowlist": [],
    "timeout_seconds": 5,
    "max_output_bytes": 1 << 20,
    "additional_read_paths": [],
    "allow_outbound_network": False,
}
_POLICY: dict[str, object] = {
    "schema_version": "containment-contract-v1",
    "action": "run",
    "workspace_read_paths": [],
    "workspace_write_paths": ["/workspace/out"],
    "env_allowlist": [],
    "allowed_domains": [],
    "timeout_seconds": 5,
    "max_processes": 64,
    "max_open_files": 1024,
    "max_file_size_bytes": 1 << 22,
    "max_write_bytes_total": 1 << 22,
    "max_output_bytes": 1 << 20,
    "memory_mb": 512,
    "additional_read_paths": [],
    "allow_outbound_network": False,
}


def _capture(monkeypatch: pytest.MonkeyPatch, reply: object) -> dict[str, Any]:
    seen: dict[str, Any] = {}

    def resident(**kwargs: Any) -> object:
        seen.update(kwargs)
        return reply

    monkeypatch.setattr(native_execution, "_resident_request", resident)
    return seen


def test_contained_execute_sends_the_payload_the_resident_validates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = {"exit_code": 0, "stdout": "", "stderr": "", "enforcement": "bubblewrap"}
    seen = _capture(monkeypatch, {"result": evidence})

    result = native_execution.contained_execute_native(_REQUEST, _POLICY, guard_home=tmp_path, run_id="run-1")

    assert result == evidence
    assert seen["operation"] == "contained_execute"
    assert seen["required_feature"] == native_execution._CONTAINED_EXECUTION_FEATURE
    assert seen["guard_home"] == tmp_path
    payload = seen["request"]
    assert payload["schema"] == "guard-contained-execute-request.v1"
    assert payload["request"] == _REQUEST
    assert payload["policy"] == _POLICY
    assert payload["guard_home"] == str(tmp_path)
    assert payload["run_id"] == "run-1"
    assert str(payload["request_id"]).startswith("contained_execute-")


def test_contained_execute_waits_longer_than_the_request_it_carries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The resident, not this client, must be the one that reports a timeout."""
    seen = _capture(monkeypatch, {"result": {}})

    _ = native_execution.contained_execute_native(_REQUEST, _POLICY, guard_home=tmp_path, run_id="run-1")

    assert seen["timeout_seconds"] > float(5)
    assert seen["timeout_seconds"] == 5 + native_execution._CONTAINED_EXECUTE_TRANSPORT_SLACK_SECONDS


@pytest.mark.parametrize("reply", [None, {}, {"result": None}, {"result": "ok"}])
def test_contained_execute_reports_an_unusable_reply_as_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reply: object
) -> None:
    _ = _capture(monkeypatch, reply)

    assert native_execution.contained_execute_native(_REQUEST, _POLICY, guard_home=tmp_path, run_id="run-1") is None


@pytest.mark.parametrize("timeout", [None, 0, -1, 5.0, "5"])
def test_contained_execute_refuses_a_request_without_a_usable_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, timeout: object
) -> None:
    """A request the resident would reject must never reach the transport."""
    called: list[object] = []
    monkeypatch.setattr(native_execution, "_resident_request", lambda **k: called.append(k))
    request = {key: value for key, value in _REQUEST.items() if key != "timeout_seconds"}
    if timeout is not None:
        request["timeout_seconds"] = timeout

    assert native_execution.contained_execute_native(request, _POLICY, guard_home=tmp_path, run_id="run-1") is None
    assert called == []
