"""Bound native context verdicts are reused without a classifier round trip."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_request_context
from codex_plugin_scanner.guard.runtime import shell_execution_context
from codex_plugin_scanner.guard.runtime.secret_file_request_services import environment_secret_dump as bridge
from codex_plugin_scanner.guard.runtime.secret_file_request_services import tool_action_requests
from codex_plugin_scanner.guard.runtime.secret_file_request_services.tool_action_requests import (
    _kubernetes_or_environment_secret_request,
)


def _payload(command: str, cwd: str | None, matched: object) -> dict:
    return {
        "schema": "guard-request-context.v1",
        "context_sha256": "sha256:" + "ab" * 32,
        "admission": {},
        "shell": {
            "context": {
                "command_text": command,
                "initial_cwd": cwd,
                "workspace_root": cwd,
                "workspace_identity": None,
                "segments": [],
                "complete": True,
                "reason_code": None,
                "directory_change_present": False,
            },
            "context_hash": "sha256:" + "cd" * 32,
            "segment_hashes": [],
            "metadata": {},
        },
        "launch": None,
        "target": None,
        "environment_secret_dump": matched,
    }


def _prime(monkeypatch: pytest.MonkeyPatch, answers: list[object]) -> list[dict]:
    captured = []
    results = iter(answers)
    monkeypatch.setattr(native_request_context, "ensure_resident_prerequisite", lambda _: True)
    monkeypatch.setattr(native_request_context, "_resolve_digest_home", lambda _: Path("/tmp"))

    def resident(**kwargs):
        request = kwargs["request"]
        captured.append(request)
        body = request["action"]["body"]
        return {
            "schema": "guard-request-context-result.v1",
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + native_request_context._canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": _payload(body["script"], body["cwd"], next(results)),
        }

    monkeypatch.setattr(native_request_context, "_resident_request", resident)
    return captured


@pytest.mark.parametrize("matched", [False, True])
def test_bound_verdict_uses_existing_context_response(tmp_path: Path, monkeypatch, matched: bool) -> None:
    calls = _prime(monkeypatch, [matched])
    command = "opaque-command"
    context = shell_execution_context.model_shell_execution_context(command, cwd=tmp_path, home_dir=tmp_path)
    request = _kubernetes_or_environment_secret_request(
        tool_name="Shell",
        normalized_tool_name="shell",
        command_text=command,
        raw_command_text=command,
        cwd=tmp_path,
        home_dir=tmp_path,
        wrapper_chain=(),
        execution_context=context,
    )
    assert (request is not None) == matched
    assert len(calls) == 1
    assert calls[0]["action"]["body"]["script"] == command
    if request is not None:
        assert request.action_class == "process environment secret read"


@pytest.mark.parametrize("value", [None, 0, 1, "false", [], {}])
def test_missing_or_non_boolean_verdict_fails_closed(tmp_path: Path, monkeypatch, value: object) -> None:
    _prime(monkeypatch, [value])
    with pytest.raises(ValueError, match="native_environment_secret_dump_unavailable"):
        bridge.environment_secret_dump_request(
            tool_name="Shell", normalized_tool_name="shell", command_text="printenv", cwd=tmp_path, home_dir=tmp_path
        )


def test_outage_cannot_become_a_nonmatch(tmp_path: Path, monkeypatch) -> None:
    _prime(monkeypatch, [])
    monkeypatch.setattr(native_request_context, "_resident_request", lambda **kwargs: None)
    with pytest.raises(ValueError, match="native_environment_secret_dump_unavailable"):
        bridge.environment_secret_dump_request(
            tool_name="Shell", normalized_tool_name="shell", command_text="printenv", cwd=tmp_path, home_dir=tmp_path
        )


def test_result_cannot_be_reused_for_different_path_scope(tmp_path: Path, monkeypatch) -> None:
    calls = _prime(monkeypatch, [False])
    context = shell_execution_context.model_shell_execution_context("python reader.py", cwd=tmp_path, home_dir=tmp_path)
    with pytest.raises(ValueError, match="native_environment_secret_dump_unavailable"):
        bridge.environment_secret_dump_request(
            tool_name="Shell",
            normalized_tool_name="shell",
            command_text="python reader.py",
            cwd=tmp_path,
            home_dir=tmp_path / "different-home",
            execution_context=context,
        )
    assert len(calls) == 1


def test_new_calls_observe_new_native_script_verdicts(tmp_path: Path, monkeypatch) -> None:
    calls = _prime(monkeypatch, [False, True])
    kwargs = dict(
        tool_name="Shell",
        normalized_tool_name="shell",
        command_text="python reader.py",
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    assert bridge.environment_secret_dump_request(**kwargs) is None
    assert bridge.environment_secret_dump_request(**kwargs) is not None
    assert len(calls) == 2


@pytest.mark.parametrize("matched", [False, True])
def test_tool_pipeline_builds_one_context_and_reuses_it(tmp_path: Path, monkeypatch, matched: bool) -> None:
    calls = _prime(monkeypatch, [matched])
    classified = []

    def destructive(**kwargs):
        classified.append(kwargs["execution_context"])
        return None

    monkeypatch.setattr(tool_action_requests, "_destructive_shell_tool_action_request", destructive)
    result = tool_action_requests.extract_sensitive_tool_action_request(
        "Shell", {"command": "opaque-command"}, cwd=tmp_path, home_dir=tmp_path
    )
    assert (result is not None) == matched
    assert len(calls) == 1
    assert len(classified) == (0 if matched else 1)
    assert calls[0]["action"]["body"]["classify_environment_secrets"] is True


def test_unrelated_context_build_does_not_request_secret_scan(tmp_path: Path, monkeypatch) -> None:
    calls = _prime(monkeypatch, [None])
    context = shell_execution_context.model_shell_execution_context("ls", cwd=tmp_path, home_dir=tmp_path)
    assert context.native is not None
    assert context.environment_secret_dump is None
    assert "classify_environment_secrets" not in calls[0]["action"]["body"]


def test_benign_shell_pipeline_fails_closed_on_native_outage(tmp_path: Path, monkeypatch) -> None:
    _prime(monkeypatch, [])
    monkeypatch.setattr(native_request_context, "_resident_request", lambda **kwargs: None)
    with pytest.raises(ValueError, match="native_environment_secret_dump_unavailable"):
        tool_action_requests.extract_sensitive_tool_action_request(
            "Shell", {"command": "ls"}, cwd=tmp_path, home_dir=tmp_path
        )
