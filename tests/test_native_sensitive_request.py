"""The sensitive-request client presents resident answers and never invents one."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_sensitive_request as client
from codex_plugin_scanner.guard.native_request_context import NativeRequestContextFailure
from codex_plugin_scanner.guard.runtime import secret_file_requests


def _reply(query: str, result: object) -> dict[str, object]:
    return {"kind": "sensitive_request", "query": query, "result": result}


def _answer(monkeypatch: pytest.MonkeyPatch, reply: object, seen: list[dict[str, Any]] | None = None) -> None:
    def fake_call(action: dict[str, Any], **_kwargs: object) -> object:
        if seen is not None:
            seen.append(action)
        return reply

    monkeypatch.setattr(client, "_call", fake_call)
    monkeypatch.setattr(client, "_control_snapshot", lambda: None)


@pytest.mark.parametrize(
    "reply",
    [
        NativeRequestContextFailure("native_request_context_unavailable"),
        {},
        {"kind": "other", "query": "tool_action", "result": {"match": None}},
        {"kind": "sensitive_request", "query": "file_read", "result": {"match": None}},
        {"kind": "sensitive_request", "query": "tool_action", "result": {"match": None}, "extra": 1},
        _reply("tool_action", {"match": {"tool_name": "Bash"}}),
        _reply("tool_action", "unreviewed"),
    ],
)
def test_refused_or_malformed_reply_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, reply: Any) -> None:
    _answer(monkeypatch, reply)
    with pytest.raises(client.NativeSensitiveRequestError):
        secret_file_requests.extract_sensitive_tool_action_request(
            "Bash", {"command": "cat ~/.ssh/id_rsa"}, cwd=tmp_path, home_dir=tmp_path
        )


def test_classifier_error_keeps_the_legacy_value_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _answer(monkeypatch, _reply("tool_action", {"error": "native command evaluation does not match"}))
    with pytest.raises(ValueError, match="does not match"):
        secret_file_requests.extract_sensitive_tool_action_request("Bash", {"command": "ls"}, cwd=tmp_path)


def test_file_read_match_is_rebuilt_from_the_reply(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    seen: list[dict[str, Any]] = []
    path_match = {
        "family": "ssh_private_key",
        "path": str(tmp_path / ".ssh/id_rsa"),
        "reason": "synthetic",
        "requested_path": "~/.ssh/id_rsa",
        "sensitivity": "critical",
    }
    _answer(
        monkeypatch,
        _reply("file_read", {"tool_name": "Read", "normalized_tool_name": "read", "path_match": path_match}),
        seen,
    )
    found = secret_file_requests.extract_sensitive_file_read_request(
        "Read", {"file_path": "~/.ssh/id_rsa"}, cwd=tmp_path, home_dir=tmp_path
    )
    assert found is not None
    assert found.path_match.family == "ssh_private_key"
    assert found.path_match.sensitivity == "critical"
    body = seen[0]["body"]
    assert body["query"] == "file_read"
    assert body["input"]["home_dir"] == str(tmp_path)
    assert "verdict" not in body["input"]


def test_unknown_sensitivity_is_not_presented(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path_match = {"family": "x", "path": "/x", "reason": "x", "requested_path": "x", "sensitivity": "low"}
    _answer(
        monkeypatch,
        _reply("file_read", {"tool_name": "Read", "normalized_tool_name": "read", "path_match": path_match}),
    )
    with pytest.raises(client.NativeSensitiveRequestError):
        secret_file_requests.extract_sensitive_file_read_request("Read", {"file_path": "x"}, cwd=tmp_path)


def test_boolean_answers_must_be_booleans(monkeypatch: pytest.MonkeyPatch) -> None:
    _answer(monkeypatch, _reply("read_only_lookup_target_is_safe", 1))
    with pytest.raises(client.NativeSensitiveRequestError):
        secret_file_requests._read_only_lookup_target_is_safe("README.md", allow_dirs=False)


def test_tool_action_reply_rejects_a_non_string_command(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from dataclasses import fields

    from codex_plugin_scanner.guard.runtime.secret_file_request_services.request_models import (
        ToolActionRequestMatch,
    )

    match = {item.name: None for item in fields(ToolActionRequestMatch)}
    for name in ("tool_name", "normalized_tool_name", "action_class", "reason"):
        match[name] = "Bash"
    match["command_text"] = 1
    for name in (
        "wrapper_chain",
        "shell_execution_effective_cwds",
        "pytest_config_sources",
        "pytest_config_reason_codes",
        "interpreter_executable_identities",
    ):
        match[name] = []
    _answer(monkeypatch, _reply("tool_action", {"match": match}))
    with pytest.raises(client.NativeSensitiveRequestError):
        secret_file_requests.extract_sensitive_tool_action_request(
            "Bash", {"command": "ls"}, cwd=tmp_path, home_dir=tmp_path
        )


def test_tool_action_reply_keeps_embedded_command_text(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from dataclasses import fields

    from codex_plugin_scanner.guard.runtime.secret_file_request_services.request_models import (
        ToolActionRequestMatch,
    )

    match = {item.name: None for item in fields(ToolActionRequestMatch)}
    for name in ("tool_name", "normalized_tool_name", "command_text", "action_class", "reason"):
        match[name] = "Bash"
    for name in (
        "wrapper_chain",
        "shell_execution_effective_cwds",
        "pytest_config_sources",
        "pytest_config_reason_codes",
        "interpreter_executable_identities",
    ):
        match[name] = []
    match["canonical_command"] = {
        "raw_text": "cat $(echo ~/.ssh/id_rsa) <<'EOF'\nsecret\nEOF",
        "normalized_text": "cat $(echo ~/.ssh/id_rsa) <<'EOF'\nsecret\nEOF",
        "dialect": "posix",
        "transport": "shell_string",
        "extraction_provenance": "guard-shell",
        "wrapper_chain": [],
        "segments": [
            {
                "text": "cat $(echo ~/.ssh/id_rsa)",
                "tokens": ["cat", "$(echo ~/.ssh/id_rsa)"],
                "executable": "cat",
                "arguments": ["$(echo ~/.ssh/id_rsa)"],
                "environment_names": [],
                "wrapper_chain": [],
                "path_overridden": False,
                "execution_context": "direct",
                "pipeline_index": 0,
                "span": {"source": "normalized", "start": 0, "end": 24},
            }
        ],
        "redirects": [],
        "embedded_commands": [
            {
                "kind": "substitution",
                "text": "echo ~/.ssh/id_rsa",
                "execution_context": "direct",
                "span": {"source": "normalized", "start": 4, "end": 24},
            },
            {
                "kind": "heredoc",
                "text": "secret\n",
                "execution_context": "direct",
                "span": {"source": "normalized", "start": 25, "end": 32},
            },
        ],
        "confidence": "exact",
        "uncertainty_reason": None,
        "security_identity": "command-security-v2:test",
        "path_overridden": False,
    }
    _answer(monkeypatch, _reply("tool_action", {"match": match}))
    found = secret_file_requests.extract_sensitive_tool_action_request(
        "Bash",
        {"command": match["canonical_command"]["raw_text"]},
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    assert found is not None
    assert found.canonical_command is not None
    texts = [item.text for item in found.canonical_command.embedded_commands]
    assert "echo ~/.ssh/id_rsa" in texts
    assert "secret\n" in texts


def test_command_list_outage_blocks_the_post_tool_artifact(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.cli import commands_support_codex_commands as codex
    from codex_plugin_scanner.guard.cli import commands_support_runtime_artifacts as artifacts

    def down(*_args: object, **_kwargs: object) -> tuple[str, ...]:
        raise client.NativeSensitiveRequestError("native_sensitive_request_unavailable")

    monkeypatch.setattr(codex, "command_list_candidate_texts", down)
    result = artifacts._hook_runtime_artifact(
        harness="codex",
        payload={
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {
                "command": "cat ~/.ssh/id_rsa",
                "commands": ["cat ~/.ssh/id_rsa"],
            },
        },
        workspace=tmp_path,
        home_dir=tmp_path,
        guard_home=tmp_path / "guard",
        action_envelope=None,
    )
    assert result is not None
    assert result.metadata["guard_default_action"] == "block"
    assert result.metadata["native_command_evaluation_status"] == "unavailable"
    assert result.metadata.get("command_text") != "Bash"


def test_command_list_outage_is_not_a_read_only_post_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.cli import commands_support_codex_commands as codex

    def down(*_args: object, **_kwargs: object) -> tuple[str, ...]:
        raise client.NativeSensitiveRequestError("native_sensitive_request_unavailable")

    monkeypatch.setattr(codex, "command_list_candidate_texts", down)
    assert (
        codex._codex_post_tool_command_is_read_only_source_inspection(
            payload={"tool_input": {"commands": ["ls"]}},
            cwd=None,
            home_dir=None,
        )
        is False
    )


def test_command_list_texts_are_a_tuple_of_strings(monkeypatch: pytest.MonkeyPatch) -> None:
    _answer(monkeypatch, _reply("command_list_candidate_texts", ["cat README.md"]))
    assert secret_file_requests.command_list_candidate_texts(["cat", "README.md"]) == ("cat README.md",)
