from __future__ import annotations

import os

import pytest

from codex_plugin_scanner.cli import _build_parser, _resolve_legacy_args
from codex_plugin_scanner.guard.mcp_tool_calls import build_tool_call_artifact, build_tool_call_hash
from codex_plugin_scanner.guard.proxy import stdio as stdio_module
from codex_plugin_scanner.guard.proxy.stdio import ProxyIoTimeoutError, _readline_with_timeout

pytestmark = pytest.mark.usefixtures("approval_questionnaire_mode")


class _BlockingPipeInput:
    def __init__(self) -> None:
        read_fd, write_fd = os.pipe()
        self._reader = os.fdopen(read_fd, "r", encoding="utf-8")
        self._writer_fd = write_fd

    def fileno(self) -> int:
        return self._reader.fileno()

    def readline(self) -> str:
        return self._reader.readline()

    def close(self) -> None:
        self._reader.close()
        os.close(self._writer_fd)


class _NoFilenoBlockingInput:
    def readline(self) -> str:
        raise AssertionError("shared stream should fail closed before blocking readline()")


def test_codex_guard_proxy_parser_keeps_guard_subcommand_dispatch_intact():
    parser = _build_parser("cli.py", program_mode="combined")
    args = parser.parse_args(
        _resolve_legacy_args(
            [
                "guard",
                "codex-mcp-proxy",
                "--guard-home",
                "/tmp/guard",
                "--server-name",
                "danger_lab",
                "--config-path",
                "/tmp/config.toml",
                "--command",
                "python3",
                "--arg=/tmp/server.py",
            ],
            program_mode="combined",
        )
    )

    assert args.command == "guard"
    assert args.guard_command == "codex-mcp-proxy"
    assert args.server_command == "python3"


def test_tool_call_hash_changes_when_server_identity_changes():
    artifact_a = build_tool_call_artifact(
        harness="codex",
        server_name="danger_lab",
        tool_name="dangerous_delete",
        source_scope="project",
        config_path="/workspace-a/.codex/config.toml",
        transport="stdio",
        server_fingerprint={"command": ["python3", "server-a.py"], "transport": "stdio"},
    )
    artifact_b = build_tool_call_artifact(
        harness="codex",
        server_name="danger_lab",
        tool_name="dangerous_delete",
        source_scope="project",
        config_path="/workspace-b/.codex/config.toml",
        transport="stdio",
        server_fingerprint={"command": ["python3", "server-b.py"], "transport": "stdio"},
    )

    assert build_tool_call_hash(artifact_a, {"target": "canary.txt"}) != build_tool_call_hash(
        artifact_b,
        {"target": "canary.txt"},
    )


def test_tool_call_hash_changes_when_tool_schema_identity_changes():
    artifact_a = build_tool_call_artifact(
        harness="codex",
        server_name="danger_lab",
        tool_name="dangerous_delete",
        source_scope="project",
        config_path="/workspace/.codex/config.toml",
        transport="stdio",
        server_id="mcp_server:codex:project:danger_lab:1234",
        tool_schema={"type": "object", "properties": {"target": {"type": "string"}}},
        tool_description="Delete a file target.",
    )
    artifact_b = build_tool_call_artifact(
        harness="codex",
        server_name="danger_lab",
        tool_name="dangerous_delete",
        source_scope="project",
        config_path="/workspace/.codex/config.toml",
        transport="stdio",
        server_id="mcp_server:codex:project:danger_lab:1234",
        tool_schema={"type": "object", "properties": {"target": {"type": "string"}, "force": {"type": "boolean"}}},
        tool_description="Delete files and directories.",
    )

    assert build_tool_call_hash(artifact_a, {"target": "canary.txt"}) != build_tool_call_hash(
        artifact_b,
        {"target": "canary.txt"},
    )


def test_readline_with_timeout_rejects_shared_stream_without_fileno() -> None:
    with pytest.raises(ProxyIoTimeoutError):
        _readline_with_timeout(
            _NoFilenoBlockingInput(),
            0.05,
            source="inline_approval",
            allow_background_wait=False,
        )


def test_readline_with_timeout_rejects_shared_stream_when_select_fails(monkeypatch) -> None:
    blocking_input = _BlockingPipeInput()
    try:
        monkeypatch.setattr(
            stdio_module.select,
            "select",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("select unavailable")),
        )
        with pytest.raises(ProxyIoTimeoutError):
            _readline_with_timeout(
                blocking_input,
                0.05,
                source="nested_client_response",
                allow_background_wait=False,
            )
    finally:
        blocking_input.close()
