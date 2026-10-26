"""The proxy reports a relay harness's MCP server catalog to the resident."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_mcp_relay_server_report as report


def _send(harness: str, guard_home: Path):
    return report.report_mcp_relay_server(
        guard_home=guard_home,
        harness=harness,
        server_name="docs",
        source_scope="project",
        config_path="/work/.codex/config.toml",
        server_id=None,
        identity_hash="a" * 64,
        tools=[{"name": "read_note", "inputSchema": {"type": "object"}}],
    )


def test_a_relay_harness_reports_the_server_and_its_catalog(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(report, "_resident_request", lambda **kwargs: calls.append(kwargs))

    thread = _send("codex", tmp_path)
    assert thread is not None
    thread.join(timeout=5)

    assert len(calls) == 1
    call = calls[0]
    assert call["operation"] == "mcp_relay_server_report"
    assert call["required_feature"] == report.MCP_RELAY_SERVER_REPORT_FEATURE
    assert call["response_schema"] == "guard-mcp-relay-server-report-result.v1"
    assert call["record_success"] is False and call["record_resilience"] is False
    assert call["request"] == {
        "guard_home": str(tmp_path),
        "server": {
            "harness": "codex",
            "server_name": "docs",
            "source_scope": "project",
            "config_path": "/work/.codex/config.toml",
            "server_id": None,
            "identity_hash": "a" * 64,
        },
        "tools": [{"name": "read_note", "inputSchema": {"type": "object"}}],
    }


def test_another_harness_sends_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(report, "_resident_request", lambda **kwargs: pytest.fail("sent a report"))

    assert _send("claude-code", tmp_path) is None


def test_a_failed_report_is_swallowed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fail(**kwargs: object) -> None:
        raise RuntimeError("resident unavailable")

    monkeypatch.setattr(report, "_resident_request", fail)
    errors: list[BaseException] = []
    monkeypatch.setattr("threading.excepthook", lambda args: errors.append(args.exc_value))

    thread = _send("cursor", tmp_path)
    assert thread is not None
    thread.join(timeout=5)

    assert errors == []
