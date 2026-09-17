"""Offline-gating behavior for env-triggered external analyzer credentials."""

from __future__ import annotations

import os

from codex_plugin_scanner.action_environment import drop_external_analyzer_credentials


def test_offline_action_drops_external_analyzer_credentials(monkeypatch, capsys) -> None:
    monkeypatch.setenv("MCP_SCANNER_API_KEY", "runner-secret")
    monkeypatch.setenv("MCP_SCANNER_LLM_API_KEY", "llm-secret")

    dropped = drop_external_analyzer_credentials(online=False)

    assert dropped == ("MCP_SCANNER_API_KEY", "MCP_SCANNER_LLM_API_KEY")
    assert "MCP_SCANNER_API_KEY" not in os.environ
    assert "MCP_SCANNER_LLM_API_KEY" not in os.environ
    stdout = capsys.readouterr().out
    assert "MCP_SCANNER_API_KEY" in stdout
    assert "online is disabled" in stdout


def test_online_action_keeps_external_analyzer_credentials(monkeypatch, capsys) -> None:
    monkeypatch.setenv("MCP_SCANNER_API_KEY", "runner-secret")
    monkeypatch.setenv("MCP_SCANNER_LLM_API_KEY", "llm-secret")

    dropped = drop_external_analyzer_credentials(online=True)

    assert dropped == ()
    assert os.environ["MCP_SCANNER_API_KEY"] == "runner-secret"
    assert os.environ["MCP_SCANNER_LLM_API_KEY"] == "llm-secret"
    assert capsys.readouterr().out == ""


def test_offline_action_without_credentials_is_silent(monkeypatch, capsys) -> None:
    monkeypatch.delenv("MCP_SCANNER_API_KEY", raising=False)
    monkeypatch.delenv("MCP_SCANNER_LLM_API_KEY", raising=False)

    assert drop_external_analyzer_credentials(online=False) == ()
    assert capsys.readouterr().out == ""
