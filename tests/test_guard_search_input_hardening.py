"""Regression tests for verified search-command inspection safety."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.secret_file_requests import is_explicitly_benign_tool_action_request


@pytest.mark.parametrize(
    "command",
    (
        "grep -f ~/.ssh/id_rsa src",
        "grep -fpatterns.txt GuardStore src",
        "grep -nf ~/.ssh/id_rsa src",
        "grep -inHf ~/.ssh/id_rsa src",
        "grep -nfpatterns.txt GuardStore src",
        "grep --file patterns.txt GuardStore src",
        "grep --file=patterns.txt GuardStore src",
        "rg -f patterns.txt GuardStore src",
        "rg -fpatterns.txt GuardStore src",
        "rg -nf ~/.env TOKEN src",
        "rg -inHf ~/.env TOKEN src",
        "rg -nfpatterns.txt GuardStore src",
        "rg --file ~/.env TOKEN src",
        "rg --file=patterns.txt GuardStore src",
        "rg --ignore-file ignore.list GuardStore src",
        "rg --ignore-file=ignore.list GuardStore src",
    ),
)
def test_verified_search_rejects_file_backed_inputs(command: str) -> None:
    assert not is_explicitly_benign_tool_action_request("bash", {"command": command})


def test_verified_ripgrep_rejects_ambient_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RIPGREP_CONFIG_PATH", "/tmp/rg.conf")

    assert not is_explicitly_benign_tool_action_request("bash", {"command": "rg GuardStore src"})
    assert not is_explicitly_benign_tool_action_request("bash", {"command": "rg -- --no-config src"})
    assert is_explicitly_benign_tool_action_request("bash", {"command": "rg --no-config GuardStore src"})


def test_verified_ripgrep_rejects_command_scoped_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("RIPGREP_CONFIG_PATH", raising=False)

    assert not is_explicitly_benign_tool_action_request(
        "bash", {"command": "RIPGREP_CONFIG_PATH=/tmp/rg.conf rg GuardStore src"}
    )
    assert not is_explicitly_benign_tool_action_request(
        "bash", {"command": "env RIPGREP_CONFIG_PATH=/tmp/rg.conf rg GuardStore src"}
    )
    assert is_explicitly_benign_tool_action_request(
        "bash", {"command": "RIPGREP_CONFIG_PATH=/tmp/rg.conf rg --no-config GuardStore src"}
    )


def test_verified_search_keeps_plain_local_reads_benign(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("RIPGREP_CONFIG_PATH", raising=False)

    assert is_explicitly_benign_tool_action_request("bash", {"command": "rg GuardStore src"})
    assert is_explicitly_benign_tool_action_request("bash", {"command": "grep GuardStore src/file.py"})
    assert is_explicitly_benign_tool_action_request("bash", {"command": "rg -g'*.foo' needle ."})
    assert is_explicitly_benign_tool_action_request("bash", {"command": "rg needle -- -f"})
