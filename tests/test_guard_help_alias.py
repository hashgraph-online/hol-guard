"""Focused compatibility tests for conventional Guard help commands."""

from __future__ import annotations

import sys

import pytest

from codex_plugin_scanner.cli import main


def test_hol_guard_help_alias_shows_root_help(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "argv", ["hol-guard"])

    with pytest.raises(SystemExit) as exc_info:
        main(["help"])

    assert exc_info.value.code == 0
    output = capsys.readouterr().out
    assert "usage: hol-guard" in output
    assert "dashboard" in output


def test_hol_guard_help_alias_shows_command_help(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "argv", ["hol-guard"])

    with pytest.raises(SystemExit) as exc_info:
        main(["help", "dashboard"])

    assert exc_info.value.code == 0
    output = capsys.readouterr().out
    assert "usage: hol-guard dashboard" in output
