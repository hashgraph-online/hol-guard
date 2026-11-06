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


@pytest.mark.parametrize(
    ("requested", "routed"),
    ((["help", "secrets"], ["--help"]), (["help", "secrets", "scan"], ["scan", "--help"])),
)
def test_hol_guard_help_alias_preserves_secrets_routing(monkeypatch, requested, routed) -> None:
    calls: list[tuple[list[str], str]] = []
    monkeypatch.setattr(sys, "argv", ["hol-guard"])
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.secrets.cli.main",
        lambda argv, *, program_name: calls.append((argv, program_name)) or 0,
    )

    assert main(requested) == 0
    assert calls == [(routed, "hol-guard secrets")]
