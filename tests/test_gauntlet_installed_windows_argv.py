"""The installed lane reads a Windows hook command the way Windows runs it."""

from __future__ import annotations

import subprocess

import pytest

from ci.gauntlet.installed_registration import (
    handler_argv,
    split_command_line,
    split_powershell_call,
    split_windows_command_line,
)

ARGVS = [
    [r"D:\a\_temp\wheel-venv\Scripts\hol-guard.exe", "hook", "--harness", "claude-code"],
    [r"C:\Program Files\HOL Guard\hol-guard.exe", "--guard-home", r"C:\Users\synthetic\.hol-guard"],
    [r"C:\dir with space\\", 'say "hi"', "", r"trailing\\"],
    ['a\\\\"b', "tab\there", r"\\server\share\x"],
]


@pytest.mark.parametrize("argv", ARGVS)
def test_a_windows_command_line_splits_back_to_its_argv(argv):
    assert split_windows_command_line(subprocess.list2cmdline(argv)) == argv


def test_a_registered_windows_handler_keeps_its_backslashes():
    command = subprocess.list2cmdline(ARGVS[0])

    assert split_command_line(command, windows=True)[0] == ARGVS[0][0]
    assert split_command_line(command, windows=False)[0] != ARGVS[0][0]


def test_a_posix_handler_still_splits_as_a_posix_shell_would():
    assert split_command_line("'/opt/hol guard/bin/hol-guard' hook", windows=False) == [
        "/opt/hol guard/bin/hol-guard",
        "hook",
    ]


def test_an_unbalanced_windows_quote_yields_no_argv(monkeypatch):
    monkeypatch.setattr("ci.gauntlet.installed_registration.os.name", "nt")

    assert handler_argv({"command": '"C:\\guard\\hol-guard.exe hook'}) == []


def test_a_powershell_call_with_a_spaced_path_keeps_the_path_whole():
    command = "& 'C:\\Program Files\\HOL Guard\\hol-guard-runtime.exe' hook --harness codex 'it''s'"

    assert split_command_line(command, windows=True) == [
        "C:\\Program Files\\HOL Guard\\hol-guard-runtime.exe",
        "hook",
        "--harness",
        "codex",
        "it's",
    ]


@pytest.mark.parametrize("command", ["& 'C:\\unterminated", "&", "& 'a'b", "& a'b"])
def test_an_unreadable_powershell_call_is_refused(command):
    with pytest.raises(ValueError):
        split_powershell_call(command)


def test_a_powershell_literal_reads_typographic_quotes_as_quotes():
    command = "& \u2018C:\\Users\\O\u2019\u2019Neil\\hol-guard.exe\u2019 hook"

    assert split_powershell_call(command) == ["C:\\Users\\O\u2019Neil\\hol-guard.exe", "hook"]
