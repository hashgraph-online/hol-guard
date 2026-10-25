"""Quoting of the contained sink command for Windows Codex."""

from __future__ import annotations

import re

import pytest

from codex_plugin_scanner.guard.windows_powershell_quote import powershell_join, sink_command_line

_LITERAL = re.compile(r"'((?:[^'\u2018\u2019\u201a\u201b]|(?P<q>['\u2018\u2019\u201a\u201b])(?P=q))*)'")


def _arguments(command: str) -> list[str]:
    """Read the literals back the way PowerShell does: a doubled quote is one quote."""

    assert command.startswith("& ")
    rest = command[2:]
    out: list[str] = []
    position = 0
    while position < len(rest):
        match = _LITERAL.match(rest, position)
        assert match is not None, command
        out.append(re.sub(r"(['\u2018\u2019\u201a\u201b])\1", r"\1", match.group(1)))
        position = match.end()
        if position < len(rest):
            assert rest[position] == " "
            position += 1
    return out


@pytest.mark.parametrize(
    "argument",
    [
        "plain",
        r"C:\Users\Test User\a b",
        "it's",
        "$env:USERNAME",
        "$(whoami)",
        "back`tick`",
        "%PATH%",
        "a&b",
        "a;b",
        "a|b",
        "(x) {y} @z <w> a>b a,b ^c",
        r"trail\\",
        "x' ; calc ; 'y",
        "\u2018smart\u2019 \u201alow\u201b \u2019",
        "日本語 né",
        "--%",
    ],
)
def test_hostile_arguments_stay_one_literal_each(argument: str) -> None:
    command = powershell_join(["C:\\Program Files\\Python\\python.exe", "-I", argument])
    assert command is not None
    assert _arguments(command) == ["C:\\Program Files\\Python\\python.exe", "-I", argument]


@pytest.mark.parametrize(
    "argument",
    ["", 'say "hi"', "a\nb", "a\rb", "a\x00b", "a\x07b", "has space\\", 'q\\"x'],
)
def test_arguments_windows_powershell_cannot_carry_are_refused(argument: str) -> None:
    assert powershell_join(["python.exe", argument]) is None


def test_nothing_to_run_is_refused() -> None:
    assert powershell_join([]) is None


def test_the_command_is_a_single_call_operator_statement() -> None:
    command = powershell_join(["C:\\py thon\\python.exe", "-I", "-c", "import sys;print(1)", "guard"])
    assert command == "& 'C:\\py thon\\python.exe' '-I' '-c' 'import sys;print(1)' 'guard'"


_BOOTSTRAP = (
    "import sys;sys.path.insert(0, {root!r});from codex_plugin_scanner.cli import main;"
    "raise SystemExit(main(sys.argv[1:]))"
)
_ARGV_BOOTSTRAP = (
    "import sys;sys.path.insert(0,sys.argv.pop(1));from codex_plugin_scanner.cli import main;"
    "raise SystemExit(main(sys.argv[1:]))"
)


def test_the_sink_line_is_one_powershell_and_git_bash_read_the_same_way() -> None:
    argv = [
        "C:\\Python\\python.exe",
        "-I",
        "-c",
        _BOOTSTRAP.format(root="C:/Guard/site-packages"),
        "guard",
        "C:\\Users\\a b\\x;$y&`z`",
    ]
    assert sink_command_line(argv) == (
        f"C:/Python/python.exe '-I' '-c' '{_ARGV_BOOTSTRAP}' 'C:/Guard/site-packages' 'guard' "
        "'C:\\Users\\a b\\x;$y&`z`'"
    )
    assert sink_command_line(["C:\\Guard\\hol-guard.exe", "run"]) == "C:/Guard/hol-guard.exe 'run'"


@pytest.mark.parametrize(
    "argv",
    [
        ["C:\\Program Files\\py.exe", "x"],
        ["C:\\Guard\\hol-guard.exe", "it's"],
        ["C:\\Guard\\hol-guard.exe", "it\u2019s"],
        ["\\\\server\\py.exe", "x"],
        ["C:\\Python\\python.exe", "-I", "-c", _BOOTSTRAP.format(root="C:\\Guard"), "guard"],
        ["C:\\Python\\python.exe", "-I", "-c", "print(1)", "guard"],
    ],
)
def test_an_argv_only_powershell_can_carry_falls_back_to_its_form(argv: list[str]) -> None:
    assert sink_command_line(argv) == powershell_join(argv)
    assert sink_command_line(argv).startswith("& ")


def test_an_argv_neither_shell_can_carry_is_refused() -> None:
    assert sink_command_line(["C:\\Python\\python.exe", 'say "hi"']) is None
    assert sink_command_line([]) is None
