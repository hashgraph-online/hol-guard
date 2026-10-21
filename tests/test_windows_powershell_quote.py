"""PowerShell quoting of the contained sink command for Windows Codex."""

from __future__ import annotations

import re

import pytest

from codex_plugin_scanner.guard.windows_powershell_quote import powershell_join

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
