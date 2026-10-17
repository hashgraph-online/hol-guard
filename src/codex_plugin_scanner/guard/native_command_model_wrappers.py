"""Validate the bounded wrapper metadata emitted by the native command parser."""

from __future__ import annotations

import shlex


def decode_sudo_prefix(tokens: list[str], index: int) -> tuple[int, list[str]] | None:
    wrappers: list[str] = []
    while index < len(tokens) and tokens[index].replace("\\", "/").rsplit("/", 1)[-1] == "sudo":
        if len(wrappers) == 4:
            return None
        wrappers.append("sudo")
        index += 1
        while index < len(tokens):
            option = tokens[index]
            if option == "--":
                index += 1
                break
            if option in {"-n", "--non-interactive"}:
                index += 1
            elif option in {"-T", "--command-timeout"}:
                if index + 1 >= len(tokens) or not _timeout(tokens[index + 1]):
                    return None
                index += 2
            elif option.startswith("--command-timeout="):
                if not _timeout(option.removeprefix("--command-timeout=")):
                    return None
                index += 1
            elif option.startswith("-"):
                return None
            else:
                break
        if index == len(tokens) or not tokens[index]:
            return None
        name, separator, _value = tokens[index].partition("=")
        if separator and name.isascii() and name.isidentifier():
            return None
    return index, wrappers


def _timeout(value: str) -> bool:
    return bool(value) and len(value) <= 10 and value.isascii() and value.isdigit()


_INLINE_SHELLS = frozenset({"sh", "bash", "dash", "ash", "zsh"})
_INLINE_SCRIPT_OPTIONS = frozenset({"-c", "-lc", "-cl"})


def inline_shell_script(command: str) -> str | None:
    """Return the whole script a shell carries, for the one spelling that is it.

    A shell named with a script option and nothing after the script runs
    exactly that script, so the native parser reads the command as the script
    and reports the script's own normalized text. This repeats that grammar so
    a reported model can be bound back to the request it came from; every
    other spelling, including one that expands a word or runs the shell over
    more than its script, returns None and keeps the strict binding.
    """

    if any(character in command for character in "$`\n\r"):
        return None
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    if len(tokens) != 3:
        return None
    shell, option, script = tokens
    if shell not in _INLINE_SHELLS or option not in _INLINE_SCRIPT_OPTIONS or not script.strip():
        return None
    return script
