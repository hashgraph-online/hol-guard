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


def skip_exec_launcher(tokens: list[str], index: int) -> int:
    """Step past an ``exec`` that hands the run to the program the text names.

    The native parser reads a bare ``exec`` as a launcher and reports the
    program behind it as the executable. Every spelling it refuses to read that
    way - an option word, a script file, a path, an interpreter, or no program
    at all - leaves ``exec`` itself as the executable, and ``exec`` there is a
    nested command executor, which the parser reports as uncertain with no
    segment at all. So a segment that still carries ``exec`` in front of its
    program is one the parser stepped past, and stepping past it here reads the
    same words rather than repeating the launcher's grammar.
    """
    while index + 1 < len(tokens) and tokens[index] == "exec":
        index += 1
    return index


_INLINE_SHELLS = frozenset({"sh", "bash", "dash", "ash"})


def inline_shell_script(command: str) -> str | None:
    """Return the whole script a shell carries, for the one spelling that is it.

    A shell named with ``-c`` and nothing after the script runs exactly that
    script, so the native parser reads the command as the script and reports
    the script's own normalized text. This repeats that grammar so a reported
    model can be bound back to the request it came from; every other spelling
    returns None and keeps the strict binding, including a login shell or
    ``zsh``, which read a startup file the script does not name, and one that
    expands a word or runs the shell over more than its script.
    """

    if any(character in command for character in "$`\n\r") or _unquoted_operator(command):
        return None
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    if len(tokens) != 3:
        return None
    shell, option, script = tokens
    if shell not in _INLINE_SHELLS or option != "-c" or not script.strip():
        return None
    return script


def _unquoted_operator(command: str) -> bool:
    """Whether an operator stands outside the quoting, as its own shell word.

    ``shlex.split`` splits on whitespace alone, so ``sh -c 'a; b'>out`` comes
    back as three words with the redirect stuck to the script. The shell
    redirects the whole invocation instead, so the script is not the command
    the text runs.
    """

    quote: str | None = None
    characters = iter(command)
    for character in characters:
        if character == "\\" and quote in (None, '"'):
            next(characters, None)
        elif quote is not None:
            if character == quote:
                quote = None
        elif character in "'\"":
            quote = character
        elif character in "<>|&;()":
            return True
    return False
