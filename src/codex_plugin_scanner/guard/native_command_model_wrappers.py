"""Validate the bounded wrapper metadata emitted by the native command parser."""

from __future__ import annotations


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
