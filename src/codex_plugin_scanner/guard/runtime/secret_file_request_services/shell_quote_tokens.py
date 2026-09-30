"""Quote-preserving shell tokens shared by command classifiers."""

from __future__ import annotations

import shlex
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ShellTokenWithQuoteContext:
    raw: str
    plain: str


def shell_tokens_preserving_quote_context(command_text: str) -> list[ShellTokenWithQuoteContext]:
    tokens: list[ShellTokenWithQuoteContext] = []
    index = 0
    while index < len(command_text):
        if command_text[index] in {"\n", "\r"}:
            tokens.append(ShellTokenWithQuoteContext(raw=";", plain=";"))
            index += 1
            continue
        while index < len(command_text) and command_text[index].isspace() and command_text[index] not in {"\n", "\r"}:
            index += 1
        if index >= len(command_text):
            break
        if command_text[index] in {"\n", "\r"}:
            tokens.append(ShellTokenWithQuoteContext(raw=";", plain=";"))
            index += 1
            continue
        if command_text[index] in {";", "&", "|"}:
            if command_text.startswith("&&", index) or command_text.startswith("||", index):
                raw_token = command_text[index : index + 2]
                index += 2
            else:
                raw_token = command_text[index]
                index += 1
            tokens.append(ShellTokenWithQuoteContext(raw=raw_token, plain=raw_token))
            continue
        start = index
        quote: str | None = None
        escaped = False
        while index < len(command_text):
            char = command_text[index]
            if escaped:
                escaped = False
                index += 1
                continue
            if char == "\\" and quote != "'":
                escaped = True
                index += 1
                continue
            if quote is not None:
                if char == ("'" if quote == "$'" else quote):
                    quote = None
                index += 1
                continue
            if command_text.startswith("$'", index):
                quote = "$'"
                index += 2
                continue
            if char in {"'", '"'}:
                quote = char
                index += 1
                continue
            if char == "&" and _is_fd_duplication_ampersand(command_text, index=index, token_start=start):
                index += 1
                continue
            if char.isspace() or char in {";", "&", "|"}:
                break
            index += 1
        raw_token = command_text[start:index]
        if raw_token:
            tokens.append(ShellTokenWithQuoteContext(raw=raw_token, plain=plain_shell_token(raw_token)))
    return tokens


def _is_fd_duplication_ampersand(command_text: str, *, index: int, token_start: int) -> bool:
    if index <= token_start or command_text[index - 1] not in {"<", ">"}:
        return False
    descriptor_index = index + 1
    if descriptor_index >= len(command_text):
        return False
    if command_text[descriptor_index] == "-":
        descriptor_index += 1
    else:
        if not command_text[descriptor_index].isdigit():
            return False
        while descriptor_index < len(command_text) and command_text[descriptor_index].isdigit():
            descriptor_index += 1
    return descriptor_index >= len(command_text) or (
        command_text[descriptor_index].isspace() or command_text[descriptor_index] in {";", "&", "|"}
    )


def plain_shell_token(raw_token: str) -> str:
    try:
        parts = shlex.split(raw_token, posix=True)
    except ValueError:
        return raw_token.strip("'\"")
    return parts[0] if parts else ""


def shell_token_segments(tokens: list[ShellTokenWithQuoteContext]) -> list[list[ShellTokenWithQuoteContext]]:
    segments: list[list[ShellTokenWithQuoteContext]] = []
    current: list[ShellTokenWithQuoteContext] = []
    for token in tokens:
        if token.plain in {"&&", "||", ";", "&", "|", "|&"}:
            if current:
                segments.append(current)
                current = []
            continue
        current.append(token)
    if current:
        segments.append(current)
    return segments
