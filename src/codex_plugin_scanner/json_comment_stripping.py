"""Shared JSONC comment stripping for config readers."""

from __future__ import annotations

from collections.abc import Collection

DOUBLE_QUOTE_ONLY = frozenset({'"'})
SINGLE_AND_DOUBLE_QUOTE = frozenset({"'", '"'})


def strip_jsonc_comments(text: str, *, string_quotes: Collection[str] = DOUBLE_QUOTE_ONLY) -> str:
    """Remove // and /* */ comments while preserving strings and newlines."""

    output: list[str] = []
    quote: str | None = None
    escape = False
    in_line_comment = False
    in_block_comment = False
    index = 0
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if in_line_comment:
            if char == "\n":
                in_line_comment = False
                output.append(char)
            index += 1
            continue
        if in_block_comment:
            if char == "*" and next_char == "/":
                in_block_comment = False
                index += 2
                continue
            if char == "\n":
                output.append(char)
            index += 1
            continue
        if quote is not None:
            output.append(char)
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in string_quotes:
            quote = char
            output.append(char)
            index += 1
            continue
        if char == "/" and next_char == "/":
            in_line_comment = True
            index += 2
            continue
        if char == "/" and next_char == "*":
            in_block_comment = True
            index += 2
            continue
        output.append(char)
        index += 1
    return "".join(output)
