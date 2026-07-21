"""Small, bounded JSON-with-comments decoder used by Bun lockfiles."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import cast


def loads_jsonc(
    text: str,
    *,
    object_pairs_hook: Callable[[list[tuple[str, object]]], object] | None = None,
    deadline_check: Callable[[], None] | None = None,
) -> object:
    """Decode JSONC while preserving JSON's duplicate-key hook semantics."""

    without_comments = _strip_comments(text, deadline_check=deadline_check)
    normalized = _strip_trailing_commas(without_comments, deadline_check=deadline_check)
    return cast(object, json.loads(normalized, object_pairs_hook=object_pairs_hook))


def _strip_comments(text: str, *, deadline_check: Callable[[], None] | None) -> str:
    output = list(text)
    in_string = False
    escaped = False
    index = 0
    while index < len(text):
        if deadline_check is not None and index % 4096 == 0:
            deadline_check()
        character = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            index += 1
            continue
        if character == '"':
            in_string = True
            index += 1
            continue
        if character != "/" or index + 1 >= len(text):
            index += 1
            continue
        marker = text[index + 1]
        if marker == "/":
            output[index] = " "
            output[index + 1] = " "
            index += 2
            while index < len(text) and text[index] not in "\r\n":
                output[index] = " "
                index += 1
            continue
        if marker != "*":
            index += 1
            continue
        comment_start = index
        output[index] = " "
        output[index + 1] = " "
        index += 2
        while index + 1 < len(text) and text[index : index + 2] != "*/":
            if deadline_check is not None and index % 4096 == 0:
                deadline_check()
            if text[index] not in "\r\n":
                output[index] = " "
            index += 1
        if index + 1 >= len(text):
            raise json.JSONDecodeError("Unterminated block comment", text, comment_start)
        output[index] = " "
        output[index + 1] = " "
        index += 2
    if deadline_check is not None:
        deadline_check()
    return "".join(output)


def _strip_trailing_commas(text: str, *, deadline_check: Callable[[], None] | None) -> str:
    output = list(text)
    in_string = False
    escaped = False
    for index, character in enumerate(text):
        if deadline_check is not None and index % 4096 == 0:
            deadline_check()
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
            continue
        if character != ",":
            continue
        next_index = index + 1
        while next_index < len(text) and text[next_index].isspace():
            next_index += 1
        if next_index < len(text) and text[next_index] in "}]":
            output[index] = " "
    if deadline_check is not None:
        deadline_check()
    return "".join(output)
