"""Bound JSON nesting before decoding an already size-bounded RPC message."""

from __future__ import annotations


def check_json_depth(message: bytes, *, maximum: int, error_code: str) -> None:
    depth, quoted, escaped = 0, False, False
    for character in message:
        if quoted:
            if escaped:
                escaped = False
            elif character == 92:
                escaped = True
            elif character == 34:
                quoted = False
        elif character == 34:
            quoted = True
        elif character in (91, 123):
            depth += 1
            if depth > maximum:
                raise ValueError(error_code)
        elif character in (93, 125):
            depth -= 1
            if depth < 0:
                raise ValueError(error_code)
