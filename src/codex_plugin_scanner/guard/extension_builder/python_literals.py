"""Small deterministic Python data emitter, independent of formatter installations.

Only strings, None, tuples, and explicitly constructed single-argument calls are
supported. This is not a template evaluator and never consumes source-code input.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypeAlias


@dataclass(frozen=True, slots=True)
class LiteralCall:
    name: str
    value: LiteralValue


LiteralValue: TypeAlias = "str | tuple[LiteralValue, ...] | LiteralCall | None"


def quoted(value: str) -> str:
    escaped = value.encode("unicode_escape").decode("ascii").replace('"', '\\"')
    return f'"{escaped}"'


def inline(value: LiteralValue) -> str:
    if value is None:
        return "None"
    if isinstance(value, str):
        return quoted(value)
    if isinstance(value, LiteralCall):
        if value.name not in {"frozenset", "_safe_for"}:
            raise ValueError("Unsupported generated literal constructor")
        return f"{value.name}({inline(value.value)})"
    items = ", ".join(inline(item) for item in value)
    return f"({items}{',' if len(value) == 1 else ''})"


def _string_chunks(value: str) -> tuple[str, ...]:
    chunks: list[str] = []
    current = ""
    for character in value:
        if current and len(quoted(current + character)) > 80:
            chunks.append(current)
            current = ""
        current += character
    if current:
        chunks.append(current)
    return tuple(chunks)


def emit(value: LiteralValue, *, prefix: str, suffix: str = "", width: int = 120) -> list[str]:
    rendered = inline(value)
    if len(prefix + rendered + suffix) <= width:
        return [prefix + rendered + suffix]
    indentation = " " * (len(prefix) - len(prefix.lstrip()))
    nested = indentation + "    "
    if isinstance(value, LiteralCall):
        return [
            prefix + value.name + "(",
            *emit(value.value, prefix=nested, suffix=",", width=width),
            indentation + ")" + suffix,
        ]
    if isinstance(value, str):
        return [prefix + "(", *(nested + quoted(chunk) for chunk in _string_chunks(value)), indentation + ")" + suffix]
    if isinstance(value, tuple):
        return [
            prefix + "(",
            *(line for item in value for line in emit(item, prefix=nested, suffix=",", width=width)),
            indentation + ")" + suffix,
        ]
    raise ValueError("Generated expression cannot fit the supported source width")
