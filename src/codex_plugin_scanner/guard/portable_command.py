"""Portable copy-paste command rendering for bounded identifiers."""

from __future__ import annotations

import re
from collections.abc import Sequence

_PORTABLE_ARGUMENT = re.compile(r"[A-Za-z0-9._:@/+=,\-]+")


def portable_command_argument(value: str) -> bool:
    return bool(value) and _PORTABLE_ARGUMENT.fullmatch(value) is not None


def render_portable_command(arguments: Sequence[str]) -> str:
    if not arguments or any(not portable_command_argument(argument) for argument in arguments):
        raise ValueError("command_contains_non_portable_argument")
    return " ".join(arguments)


def portable_command_payload(field: str, arguments: Sequence[str]) -> dict[str, str]:
    if all(portable_command_argument(argument) for argument in arguments):
        return {field: render_portable_command(arguments)}
    return {f"{field}_unavailable": "binding_identifiers_invalid"}
