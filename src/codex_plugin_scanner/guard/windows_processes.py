"""Bounded native Windows process discovery for daemon ownership checks.

The native runtime reads the process table (`windows-process-command-lines`);
this module only checks the bounds callers pass and shapes its answer.
"""

from __future__ import annotations

import os
from typing import cast

_FEATURE = "native-windows-process-command-lines-v1"
_COMMAND = "windows-process-command-lines"
_SCHEMA = "windows-process-command-lines.v1"
_WINDOWS_PROCESS_ENUMERATION_LIMIT = 65_536
_WINDOWS_PROCESS_COMMAND_LINE_TOTAL_LIMIT_BYTES = 1024 * 1024
_TIMEOUT_SECONDS = 10.0
# JSON may spell one command-line byte as six (`\u001f`); each process adds
# its id and punctuation.
_OUTPUT_OVERHEAD_BYTES = 64 * 1024


def _runtime_answer(request: dict[str, object], *, output_limit: int) -> dict[str, object] | None:
    from .mdm.runtime_request import runtime_answer

    return runtime_answer(
        _FEATURE,
        _COMMAND,
        {"schema": _SCHEMA, **request},
        output_limit=output_limit,
        timeout_seconds=_TIMEOUT_SECONDS,
    )


def windows_process_command_line(
    pid: int,
    *,
    max_command_line_bytes: int = _WINDOWS_PROCESS_COMMAND_LINE_TOTAL_LIMIT_BYTES,
) -> str | None:
    """Read one Windows process command line through bounded native APIs."""

    if os.name != "nt" or pid <= 0:
        return None
    if not 0 < max_command_line_bytes <= _WINDOWS_PROCESS_COMMAND_LINE_TOTAL_LIMIT_BYTES:
        return None
    answer = _runtime_answer(
        {"op": "read", "pids": [pid], "max_command_line_bytes": max_command_line_bytes},
        output_limit=max_command_line_bytes * 6 + _OUTPUT_OVERHEAD_BYTES,
    )
    command_lines = answer.get("command_lines") if answer is not None else None
    if not isinstance(command_lines, list) or len(cast(list[object], command_lines)) != 1:
        return None
    command_line = cast(list[object], command_lines)[0]
    return command_line if isinstance(command_line, str) and command_line else None


def windows_process_command_line_inventory(
    *,
    candidate_executable_names: frozenset[str],
    max_processes: int = _WINDOWS_PROCESS_ENUMERATION_LIMIT,
    max_command_line_bytes: int = _WINDOWS_PROCESS_COMMAND_LINE_TOTAL_LIMIT_BYTES,
) -> list[tuple[int, str]] | None:
    """Return bounded command lines for candidate Windows process images."""

    if (
        not 0 < max_processes <= _WINDOWS_PROCESS_ENUMERATION_LIMIT
        or not 0 < max_command_line_bytes <= _WINDOWS_PROCESS_COMMAND_LINE_TOTAL_LIMIT_BYTES
    ):
        return None
    candidates = sorted(value for value in candidate_executable_names if isinstance(value, str) and value.strip())
    if not candidates:
        return []
    if os.name != "nt":
        return None
    answer = _runtime_answer(
        {
            "op": "inventory",
            "candidate_executable_names": candidates,
            "max_processes": max_processes,
            "max_command_line_bytes": max_command_line_bytes,
        },
        output_limit=max_command_line_bytes * 6 + max_processes * 24 + _OUTPUT_OVERHEAD_BYTES,
    )
    entries = answer.get("entries") if answer is not None else None
    if not isinstance(entries, list):
        return None
    inventory: list[tuple[int, str]] = []
    for entry in cast(list[object], entries):
        if not isinstance(entry, list) or len(cast(list[object], entry)) != 2:
            return None
        pid, command_line = cast(list[object], entry)
        if type(pid) is not int or pid <= 0 or not isinstance(command_line, str) or not command_line:
            return None
        inventory.append((pid, command_line))
    return inventory


__all__ = [
    "windows_process_command_line",
    "windows_process_command_line_inventory",
]
