"""Bounded POSIX process queries for daemon ownership checks.

The native runtime runs the trusted `ps` or reads procfs (`posix-processes`);
this module only shapes its answer. Every query answers `None` when the
process table cannot be read in full.
"""

from __future__ import annotations

import os
from typing import cast

_FEATURE = "native-posix-processes-v1"
_COMMAND = "posix-processes"
_SCHEMA = "posix-processes.v1"
_TIMEOUT_SECONDS = 10.0
# The runtime reads at most 1 MiB of process text; JSON may spell one byte as
# six (`\u001f`), and each procfs entry adds its id and punctuation.
_OUTPUT_LIMIT_BYTES = 6 * 1024 * 1024 + 64 * 1024


def _runtime_answer(request: dict[str, object]) -> dict[str, object] | None:
    from .mdm.runtime_request import runtime_answer

    return runtime_answer(
        _FEATURE,
        _COMMAND,
        {"schema": _SCHEMA, **request},
        output_limit=_OUTPUT_LIMIT_BYTES,
        timeout_seconds=_TIMEOUT_SECONDS,
    )


def _text(answer: dict[str, object] | None, key: str) -> str | None:
    value = answer.get(key) if answer is not None else None
    return value if isinstance(value, str) else None


def posix_process_inventory() -> str | list[tuple[int, str]] | None:
    """The `ps -axo pid=,command=` listing, Linux procfs entries without `ps`, or `None`."""

    if os.name == "nt":
        return None
    answer = _runtime_answer({"op": "inventory"})
    listing = _text(answer, "listing")
    if listing is not None:
        return listing
    entries = answer.get("entries") if answer is not None else None
    if not isinstance(entries, list):
        return None
    inventory: list[tuple[int, str]] = []
    for entry in cast(list[object], entries):
        if not isinstance(entry, list) or len(cast(list[object], entry)) != 2:
            return None
        pid, command = cast(list[object], entry)
        if isinstance(pid, bool) or not isinstance(pid, int) or not isinstance(command, str):
            return None
        inventory.append((pid, command))
    return inventory


def posix_process_elapsed_listing() -> str | None:
    """The `ps -axo pid=,etime=,command=` listing, or `None`."""

    if os.name == "nt":
        return None
    return _text(_runtime_answer({"op": "elapsed"}), "listing")


def posix_parent_pid(pid: int) -> int | None:
    """The parent of a live process, or `None` when it cannot be proven."""

    if os.name == "nt" or pid <= 0:
        return None
    answer = _runtime_answer({"op": "parent", "pid": pid})
    parent = answer.get("parent_pid") if answer is not None else None
    if isinstance(parent, bool) or not isinstance(parent, int) or parent <= 0:
        return None
    return parent


def posix_process_command(pid: int) -> str | None:
    """The command line of a live process, or `None`."""

    if os.name == "nt" or pid <= 0:
        return None
    command = _text(_runtime_answer({"op": "command", "pid": pid}), "command")
    return command or None


__all__ = [
    "posix_parent_pid",
    "posix_process_command",
    "posix_process_elapsed_listing",
    "posix_process_inventory",
]
