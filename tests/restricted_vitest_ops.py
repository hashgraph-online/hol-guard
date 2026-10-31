"""Tests' entry points to the restricted Vitest argument ops.

The runtime reaches these ops through the native launch plan; the tests call
them directly to pin how the resident reads each command shape.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from codex_plugin_scanner.guard.native_restricted_pytest import restricted_native


def bun_vitest_invocation(command: Sequence[str]) -> tuple[str | None, tuple[str, ...]] | None:
    result = restricted_native("bun_vitest_invocation", {"command": list(command)}, (list, type(None)))
    if result is None:
        return None
    if (
        len(result) != 2
        or (result[0] is not None and not isinstance(result[0], str))
        or not isinstance(result[1], list)
    ):
        raise ValueError("Invalid native Bun invocation")
    return result[0], tuple(result[1])


def tsx_test_invocation(command: Sequence[str]) -> tuple[str, tuple[str, ...]] | None:
    result = restricted_native("tsx_test_invocation", {"command": list(command)}, (list, type(None)))
    if result is None:
        return None
    if len(result) != 2 or not isinstance(result[0], str) or not isinstance(result[1], list):
        raise ValueError("Invalid native tsx invocation")
    return result[0], tuple(result[1])


def vitest_arguments(command: Sequence[str]) -> tuple[str, ...]:
    return tuple(restricted_native("vitest_arguments", {"command": list(command)}, list))


def readonly_config_arguments(args: tuple[str, ...], manifest: Path) -> tuple[str, ...]:
    return tuple(restricted_native("readonly_config_arguments", {"command": args, "path": manifest}, list))
