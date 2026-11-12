"""Test clients for resident contained-run readings no runtime module asks for.

The sink reads every kind at once through `contained_kind`; these single-kind
clients keep the tests driving the resident's per-kind answers directly.
"""

from __future__ import annotations

from collections.abc import Sequence

from codex_plugin_scanner.guard.native_restricted_pytest import restricted_native
from codex_plugin_scanner.guard.runtime.restricted_package_test import KIND_NAMES
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import RestrictedPytestError


def is_inline_eval(command: Sequence[str]) -> bool:
    return restricted_native("inline_eval", {"command": list(command)}, bool)


def python_runtime_args(command: Sequence[str]) -> tuple[str, ...] | None:
    value = restricted_native("python_runtime_args", {"command": list(command)}, (list, type(None)))
    return tuple(value) if value is not None else None


def is_package_test(command: Sequence[str]) -> bool:
    """True when the command is a package manager running its own test script.

    The answer rides on the reading the sink already asks for, so a contained
    run learns every route its words can take from one call to native
    authority rather than one call per route.
    """

    kinds = restricted_native("contained_kind", {"command": [str(item) for item in command]}, dict)
    answer = kinds.get("package_test")
    if set(kinds) != KIND_NAMES or type(answer) is not bool:
        raise RestrictedPytestError("package_test_invalid_command", "Guard could not read this command.")
    return answer
