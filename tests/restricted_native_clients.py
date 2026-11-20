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


_EXPECTATIONS = {
    ("inline_eval", "python-eval-readonly-v1"): "native_python_eval_readonly_containment_required",
    ("node_tool", "node-build-output-v1"): "native_node_build_output_containment_required",
    ("node_tool", "node-tool-readonly-v1"): "native_node_tool_readonly_containment_required",
    ("git", None): "native_git_readonly_containment_required",
    ("vitest", None): "native_vitest_readonly_containment_required",
    ("node_test", None): "native_node_test_readonly_containment_required",
    ("pytest", None): "native_pytest_readonly_containment_required",
}
_PROFILES = {
    "native_bun_eval_readonly_containment_required": "node-eval-readonly-v1",
    "native_node_eval_readonly_containment_required": "node-eval-readonly-v1",
    "native_python_eval_readonly_containment_required": "python-eval-readonly-v1",
    "native_node_build_output_containment_required": "node-build-output-v1",
    "native_node_tool_readonly_containment_required": "node-tool-readonly-v1",
    "native_git_readonly_containment_required": "git-readonly-v1",
    "native_vitest_readonly_containment_required": "vitest-readonly-v1",
    "native_node_test_readonly_containment_required": "node-test-readonly-v1",
    "native_pytest_readonly_containment_required": "pytest-readonly-v2",
}


def contained_expectation_reply(fields: object) -> dict[str, str]:
    """A stand-in resident's `contained_expectation` answer, for tests that fake every other reading.

    The table is the resident's, written out: a test that fakes the kinds still
    needs the receipt the planned run must carry. `contained_expectation.rs`
    owns the real one, and the Rust tests pin it.
    """

    assert isinstance(fields, dict)
    kind, plan_profile, command = fields["kind"], fields["plan_profile"], fields["command"]
    if kind == "inline_eval" and plan_profile == "node-eval-readonly-v1":
        program = str(command[0]).replace("\\", "/").rsplit("/", 1)[-1] if command else ""
        reason = (
            "native_bun_eval_readonly_containment_required"
            if program == "bun"
            else "native_node_eval_readonly_containment_required"
        )
    else:
        reason = _EXPECTATIONS[(kind, plan_profile)]
    return {"reason": reason, "profile": _PROFILES[reason]}
