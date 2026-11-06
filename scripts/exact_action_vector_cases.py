"""Case catalogue for the native exact-action vectors.

Every case is a plain dict: a materialized file ``tree`` (paths relative to the
``{ROOT}`` placeholder), the package-intent answer the fake resident engine
returns, and the wire ``request`` the Rust op receives. The recorder runs the
retired Python on the same case; ``record_exact_action_vectors.py`` owns that.
"""

from __future__ import annotations

from typing import Any

from exact_action_cases_basic import command_cases, gating_cases, tool_cases
from exact_action_cases_binding import binding_cases
from exact_action_cases_git import git_cases
from exact_action_cases_runner import runner_cases


def all_cases() -> list[dict[str, Any]]:
    groups = (gating_cases, tool_cases, command_cases, git_cases, runner_cases, binding_cases)
    cases = [case for group in groups for case in group()]
    names = [case["name"] for case in cases]
    assert len(names) == len(set(names)), "duplicate case name"
    return cases
