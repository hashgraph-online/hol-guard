"""Narrow argument equivalence for delegated task host events."""

from __future__ import annotations

from typing import Any

# The task schema's default for an omitted ``agent``; OMP fills it in before the host event.
DEFAULT_TASK_AGENT = "task"


def task_arguments_match(model_tasks: Any, host_tasks: Any) -> bool:
    """OMP omits an unused nullable outputSchema and fills in the default agent."""
    if not isinstance(model_tasks, list) or not isinstance(host_tasks, list):
        return model_tasks == host_tasks
    if len(model_tasks) != len(host_tasks):
        return False
    for expected, actual in zip(model_tasks, host_tasks, strict=True):
        if not isinstance(expected, dict) or not isinstance(actual, dict):
            return False
        expected = dict(expected)
        if "outputSchema" in expected and expected["outputSchema"] is None and "outputSchema" not in actual:
            del expected["outputSchema"]
        if "agent" not in expected and actual.get("agent") == DEFAULT_TASK_AGENT:
            actual = {key: value for key, value in actual.items() if key != "agent"}
        if expected != actual:
            return False
    return True
