"""Narrow argument equivalence for delegated task host events."""

from __future__ import annotations

from typing import Any


def task_arguments_match(model_tasks: Any, host_tasks: Any) -> bool:
    """OMP omits an unused nullable outputSchema when creating task requests."""
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
        if expected != actual:
            return False
    return True
