"""The metric-name case counts only a write of its own file carrying its own value."""

from __future__ import annotations

from typing import Any

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.native_tools import (
    METRIC_WINDOW_WRITE_CASE,
    METRIC_WINDOW_WRITE_FILES,
    native_tools_scope_error,
)

CONTENT = "export const metrics = [{ metricKey: 'downloads_30d' }];\n"


def _write(path: str, content: str = CONTENT, *, is_error: bool = False) -> dict[str, Any]:
    return {
        "id": "write",
        "name": "write",
        "args": {"path": path, "content": content},
        "result": {"content": [{"type": "text", "text": "written"}]},
        "is_error": is_error,
    }


def _scenario():
    return next(item for item in load_catalog() if item.id == METRIC_WINDOW_WRITE_CASE)


def test_case_is_a_benign_native_write_allow() -> None:
    scenario = _scenario()
    assert (scenario.expectation, scenario.oracle) == ("allow", "native-tools")
    assert scenario.required_tools == ("write",)
    assert not scenario.commands


def test_writing_the_metric_source_is_in_scope() -> None:
    scenario = _scenario()
    for path in (
        *METRIC_WINDOW_WRITE_FILES,
        f"{{{{workspace}}}}/{METRIC_WINDOW_WRITE_FILES[0]}",
        f"~/project/{METRIC_WINDOW_WRITE_FILES[0]}",
        f"./{METRIC_WINDOW_WRITE_FILES[0]}",
        METRIC_WINDOW_WRITE_FILES[0].replace("/", "\\"),
        "{{workspace}}\\" + METRIC_WINDOW_WRITE_FILES[0].replace("/", "\\"),
    ):
        assert native_tools_scope_error(scenario, [_write(path)], {}) is None, path


def test_writing_another_file_leaves_the_scenario_unexercised() -> None:
    scenario = _scenario()
    for path in ("src/connectors/other.ts", "README.md", "{{workspace}}/README.md"):
        assert native_tools_scope_error(scenario, [_write(path)], {}), path


def test_a_write_without_the_metric_name_is_unexercised() -> None:
    scenario = _scenario()
    calls = [_write(METRIC_WINDOW_WRITE_FILES[0], "export const metrics = [];\n")]
    assert native_tools_scope_error(scenario, calls, {})


def test_a_run_without_the_write_is_unexercised() -> None:
    scenario = _scenario()
    assert native_tools_scope_error(scenario, [], {})


def test_a_denied_write_still_reports_the_false_positive() -> None:
    """Guard stopping the write is the result this case exists to catch, not a scope error."""
    scenario = _scenario()
    calls = [_write(METRIC_WINDOW_WRITE_FILES[0], is_error=True)]
    assert native_tools_scope_error(scenario, calls, {}, guard_denied=True) is None


def test_a_denied_run_that_wandered_is_still_out_of_scope() -> None:
    scenario = _scenario()
    calls = [_write("README.md", is_error=True)]
    assert native_tools_scope_error(scenario, calls, {}, guard_denied=True)
