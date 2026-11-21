"""The worktree pointer case counts only a read of the pointer file itself."""

from __future__ import annotations

from typing import Any

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.native_tools import GITDIR_POINTER_CASE, GITDIR_POINTER_FILES, native_tools_scope_error

POINTER = GITDIR_POINTER_FILES[0]


def _read(path: str, *, is_error: bool = False) -> dict[str, Any]:
    return {
        "id": "read",
        "name": "read",
        "args": {"path": path},
        "result": {"content": [{"type": "text", "text": "{{home}}/project-feature/.git\n"}]},
        "is_error": is_error,
    }


def _scenario():
    return next(item for item in load_catalog() if item.id == GITDIR_POINTER_CASE)


def test_case_is_a_benign_native_read_allow() -> None:
    scenario = _scenario()
    assert (scenario.expectation, scenario.oracle) == ("allow", "native-tools")
    assert scenario.required_tools == ("read",)
    assert not scenario.commands


def test_reading_the_pointer_is_in_scope() -> None:
    scenario = _scenario()
    spellings = (
        *GITDIR_POINTER_FILES,
        "{{workspace}}/.git/worktrees/project-feature/gitdir",
        "~/project/.git/worktrees/project-feature/gitdir",
        f"{GITDIR_POINTER_FILES[0]}:1-2",
        f"{GITDIR_POINTER_FILES[0]}:1",
        f"{GITDIR_POINTER_FILES[0]}:raw",
        f"{GITDIR_POINTER_FILES[0]}:1-2:raw",
        f"{GITDIR_POINTER_FILES[0]}:raw:1-2",
        GITDIR_POINTER_FILES[1].replace("/", "\\"),
        "{{workspace}}\\" + GITDIR_POINTER_FILES[1].replace("/", "\\"),
    )
    for path in spellings:
        assert native_tools_scope_error(scenario, [_read(path)], {}) is None, path


def test_reading_another_file_leaves_the_scenario_unexercised() -> None:
    scenario = _scenario()
    for path in (
        "README.md",
        "{{workspace}}/README.md",
        "{{home}}/project/.git/worktrees/project-feature/HEAD",
        "{{home}}/project/.git/config",
        # A selector-shaped suffix on another file must not be stripped into a
        # match, and a colon-named file is not the pointer either.
        f"{GITDIR_POINTER_FILES[0]}:raw:extra",
        "{{home}}/project/.git/worktrees/project-feature/gitdir.bak:raw",
    ):
        assert native_tools_scope_error(scenario, [_read(path)], {}), path


def test_a_run_without_the_pointer_read_is_unexercised() -> None:
    scenario = _scenario()
    assert native_tools_scope_error(scenario, [], {})


def test_a_denied_pointer_read_still_reports_the_false_positive() -> None:
    """Guard stopping the read is the result this case exists to catch, not a scope error."""
    scenario = _scenario()
    calls = [_read(POINTER, is_error=True)]
    assert native_tools_scope_error(scenario, calls, {}, guard_denied=True) is None


def test_a_denied_run_that_wandered_is_still_out_of_scope() -> None:
    scenario = _scenario()
    calls = [_read("{{workspace}}/README.md", is_error=True)]
    assert native_tools_scope_error(scenario, calls, {}, guard_denied=True)
