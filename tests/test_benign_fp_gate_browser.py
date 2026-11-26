"""Closed lists for the browser rows of the benign false-positive gate."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ci.gauntlet.browser_fixtures import PAGE_NAMES, recorded_tools
from tests.benign_fp_gate_browser import BROWSER_STATES, browser_server_command, unwired_state
from tests.benign_fp_gate_mcp import McpCase, mcp_cases, mcp_failure, server_command

_DOCUMENT = json.loads((Path(__file__).parent / "fixtures" / "benign_false_positive_gate.json").read_text())


def _row(**overrides: object) -> dict[str, object]:
    return {
        "id": "browser-row",
        "server": "playwright",
        "tool": "browser_snapshot",
        "arguments": {},
        "expect": "setup",
        **overrides,
    }


def test_every_recorded_reference_tool_has_a_baseline_row() -> None:
    covered = {case.tool for case in mcp_cases(_DOCUMENT) if case.server == "playwright"}
    assert covered == {tool["name"] for tool in recorded_tools()}


def test_rows_default_to_no_seeded_state() -> None:
    (case,) = mcp_cases({"mcp_cases": [_row()]})
    assert (case.state, case.page) == ("none", None)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"state": "site-granted"}, "unknown state preset"),
        ({"page": "bank-login"}, "unknown page"),
        ({"server": "echo-mcp", "page": "docs-article"}, "browser driver rows only"),
        ({"server": "echo-mcp", "state": "site-grant"}, "browser driver rows only"),
    ],
)
def test_unknown_presets_and_pages_are_rejected(overrides: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        mcp_cases({"mcp_cases": [_row(**overrides)]})


def test_a_known_preset_that_is_not_wired_fails_its_row() -> None:
    assert unwired_state("none") is None
    for state in BROWSER_STATES[1:]:
        reason = unwired_state(state)
        assert reason is not None and state in reason
    case = McpCase("browser-row", "playwright", "browser_snapshot", {}, "setup", "site-grant")
    assert mcp_failure(case, {"unwired_state": unwired_state("site-grant")}, [], "") == unwired_state("site-grant")


def test_the_start_page_reaches_the_driver_argv(tmp_path: Path) -> None:
    assert set(PAGE_NAMES) >= {"docs-article", "local-dev"}
    plain = browser_server_command(tmp_path, "playwright", None)
    paged = server_command(tmp_path, "playwright", "docs-article")
    assert paged == [*plain, "docs-article"]
    assert plain[-1] == "playwright"
