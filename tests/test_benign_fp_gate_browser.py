"""Closed lists for the browser rows of the benign false-positive gate."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from ci.gauntlet.browser_driver_server import START_PAGE_FILE
from ci.gauntlet.browser_fixtures import PAGE_NAMES, install_server, recorded_tools
from tests.benign_fp_gate_browser import (
    BROWSER_STATES,
    PENDING_SAME_CALL,
    WIRED_STATES,
    browser_server_command,
    start_page,
    unwired_state,
)
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
    for state in WIRED_STATES:
        assert unwired_state(state) is None
    for state in (state for state in BROWSER_STATES if state not in WIRED_STATES):
        reason = unwired_state(state)
        assert reason is not None and state in reason
    case = McpCase("browser-row", "playwright", "browser_snapshot", {}, "setup", "site-grant")
    assert mcp_failure(case, {"unwired_state": unwired_state("site-grant")}, [], "") == unwired_state("site-grant")


def _block_row(dedupe_count: int) -> dict[str, object]:
    return {"queue_group_id": "group", "allow_scopes": ["once", "always"], "dedupe_count": dedupe_count}


@pytest.mark.parametrize(
    ("dedupe_counts", "attached"),
    [((2,), True), ((3,), True), ((1,), False), ((1, 1), False), ((), False)],
)
def test_a_retry_while_pending_must_attach_to_the_first_row(dedupe_counts: tuple[int, ...], attached: bool) -> None:
    case = McpCase("browser-row", "playwright", "browser_click", {}, "block", PENDING_SAME_CALL, "docs-article")
    response = {"error": {"data": {"transportOutcome": "not-forwarded", "guardPolicyAction": "block"}}}
    failure = mcp_failure(case, response, [_block_row(count) for count in dedupe_counts], "")
    assert (failure is None) is attached, failure


def test_the_start_page_never_changes_the_configured_launch(tmp_path: Path) -> None:
    assert set(PAGE_NAMES) >= {"docs-article", "local-dev"}
    launch = browser_server_command(tmp_path, "playwright")
    assert server_command(tmp_path, "playwright") == launch
    assert launch[-1] == "playwright"
    marker = Path(launch[-2]).with_name(START_PAGE_FILE)
    with start_page(tmp_path, "docs-article"):
        assert marker.read_text(encoding="utf-8") == "docs-article"
        assert server_command(tmp_path, "playwright") == launch
    assert not marker.exists()


def _snapshot(launch: list[str]) -> str:
    request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "browser_snapshot"}}
    done = subprocess.run(launch, input=json.dumps(request) + "\n", capture_output=True, text=True, timeout=30)
    assert done.returncode == 0, done.stderr
    return done.stdout


def test_the_driver_starts_on_the_page_the_marker_names(tmp_path: Path) -> None:
    install_server(tmp_path)
    launch = browser_server_command(tmp_path, "playwright")
    with start_page(tmp_path, "docs-article"):
        paged = _snapshot(launch)
    plain = _snapshot(launch)
    assert "Page title:" in paged
    assert "(empty page)" in plain
