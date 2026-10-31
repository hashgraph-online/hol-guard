"""Guard the recorded MCP launch decisions the Rust twin replays.

``rust/crates/guard-command/tests/guard_mcp_launch_tokens_parity.rs`` reads the
same fixture. ``mcp_launch_tokens`` is the gate that decides whether pasted text
is one safe invocation Guard may launch as an MCP server, and the CLI route and
the resident route reach it through two separate implementations of the same
predicate. A change to either that this file does not also record is caught here
first.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.runtime.local_mcp_probe import mcp_launch_tokens

FIXTURE = Path(__file__).resolve().parents[1] / "tests/fixtures/mcp-launch-tokens.v1.json"


def _cases() -> list[dict[str, Any]]:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert document["schema"] == "guard-mcp-launch-tokens-parity.v1"
    return document["cases"]


@pytest.mark.parametrize("case", _cases(), ids=lambda case: case["name"])
def test_recorded_launch_decision_still_holds(case: dict[str, Any], tmp_path: Path) -> None:
    # One empty directory for both roles, so no case can depend on what is on disk.
    root = tmp_path / "empty"
    root.mkdir()
    tokens = mcp_launch_tokens(case["command_text"], cwd=root, home_dir=root)

    expected = case["tokens"]
    assert (list(tokens) if tokens is not None else None) == expected


def test_the_fixture_keeps_recording_text_that_launches() -> None:
    accepted = [case["name"] for case in _cases() if case["tokens"] is not None]
    assert len(accepted) >= 8, accepted


def test_the_fixture_keeps_recording_text_that_is_refused() -> None:
    refused = [case["name"] for case in _cases() if case["tokens"] is None]
    assert len(refused) >= 8, refused
