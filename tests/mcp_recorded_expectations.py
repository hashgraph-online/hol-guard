"""Recorded, language-neutral expectations for the contributed MCP decision.

The expectations live in a JSON fixture shared with the Rust resident's tests, so
no Python algorithm stands in for the decision. Tests compare the resident's
answers with these recorded rows.
"""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from typing import Any

FIXTURE = Path(__file__).resolve().parents[1] / "rust/crates/guard-command/testdata/contributed-mcp-matching-v1.json"


@cache
def recorded() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def expected_decision(state: str, lockdown: bool, action: str) -> tuple[str, str, str] | None:
    """The recorded ``(action, source, reason)`` for a tool state, or ``None``."""
    fixture = recorded()
    rows = [
        row
        for row in fixture["decision_table"]
        if row["state"] == state and row["lockdown"] is lockdown and row["action"] == action
    ]
    assert len(rows) == 1, (state, lockdown, action)
    decided = rows[0]["expected"]
    if decided is None:
        return None
    return decided, fixture["source"], fixture["reasons"][decided]


def instapods_matches(artifact: Any) -> bool:
    """Whether the resident matches the bundled hosted instapods contribution.

    ``delete_pod`` carries the review default, so a match strengthens an allow to
    review while a non-match decides nothing.
    """
    from codex_plugin_scanner.guard.runtime import mcp_server_grants
    from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlLayerKind, ControlState

    from .test_guard_mcp_server_grants import _AuthorityStore, _layer

    store = _AuthorityStore((_layer(ControlLayerKind.LOCAL_ADMIN, "command.mcp-instapods", ControlState.ENABLED),))
    decision = mcp_server_grants.apply_contributed_mcp_decision(store, artifact, "allow")
    if decision is None:
        return False
    assert decision[0:2] == ("review", "catalog-mcp-extension")
    return True
