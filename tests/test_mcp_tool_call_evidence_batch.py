"""MCP tool-call evidence is one resident store transaction, not three."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.mcp_tool_calls import allow_tool_call, block_tool_call
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.store import GuardStore


def _artifact() -> GuardArtifact:
    return GuardArtifact(
        artifact_id="codex:runtime:mcp:lean-ctx:ctx_read",
        name="lean-ctx:ctx_read",
        harness="codex",
        artifact_type="tool_call",
        source_scope="mcp",
        config_path="/tmp/config.json",
        command="ctx_read",
        args=("--fast",),
        transport="stdio",
        metadata={"server_name": "lean-ctx", "mcpSkillFirewall": {}},
    )


def _operations(log_path: Path) -> list[str]:
    return log_path.read_text().splitlines() if log_path.is_file() else []


def _count(store: GuardStore, table: str, where: str = "1=1") -> int:
    with sqlite3.connect(store.path) as connection:
        return connection.execute(f"select count(*) from {table} where {where}").fetchone()[0]


@pytest.mark.parametrize("blocked", [False, True])
def test_tool_call_evidence_is_one_resident_store_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, blocked: bool
) -> None:
    store = GuardStore(tmp_path / "guard")
    store.list_receipts(limit=1)  # warm the resident so only the call under test is logged
    log_path = tmp_path / "resident-requests.log"
    monkeypatch.setenv("HOL_GUARD_RESIDENT_REQUEST_LOG", os.fspath(log_path))
    common = {
        "store": store,
        "artifact": _artifact(),
        "artifact_hash": "sha256:abc",
        "decision_source": "policy-block" if blocked else "policy-allow",
        "now": "2026-04-02T12:30:00.123456+00:00",
        "signals": ("signal-a",),
    }
    if blocked:
        block_tool_call(**common)
        event_name = "runtime_tool_call_blocked"
    else:
        allow_tool_call(**common, remember=False)
        event_name = "runtime_tool_call_allowed"

    # Display-evidence ops are separate; the three durable writes must share one store call.
    assert _operations(log_path).count("guard_store") == 1
    assert _count(store, "artifact_inventory", "artifact_id = 'codex:runtime:mcp:lean-ctx:ctx_read'") == 1
    assert _count(store, "runtime_receipts") == 1
    assert _count(store, "guard_events", f"event_name = '{event_name}'") == 1
