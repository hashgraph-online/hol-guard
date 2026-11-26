"""R-QUIET-1 (BP-T169): a retried browser call attaches to its pending row instead of adding a card.

A driver retries a call the person has not answered yet. The queue write finds the pending row for
the same action and raises its ``dedupe_count``; it never adds a second card. A call on another page
is another action and gets its own row.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.approvals import queue_blocked_approvals
from codex_plugin_scanner.guard.mcp_tool_calls import build_tool_call_artifact
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity
from codex_plugin_scanner.guard.store import GuardStore

SERVER = "playwright"


def _artifact() -> GuardArtifact:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="npx",
        args=("-y", "@example-org/browser-driver"),
        transport="stdio",
    )
    return build_tool_call_artifact(
        harness="codex",
        server_name=SERVER,
        tool_name="browser_click",
        source_scope="project",
        config_path=".mcp.json",
        transport="stdio",
        server_identity=identity,
        tool_schema=None,
    )


def _queue(store: GuardStore, artifact: GuardArtifact, origin: str, now: str) -> list[dict[str, Any]]:
    identity = artifact.metadata["mcp_server_identity"]
    assert isinstance(identity, dict)
    domain = origin.removeprefix("https://")
    browser_intent = {
        "version": 1,
        "intent": "browser.interact",
        "operation": "browser_click",
        "target_origin": origin,
        "target_domain": domain,
        "mcp_server_name": SERVER,
        "mcp_server_identity_hash": identity["identity_hash"],
        "risk_categories": ["browser_interaction"],
    }
    return queue_blocked_approvals(
        detection=HarnessDetection(
            harness="codex",
            installed=True,
            command_available=True,
            config_paths=(".mcp.json",),
            artifacts=(artifact,),
        ),
        evaluation={
            "artifacts": [
                {
                    "artifact_id": artifact.artifact_id,
                    "artifact_hash": f"exact-hash-{domain}",
                    "artifact_type": "tool_call",
                    "source_scope": "project",
                    "config_path": ".mcp.json",
                    "policy_action": "review",
                    "changed_fields": ["runtime_browser_tool_call"],
                    "launch_target": f"{SERVER} browser_click {domain}",
                    "browser_intent": browser_intent,
                }
            ]
        },
        store=store,
        approval_center_url="http://127.0.0.1:5474",
        now=now,
    )


def _pending(store: GuardStore) -> list[dict[str, Any]]:
    return store.list_approval_requests(status="pending", limit=50)


def test_a_retried_browser_call_attaches_to_its_pending_row(tmp_path: Path, native_context_digest: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    artifact = _artifact()

    first = _queue(store, artifact, "https://shop.example.test", "2026-11-26T12:00:00+00:00")
    retry = _queue(store, artifact, "https://shop.example.test", "2026-11-26T12:00:05+00:00")

    rows = _pending(store)
    assert len(rows) == 1, rows
    assert first[0]["request_id"] == retry[0]["request_id"] == rows[0]["request_id"]
    assert rows[0]["dedupe_count"] == 2
    assert rows[0]["last_seen_at"] == "2026-11-26T12:00:05+00:00"


def test_the_same_click_on_another_site_is_its_own_row(tmp_path: Path, native_context_digest: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    artifact = _artifact()

    first = _queue(store, artifact, "https://shop.example.test", "2026-11-26T12:00:00+00:00")
    other = _queue(store, artifact, "https://docs.example.test", "2026-11-26T12:00:05+00:00")

    rows = _pending(store)
    assert len(rows) == 2, rows
    assert first[0]["request_id"] != other[0]["request_id"]
    assert all(row["dedupe_count"] == 1 for row in rows)
