"""Actual installed daemon/resident restart with independent MCP consumers.

Operator grants/admission use the trusted native control surface. Browser proof
and password handling are separately qualified by the installed browser flow.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_context_assistance import workspace
from tests.context_persistence_installed_support import Host, agent, call, operator, stop_resident


@pytest.mark.integration
@pytest.mark.installed
@pytest.mark.skipif(
    not os.environ.get("GUARD_CIGAR_TEST_SELECTION")
    or not os.environ.get("GUARD_CIGAR_TEST_APPROVAL")
    or os.environ.get("HOL_GUARD_TEST_USE_INSTALLED") != "1",
    reason="requires the explicitly approved installed CIGAR 0.14.1 candidate",
)
def test_shared_saved_evidence_requires_fresh_authority_after_daemon_and_resident_restart(
    native_hook_force: Path, tmp_path: Path
) -> None:
    root = tmp_path.resolve()
    guard_path, project = root / "guard", root / "workspace"
    for directory in (guard_path, project, root / "profile"):
        directory.mkdir(mode=0o700)
    (root / "fixture-owned").write_text("guard-cigar-restart-fixture.v1\n")
    (project / "README.md").write_text("Shared saved deployment evidence requires a reviewed release checklist.\n")

    def host(action: str, scope_id: str | None = None, **fields) -> dict:
        payload = {"action": action, **fields}
        if scope_id is not None:
            payload["scope_id"] = scope_id
        kind = "workspace_grant" if action in {"grant", "authorize_agent", "admit_proposal"} else "workspace"
        return workspace(kind, guard_home=guard_path, payload=payload)["result"]

    def grant() -> str:
        return host(
            "grant",
            workspace=str(project),
            app="codex",
            sources=["README.md"],
            shared_notes={"read": True, "propose": True},
        )["scope_id"]

    async def pair(client, scope_id: str) -> str:
        pending = await call(client, "get_context_status")
        assert pending["ok"] and pending["data"]["phase"] == "pending"
        assert "credential" not in json.dumps(pending)
        session_id = pending["data"]["session_id"]
        host("authorize_agent", scope_id, session_id=session_id)
        ready = await call(client, "get_context_status")
        assert ready["data"]["phase"] == "authorized"
        assert ready["data"]["harness_route_qualification"] == "not_established"
        return session_id

    async def scenario() -> None:
        first_host = Host(root, 1)
        second_host = None
        third_host = None
        try:
            enrolled = operator(
                native_hook_force,
                "context-assistance-enroll-local",
                {
                    "schema": "guard-cigar-enroll-local.v1",
                    "guard_home": str(guard_path),
                    "runtime_id": "restart-candidate",
                    "local_candidate_approved": True,
                    "source_revision": "b47380e5a5cbeaaad5a61cab3372e9e67368732f",
                    "selection": json.loads(Path(os.environ["GUARD_CIGAR_TEST_SELECTION"]).read_text()),
                    "approval": json.loads(Path(os.environ["GUARD_CIGAR_TEST_APPROVAL"]).read_text()),
                },
            )
            assert enrolled["ok"] and not enrolled["installation"]["activation_granted"]
            updated = operator(
                native_hook_force,
                "guard-config-update",
                {
                    "schema": "guard-config-update.v1",
                    "guard_home": str(guard_path),
                    "kind": "settings",
                    "value_text": json.dumps(
                        {
                            "context_assistance": {
                                "enabled": True,
                                "runtime_id": "restart-candidate",
                                "features": {"agent_context": True, "shared_agents": True},
                                "sources": {"workspace_documents": True, "source_set_id": "restart-selection"},
                                "storage": {"mode": "sqlite", "retention_hours": 1},
                            }
                        }
                    ),
                },
            )
            assert updated["ok"]
            await first_host.activate()
            old_scope = grant()
            note = "Reviewed saved release checklist requires explicit deployment review."
            hidden_note = "UNADMITTED_RESTART_PROPOSAL must remain quarantined."
            async with agent(guard_path) as a, agent(guard_path) as b:
                old_sessions = {await pair(a, old_scope), await pair(b, old_scope)}
                context = await call(a, "get_guard_context", {"query": "deployment release checklist"})
                assert context["ok"]
                old_snapshot = context["data"]["result"]["brief"]["snapshot_id"]
                proposal = await call(
                    a,
                    "propose_guard_context_note",
                    {"snapshot_id": old_snapshot, "request_key": "restart:reviewed", "text": note},
                )
                assert proposal["ok"] and proposal["data"]["outcome"]["status"] == "pending"
                quarantined = await call(b, "get_guard_context", {"query": "release checklist"})
                assert note not in quarantined["data"]["result"]["brief"]["rendered"]
                host("admit_proposal", old_scope, proposal_id=proposal["data"]["proposal_id"])
                shared = await call(
                    b, "get_guard_context", {"query": "reviewed saved release checklist explicit deployment review"}
                )
                assert shared["ok"] and note in shared["data"]["result"]["brief"]["rendered"]
                pending = await call(
                    b,
                    "propose_guard_context_note",
                    {
                        "snapshot_id": shared["data"]["result"]["brief"]["snapshot_id"],
                        "request_key": "restart:unadmitted",
                        "text": hidden_note,
                    },
                )
                assert pending["ok"] and pending["data"]["outcome"]["status"] == "pending"

                # Shut down the actual Python host, then contain its actual Rust
                # resident while old independent MCP clients remain connected.
                first_host.stop()
                stop_resident(native_hook_force, guard_path)
                second_host = Host(root, 2)
                assert second_host.pid != first_host.pid
                code, state = second_host.request()
                assert code == 200 and state["requested_enabled"] is True
                assert state["effective_enabled"] is False and state["runtime"] is None and state["job"] is None
                assert not (await call(a, "get_guard_context", {"query": "release checklist"}))["ok"]
                await second_host.activate()
                assert host("list")["scopes"] == []
                assert host("list_agents")["agent_sessions"] == []
                for old in (a, b):
                    assert not (await call(old, "get_guard_context", {"query": "release checklist"}))["ok"]
                code, _ = second_host.request(
                    "/workspace", {"input": {"action": "compile", "scope_id": old_scope, "query": "release"}}
                )
                assert code == 403

            fresh_scope = grant()
            assert fresh_scope != old_scope
            assert host("proposals", fresh_scope)["proposals"] == []
            assert host("history", fresh_scope)["entries"] == []
            async with agent(guard_path) as c, agent(guard_path) as d:
                new_sessions = {await pair(c, fresh_scope), await pair(d, fresh_scope)}
                assert not old_sessions & new_sessions
                for client in (c, d):
                    restored = await call(
                        client,
                        "get_guard_context",
                        {"query": "reviewed saved release checklist explicit deployment review"},
                    )
                    assert restored["ok"]
                    brief = restored["data"]["result"]["brief"]
                    assert note in brief["rendered"] and hidden_note not in brief["rendered"]
                    assert len(brief["citations"]) >= 2
                    assert not (await call(client, "explain_guard_context", {"snapshot_id": old_snapshot}))["ok"]
                code, _ = second_host.request("/stop", {})
                assert code == 200
                for client in (c, d):
                    assert not (await call(client, "get_guard_context", {"query": "release"}))["ok"]

            second_host.stop()
            stop_resident(native_hook_force, guard_path)
            saved = list((guard_path / "context-assistance/saved-evidence").glob("*/state.json"))
            assert len(saved) == 1 and not saved[0].is_symlink()
            # Advance only this disposable record's age rather than waiting two
            # hours. Its saved expiry remains future, so the current one-hour
            # preference must drive native startup cleanup without a request.
            record = json.loads(saved[0].read_text())
            now = time.time_ns() // 1_000_000
            record.update(
                created_at_ms=now - 7_200_000, last_seen_ms=now - 7_200_000, expires_at_ms=now + 22 * 3_600_000
            )
            saved[0].write_text(json.dumps(record))
            third_host = Host(root, 3)
            deadline = time.monotonic() + 8
            while saved[0].exists():
                assert time.monotonic() < deadline, "headless daemon/resident startup did not enforce retention"
                await asyncio.sleep(0.05)
            cleared = workspace("workspace_access", guard_home=guard_path, payload={"action": "forget_saved"})["result"]
            assert cleared["saved_evidence"]["status"] == "empty"
            code, off = third_host.request()
            assert code == 200 and not off["requested_enabled"] and off["runtime"] is None
            assert off["job"] is None and off["last_check"] is None
        finally:
            if third_host is not None:
                third_host.stop()
            if second_host is not None:
                second_host.stop()
            first_host.stop()
            stop_resident(native_hook_force, guard_path)

    asyncio.run(asyncio.wait_for(scenario(), timeout=240))
