"""Optional actual-CIGAR setup for the pinned Pi/OMP SDK execution fixture."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from codex_plugin_scanner.guard.config import update_guard_settings
from codex_plugin_scanner.guard.store import GuardStore


def cli_bootstrap(repo: Path) -> str:
    root = repo / "src"
    if os.environ.get("HOL_GUARD_TEST_USE_INSTALLED") == "1":
        import codex_plugin_scanner

        root = Path(codex_plugin_scanner.__file__).resolve().parents[1]
        assert root != (repo / "src").resolve(), "installed SDK delivery must not import the checkout"
    return f"sys.path.insert(0, {str(root)!r})\n"


def prepare_store(guard: Path, duration: str, *, cigar_execution: bool, binary: Path, workspace: Path, app: str):
    settings: dict[str, object] = {"blocked_request_mode": "ask"}
    if duration == "quiet":
        settings.update(
            {
                "default_action": "allow",
                "subprocess_action": "allow",
                "risk_actions": {"network_egress": "allow", "persistence": "allow"},
            }
        )
    else:
        # Preserve deliberate Ask independently of temporary-directory policy.
        settings["subprocess_action"] = "require-reapproval"
    if cigar_execution:
        from tests.context_persistence_installed_support import operator

        enrolled = operator(
            binary,
            "context-assistance-enroll-local",
            {
                "schema": "guard-cigar-enroll-local.v1",
                "guard_home": str(guard),
                "runtime_id": "sdk-execution-candidate",
                "local_candidate_approved": True,
                "source_revision": "b47380e5a5cbeaaad5a61cab3372e9e67368732f",
                "selection": json.loads(Path(os.environ["GUARD_CIGAR_TEST_SELECTION"]).read_text()),
                "approval": json.loads(Path(os.environ["GUARD_CIGAR_TEST_APPROVAL"]).read_text()),
            },
        )
        assert enrolled["ok"] and not enrolled["installation"]["activation_granted"]
        settings["context_assistance"] = {
            "enabled": True,
            "runtime_id": "sdk-execution-candidate",
            "features": {"execution_context": True, "agent_context": False, "shared_agents": False},
        }
    update_guard_settings(guard, settings)
    store = GuardStore(guard)
    if cigar_execution:
        from codex_plugin_scanner.guard.native_context_assistance import control
        from codex_plugin_scanner.guard.native_context_assistance import workspace as request_workspace
        from codex_plugin_scanner.guard.native_resident_client import close_native_residents

        try:
            control("activate", guard_home=guard)
            deadline = time.monotonic() + 90
            while True:
                state = control("status", guard_home=guard)
                if state["job"] is None:
                    assert state["effective_enabled"] and state["execution_ready"], state
                    assert state["runtime"]["execution_handoff_verified"]
                    assert state["runtime"]["interpreter"]["version"][:2] == [3, 14]
                    assert state["preferences"]["storage"]["mode"] == "memory"
                    break
                assert time.monotonic() < deadline
                time.sleep(0.05)
            grant = request_workspace(
                "workspace_grant",
                guard_home=guard,
                payload={"action": "grant", "workspace": str(workspace), "app": app, "sources": []},
            )["result"]
            assert grant["scope_id"]
        except BaseException:
            assert close_native_residents(guard_home=guard)
            raise
    return store


def assert_context_execution(guard: Path) -> None:
    from codex_plugin_scanner.guard.native_context_assistance import control

    state = control("status", guard_home=guard)
    assert state["effective_enabled"] and state["execution_ready"], state
    completed = [item for item in state["execution_observations"] if item["phase"] == "completed"]
    assert completed and any(item["association_applied"] for item in completed), state["execution_observations"]
    for item in completed:
        assert item["native_dispatch_acknowledged"]
        assert not item["approval_grant"] and not item["send_boundary_atomicity"]
        assert not {"ticket", "submission_id", "intent_digest", "command", "environment", "workspace"} & item.keys()
