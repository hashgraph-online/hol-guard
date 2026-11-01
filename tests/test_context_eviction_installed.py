"""Real selection/source/graph retirement and an actual configured idle wait."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_context_assistance import ContextAssistanceError, control, workspace
from codex_plugin_scanner.guard.native_resident_client import close_native_resident_clients, close_native_residents
from scripts.cigar_benchmark_processes import ProcessSampler
from tests.context_persistence_installed_support import operator


@pytest.mark.integration
@pytest.mark.installed
@pytest.mark.skipif(
    sys.platform != "darwin"
    or os.environ.get("HOL_GUARD_TEST_USE_INSTALLED") != "1"
    or not os.environ.get("GUARD_CIGAR_TEST_SELECTION")
    or not os.environ.get("GUARD_CIGAR_TEST_APPROVAL"),
    reason="requires the approved installed macOS/CIGAR candidate and a real 30-second idle wait",
)
@pytest.mark.parametrize("shared", [False, True], ids=["private-graph", "shared-broker"])
def test_installed_retention_withdrawal_graph_slot_reuse_and_idle_retirement(
    native_hook_force: Path, tmp_path: Path, shared: bool
) -> None:
    root = tmp_path.resolve()
    guard, alpha, bravo = root / "guard", root / "alpha", root / "bravo"
    for directory in (guard, alpha, bravo):
        directory.mkdir(mode=0o700)
    terms = ["atlas", "beryl", "cobalt", "dynamo", "ember", "fuchsia", "garnet", "helium", "indigo"]
    (alpha / "README.md").write_text("ALPHA_REVIEW_MARKER: " + " ".join(terms) + " require native deployment review.\n")
    (bravo / "README.md").write_text("BRAVO_REVIEW_MARKER: release evidence requires native deployment review.\n")
    selection = json.loads(Path(os.environ["GUARD_CIGAR_TEST_SELECTION"]).read_text())
    report = {"schema": "guard-cigar-eviction-installed.v1", "shared_broker": shared, "completed": False}

    def ask(action, scope=None, **fields):
        kind = (
            "workspace_grant"
            if action == "grant"
            else ("workspace_access" if action in {"withdraw", "revoke"} else "workspace")
        )
        payload = {"action": action, **fields}
        if scope is not None:
            payload["scope_id"] = scope
        return workspace(kind, guard_home=guard, payload=payload)["result"]

    def grant(path):
        return ask("grant", workspace=str(path), app="dashboard", sources=["README.md"])

    def refused(code, action, scope=None, **fields):
        with pytest.raises(ContextAssistanceError) as error:
            ask(action, scope, **fields)
        assert error.value.code == "native_context_assistance_" + code

    def activate():
        control("activate", guard_home=guard)
        deadline = time.monotonic() + 90
        while True:
            state = control("status", guard_home=guard)
            if state["job"] is None:
                assert state["effective_enabled"] and state["runtime"]["compile_verified"]
                assert state["runtime"]["interpreter"]["version"][:2] == [3, 14]
                assert not state["execution_ready"]
                return
            assert time.monotonic() < deadline, "installed idle fixture activation timed out"
            time.sleep(0.05)

    with ProcessSampler(Path(selection["python"])) as sampler:
        before, baseline = sampler.sample_with_identities()
        report["before"] = before
        try:
            enrolled = operator(
                native_hook_force,
                "context-assistance-enroll-local",
                {
                    "schema": "guard-cigar-enroll-local.v1",
                    "guard_home": str(guard),
                    "runtime_id": "eviction-candidate",
                    "local_candidate_approved": True,
                    "source_revision": "b47380e5a5cbeaaad5a61cab3372e9e67368732f",
                    "selection": selection,
                    "approval": json.loads(Path(os.environ["GUARD_CIGAR_TEST_APPROVAL"]).read_text()),
                },
            )
            assert enrolled["ok"] and not enrolled["installation"]["activation_granted"]
            updated = operator(
                native_hook_force,
                "guard-config-update",
                {
                    "schema": "guard-config-update.v1",
                    "guard_home": str(guard),
                    "kind": "settings",
                    "value_text": json.dumps(
                        {
                            "context_assistance": {
                                "enabled": True,
                                "runtime_id": "eviction-candidate",
                                "features": {
                                    "agent_context": shared,
                                    "shared_agents": shared,
                                    "execution_context": False,
                                },
                                "sources": {"workspace_documents": True, "source_set_id": "eviction-selected-files"},
                                "limits": {"max_active_workspaces": 1, "idle_shutdown_seconds": 30},
                                "storage": {"mode": "memory"},
                            }
                        }
                    ),
                },
            )
            assert updated["ok"]
            activate()
            admitted = grant(alpha)
            first_scope = admitted["scope_id"]
            assert admitted["sharing"]["mode"] == ("shared_broker" if shared else "private_graph")
            first = ask("compile", first_scope, query=terms[0])
            assert "ALPHA_REVIEW_MARKER" in first["brief"]["rendered"]
            first_snapshot = first["brief"]["snapshot_id"]
            refused("context_resource_limit", "grant", workspace=str(bravo), app="dashboard", sources=["README.md"])
            assert ask("explain", first_scope, snapshot_id=first_snapshot)["current"]
            snapshots = {first_snapshot}
            counts = [first["scope"]["retained_contexts"]]
            for count in range(2, 10):
                selected = ask("compile", first_scope, query=" ".join(terms[:count]))
                assert selected["current"] and selected["brief"]["graph_revision"] == first["brief"]["graph_revision"]
                snapshots.add(selected["brief"]["snapshot_id"])
                counts.append(selected["scope"]["retained_contexts"])
            assert len(snapshots) == 9, (
                "distinct public query statistics must exercise actual retained-selection pressure"
            )
            assert counts == [1, 2, 3, 4, 5, 6, 7, 8, 1]
            refused("context_stale", "explain", first_scope, snapshot_id=first_snapshot)
            assert ask("explain", first_scope, snapshot_id=selected["brief"]["snapshot_id"])["current"]
            report.update(unique_snapshots=len(snapshots), retained_context_counts=counts, old_selection_evicted=True)

            withdrawn = ask("withdraw", first_scope, source_id=admitted["sources"][0]["source_id"])
            assert withdrawn["sources"] == [] and withdrawn["retained_contexts"] == 0
            refused("context_stale", "explain", first_scope, snapshot_id=selected["brief"]["snapshot_id"])
            after_withdrawal = ask("compile", first_scope, query="ALPHA_REVIEW_MARKER")
            assert "ALPHA_REVIEW_MARKER" not in after_withdrawal["brief"]["rendered"]
            ask("revoke", first_scope)
            refused("context_scope_denied", "compile", first_scope, query="atlas")
            second_scope = grant(bravo)["scope_id"]
            assert second_scope != first_scope
            last_active_at = time.monotonic()
            current = ask("compile", second_scope, query="BRAVO_REVIEW_MARKER native deployment review")
            assert "BRAVO_REVIEW_MARKER" in current["brief"]["rendered"]
            assert "ALPHA_REVIEW_MARKER" not in current["brief"]["rendered"]
            report.update(source_withdrawn=True, graph_slot_reused=True, active=sampler.sample())
            # Status observes availability only. It must not renew an idle
            # graph or silently recreate consent after optional shutdown.
            deadline = last_active_at + 45
            while True:
                state = control("status", guard_home=guard)
                if not state["effective_enabled"] and state["runtime"] is None:
                    break
                assert time.monotonic() < deadline, "configured idle retirement did not occur"
                time.sleep(0.25)
            elapsed = time.monotonic() - last_active_at
            assert elapsed >= 30
            assert state["requested_enabled"] and state["diagnostic"] == "runtime_idle"
            assert state["job"] is None and not state["execution_ready"]
            report["idle_retirement_seconds"] = round(elapsed, 3)
            deadline = time.monotonic() + 5
            while True:
                retired = sampler.sample()
                if not any(retired["counts"].get(kind, 0) for kind in ("sdk_worker", "python_bridge")):
                    break
                assert time.monotonic() < deadline, "idle retirement left an optional worker alive"
                time.sleep(0.05)
            report["retired"] = retired
            refused("runtime_not_verified", "compile", second_scope, query="BRAVO_REVIEW_MARKER")
            refused("runtime_not_verified", "explain", second_scope, snapshot_id=current["brief"]["snapshot_id"])

            activate()
            assert ask("list")["scopes"] == [] and ask("list_agents")["agent_sessions"] == []
            refused("context_scope_denied", "compile", second_scope, query="BRAVO_REVIEW_MARKER")
            fresh_scope = grant(bravo)["scope_id"]
            assert fresh_scope != second_scope
            refused("context_stale", "explain", fresh_scope, snapshot_id=current["brief"]["snapshot_id"])
            fresh = ask("compile", fresh_scope, query="BRAVO_REVIEW_MARKER")
            assert "BRAVO_REVIEW_MARKER" in fresh["brief"]["rendered"]
            report["fresh_authority_required"] = True
            report["completed"] = True
        finally:
            try:
                control("stop", guard_home=guard)
                assert close_native_residents(guard)
                assert close_native_resident_clients(guard, deadline_monotonic=time.monotonic() + 10)
                deadline = time.monotonic() + 5
                after, remaining = sampler.sample_with_identities()
                while remaining.keys() - baseline.keys() and time.monotonic() < deadline:
                    time.sleep(0.05)
                    after, remaining = sampler.sample_with_identities()
                report.update(after=after, new_processes_remaining=len(remaining.keys() - baseline.keys()))
                report["resources"] = sampler.summary()
                assert report["new_processes_remaining"] == 0
                assert report["resources"]["sampling_errors"] == 0
                assert report["resources"]["maximum_counts"].get("sdk_worker", 0) >= 1
                assert report["resources"]["maximum_counts"].get("python_bridge", 0) >= 1
            finally:
                with (root / "lifecycle-report.json").open("x") as output:
                    json.dump(report, output, indent=2)
                    output.write("\n")
