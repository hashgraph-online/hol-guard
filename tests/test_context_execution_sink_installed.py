"""Installed Python sink + authenticated resident + actual CIGAR executor flow.

Consent uses the normal native contract/resolution machinery in an isolated
fixture. This does not establish browser proof or actual external app delivery.
"""

from __future__ import annotations

import io
import json
import os
import sys
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_scope_support import request_scope_contract
from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.native_bash_protocol import runtime_status
from codex_plugin_scanner.guard.native_context_assistance import ContextAssistanceError, control, workspace
from codex_plugin_scanner.guard.native_resident_client import close_native_residents
from codex_plugin_scanner.guard.runtime.bound_bash_sink import run_bound_bash
from codex_plugin_scanner.guard.store import GuardStore
from tests.context_persistence_installed_support import operator


@pytest.mark.integration
@pytest.mark.installed
@pytest.mark.skipif(
    sys.platform != "darwin"
    or os.environ.get("HOL_GUARD_TEST_USE_INSTALLED") != "1"
    or not os.environ.get("GUARD_CIGAR_TEST_SELECTION")
    or not os.environ.get("GUARD_CIGAR_TEST_APPROVAL"),
    reason="requires the explicitly approved installed macOS/CIGAR 0.14.1 candidate",
)
@pytest.mark.parametrize("persistent", [False, True], ids=["allow-once", "always-allow"])
def test_installed_execution_context_preserves_consent_replay_restart_and_opt_out(
    native_context_digest: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    persistent: bool,
    *,
    lease_wait_seconds: int = 0,
    fault_kind: str | None = None,
    lose_completed_response: bool = False,
    lose_running_response: bool = False,
    effect_barrier=None,
    authority_loss=None,
) -> None:
    assert not (lease_wait_seconds and fault_kind)
    assert not (lose_completed_response and (lease_wait_seconds or fault_kind))
    assert not (lose_running_response and (lose_completed_response or lease_wait_seconds or fault_kind))
    assert not lose_running_response or effect_barrier is not None
    assert not authority_loss or (
        effect_barrier is not None
        and not any((lease_wait_seconds, fault_kind, lose_completed_response, lose_running_response))
    )
    del native_context_digest
    status = runtime_status()
    assert status.identity is not None
    binary = status.identity.path
    root = tmp_path.resolve()
    project, home, guard = root / "project", root / "profile", root / "guard"
    project.mkdir(mode=0o700)
    home.mkdir(mode=0o700)
    entry = project / "execution.sh"
    script = ': > "$HOME/execution-report.txt"\nprintf "installed-cigar-owner\\n" >> "$HOME/execution-report.txt"\n'
    if lose_running_response or authority_loss:
        script += (
            f'/usr/bin/curl -q -fsS --max-time 30 "{effect_barrier.endpoint}"\n'
            'printf "native-effect-completed\\n" >> "$HOME/execution-report.txt"\n'
        )
    entry.write_text(script)
    completed_report = "installed-cigar-owner\n" + (
        "native-effect-completed\n" if lose_running_response or authority_loss else ""
    )
    monkeypatch.chdir(project)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PATH", f"{project}:/usr/bin:/bin")
    store = GuardStore(guard, prime_policy_integrity=False)
    original_prepare = HookWorker.prepare_workspace_policy

    def checked_prepare(worker, *args, **kwargs):
        binding = original_prepare(worker, *args, **kwargs)
        assert binding is not None, worker.policy_snapshot_publisher.last_error
        return binding

    monkeypatch.setattr(HookWorker, "prepare_workspace_policy", checked_prepare)
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "bash",
        "tool_input": {"command": f"/bin/bash '{entry}'"},
        "cwd": str(project),
    }
    operation = "installed-cigar-execution-operation-0001"
    report = home / "execution-report.txt"

    def run(operation_id: str) -> tuple[int, str]:
        output, errors = io.StringIO(), io.StringIO()
        result = run_bound_bash(
            payload,
            store=store,
            workspace=project,
            harness="omp",
            operation_id=operation_id,
            output=output,
            errors=errors,
        )
        return result, errors.getvalue()

    def activate() -> None:
        control("activate", guard_home=guard)
        deadline = time.monotonic() + 90
        while True:
            observed = control("status", guard_home=guard)
            if observed["job"] is None:
                assert observed["effective_enabled"] and observed["execution_ready"], observed
                assert observed["runtime"]["execution_handoff_verified"]
                assert observed["runtime"]["interpreter"]["version"][:2] == [3, 14]
                assert not observed["preferences"]["features"]["agent_context"]
                assert not observed["preferences"]["features"]["shared_agents"]
                assert observed["preferences"]["storage"]["mode"] == "memory"
                return
            assert time.monotonic() < deadline, "installed execution qualification timed out"
            time.sleep(0.05)

    fault = None
    response_loss = None
    completed = False
    try:
        enrolled = operator(
            binary,
            "context-assistance-enroll-local",
            {
                "schema": "guard-cigar-enroll-local.v1",
                "guard_home": str(guard),
                "runtime_id": "installed-execution-candidate",
                "local_candidate_approved": True,
                "source_revision": "b47380e5a5cbeaaad5a61cab3372e9e67368732f",
                "selection": json.loads(Path(os.environ["GUARD_CIGAR_TEST_SELECTION"]).read_text()),
                "approval": json.loads(Path(os.environ["GUARD_CIGAR_TEST_APPROVAL"]).read_text()),
            },
        )
        assert enrolled["ok"] and not enrolled["installation"]["activation_granted"]
        updated = operator(
            binary,
            "guard-config-update",
            {
                "schema": "guard-config-update.v1",
                "guard_home": str(guard),
                "kind": "settings",
                "value_text": json.dumps(
                    {
                        "subprocess_action": "review",
                        "context_assistance": {
                            "enabled": True,
                            "runtime_id": "installed-execution-candidate",
                            "features": {"execution_context": True, "agent_context": False, "shared_agents": False},
                        },
                    }
                ),
            },
        )
        assert updated["ok"], updated
        activate()
        grant = workspace(
            "workspace_grant",
            guard_home=guard,
            payload={
                "action": "grant",
                "workspace": str(project),
                "app": "omp",
                "sources": [],
            },
        )["result"]
        result, error = run(operation)
        assert result == 125 and "native_bash_consent_required" in error
        assert not report.exists(), "SDK context cannot authorize the native effect"
        (queued,) = store.list_approval_requests()
        contract = request_scope_contract(queued, guard_home=guard)
        assert contract.can_run_once and contract.can_persist_exact_version
        apply_approval_resolution(
            store=store,
            request_id=queued["request_id"],
            action="allow",
            scope="artifact",
            workspace=str(project),
            reason="Disposable installed CIGAR consent fixture",
            persist_policy=persistent,
            scope_contract_version=queued["scope_contract_version"],
            scope_contract_digest=queued["scope_contract_digest"],
        )
        if authority_loss:
            authority_loss(
                payload=payload,
                guard_home=guard,
                project=project,
                operation=operation,
                report=report,
                barrier=effect_barrier,
                binary=binary,
                store=store,
                run=run,
                activate=activate,
                grant=grant,
                persistent=persistent,
            )
            completed = True
            return
        if fault_kind:
            from tests.context_process_fault import OwnedOptionalProcesses

            healthy = control("status", guard_home=guard)
            assert healthy["effective_enabled"] and healthy["execution_ready"]
            prior_references = {event["execution_reference"] for event in healthy["execution_observations"]}
            fault = OwnedOptionalProcesses.capture(
                binary,
                json.loads(Path(os.environ["GUARD_CIGAR_TEST_SELECTION"]).read_text()),
                json.loads(Path(os.environ["GUARD_CIGAR_TEST_APPROVAL"]).read_text()),
            )
            fault.metrics.update(approval="always" if persistent else "once", ready_before_fault=True)
            assert not report.exists()
            fault.interrupt(fault_kind)
        effect_started = time.monotonic()
        if lose_running_response:
            from tests.context_native_response_loss import lose_running_reply

            response_loss = lose_running_reply(
                payload,
                guard_home=guard,
                workspace=project,
                operation_id=operation,
                report=report,
                barrier=effect_barrier,
            )
            response_loss["approval"] = "always" if persistent else "once"
        elif lose_completed_response:
            from tests.context_native_response_loss import lose_completed_reply

            response_loss = lose_completed_reply(payload, guard_home=guard, workspace=project, operation_id=operation)
            response_loss["approval"] = "always" if persistent else "once"
        else:
            result, error = run(operation)
            assert result == 0, error
        effect_ms = round((time.monotonic() - effect_started) * 1000, 3)
        assert report.read_text() == "installed-cigar-owner\n"
        observed = control("status", guard_home=guard)
        events = observed["execution_observations"]
        if fault:
            fault.metrics["approved_effect_ms"] = effect_ms
            fault.metrics["approved_native_effect_completed"] = True
            # The original consent refusal can leave a historical prepared
            # observation. It is not an applied association or a dispatch.
            assert all(event["execution_reference"] in prior_references for event in events)
            assert all(event["phase"] == "not_dispatched" for event in events)
            assert all(
                not event["association_applied"] and not event["native_dispatch_acknowledged"] for event in events
            )
            fault.metrics["prior_non_dispatch_observations_before_retirement"] = len(events)
            deadline = time.monotonic() + 8
            while (
                observed["effective_enabled"] or observed["runtime"] is not None or observed["execution_observations"]
            ) and time.monotonic() < deadline:
                time.sleep(0.05)
                observed = control("status", guard_home=guard)
            assert observed["requested_enabled"] and not observed["effective_enabled"]
            assert not observed["execution_ready"] and observed["job"] is None
            assert observed["runtime"] is None
            assert observed["execution_observations"] == []
            fault.metrics["effect_start_to_optional_retirement_ms"] = round(
                (time.monotonic() - effect_started) * 1000, 3
            )
            with pytest.raises(ContextAssistanceError) as failed_runtime:
                workspace(
                    "workspace",
                    guard_home=guard,
                    payload={
                        "action": "compile",
                        "scope_id": grant["scope_id"],
                        "query": "native execution",
                    },
                )
            assert failed_runtime.value.code == "native_context_assistance_runtime_not_verified"
            fault.verify_containment()
        else:
            assert events and events[0]["phase"] == "completed", events
            assert events[0]["association_applied"] and events[0]["native_dispatch_acknowledged"]
            assert events[0]["scope_id"] == grant["scope_id"]
            assert not events[0]["approval_grant"] and not events[0]["send_boundary_atomicity"]
            for field in ("ticket", "submission_id", "intent_digest", "command", "environment", "workspace"):
                assert field not in events[0]
        if lease_wait_seconds:
            assert persistent and lease_wait_seconds == 310
            first_reference = events[0]["execution_reference"]
            generation = observed["generation"]
            started = time.monotonic()
            deadline = started + lease_wait_seconds
            while time.monotonic() < deadline:
                # Status is observation only: no operator compile, fresh
                # activation, scope grant or native execution renews the lane.
                state = control("status", guard_home=guard)
                assert state["effective_enabled"] and state["generation"] == generation
                assert state["job"] is None
                print(json.dumps({"late_execution_wait_seconds": round(time.monotonic() - started, 2)}), flush=True)
                time.sleep(min(30, max(0, deadline - time.monotonic())))
            assert time.monotonic() - started >= 310
            report.write_text("late execution must replace this sentinel")
            result, error = run("installed-cigar-execution-after-initial-lease")
            assert result == 0, error
            assert report.read_text() == "installed-cigar-owner\n"
            late = control("status", guard_home=guard)
            assert late["execution_ready"] and late["generation"] == generation
            event = late["execution_observations"][0]
            assert event["phase"] == "completed" and event["association_applied"]
            assert event["native_dispatch_acknowledged"] and event["scope_id"] == grant["scope_id"]
            assert event["execution_reference"] != first_reference
            assert not event["approval_grant"] and not event["send_boundary_atomicity"]
        report.write_text("preserved after completed native execution")
        expected_replay = 125 if lose_running_response else 0
        if lose_running_response:
            from tests.context_native_response_loss import observe_native_reply

            def journal_counts():
                with store._connect() as connection:
                    return {
                        "operations": connection.execute("select count(*) from guard_bash_operations").fetchone()[0],
                        "claimed_once": connection.execute(
                            "select count(*) from guard_local_once_approvals where claimed_at is not null"
                        ).fetchone()[0],
                    }

            before_replay = journal_counts()
            assert before_replay == {"operations": 1, "claimed_once": int(not persistent)}
            with observe_native_reply(monkeypatch) as replies:
                result, error = run(operation)
            assert replies == [
                {
                    "status": "recorded",
                    "replayed": True,
                    # Native replay reports the original operation's saved
                    # authorization, not a fresh claim on this request.
                    "grant_claimed": True,
                    "state": "completed",
                    "cancelled": True,
                    "timed_out": False,
                    "output_limited": False,
                }
            ], replies
            after_replay = journal_counts()
            assert after_replay == before_replay
            response_loss.update(journal_before_replay=before_replay, journal_after_replay=after_replay)
            response_loss["reconciled_native_completion"] = replies[0]
        else:
            result, error = run(operation)
        assert result == expected_replay and "output_not_retained" in error
        assert report.read_text() == "preserved after completed native execution"
        if response_loss is not None:
            response_loss["native_journal_reconciled_without_reexecution"] = True
        # Contain the actual resident while the SDK preference stays enabled.
        # A fresh native generation must recover the execution journal and
        # saved native approval without restoring optional context authority.
        assert close_native_residents(guard_home=guard)
        recovered = control("status", guard_home=guard)
        assert recovered["requested_enabled"] and not recovered["effective_enabled"]
        assert recovered["runtime"] is None and recovered["job"] is None
        assert not recovered["execution_ready"] and recovered["execution_observations"] == []
        old_scope = {"action": "compile", "scope_id": grant["scope_id"], "query": "native execution"}
        with pytest.raises(ContextAssistanceError) as unavailable:
            workspace("workspace", guard_home=guard, payload=old_scope)
        assert unavailable.value.code == "native_context_assistance_runtime_not_verified"
        result, error = run(operation)
        assert result == expected_replay and "output_not_retained" in error
        assert report.read_text() == "preserved after completed native execution"
        if response_loss is not None:
            response_loss["native_restart_replay_without_reexecution"] = True
        if persistent:
            result, error = run("installed-cigar-execution-operation-0002")
            assert result == 0, error
            assert report.read_text() == completed_report
        else:
            result, _ = run("installed-cigar-execution-operation-after-restart")
            assert result == 125, "resident restart cannot replenish a spent once grant"
        recovered = control("status", guard_home=guard)
        assert recovered["runtime"] is None and recovered["execution_observations"] == []
        activate()
        scopes = workspace("workspace", guard_home=guard, payload={"action": "list"})["result"]
        assert scopes["scopes"] == []
        with pytest.raises(ContextAssistanceError) as revoked:
            workspace("workspace", guard_home=guard, payload=old_scope)
        assert revoked.value.code == "native_context_assistance_context_scope_denied"
        stopped = control("stop", guard_home=guard)
        assert not stopped["requested_enabled"] and not stopped["effective_enabled"]
        assert stopped["execution_observations"] == []
        if persistent:
            result, error = run("installed-cigar-execution-operation-0003")
            assert result == 0, error
            assert report.read_text() == completed_report
        else:
            result, _ = run("installed-cigar-execution-operation-0002")
            assert result == 125, "a spent once grant cannot become a saved allow"
        with store._connect() as connection:
            count = connection.execute("select count(*) from policy_decisions").fetchone()[0]
            assert count == int(persistent)
            if not persistent:
                assert (
                    connection.execute(
                        "select count(*) from guard_local_once_approvals where claimed_at is not null"
                    ).fetchone()[0]
                    == 1
                )
        assert control("status", guard_home=guard)["execution_observations"] == []
        if response_loss is not None:
            response_loss["approval_and_fresh_scope_recovery_verified"] = True
        completed = True
    finally:
        try:
            control("stop", guard_home=guard)
            assert close_native_residents(guard_home=guard)
            if response_loss is not None:
                response_loss["native_cleanup_acknowledged"] = True
        finally:
            if response_loss is not None:
                response_loss["completed"] = completed
                with (root / "response-loss-report.json").open("x") as output:
                    json.dump(response_loss, output, indent=2)
                    output.write("\n")
            if fault:
                fault.cleanup_owned()
                fault.metrics["completed"] = completed
                with (root / "fault-report.json").open("x") as output:
                    json.dump(fault.metrics, output, indent=2)
                    output.write("\n")
                assert fault.metrics["fallback_signals"] == 0, "normal Rust containment must own cleanup"
