"""Preserve native uncertainty and approval state after an actual owner crash."""

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
from tests.context_execution_barrier import NativeEffectBarrier
from tests.context_native_authority_loss import lose_native_owner_reply
from tests.context_native_response_loss import observe_native_reply
from tests.context_process_fault import OwnedOptionalProcesses
from tests.test_context_execution_sink_installed import (
    test_installed_execution_context_preserves_consent_replay_restart_and_opt_out as _execution_case,
)


@pytest.mark.integration
@pytest.mark.installed
@pytest.mark.skipif(
    sys.platform != "darwin"
    or os.environ.get("HOL_GUARD_TEST_USE_INSTALLED") != "1"
    or not os.environ.get("GUARD_CIGAR_TEST_SELECTION")
    or not os.environ.get("GUARD_CIGAR_TEST_APPROVAL"),
    reason="requires the exact installed macOS candidate, real CIGAR and a verified disposable native owner",
)
@pytest.mark.parametrize("persistent", [False, True], ids=["allow-once", "always-allow"])
def test_native_owner_loss_keeps_partial_effect_uncertain_and_never_restores_authority(
    native_context_digest,
    tmp_path,
    monkeypatch,
    persistent,
):
    selection = json.loads(Path(os.environ["GUARD_CIGAR_TEST_SELECTION"]).read_text())
    approval = json.loads(Path(os.environ["GUARD_CIGAR_TEST_APPROVAL"]).read_text())
    metrics = {
        "schema": "guard-cigar-native-owner-loss.v1",
        "completed": False,
        "approval": "always" if persistent else "once",
        "native_owner_signals": 0,
        "fallback_signals": 0,
    }

    def loss(**case):
        owned = OwnedOptionalProcesses.capture(case["binary"], selection, approval)
        try:
            lose_native_owner_reply(
                **{
                    key: case[key]
                    for key in ("payload", "guard_home", "project", "operation", "report", "barrier", "binary")
                },
                owned=owned,
                metrics=metrics,
            )
            state = control("status", guard_home=case["guard_home"])
            assert state["requested_enabled"] and not state["effective_enabled"]
            assert state["runtime"] is None and not state["execution_ready"] and state["execution_observations"] == []
            old_scope = {"action": "compile", "scope_id": case["grant"]["scope_id"], "query": "native execution"}
            with pytest.raises(ContextAssistanceError) as unavailable:
                workspace("workspace", guard_home=case["guard_home"], payload=old_scope)
            assert unavailable.value.code == "native_context_assistance_runtime_not_verified"

            def counts():
                with case["store"]._connect() as connection:
                    return {
                        "operations": connection.execute("select count(*) from guard_bash_operations").fetchone()[0],
                        "claimed_once": connection.execute(
                            "select count(*) from guard_local_once_approvals where claimed_at is not null"
                        ).fetchone()[0],
                    }

            before = counts()
            assert before == {"operations": 1, "claimed_once": int(not persistent)}
            case["report"].write_text("preserve the uncertain operation sentinel")
            with observe_native_reply(monkeypatch) as replies:
                status, error = case["run"](case["operation"])
            assert status == 125 and "native_bash_operation_in_progress_or_uncertain" in error
            assert len(replies) == 1 and replies[0]["status"] == "recorded" and replies[0]["replayed"]
            assert replies[0]["grant_claimed"] is True  # Historical authorization, never a new claim.
            assert replies[0]["state"] in {"claimed", "dispatched", "uncertain"}
            assert all(replies[0][key] is None for key in ("cancelled", "timed_out", "output_limited"))
            assert counts() == before
            assert case["report"].read_text() == "preserve the uncertain operation sentinel"
            metrics.update(
                reconciliation=replies[0],
                journal_before=before,
                journal_after=counts(),
                uncertain_replay_without_reexecution=True,
            )
            assert close_native_residents(guard_home=case["guard_home"])
            status, error = case["run"](case["operation"])
            assert status == 125 and "native_bash_operation_in_progress_or_uncertain" in error
            assert counts() == before
            assert case["report"].read_text() == "preserve the uncertain operation sentinel"
            status, _error = case["run"]("fresh-native-owner-loss-operation")
            assert status == (0 if persistent else 125)
            if persistent:
                assert case["report"].read_text() == "installed-cigar-owner\nnative-effect-completed\n"
            else:
                assert case["report"].read_text() == "preserve the uncertain operation sentinel"
            case["activate"]()
            scopes = workspace("workspace", guard_home=case["guard_home"], payload={"action": "list"})["result"]
            assert scopes["scopes"] == []
            with pytest.raises(ContextAssistanceError) as revoked:
                workspace("workspace", guard_home=case["guard_home"], payload=old_scope)
            assert revoked.value.code == "native_context_assistance_context_scope_denied"
            metrics.update(approval_parity_verified=True, reactivation_restores_no_scope=True)
        finally:
            owned.cleanup_owned()
            metrics["fallback_signals"] += owned.metrics["fallback_signals"]

    with NativeEffectBarrier() as barrier, ProcessSampler(Path(selection["python"])) as sampler:
        before, baseline = sampler.sample_with_identities()
        metrics["before"] = before
        scenario_completed = False
        try:
            _execution_case(
                native_context_digest, tmp_path, monkeypatch, persistent, effect_barrier=barrier, authority_loss=loss
            )
            assert metrics["native_owner_signals"] == 1 and metrics["fallback_signals"] == 0
            scenario_completed = True
        finally:
            metrics["client_cleanup_confirmed"] = False
            try:
                metrics["client_cleanup_confirmed"] = (
                    close_native_resident_clients(tmp_path / "guard", deadline_monotonic=time.monotonic() + 10) is True
                )
                deadline = time.monotonic() + 5
                after, remaining = sampler.sample_with_identities()
                while remaining.keys() - baseline.keys() and time.monotonic() < deadline:
                    time.sleep(0.05)
                    after, remaining = sampler.sample_with_identities()
                metrics.update(
                    after=after,
                    new_live_descendants_remaining=len(remaining.keys() - baseline.keys()),
                    resources=sampler.summary(),
                )
                metrics["completed"] = (
                    scenario_completed
                    and metrics["client_cleanup_confirmed"]
                    and metrics["new_live_descendants_remaining"] == 0
                    and metrics["resources"]["sampling_errors"] == 0
                )
            finally:
                with (tmp_path / "native-owner-loss-report.json").open("x") as output:
                    json.dump(metrics, output, indent=2)
                    output.write("\n")
            assert metrics["client_cleanup_confirmed"]
            assert metrics["new_live_descendants_remaining"] == 0
            assert metrics["resources"]["sampling_errors"] == 0
