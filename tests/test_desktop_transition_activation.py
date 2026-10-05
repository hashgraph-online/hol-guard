"""Core CLI exact authorization handoff; lifecycle proofs here are unit fixtures."""

import argparse
import io
import json
import time
import uuid
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.approval_gate import ApprovalGateError
from codex_plugin_scanner.guard.cli import desktop_runtime_transition as module
from codex_plugin_scanner.guard.runtime_transition import TransitionInstall
from codex_plugin_scanner.guard.runtime_transition_coordinator import RuntimeTransitionCoordinator
from codex_plugin_scanner.guard.runtime_transition_prepare import RuntimeTransitionPreparation

from .test_runtime_transition import (
    core_dependencies,
    install_row,
    proof,
    transition,  # noqa: F401 -- shared fixture
    with_install_store,
)


def test_stage_output_failure_does_not_replace_transaction_cause(monkeypatch):
    class ClosedDiagnostics:
        def write(self, value):
            raise OSError("generated closed diagnostic stream")

    monkeypatch.setattr(module.sys, "stderr", ClosedDiagnostics())
    timing = module._TransitionStageTimings(time.monotonic())
    timing.enter("approval")
    timing.finish()
    assert timing.stage is None


def test_stage_start_is_flushed_before_stage_can_block(capsys):
    timing = module._TransitionStageTimings(time.monotonic())
    timing.enter("plan_preparation")
    line = capsys.readouterr().err.removeprefix("guard_runtime_stage ")
    entry = json.loads(line)
    assert entry["stage"] == "plan_preparation" and entry["phase"] == "started"
    assert entry["duration_ms"] == 0
    assert timing.stage == "plan_preparation", "start marker must precede completion"


def test_configured_observer_uses_each_signed_executable_dependency(transition, monkeypatch):  # noqa: F811
    runtime, plan, bindings, _ = transition
    plan = core_dependencies(plan)
    before, after = install_row("codex", "before"), install_row("codex", "after")
    for row in (before, after):
        row["manifest"]["managed_hook_config_path"] = str(bindings)
    store, plan = with_install_store(runtime, plan, [TransitionInstall("codex", before, after)])
    context = HarnessContext(runtime.home.parent, None, runtime.home)
    seen = []

    def observe(**kwargs):
        binding = kwargs["artifact_binding"]
        artifact = plan.candidate if binding.executable == Path(plan.candidate["path"]) else plan.predecessor
        dependency = next(change for change in plan.files if change.path == binding.executable)
        assert binding.executable_sha256 == dependency.expected_digest
        assert binding.package_version == artifact["version"]
        seen.append(binding.executable)
        return proof(plan, artifact["generation"], installed=True)

    monkeypatch.setattr(module, "observe_configured_codex_hook", observe)
    observe_signed = module._codex_observer(plan, context, store)
    deadline = time.monotonic() + 10
    for artifact in (plan.predecessor, plan.candidate):
        observe_signed(artifact, {}, plan.operation_id, deadline_monotonic=deadline)
    assert seen == [Path(plan.predecessor["path"]), Path(plan.candidate["path"])]


@pytest.mark.parametrize("failure", [None, "approval", "hook"])
def test_activation_cli_exact_grant_before_publish_and_truthful_rollback(transition, monkeypatch, failure, capsys):  # noqa: F811
    runtime, plan, bindings, pointer = transition
    plan = core_dependencies(replace(plan, operation_id=str(uuid.uuid4())))
    before, after = install_row("codex", "before"), install_row("codex", "after")
    for row in (before, after):
        row["manifest"]["managed_hook_config_path"] = str(bindings)
    store, plan = with_install_store(runtime, plan, [TransitionInstall("codex", before, after)])
    request = RuntimeTransitionPreparation(
        plan.operation_id,
        plan.predecessor,
        plan.candidate,
        tuple(change for change in plan.files if change.kind == "selection"),
        plan.native_runtimes,
        plan.deadline_epoch,
    )
    context = HarnessContext(runtime.home.parent, None, runtime.home)
    monkeypatch.setattr(module.sys, "frozen", True, raising=False)
    monkeypatch.setattr(module.sys, "executable", str(plan.candidate["path"]))
    monkeypatch.setattr(module, "__version__", plan.candidate["version"])
    monkeypatch.setattr(module, "RuntimeTransition", lambda *args, **kwargs: runtime)
    monkeypatch.setattr(module, "load_desktop_transition_request", lambda *args, **kwargs: request)
    monkeypatch.setattr(module, "prepare_runtime_transition", lambda *args, **kwargs: plan)
    monkeypatch.setattr(module, "lifecycle_authority_home", lambda *args, **kwargs: runtime.home)
    events, deadlines = [], []

    def require(guard_home, **kwargs):
        assert guard_home == runtime.home and not runtime.path.exists()
        assert kwargs["action"] == "runtime.transition" and kwargs["subject"] == plan.subject()
        assert kwargs["purpose"] == "protection_lifecycle" and kwargs["scope"] == "local-protection"
        events.append("authorize")
        if failure == "approval":
            raise ApprovalGateError("approval_gate_invalid", "fixture rejected factor")
        return None  # The generated fixture gate is disabled; no synthetic grant.

    monkeypatch.setattr(module, "require_high_risk", require)

    class Driver:
        def __init__(self, *args, **kwargs):
            pass

        def stop(self, artifact, *, deadline_monotonic):
            events.append("stop")
            deadlines.append(deadline_monotonic)

        def start(self, artifact, *, deadline_monotonic):
            events.append("start")
            deadlines.append(deadline_monotonic)

        def observe_protection(self, artifact, operation_id, *, deadline_monotonic):
            assert operation_id == plan.operation_id
            deadlines.append(deadline_monotonic)
            if failure == "hook" and artifact == plan.candidate:
                raise RuntimeError("fixture candidate hook failure")
            return proof(plan, artifact["generation"], installed=True)

    monkeypatch.setattr(module, "TransitionDaemonDriver", Driver)
    args = argparse.Namespace(
        desktop_command="transition-activate",
        operation_id=plan.operation_id,
        deadline_epoch=plan.deadline_epoch,
        request="fixture-only-decoder-seam",
        request_sha256="a" * 64,
    )
    output = io.StringIO()
    result = module.run_desktop_runtime_transition(args, context=context, store=store, output_stream=output)
    response = json.loads(output.getvalue())
    timing_lines = [
        json.loads(line.removeprefix("guard_runtime_stage "))
        for line in capsys.readouterr().err.splitlines()
        if line.startswith("guard_runtime_stage ")
    ]
    stages = [entry["stage"] for entry in timing_lines if entry["phase"] == "finished"]
    assert [entry["stage"] for entry in timing_lines if entry["phase"] == "started"] == stages
    assert stages[:7] == [
        "authority",
        "factor_consumption",
        "owner_wait",
        "control",
        "request_verification",
        "plan_preparation",
        "approval",
    ]
    assert stages[7:] == ([] if failure == "approval" else ["daemon_owner_wait", "activation"])
    assert all(set(entry) == {"stage", "phase", "elapsed_ms", "duration_ms"} for entry in timing_lines)
    assert all(0 <= entry["duration_ms"] <= entry["elapsed_ms"] for entry in timing_lines)
    assert events[0] == "authorize"
    if failure == "approval":
        assert result == 1 and response["reason_code"] == "approval_gate_invalid"
        assert events == ["authorize"] and not runtime.path.exists()
        assert bindings.read_bytes() == b"previous hooks" and pointer.read_bytes() == b"previous pointer"
        for command in ("transition-status", "transition-recover"):
            args.desktop_command = command
            checked = io.StringIO()
            assert module.run_desktop_runtime_transition(args, context=context, store=store, output_stream=checked) == 0
            receipt = json.loads(checked.getvalue())
            assert receipt["phase"] == "NotStarted"
            assert receipt["artifact_generation"] == plan.candidate["generation"]
            assert receipt["first_cause"] == "approval_gate_invalid" and receipt["recovery_causes"] == []
            assert events == ["authorize"] and not runtime.path.exists()
        args.desktop_command = "transition-activate"
        repeated = io.StringIO()
        assert module.run_desktop_runtime_transition(args, context=context, store=store, output_stream=repeated) == 1
        assert json.loads(repeated.getvalue())["reason_code"] == "operation_previously_refused"
        assert events == ["authorize"]
        return
    assert len(set(deadlines)) == 1
    assert response["artifact_generation"] == plan.candidate["generation"]
    assert response["phase"] == ("FailedWithVerifiedRollback" if failure == "hook" else "Committed")
    assert result == (1 if failure == "hook" else 0)
    assert "fixture candidate hook failure" not in output.getvalue()
    if failure == "hook":
        assert bindings.read_bytes() == b"previous hooks" and pointer.read_bytes() == b"previous pointer"
    else:
        assert bindings.read_bytes() == b"candidate hooks" and pointer.read_bytes() == b"candidate pointer"


def test_activation_uses_the_controlling_process_deadline(transition):  # noqa: F811
    runtime, plan, *_ = transition
    deadline = time.monotonic() + 5
    observed = []

    class Driver:
        def stop(self, artifact, *, deadline_monotonic):
            observed.append(deadline_monotonic)

        def start(self, artifact, *, deadline_monotonic):
            observed.append(deadline_monotonic)

        def observe_protection(self, artifact, operation_id, *, deadline_monotonic):
            observed.append(deadline_monotonic)
            return proof(plan, artifact["generation"], installed=True)

    status = RuntimeTransitionCoordinator(runtime, Driver()).activate(
        plan,
        authority_home=runtime.home,
        grant=None,
        deadline_monotonic=deadline,
    )
    assert status.phase == "Committed" and observed == [deadline, deadline, deadline]
    assert runtime._read(plan.operation_id)["deadline_monotonic"] <= deadline


def test_status_cli_binds_authenticated_generation_without_replaying_authorization(transition, monkeypatch):  # noqa: F811
    runtime, plan, bindings, pointer = transition
    plan = replace(plan, operation_id=str(uuid.uuid4()))
    store, plan = with_install_store(runtime, plan, [])
    runtime.begin(plan, authority_home=runtime.home, grant=None)
    before = (runtime.path.read_bytes(), bindings.read_bytes(), pointer.read_bytes())
    monkeypatch.setattr(module, "RuntimeTransition", lambda *args, **kwargs: runtime)
    monkeypatch.setattr(module, "lifecycle_authority_home", lambda *args, **kwargs: runtime.home)

    def forbidden(*args, **kwargs):
        pytest.fail("status must not authorize, reconstruct an inverse, or launch a daemon")

    monkeypatch.setattr(module, "require_high_risk", forbidden)
    monkeypatch.setattr(module, "TransitionDaemonDriver", forbidden)
    monkeypatch.setattr(runtime, "recovery_plan", forbidden)
    args = argparse.Namespace(
        desktop_command="transition-status", operation_id=plan.operation_id, deadline_epoch=time.time() + 10
    )
    output = io.StringIO()
    context = HarnessContext(runtime.home.parent, None, runtime.home)
    result = module.run_desktop_runtime_transition(args, context=context, store=store, output_stream=output)
    response = json.loads(output.getvalue())
    assert result == 0 and response["phase"] == "AuthorizedForExactTransition"
    assert response["artifact_generation"] == plan.candidate["generation"]
    assert (runtime.path.read_bytes(), bindings.read_bytes(), pointer.read_bytes()) == before
    assert "previous hooks" not in output.getvalue() and "authorized_subject" not in response


def test_not_started_requires_existing_authority_intact_receipt_and_absent_journal(transition):  # noqa: F811
    from codex_plugin_scanner.guard.runtime_transition import TransitionError

    runtime, plan, *_ = transition
    plan = replace(plan, operation_id=str(uuid.uuid4()))
    with pytest.raises(TransitionError, match="record_unavailable"):
        runtime.refusal_status(plan.operation_id)
    runtime.record_approval_refusal(plan, "approval_gate_invalid", deadline_monotonic=time.monotonic() + 10)
    path = runtime._refusal_path(plan.operation_id)
    original = path.read_bytes()
    payload = json.loads(original)
    payload["reason_code"] = "changed_reason"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(TransitionError, match="refusal_unauthenticated"):
        runtime.refusal_status(plan.operation_id)
    path.write_bytes(original)
    with pytest.raises(TransitionError, match="operation_previously_refused"):
        runtime.begin(plan, authority_home=runtime.home, grant=None)
    other = replace(plan, operation_id=str(uuid.uuid4()))
    runtime.begin(other, authority_home=runtime.home, grant=None)
    with pytest.raises(TransitionError, match="pending_transition"):
        runtime.refusal_status(plan.operation_id)
    with pytest.raises(TransitionError, match="pending_transition"):
        runtime.record_approval_refusal(
            replace(plan, operation_id=str(uuid.uuid4())),
            "approval_gate_invalid",
            deadline_monotonic=time.monotonic() + 10,
        )
    assert path.read_bytes() == original


def test_refusal_never_creates_authority_or_overwrites_prior_evidence(transition, monkeypatch):  # noqa: F811
    from codex_plugin_scanner.guard.runtime_transition import TransitionError

    runtime, plan, *_ = transition
    plan = replace(plan, operation_id=str(uuid.uuid4()))
    original_key = runtime.authority._policy_integrity_secret_material
    calls = []

    def unavailable(*, create):
        calls.append(create)
        return None, None

    monkeypatch.setattr(runtime.authority, "_policy_integrity_secret_material", unavailable)
    with pytest.raises(TransitionError, match="signing_authority_unavailable"):
        runtime.record_approval_refusal(plan, "approval_gate_invalid", deadline_monotonic=time.monotonic() + 10)
    assert calls == [False] and not runtime._refusal_path(plan.operation_id).exists()
    monkeypatch.setattr(runtime.authority, "_policy_integrity_secret_material", original_key)
    runtime.record_approval_refusal(plan, "approval_gate_invalid", deadline_monotonic=time.monotonic() + 10)
    before = runtime._refusal_path(plan.operation_id).read_bytes()
    with pytest.raises(FileExistsError):
        runtime.record_approval_refusal(plan, "another_reason", deadline_monotonic=time.monotonic() + 10)
    assert runtime._refusal_path(plan.operation_id).read_bytes() == before
    with pytest.raises(TransitionError, match="deadline_exceeded"):
        runtime.record_approval_refusal(
            replace(plan, operation_id=str(uuid.uuid4())),
            "approval_gate_invalid",
            deadline_monotonic=time.monotonic() - 1,
        )


@pytest.mark.parametrize("state", ["pending", "changed", "rollback"])
def test_finalize_requires_terminal_exact_live_generation_and_preserves_archived_status(
    transition,
    monkeypatch,
    state,
):
    from codex_plugin_scanner.guard.runtime_transition import TransitionError

    runtime, plan, bindings, _ = transition
    plan = replace(plan, operation_id=str(uuid.uuid4()))
    store, plan = with_install_store(runtime, plan, [])
    runtime.begin(plan, authority_home=runtime.home, grant=None)
    if state != "pending":
        runtime.restore_files(plan.operation_id, first_cause="candidate_failed")
        runtime.finish_rollback(plan.operation_id, functional_proof=proof(plan, plan.predecessor["generation"]))
    if state == "changed":
        bindings.write_bytes(b"foreign binding generation")
    next_plan = replace(plan, operation_id=str(uuid.uuid4()))
    with pytest.raises(TransitionError, match="pending_transition"):
        runtime.begin(next_plan, authority_home=runtime.home, grant=None)
    before = runtime.path.read_bytes()
    monkeypatch.setattr(module, "RuntimeTransition", lambda *args, **kwargs: runtime)
    monkeypatch.setattr(module, "lifecycle_authority_home", lambda *args, **kwargs: runtime.home)

    def forbidden(*args, **kwargs):
        pytest.fail("terminal finalization must not authorize or start/stop a runtime")

    monkeypatch.setattr(module, "require_high_risk", forbidden)
    monkeypatch.setattr(module, "TransitionDaemonDriver", forbidden)
    args = argparse.Namespace(
        desktop_command="transition-finalize",
        operation_id=plan.operation_id,
        artifact_generation=plan.candidate["generation"],
        deadline_epoch=time.time() + 10,
    )
    context = HarnessContext(runtime.home.parent, None, runtime.home)
    output = io.StringIO()
    args.artifact_generation = "f" * 64
    mismatched = io.StringIO()
    assert module.run_desktop_runtime_transition(args, context=context, store=store, output_stream=mismatched) == 1
    assert json.loads(mismatched.getvalue())["reason_code"] == "artifact_generation_mismatch"
    assert runtime.path.read_bytes() == before
    args.artifact_generation = plan.candidate["generation"]
    result = module.run_desktop_runtime_transition(args, context=context, store=store, output_stream=output)
    document = json.loads(output.getvalue())
    if state != "rollback":
        assert result == 1
        assert document["reason_code"] == ("nonterminal_transition" if state == "pending" else "generation_changed")
        assert runtime.path.read_bytes() == before
        assert not runtime.path.with_name("runtime-transition.previous.json").exists()
        return
    assert result == 0 and document["phase"] == "FailedWithVerifiedRollback"
    assert not runtime.path.exists()
    previous = runtime.path.with_name("runtime-transition.previous.json")
    assert previous.read_bytes() == before
    for command in ("transition-status", "transition-recover", "transition-finalize"):
        args.desktop_command = command
        checked = io.StringIO()
        assert module.run_desktop_runtime_transition(args, context=context, store=store, output_stream=checked) == 0
        assert json.loads(checked.getvalue())["phase"] == "FailedWithVerifiedRollback"
        assert previous.read_bytes() == before and not runtime.path.exists()
    runtime.begin(next_plan, authority_home=runtime.home, grant=None)
    assert runtime.status(next_plan.operation_id).phase == "AuthorizedForExactTransition"
    with pytest.raises(TransitionError, match="pending_transition"):
        runtime.archived_status(plan.operation_id)
