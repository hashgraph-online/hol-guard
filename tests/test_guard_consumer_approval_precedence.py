"""Consumer-service saved-approval precedence regressions (P44)."""

from __future__ import annotations

import json
import os
import shlex
import sqlite3
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import codex_remote_control
from codex_plugin_scanner.guard.adapters import grok as grok_adapter_module
from codex_plugin_scanner.guard.adapters import grok_executable as grok_executable_module
from codex_plugin_scanner.guard.adapters.base import HarnessAdapter, HarnessContext
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter
from codex_plugin_scanner.guard.adapters.grok import GrokHarnessAdapter
from codex_plugin_scanner.guard.adapters.opencode import OpenCodeHarnessAdapter
from codex_plugin_scanner.guard.adapters.opencode_artifacts import runtime_config_path
from codex_plugin_scanner.guard.approvals import queue_blocked_approvals
from codex_plugin_scanner.guard.config import GuardConfig, load_guard_config
from codex_plugin_scanner.guard.consumer import evaluate_detection
from codex_plugin_scanner.guard.consumer.service import _consumer_execution_identity
from codex_plugin_scanner.guard.models import GuardAction, GuardArtifact, HarnessDetection, PolicyDecision
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.runtime.approval_context import (
    build_approval_context_token,
    parse_approval_context_token,
)
from codex_plugin_scanner.guard.store import GuardStore


@pytest.fixture(autouse=True)
def _stable_guard_run_launch_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep consumer precedence tests independent from real harness startup."""

    class LaunchAdapter(HarnessAdapter):
        def launch_command(self, _context: HarnessContext, args: list[str]) -> list[str]:
            return [sys.executable, "-c", "pass", *args]

        def prepare_launch_environment(
            self,
            _context: HarnessContext,
            inherited: dict[str, str],
        ) -> dict[str, str]:
            return dict(inherited)

    monkeypatch.setattr(guard_runner_module, "get_adapter", lambda _harness: LaunchAdapter())


def test_consumer_execution_identity_resolves_dot_slash_from_runtime_cwd(tmp_path: Path) -> None:
    runtime_cwd = tmp_path / "runtime"
    runtime_cwd.mkdir()
    executable = runtime_cwd / "server"
    executable.write_bytes(b"#!/bin/sh\necho runtime\n")
    executable.chmod(0o755)

    identity = _consumer_execution_identity("./server --stdio", cwd=runtime_cwd)

    resolved = identity["resolved"]
    assert isinstance(resolved, dict)
    assert resolved["path"] == str(executable.resolve())
    assert resolved["launch_cwd"] == str(runtime_cwd.resolve())
    assert resolved["status"] == "verified"


def test_consumer_execution_identity_resolves_relative_path_entries_from_runtime_cwd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_cwd = tmp_path / "runtime"
    binary_dir = runtime_cwd / "bin"
    binary_dir.mkdir(parents=True)
    executable = binary_dir / "server"
    executable.write_bytes(b"#!/bin/sh\necho runtime\n")
    executable.chmod(0o755)
    monkeypatch.setenv("PATH", "bin")

    identity = _consumer_execution_identity("server --stdio", cwd=runtime_cwd)

    resolved = identity["resolved"]
    assert isinstance(resolved, dict)
    assert resolved["path"] == str(executable.resolve())
    assert resolved["launch_cwd"] == str(runtime_cwd.resolve())
    assert resolved["status"] == "verified"


def _artifact(tmp_path: Path) -> GuardArtifact:
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "consumer-review.js").write_text("console.log('consumer review');\n", encoding="utf-8")
    return GuardArtifact(
        artifact_id="codex:project:consumer-review",
        name="consumer-review",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
        command="node",
        args=("consumer-review.js",),
        transport="stdio",
        publisher="trusted-publisher",
        metadata={
            "guard_default_action": "review",
            "action_class": "consumer approval precedence proof",
        },
    )


def _detection(artifact: GuardArtifact) -> HarnessDetection:
    return HarnessDetection(
        harness=artifact.harness,
        installed=True,
        command_available=True,
        config_paths=(artifact.config_path,),
        artifacts=(artifact,),
    )


def _raw_interpreted_artifact(tmp_path: Path, script: Path) -> GuardArtifact:
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    return GuardArtifact(
        artifact_id="codex:project:raw-interpreted-consumer-action",
        name="raw interpreted consumer action",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=str(workspace / ".codex" / "config.toml"),
        command=shlex.join((sys.executable, str(script))),
        publisher="trusted-publisher",
        metadata={
            "guard_default_action": "review",
            "action_class": "raw interpreted consumer action",
        },
    )


def _config(tmp_path: Path, *, action: GuardAction | None = None) -> GuardConfig:
    artifact = _artifact(tmp_path)
    return GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
        artifact_actions={artifact.artifact_id: action} if action is not None else None,
    )


def _record_once(
    store: GuardStore,
    *,
    artifact: GuardArtifact,
    context_hash: str,
    workspace: Path,
    request_id: str = "consumer-review-once",
) -> str:
    approval_id = store.record_local_once_approval(
        request_id=request_id,
        harness=artifact.harness,
        artifact_id=artifact.artifact_id,
        artifact_hash=context_hash,
        workspace=str(workspace),
        publisher=artifact.publisher,
        action="allow",
        created_at="2026-07-17T00:00:00+00:00",
        expires_at="2099-07-17T00:00:00+00:00",
    )
    assert approval_id is not None
    return approval_id


def _write_test_executable(path: Path, body: str = "#!/bin/sh\nexit 0\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


def test_guard_run_launch_environment_hash_is_canonical_and_value_sensitive() -> None:
    first = guard_runner_module._guard_run_launch_environment_hash({"B": "two", "A": "one"})
    reordered = guard_runner_module._guard_run_launch_environment_hash({"A": "one", "B": "two"})
    changed = guard_runner_module._guard_run_launch_environment_hash({"A": "one", "B": "changed"})

    assert first == reordered
    assert first != changed
    assert len(first) == 64


def test_unchanged_raw_interpreted_tool_action_reuses_exact_approval(tmp_path: Path) -> None:
    script = tmp_path / "consumer_action.py"
    script.write_text("print('unchanged')\n", encoding="utf-8")
    artifact = _raw_interpreted_artifact(tmp_path, script)
    detection = _detection(artifact)
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )
    store = GuardStore(tmp_path / "guard-home")
    initial = evaluate_detection(detection, store, config, persist=False)
    context_hash = str(initial["artifacts"][0]["approval_context_hash"])
    _record_once(
        store,
        artifact=artifact,
        context_hash=context_hash,
        workspace=tmp_path / "workspace",
    )

    result = evaluate_detection(detection, store, config, persist=False)

    assert result["artifacts"][0]["approval_context_hash"] == context_hash
    assert result["artifacts"][0]["approval_reuse_status"] == "accepted"
    assert result["artifacts"][0]["approval_reuse_reason_code"] == "approval_reuse_accepted"


def test_raw_interpreted_tool_action_entrypoint_mutation_rejects_exact_approval(tmp_path: Path) -> None:
    script = tmp_path / "consumer_action.py"
    script.write_text("print('before')\n", encoding="utf-8")
    artifact = _raw_interpreted_artifact(tmp_path, script)
    detection = _detection(artifact)
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )
    store = GuardStore(tmp_path / "guard-home")
    initial = evaluate_detection(detection, store, config, persist=False)
    context_hash = str(initial["artifacts"][0]["approval_context_hash"])
    _record_once(
        store,
        artifact=artifact,
        context_hash=context_hash,
        workspace=tmp_path / "workspace",
    )
    script.write_text("print('after')\n", encoding="utf-8")

    result = evaluate_detection(detection, store, config, persist=False)

    assert result["artifacts"][0]["approval_context_hash"] != context_hash
    assert result["artifacts"][0]["approval_reuse_status"] == "rejected"
    assert result["artifacts"][0]["approval_reuse_reason_code"] == "approval_reuse_identity_changed"


def test_publisher_mutation_rejects_exact_approval_without_consuming_it(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    config = _config(tmp_path)
    store = GuardStore(tmp_path / "guard-home")
    initial = evaluate_detection(_detection(artifact), store, config, persist=False)
    context_hash = str(initial["artifacts"][0]["approval_context_hash"])
    _record_once(
        store,
        artifact=artifact,
        context_hash=context_hash,
        workspace=tmp_path / "workspace",
    )
    changed_artifact = replace(artifact, publisher="different-publisher")

    result = evaluate_detection(_detection(changed_artifact), store, config, persist=False)
    item = result["artifacts"][0]

    assert item["approval_context_hash"] != context_hash
    assert item["policy_action"] == "review"
    assert item["approval_reuse_status"] == "rejected"
    assert item["approval_reuse_reason_code"] == "approval_reuse_identity_changed"
    assert (
        store.peek_local_once_approval(
            harness=artifact.harness,
            artifact_id=artifact.artifact_id,
            artifact_hash=context_hash,
            workspace=str(tmp_path / "workspace"),
            publisher=artifact.publisher,
            now="2026-07-17T00:01:00+00:00",
        )
        is not None
    )


@pytest.mark.parametrize("stronger_action", ("require-reapproval", "sandbox-required", "block"))
def test_saved_review_allow_never_lowers_current_stronger_action_and_is_not_consumed(
    tmp_path: Path,
    stronger_action: GuardAction,
) -> None:
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    store = GuardStore(tmp_path / "guard-home")
    baseline = evaluate_detection(detection, store, _config(tmp_path), persist=False)
    baseline_item = baseline["artifacts"][0]
    context_hash = str(baseline_item["approval_context_hash"])
    assert parse_approval_context_token(context_hash) is not None
    _record_once(
        store,
        artifact=artifact,
        context_hash=context_hash,
        workspace=tmp_path / "workspace",
    )

    result = evaluate_detection(
        detection,
        store,
        _config(tmp_path, action=stronger_action),
        persist=True,
    )
    item = result["artifacts"][0]
    receipt = store.list_receipts(limit=1)[0]
    queued = queue_blocked_approvals(
        detection=detection,
        evaluation=result,
        store=store,
        approval_center_url="http://127.0.0.1:4455",
    )

    assert item["policy_action"] == stronger_action
    assert item["decision_v2_json"]["action"] == ("block" if stronger_action == "block" else "ask")
    assert item["policy_composition"]["current_action"] == stronger_action
    assert item["policy_composition"]["final_action"] == stronger_action
    assert item["approval_reuse_status"] == "rejected"
    assert result["blocked"] is True
    assert receipt["policy_decision"] == stronger_action
    assert receipt["scanner_evidence"][-1]["reason_code"] == item["approval_reuse_reason_code"]
    inventory = store.find_inventory_item(artifact.artifact_id)
    assert artifact.artifact_id not in store.list_snapshots(artifact.harness)
    assert inventory is not None
    assert inventory["last_approved_at"] is None
    if stronger_action == "require-reapproval":
        assert queued[0]["policy_action"] == stronger_action
        assert queued[0]["scanner_evidence"][-1]["reason_code"] == item["approval_reuse_reason_code"]
    else:
        assert queued == []
        assert store.list_approval_requests(limit=None) == []
    assert (
        store.peek_local_once_approval(
            harness=artifact.harness,
            artifact_id=artifact.artifact_id,
            artifact_hash=context_hash,
            workspace=str(tmp_path / "workspace"),
            publisher=artifact.publisher,
            now="2026-07-17T00:01:00+00:00",
        )
        is not None
    )


def test_guard_run_claims_exact_saved_review_allow_only_at_real_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    config = _config(tmp_path)
    store = GuardStore(tmp_path / "guard-home")
    initial = evaluate_detection(detection, store, config, persist=False)
    context_hash = str(initial["artifacts"][0]["approval_context_hash"])
    _record_once(store, artifact=artifact, context_hash=context_hash, workspace=tmp_path / "workspace")
    launch_calls: list[object] = []
    monkeypatch.setattr(guard_runner_module, "detect_harness", lambda _harness, _context: detection)
    monkeypatch.setattr(
        guard_runner_module.subprocess,
        "run",
        lambda *args, **kwargs: (
            launch_calls.append((args, kwargs)) or subprocess.CompletedProcess(args=[], returncode=0)
        ),
    )

    result = guard_runner_module.guard_run(
        "codex",
        HarnessContext(
            home_dir=tmp_path,
            workspace_dir=tmp_path / "workspace",
            guard_home=tmp_path / "guard-home",
        ),
        store,
        config,
        dry_run=False,
        passthrough_args=[],
    )

    assert result["blocked"] is False
    assert result["launched"] is True
    assert launch_calls
    assert (
        store.peek_local_once_approval(
            harness=artifact.harness,
            artifact_id=artifact.artifact_id,
            artifact_hash=context_hash,
            workspace=str(tmp_path / "workspace"),
            publisher=artifact.publisher,
            now="2026-07-17T00:01:00+00:00",
        )
        is None
    )
    receipt = store.list_receipts(limit=1)[0]
    inventory = store.find_inventory_item(artifact.artifact_id)
    assert receipt["policy_decision"] == "allow"
    assert receipt["approval_source"] == "saved-approval"
    assert artifact.artifact_id in store.list_snapshots(artifact.harness)
    assert inventory is not None
    assert isinstance(inventory["last_approved_at"], str)


def test_guard_run_executes_canonical_launch_argv_pinned_after_saved_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    config = _config(tmp_path)
    store = GuardStore(tmp_path / "guard-home")
    initial = evaluate_detection(detection, store, config, persist=False)
    context_hash = str(initial["artifacts"][0]["approval_context_hash"])
    _record_once(store, artifact=artifact, context_hash=context_hash, workspace=tmp_path / "workspace")
    executable_alias = tmp_path / "approved-python"
    executable_alias.symlink_to(Path(sys.executable).resolve())
    adapter_calls: list[tuple[str, ...]] = []
    preview_calls: list[tuple[str, ...]] = []
    authority_events: list[str] = []

    class LaunchAdapter(HarnessAdapter):
        @staticmethod
        def _command(args: list[str]) -> tuple[str, ...]:
            return (str(executable_alias), "-c", "pass", *args)

        def preview_launch_commands(
            self,
            _context: HarnessContext,
            args: list[str],
        ) -> tuple[list[str], ...]:
            command = self._command(args)
            preview_calls.append(command)
            authority_events.append("preview")
            return (list(command),)

        def launch_command(self, _context: HarnessContext, args: list[str]) -> list[str]:
            command = self._command(args)
            adapter_calls.append(command)
            authority_events.append("launch-setup")
            return list(command)

        def prepare_launch_environment(
            self,
            _context: HarnessContext,
            inherited: dict[str, str],
        ) -> dict[str, str]:
            return dict(inherited)

    launch_calls: list[list[str]] = []

    def launch(command: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        authority_events.append("execute")
        executable_alias.unlink()
        executable_alias.symlink_to("/bin/echo")
        launch_calls.append(command)
        return subprocess.CompletedProcess(args=command, returncode=0)

    original_claim = store.claim_approval_reuse_decisions

    def claim_and_record(decisions, **kwargs) -> bool:
        authority_events.append("claim")
        return original_claim(decisions, **kwargs)

    monkeypatch.setattr(guard_runner_module, "detect_harness", lambda _harness, _context: detection)
    monkeypatch.setattr(guard_runner_module, "get_adapter", lambda _harness: LaunchAdapter())
    monkeypatch.setattr(store, "claim_approval_reuse_decisions", claim_and_record)
    monkeypatch.setattr(guard_runner_module.subprocess, "run", launch)

    result = guard_runner_module.guard_run(
        "codex",
        HarnessContext(
            home_dir=tmp_path,
            workspace_dir=tmp_path / "workspace",
            guard_home=tmp_path / "guard-home",
        ),
        store,
        config,
        dry_run=False,
        passthrough_args=[],
    )

    expected_command = [str(Path(sys.executable).resolve()), "-c", "pass"]
    assert result["blocked"] is False
    assert result["launched"] is True
    assert preview_calls == [
        (str(executable_alias), "-c", "pass"),
        (str(executable_alias), "-c", "pass"),
    ]
    assert adapter_calls == [(str(executable_alias), "-c", "pass")]
    assert authority_events == ["preview", "claim", "preview", "launch-setup", "execute"]
    assert result["launch_command"] == expected_command
    assert launch_calls == [expected_command]


def test_guard_run_rejects_opencode_overlay_environment_changed_after_saved_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True)
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=workspace)
    store = GuardStore(config.guard_home)
    context = HarnessContext(
        home_dir=tmp_path,
        workspace_dir=workspace,
        guard_home=config.guard_home,
    )
    overlay_path = runtime_config_path(context)
    overlay_path.parent.mkdir(parents=True, exist_ok=True)
    overlay_path.write_text(json.dumps({"permission": {"bash": "ask"}}), encoding="utf-8")
    executable_alias = tmp_path / "bin" / "opencode"
    executable_alias.parent.mkdir(parents=True)
    executable_alias.symlink_to(Path(sys.executable).resolve())
    monkeypatch.setenv("PATH", f"{executable_alias.parent}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.delenv("OPENCODE_CONFIG_CONTENT", raising=False)

    initial = evaluate_detection(detection, store, config, persist=False)
    context_hash = str(initial["artifacts"][0]["approval_context_hash"])
    _record_once(store, artifact=artifact, context_hash=context_hash, workspace=workspace)
    original_claim = store.claim_approval_reuse_decisions

    def claim_then_mutate_overlay(decisions, **kwargs) -> bool:
        claimed = original_claim(decisions, **kwargs)
        if claimed:
            overlay_path.write_text(
                json.dumps({"permission": {"bash": "allow"}, "model": "attacker/model"}),
                encoding="utf-8",
            )
        return claimed

    monkeypatch.setattr(guard_runner_module, "detect_harness", lambda _harness, _context: detection)
    monkeypatch.setattr(guard_runner_module, "get_adapter", lambda _harness: OpenCodeHarnessAdapter())
    monkeypatch.setattr(store, "claim_approval_reuse_decisions", claim_then_mutate_overlay)
    monkeypatch.setattr(
        guard_runner_module.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("a changed prepared launch environment must not execute"),
    )

    result = guard_runner_module.guard_run(
        "codex",
        context,
        store,
        config,
        dry_run=False,
        passthrough_args=[],
    )

    assert result["blocked"] is True
    assert result["launched"] is False
    assert result["approval_claim"]["reason_code"] == "approval_reuse_context_changed_after_claim"


def test_codex_postclaim_setup_uses_authorized_canonical_prefix_after_symlink_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    config = _config(tmp_path)
    store = GuardStore(config.guard_home)
    initial = evaluate_detection(detection, store, config, persist=False)
    context_hash = str(initial["artifacts"][0]["approval_context_hash"])
    _record_once(store, artifact=artifact, context_hash=context_hash, workspace=tmp_path / "workspace")

    marker = tmp_path / "attacker-executed"
    safe_codex = _write_test_executable(tmp_path / "safe" / "codex", "#!/bin/sh\nexit 1\n")
    attacker_codex = _write_test_executable(
        tmp_path / "attacker" / "codex",
        f"#!/bin/sh\nprintf attacked > {shlex.quote(str(marker))}\nexit 0\n",
    )
    executable_alias = tmp_path / "bin" / "codex"
    executable_alias.parent.mkdir(parents=True)
    executable_alias.symlink_to(safe_codex)
    monkeypatch.setenv("PATH", f"{executable_alias.parent}{os.pathsep}{os.environ.get('PATH', '')}")

    class SwapAtAuthorizedSetupAdapter(CodexHarnessAdapter):
        def launch_command_from_authorized_plan(self, *args, **kwargs) -> list[str]:
            executable_alias.unlink()
            executable_alias.symlink_to(attacker_codex)
            return super().launch_command_from_authorized_plan(*args, **kwargs)

    monkeypatch.setattr(guard_runner_module, "detect_harness", lambda _harness, _context: detection)
    monkeypatch.setattr(
        guard_runner_module,
        "get_adapter",
        lambda _harness: SwapAtAuthorizedSetupAdapter(),
    )
    monkeypatch.setattr(codex_remote_control, "_start_direct_app_server", lambda **_kwargs: False)

    result = guard_runner_module.guard_run(
        "codex",
        HarnessContext(
            home_dir=tmp_path,
            workspace_dir=tmp_path / "workspace",
            guard_home=config.guard_home,
        ),
        store,
        config,
        dry_run=False,
        passthrough_args=[],
    )

    assert executable_alias.resolve() == attacker_codex.resolve()
    assert marker.exists() is False
    assert result["blocked"] is False
    assert result["launched"] is True
    assert result["launch_command"] == ["/bin/sh", str(safe_codex.resolve())]


def test_no_saved_codex_setup_uses_previewed_canonical_prefix_after_symlink_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    config = _config(tmp_path, action="allow")
    store = GuardStore(config.guard_home)
    marker = tmp_path / "no-saved-attacker-executed"
    safe_codex = _write_test_executable(tmp_path / "safe-no-saved" / "codex", "#!/bin/sh\nexit 1\n")
    attacker_codex = _write_test_executable(
        tmp_path / "attacker-no-saved" / "codex",
        f"#!/bin/sh\nprintf attacked > {shlex.quote(str(marker))}\nexit 0\n",
    )
    executable_alias = tmp_path / "bin-no-saved" / "codex"
    executable_alias.parent.mkdir(parents=True)
    executable_alias.symlink_to(safe_codex)
    monkeypatch.setenv("PATH", f"{executable_alias.parent}{os.pathsep}{os.environ.get('PATH', '')}")

    class SwapAtAuthorizedSetupAdapter(CodexHarnessAdapter):
        def launch_command_from_authorized_plan(self, *args, **kwargs) -> list[str]:
            executable_alias.unlink()
            executable_alias.symlink_to(attacker_codex)
            return super().launch_command_from_authorized_plan(*args, **kwargs)

    monkeypatch.setattr(guard_runner_module, "detect_harness", lambda _harness, _context: detection)
    monkeypatch.setattr(
        guard_runner_module,
        "get_adapter",
        lambda _harness: SwapAtAuthorizedSetupAdapter(),
    )
    monkeypatch.setattr(codex_remote_control, "_start_direct_app_server", lambda **_kwargs: False)

    result = guard_runner_module.guard_run(
        "codex",
        HarnessContext(
            home_dir=tmp_path,
            workspace_dir=tmp_path / "workspace",
            guard_home=config.guard_home,
        ),
        store,
        config,
        dry_run=False,
        passthrough_args=[],
    )

    assert executable_alias.resolve() == attacker_codex.resolve()
    assert marker.exists() is False
    assert result["blocked"] is False
    assert result["launched"] is True
    assert result["launch_command"] == [str(Path("/bin/sh").resolve()), str(safe_codex.resolve())]


def test_guard_run_executes_in_previewed_canonical_cwd_after_workspace_symlink_retarget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved_workspace = tmp_path / "approved-workspace"
    attacker_workspace = tmp_path / "attacker-workspace"
    approved_workspace.mkdir()
    attacker_workspace.mkdir()
    workspace_alias = tmp_path / "workspace-alias"
    workspace_alias.symlink_to(approved_workspace, target_is_directory=True)
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace_alias,
        artifact_actions={artifact.artifact_id: "allow"},
    )
    store = GuardStore(config.guard_home)
    cwd_marker = tmp_path / "executed-cwd"
    command = [
        sys.executable,
        "-c",
        f"from pathlib import Path; Path({str(cwd_marker)!r}).write_text(str(Path.cwd()), encoding='utf-8')",
    ]
    events: list[str] = []

    class RetargetingAdapter:
        def preview_launch_commands(
            self,
            _context: HarnessContext,
            _args: list[str],
        ) -> tuple[list[str], ...]:
            events.append("preview")
            return (list(command),)

        def launch_command_from_authorized_plan(self, *_args, **_kwargs) -> list[str]:
            events.append("finalize")
            workspace_alias.unlink()
            workspace_alias.symlink_to(attacker_workspace, target_is_directory=True)
            return list(command)

        def prepare_launch_environment(
            self,
            _context: HarnessContext,
            inherited: dict[str, str],
        ) -> dict[str, str]:
            return dict(inherited)

    monkeypatch.setattr(guard_runner_module, "detect_harness", lambda _harness, _context: detection)
    monkeypatch.setattr(guard_runner_module, "get_adapter", lambda _harness: RetargetingAdapter())

    result = guard_runner_module.guard_run(
        "codex",
        HarnessContext(
            home_dir=tmp_path,
            workspace_dir=workspace_alias,
            guard_home=config.guard_home,
        ),
        store,
        config,
        dry_run=False,
        passthrough_args=[],
    )

    assert events == ["preview", "finalize"]
    assert workspace_alias.resolve() == attacker_workspace.resolve()
    assert cwd_marker.read_text(encoding="utf-8") == str(approved_workspace.resolve())
    assert result["blocked"] is False
    assert result["launched"] is True


def test_no_saved_pure_default_finalizer_launches_once_in_canonical_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    config = _config(tmp_path, action="allow")
    store = GuardStore(config.guard_home)
    workspace = tmp_path / "workspace"
    command_constructions: list[tuple[str, ...]] = []

    class PureDefaultAdapter(HarnessAdapter):
        def launch_command(self, _context: HarnessContext, args: list[str]) -> list[str]:
            command = (sys.executable, "-c", "pass", *args)
            command_constructions.append(command)
            return list(command)

        def prepare_launch_environment(
            self,
            _context: HarnessContext,
            inherited: dict[str, str],
        ) -> dict[str, str]:
            return dict(inherited)

    adapter = PureDefaultAdapter()
    executions: list[tuple[list[str], Path]] = []

    def execute(command: list[str], *, cwd: Path, **_kwargs) -> subprocess.CompletedProcess[str]:
        executions.append((list(command), cwd))
        return subprocess.CompletedProcess(args=command, returncode=0)

    monkeypatch.setattr(guard_runner_module, "detect_harness", lambda _harness, _context: detection)
    monkeypatch.setattr(guard_runner_module, "get_adapter", lambda _harness: adapter)
    monkeypatch.setattr(guard_runner_module.subprocess, "run", execute)

    result = guard_runner_module.guard_run(
        "codex",
        HarnessContext(home_dir=tmp_path, workspace_dir=workspace, guard_home=config.guard_home),
        store,
        config,
        dry_run=False,
        passthrough_args=[],
    )

    assert len(command_constructions) == 2
    assert executions == [([str(Path(sys.executable).resolve()), "-c", "pass"], workspace.resolve())]
    assert result["blocked"] is False
    assert result["launched"] is True


def test_grok_previews_do_not_register_and_final_setup_registers_once_after_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True)
    executable = _write_test_executable(tmp_path / "custom-tools" / "grok")
    artifact = replace(
        _artifact(tmp_path),
        artifact_id="grok:project:consumer-review",
        harness="grok",
    )
    detection = _detection(artifact)
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=workspace)
    store = GuardStore(config.guard_home)
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=workspace,
        guard_home=config.guard_home,
        executable_overrides={"grok": str(executable)},
    )
    registration = config.guard_home / "managed" / "grok" / "trusted-executable.json"
    initial = evaluate_detection(detection, store, config, persist=False)
    context_hash = str(initial["artifacts"][0]["approval_context_hash"])
    _record_once(store, artifact=artifact, context_hash=context_hash, workspace=workspace)
    events: list[str] = []

    class RecordingGrokAdapter(GrokHarnessAdapter):
        def preview_launch_commands(self, *args, **kwargs) -> tuple[list[str], ...]:
            events.append("preview")
            assert registration.exists() is False
            return super().preview_launch_commands(*args, **kwargs)

        def launch_command(self, *args, **kwargs) -> list[str]:
            events.append("launch-setup")
            return super().launch_command(*args, **kwargs)

    original_register = grok_adapter_module.register_trusted_grok_executable

    def register_once(*args, **kwargs):
        events.append("register")
        return original_register(*args, **kwargs)

    original_claim = store.claim_approval_reuse_decisions

    def claim_and_record(decisions, **kwargs) -> bool:
        events.append("claim")
        assert registration.exists() is False
        return original_claim(decisions, **kwargs)

    def execute(command, **_kwargs) -> subprocess.CompletedProcess[str]:
        events.append("execute")
        return subprocess.CompletedProcess(args=command, returncode=0)

    monkeypatch.setattr(grok_executable_module, "_executable_security_error", lambda *_args: None)
    monkeypatch.setattr(grok_adapter_module, "register_trusted_grok_executable", register_once)
    monkeypatch.setattr(guard_runner_module, "detect_harness", lambda _harness, _context: detection)
    monkeypatch.setattr(guard_runner_module, "get_adapter", lambda _harness: RecordingGrokAdapter())
    monkeypatch.setattr(store, "claim_approval_reuse_decisions", claim_and_record)
    monkeypatch.setattr(guard_runner_module.subprocess, "run", execute)

    result = guard_runner_module.guard_run(
        "grok",
        context,
        store,
        config,
        dry_run=False,
        passthrough_args=["--help"],
    )

    assert events == ["preview", "claim", "preview", "launch-setup", "register", "execute"]
    assert registration.is_file()
    assert result["blocked"] is False
    assert result["launched"] is True


def test_no_saved_grok_preview_registers_once_only_in_authorized_finalizer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True)
    executable = _write_test_executable(tmp_path / "custom-tools-no-saved" / "grok")
    artifact = replace(
        _artifact(tmp_path),
        artifact_id="grok:project:no-saved-consumer-review",
        harness="grok",
    )
    detection = _detection(artifact)
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        artifact_actions={artifact.artifact_id: "allow"},
    )
    store = GuardStore(config.guard_home)
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=workspace,
        guard_home=config.guard_home,
        executable_overrides={"grok": str(executable)},
    )
    registration = config.guard_home / "managed" / "grok" / "trusted-executable.json"
    events: list[str] = []

    class RecordingGrokAdapter(GrokHarnessAdapter):
        def preview_launch_commands(self, *args, **kwargs) -> tuple[list[str], ...]:
            events.append("preview")
            assert registration.exists() is False
            return super().preview_launch_commands(*args, **kwargs)

        def launch_command(self, *args, **kwargs) -> list[str]:
            events.append("launch-setup")
            return super().launch_command(*args, **kwargs)

    original_register = grok_adapter_module.register_trusted_grok_executable

    def register_once(*args, **kwargs):
        events.append("register")
        return original_register(*args, **kwargs)

    def execute(command, **_kwargs) -> subprocess.CompletedProcess[str]:
        events.append("execute")
        return subprocess.CompletedProcess(args=command, returncode=0)

    monkeypatch.setattr(grok_executable_module, "_executable_security_error", lambda *_args: None)
    monkeypatch.setattr(grok_adapter_module, "register_trusted_grok_executable", register_once)
    monkeypatch.setattr(guard_runner_module, "detect_harness", lambda _harness, _context: detection)
    monkeypatch.setattr(guard_runner_module, "get_adapter", lambda _harness: RecordingGrokAdapter())
    monkeypatch.setattr(guard_runner_module.subprocess, "run", execute)

    result = guard_runner_module.guard_run(
        "grok",
        context,
        store,
        config,
        dry_run=False,
        passthrough_args=["--help"],
    )

    assert events == ["preview", "launch-setup", "register", "execute"]
    assert registration.is_file()
    assert result["blocked"] is False
    assert result["launched"] is True


def test_guard_run_rejects_launch_plan_changed_after_saved_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    config = _config(tmp_path)
    store = GuardStore(tmp_path / "guard-home")
    initial = evaluate_detection(detection, store, config, persist=False)
    context_hash = str(initial["artifacts"][0]["approval_context_hash"])
    _record_once(store, artifact=artifact, context_hash=context_hash, workspace=tmp_path / "workspace")
    executable_alias = tmp_path / "claim-bound-python"
    executable_alias.symlink_to(Path(sys.executable).resolve())
    adapter_calls: list[tuple[str, ...]] = []

    class LaunchAdapter(HarnessAdapter):
        def launch_command(self, _context: HarnessContext, args: list[str]) -> list[str]:
            command = (str(executable_alias), "-c", "pass", *args)
            adapter_calls.append(command)
            return list(command)

        def prepare_launch_environment(
            self,
            _context: HarnessContext,
            inherited: dict[str, str],
        ) -> dict[str, str]:
            return dict(inherited)

    original_claim = store.claim_approval_reuse_decisions

    def claim_then_replace_executable(decisions, **kwargs) -> bool:
        claimed = original_claim(decisions, **kwargs)
        if claimed:
            executable_alias.unlink()
            executable_alias.symlink_to("/bin/echo")
        return claimed

    monkeypatch.setattr(guard_runner_module, "detect_harness", lambda _harness, _context: detection)
    monkeypatch.setattr(guard_runner_module, "get_adapter", lambda _harness: LaunchAdapter())
    monkeypatch.setattr(store, "claim_approval_reuse_decisions", claim_then_replace_executable)
    monkeypatch.setattr(
        guard_runner_module.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("a changed post-claim executable must not launch"),
    )

    result = guard_runner_module.guard_run(
        "codex",
        HarnessContext(
            home_dir=tmp_path,
            workspace_dir=tmp_path / "workspace",
            guard_home=tmp_path / "guard-home",
        ),
        store,
        config,
        dry_run=False,
        passthrough_args=[],
    )

    assert adapter_calls == [
        (str(executable_alias), "-c", "pass"),
        (str(executable_alias), "-c", "pass"),
    ]
    assert result["blocked"] is True
    assert result["launched"] is False
    assert result["approval_claim"]["reason_code"] == "approval_reuse_context_changed_after_claim"


def test_guard_run_reloads_local_config_after_claim_before_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    config = _config(tmp_path)
    store = GuardStore(tmp_path / "guard-home")
    initial = evaluate_detection(detection, store, config, persist=False)
    context_hash = str(initial["artifacts"][0]["approval_context_hash"])
    _record_once(store, artifact=artifact, context_hash=context_hash, workspace=tmp_path / "workspace")
    config_path = store.guard_home / "config.toml"
    original_claim = store.claim_approval_reuse_decisions

    def claim_then_block(decisions, **kwargs) -> bool:
        claimed = original_claim(decisions, **kwargs)
        if claimed:
            config_path.write_text(
                f'[artifacts]\n"{artifact.artifact_id}" = "block"\n',
                encoding="utf-8",
            )
        return claimed

    config_refreshes: list[GuardConfig] = []

    def current_config() -> GuardConfig:
        fresh = load_guard_config(store.guard_home, workspace=tmp_path / "workspace")
        config_refreshes.append(fresh)
        return fresh

    monkeypatch.setattr(guard_runner_module, "detect_harness", lambda _harness, _context: detection)
    monkeypatch.setattr(store, "claim_approval_reuse_decisions", claim_then_block)
    monkeypatch.setattr(
        guard_runner_module.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("a stronger refreshed config must not launch"),
    )

    result = guard_runner_module.guard_run(
        "codex",
        HarnessContext(
            home_dir=tmp_path,
            workspace_dir=tmp_path / "workspace",
            guard_home=tmp_path / "guard-home",
        ),
        store,
        config,
        dry_run=False,
        passthrough_args=[],
        current_config_provider=current_config,
    )

    assert len(config_refreshes) == 1
    assert config_refreshes[0].artifact_actions == {artifact.artifact_id: "block"}
    assert result["blocked"] is True
    assert result["launched"] is False
    assert result["approval_claim"]["reason_code"] == "approval_reuse_context_changed_after_claim"
    assert result["artifacts"][0]["policy_action"] == "block"
    assert result["artifacts"][0]["approval_reuse_reason_code"] == ("approval_reuse_context_changed_after_claim")


@pytest.mark.parametrize("terminal_action", ("block", "sandbox-required"))
def test_guard_run_reloads_current_config_after_unpersisted_interactive_allow_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    terminal_action: GuardAction,
) -> None:
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    initial_config = _config(tmp_path)
    current_config = _config(tmp_path, action=terminal_action)
    store = GuardStore(tmp_path / "guard-home")
    config_refreshes: list[GuardConfig] = []

    def allow_once(_detection: HarnessDetection, evaluation: dict[str, object]) -> dict[str, object]:
        items = evaluation.get("artifacts")
        assert isinstance(items, list)
        item = items[0]
        assert isinstance(item, dict)
        assert item["policy_action"] == "review"
        item["policy_action"] = "allow"
        item["user_override"] = "allow-once"
        evaluation["blocked"] = False
        return evaluation

    def reload_current_config() -> GuardConfig:
        config_refreshes.append(current_config)
        return current_config

    monkeypatch.setattr(guard_runner_module, "detect_harness", lambda _harness, _context: detection)
    monkeypatch.setattr(
        guard_runner_module.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("an allow-once approved under stale policy must not launch"),
    )

    result = guard_runner_module.guard_run(
        "codex",
        HarnessContext(
            home_dir=tmp_path,
            workspace_dir=tmp_path / "workspace",
            guard_home=tmp_path / "guard-home",
        ),
        store,
        initial_config,
        dry_run=False,
        passthrough_args=[],
        interactive_resolver=allow_once,
        current_config_provider=reload_current_config,
    )

    assert config_refreshes == [current_config]
    assert result["blocked"] is True
    assert result["launched"] is False
    item = result["artifacts"][0]
    assert item["policy_action"] == terminal_action
    assert item["decision_v2_json"]["action"] == ("ask" if terminal_action == "sandbox-required" else terminal_action)
    assert item["policy_composition"]["current_action"] == terminal_action
    assert item["policy_composition"]["trusted_request_override"] is False
    assert item["trusted_request_override"]["applied"] is False
    receipts = store.list_receipts(limit=10)
    assert len(receipts) == 1
    assert receipts[0]["policy_decision"] == terminal_action


def test_guard_run_redetects_interpreted_entrypoint_after_claim_before_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True)
    entrypoint = workspace / "claimed_entrypoint.py"
    entrypoint.write_text("print('approved')\n", encoding="utf-8")
    artifact = GuardArtifact(
        artifact_id="codex:project:claim-time-entrypoint",
        name="claim-time-entrypoint",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=str(workspace / ".codex" / "config.toml"),
        command=sys.executable,
        args=(str(entrypoint),),
        publisher="trusted-publisher",
        metadata={
            "guard_default_action": "review",
            "action_class": "claim-time entrypoint revalidation",
        },
    )
    detection = _detection(artifact)
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=workspace)
    store = GuardStore(tmp_path / "guard-home")
    initial = evaluate_detection(detection, store, config, persist=False)
    original_context_hash = str(initial["artifacts"][0]["approval_context_hash"])
    _record_once(store, artifact=artifact, context_hash=original_context_hash, workspace=workspace)
    detect_calls: list[str] = []

    def detect_current(harness: str, _context: HarnessContext) -> HarnessDetection:
        detect_calls.append(harness)
        return detection

    original_claim = store.claim_approval_reuse_decisions

    def claim_then_mutate(decisions, **kwargs) -> bool:
        claimed = original_claim(decisions, **kwargs)
        if claimed:
            entrypoint.write_text("print('changed after claim')\n", encoding="utf-8")
        return claimed

    monkeypatch.setattr(guard_runner_module, "detect_harness", detect_current)
    monkeypatch.setattr(store, "claim_approval_reuse_decisions", claim_then_mutate)
    monkeypatch.setattr(
        guard_runner_module.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("changed post-claim entrypoint must not launch"),
    )

    result = guard_runner_module.guard_run(
        "codex",
        HarnessContext(
            home_dir=tmp_path,
            workspace_dir=workspace,
            guard_home=tmp_path / "guard-home",
        ),
        store,
        config,
        dry_run=False,
        passthrough_args=[],
    )

    assert detect_calls == ["codex", "codex"]
    assert result["blocked"] is True
    assert result["launched"] is False
    assert result["approval_claim"] == {
        "status": "rejected",
        "reason_code": "approval_reuse_context_changed_after_claim",
        "artifact_ids": [artifact.artifact_id],
    }
    item = result["artifacts"][0]
    assert item["approval_context_hash"] != original_context_hash
    assert item["policy_action"] == "require-reapproval"
    assert item["decision_v2_json"]["action"] == "ask"
    assert item["decision_v2_json"]["reason"] == "approval_reuse_context_changed_after_claim"
    assert item["approval_reuse_status"] == "rejected"
    assert item["approval_reuse_reason_code"] == "approval_reuse_context_changed_after_claim"
    assert item["policy_composition"]["claim_revalidation"] == "changed"
    assert item["scanner_evidence"][-1] == {
        "source": "approval_reuse",
        "status": "rejected",
        "reason_code": "approval_reuse_context_changed_after_claim",
        "reason": "launch authority changed after the saved approval was claimed",
    }
    inventory = store.find_inventory_item(artifact.artifact_id)
    assert inventory is not None
    assert inventory["last_policy_action"] == "require-reapproval"
    assert inventory["last_approved_at"] is None
    assert store.get_snapshot("codex", artifact.artifact_id) is None
    receipts = store.list_receipts(harness="codex")
    assert len(receipts) == 1
    assert receipts[0]["policy_decision"] == "require-reapproval"
    assert receipts[0]["approval_source"] == "approval-reuse"
    assert receipts[0]["scanner_evidence"][-1] == item["scanner_evidence"][-1]
    assert (
        store.peek_local_once_approval(
            harness=artifact.harness,
            artifact_id=artifact.artifact_id,
            artifact_hash=original_context_hash,
            workspace=str(workspace),
            publisher=artifact.publisher,
            now="2026-07-17T00:01:00+00:00",
        )
        is None
    )


def test_guard_run_redetects_changed_mcp_command_immediately_after_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True)
    (workspace / "approved-server.js").write_text("console.log('approved');\n", encoding="utf-8")
    (workspace / "changed-server.py").write_text("print('changed')\n", encoding="utf-8")
    initial_artifact = GuardArtifact(
        artifact_id="codex:project:mcp:claim-time-command",
        name="claim-time-command",
        harness="codex",
        artifact_type="mcp_server",
        source_scope="project",
        config_path=str(workspace / ".codex" / "config.toml"),
        command="node",
        args=("approved-server.js",),
        transport="stdio",
        publisher="trusted-publisher",
    )
    changed_artifact = replace(initial_artifact, command="python", args=("changed-server.py",))
    initial_detection = _detection(initial_artifact)
    changed_detection = _detection(changed_artifact)
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        artifact_actions={initial_artifact.artifact_id: "review"},
    )
    store = GuardStore(tmp_path / "guard-home")
    initial = evaluate_detection(initial_detection, store, config, persist=False)
    original_context_hash = str(initial["artifacts"][0]["approval_context_hash"])
    _record_once(
        store,
        artifact=initial_artifact,
        context_hash=original_context_hash,
        workspace=workspace,
    )
    claim_completed = False
    detect_states: list[str] = []

    def detect_current(_harness: str, _context: HarnessContext) -> HarnessDetection:
        state = "post-claim" if claim_completed else "pre-claim"
        detect_states.append(state)
        return changed_detection if claim_completed else initial_detection

    original_claim = store.claim_approval_reuse_decisions

    def claim_and_expose_changed_config(decisions, **kwargs) -> bool:
        nonlocal claim_completed
        claimed = original_claim(decisions, **kwargs)
        claim_completed = claimed
        return claimed

    monkeypatch.setattr(guard_runner_module, "detect_harness", detect_current)
    monkeypatch.setattr(store, "claim_approval_reuse_decisions", claim_and_expose_changed_config)
    monkeypatch.setattr(
        guard_runner_module.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("changed post-claim MCP command must not launch"),
    )

    result = guard_runner_module.guard_run(
        "codex",
        HarnessContext(home_dir=tmp_path, workspace_dir=workspace, guard_home=tmp_path / "guard-home"),
        store,
        config,
        dry_run=False,
        passthrough_args=[],
    )

    assert detect_states == ["pre-claim", "post-claim"]
    assert result["blocked"] is True
    assert result["launched"] is False
    assert result["approval_claim"]["reason_code"] == "approval_reuse_context_changed_after_claim"
    item = result["artifacts"][0]
    assert item["approval_context_hash"] != original_context_hash
    assert item["policy_action"] == "require-reapproval"
    inventory = store.find_inventory_item(initial_artifact.artifact_id)
    assert inventory is not None
    assert inventory["launch_command"] == "python changed-server.py"
    assert inventory["last_policy_action"] == "require-reapproval"
    receipt = store.list_receipts(harness="codex")[0]
    assert receipt["policy_decision"] == "require-reapproval"
    assert receipt["scanner_evidence"][-1]["reason_code"] == "approval_reuse_context_changed_after_claim"


def test_guard_run_successful_persistent_exact_claim_finalizes_safe_persistence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    config = _config(tmp_path)
    store = GuardStore(tmp_path / "guard-home")
    initial = evaluate_detection(detection, store, config, persist=False)
    context_hash = str(initial["artifacts"][0]["approval_context_hash"])
    store.upsert_policy(
        PolicyDecision(
            harness=artifact.harness,
            scope="artifact",
            action="allow",
            artifact_id=artifact.artifact_id,
            artifact_hash=context_hash,
            workspace=str(tmp_path / "workspace"),
            publisher=artifact.publisher,
            source="approval-gate",
        ),
        "2026-07-17T00:00:00+00:00",
    )
    launch_calls: list[object] = []
    monkeypatch.setattr(guard_runner_module, "detect_harness", lambda _harness, _context: detection)
    monkeypatch.setattr(
        guard_runner_module.subprocess,
        "run",
        lambda *args, **kwargs: (
            launch_calls.append((args, kwargs)) or subprocess.CompletedProcess(args=[], returncode=0)
        ),
    )

    result = guard_runner_module.guard_run(
        "codex",
        HarnessContext(
            home_dir=tmp_path,
            workspace_dir=tmp_path / "workspace",
            guard_home=tmp_path / "guard-home",
        ),
        store,
        config,
        dry_run=False,
        passthrough_args=[],
    )

    inventory = store.find_inventory_item(artifact.artifact_id)
    remaining = store.resolve_policy_decision(
        artifact.harness,
        artifact.artifact_id,
        artifact_hash=context_hash,
        workspace=str(tmp_path / "workspace"),
        publisher=artifact.publisher,
        now="2026-07-17T00:01:00+00:00",
        consume_one_shot=False,
    )
    assert result["blocked"] is False
    assert result["launched"] is True
    assert launch_calls
    assert remaining is not None, "persistent exact approval must remain reusable after claim"
    assert artifact.artifact_id in store.list_snapshots(artifact.harness)
    assert inventory is not None
    assert isinstance(inventory["last_approved_at"], str)
    assert any(event["event_name"] == "approval.policy_reuse_applied" for event in store.list_events(limit=20))


def test_guard_run_retained_claim_disappearing_after_claim_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    config = _config(tmp_path)
    store = GuardStore(tmp_path / "guard-home")
    initial = evaluate_detection(detection, store, config, persist=False)
    context_hash = str(initial["artifacts"][0]["approval_context_hash"])
    store.upsert_policy(
        PolicyDecision(
            harness=artifact.harness,
            scope="artifact",
            action="allow",
            artifact_id=artifact.artifact_id,
            artifact_hash=context_hash,
            workspace=str(tmp_path / "workspace"),
            publisher=artifact.publisher,
            source="approval-gate",
        ),
        "2026-07-17T00:00:00+00:00",
    )
    original_claim = store.claim_approval_reuse_decisions

    def claim_then_delete_retained_row(decisions, **kwargs) -> bool:
        claimed = original_claim(decisions, **kwargs)
        if not claimed:
            return False
        decision_ids = [decision.get("decision_id") for decision in decisions]
        with store._connect() as connection:
            for decision_id in decision_ids:
                if isinstance(decision_id, int) and not isinstance(decision_id, bool):
                    connection.execute("delete from policy_decisions where decision_id = ?", (decision_id,))
        return True

    monkeypatch.setattr(guard_runner_module, "detect_harness", lambda _harness, _context: detection)
    monkeypatch.setattr(store, "claim_approval_reuse_decisions", claim_then_delete_retained_row)
    monkeypatch.setattr(
        guard_runner_module.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("missing retained approval must not be treated as consumed proof"),
    )

    result = guard_runner_module.guard_run(
        "codex",
        HarnessContext(
            home_dir=tmp_path,
            workspace_dir=tmp_path / "workspace",
            guard_home=tmp_path / "guard-home",
        ),
        store,
        config,
        dry_run=False,
        passthrough_args=[],
    )

    assert result["blocked"] is True
    assert result["launched"] is False
    assert result["approval_claim"]["reason_code"] == "approval_reuse_context_changed_after_claim"
    item = result["artifacts"][0]
    assert item["policy_action"] == "require-reapproval"
    assert item["approval_reuse_reason_code"] == "approval_reuse_context_changed_after_claim"
    assert artifact.artifact_id not in store.list_snapshots(artifact.harness)
    inventory = store.find_inventory_item(artifact.artifact_id)
    assert inventory is not None
    assert inventory["last_approved_at"] is None
    receipt = store.list_receipts(harness="codex")[0]
    assert receipt["policy_decision"] == "require-reapproval"
    assert receipt["scanner_evidence"][-1]["reason_code"] == "approval_reuse_context_changed_after_claim"


def test_guard_run_successful_reusable_exact_claim_finalizes_safe_persistence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = replace(
        _artifact(tmp_path),
        artifact_id="codex:project:package-request:consumer-review",
        name="reusable consumer review",
    )
    detection = _detection(artifact)
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=tmp_path / "workspace")
    store = GuardStore(tmp_path / "guard-home")
    initial = evaluate_detection(detection, store, config, persist=False)
    context_hash = str(initial["artifacts"][0]["approval_context_hash"])
    _record_once(
        store,
        artifact=artifact,
        context_hash=context_hash,
        workspace=tmp_path / "workspace",
        request_id="consumer-reusable-exact",
    )
    monkeypatch.setattr(guard_runner_module, "detect_harness", lambda _harness, _context: detection)
    monkeypatch.setattr(
        guard_runner_module.subprocess,
        "run",
        lambda *args, **_kwargs: subprocess.CompletedProcess(args=args, returncode=0),
    )

    result = guard_runner_module.guard_run(
        "codex",
        HarnessContext(
            home_dir=tmp_path,
            workspace_dir=tmp_path / "workspace",
            guard_home=tmp_path / "guard-home",
        ),
        store,
        config,
        dry_run=False,
        passthrough_args=[],
    )

    inventory = store.find_inventory_item(artifact.artifact_id)
    remaining = store.peek_local_once_approval(
        harness=artifact.harness,
        artifact_id=artifact.artifact_id,
        artifact_hash=context_hash,
        workspace=str(tmp_path / "workspace"),
        publisher=artifact.publisher,
        now="2026-07-17T00:01:00+00:00",
    )
    assert result["blocked"] is False
    assert result["launched"] is True
    assert remaining is not None, "reusable local approval must remain available after claim"
    assert artifact.artifact_id in store.list_snapshots(artifact.harness)
    assert inventory is not None
    assert isinstance(inventory["last_approved_at"], str)
    assert any(event["event_name"] == "approval.local_once_reused" for event in store.list_events(limit=20))


def test_guard_run_dry_run_never_claims_exact_saved_review_allow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    config = _config(tmp_path)
    store = GuardStore(tmp_path / "guard-home")
    initial = evaluate_detection(detection, store, config, persist=False)
    context_hash = str(initial["artifacts"][0]["approval_context_hash"])
    _record_once(store, artifact=artifact, context_hash=context_hash, workspace=tmp_path / "workspace")
    monkeypatch.setattr(guard_runner_module, "detect_harness", lambda _harness, _context: detection)

    result = guard_runner_module.guard_run(
        "codex",
        HarnessContext(
            home_dir=tmp_path,
            workspace_dir=tmp_path / "workspace",
            guard_home=tmp_path / "guard-home",
        ),
        store,
        config,
        dry_run=True,
        passthrough_args=[],
    )

    assert result["blocked"] is False
    assert result["launched"] is False
    assert artifact.artifact_id not in store.list_snapshots(artifact.harness)
    inventory = store.find_inventory_item(artifact.artifact_id)
    assert inventory is not None
    assert inventory["last_approved_at"] is None
    assert (
        store.peek_local_once_approval(
            harness=artifact.harness,
            artifact_id=artifact.artifact_id,
            artifact_hash=context_hash,
            workspace=str(tmp_path / "workspace"),
            publisher=artifact.publisher,
            now="2026-07-17T00:01:00+00:00",
        )
        is not None
    )


def test_guard_run_blocked_sibling_leaves_saved_review_allow_unclaimed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved_artifact = _artifact(tmp_path)
    blocked_artifact = replace(
        approved_artifact,
        artifact_id="codex:project:consumer-blocked-sibling",
        name="consumer-blocked-sibling",
    )
    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(approved_artifact.config_path,),
        artifacts=(approved_artifact, blocked_artifact),
    )
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
        artifact_actions={blocked_artifact.artifact_id: "block"},
    )
    store = GuardStore(tmp_path / "guard-home")
    initial = evaluate_detection(detection, store, config, persist=False)
    approved_item = next(item for item in initial["artifacts"] if item["artifact_id"] == approved_artifact.artifact_id)
    context_hash = str(approved_item["approval_context_hash"])
    _record_once(
        store,
        artifact=approved_artifact,
        context_hash=context_hash,
        workspace=tmp_path / "workspace",
    )
    monkeypatch.setattr(guard_runner_module, "detect_harness", lambda _harness, _context: detection)
    monkeypatch.setattr(
        guard_runner_module.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("blocked aggregate must not launch"),
    )

    result = guard_runner_module.guard_run(
        "codex",
        HarnessContext(
            home_dir=tmp_path,
            workspace_dir=tmp_path / "workspace",
            guard_home=tmp_path / "guard-home",
        ),
        store,
        config,
        dry_run=False,
        passthrough_args=[],
    )

    assert result["blocked"] is True
    assert result["launched"] is False
    assert (
        store.peek_local_once_approval(
            harness=approved_artifact.harness,
            artifact_id=approved_artifact.artifact_id,
            artifact_hash=context_hash,
            workspace=str(tmp_path / "workspace"),
            publisher=approved_artifact.publisher,
            now="2026-07-17T00:01:00+00:00",
        )
        is not None
    )


def test_guard_run_unverified_preclaim_launch_identity_is_persisted_separately_from_claim_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    config = _config(tmp_path)
    store = GuardStore(tmp_path / "guard-home")
    initial = evaluate_detection(detection, store, config, persist=False)
    context_hash = str(initial["artifacts"][0]["approval_context_hash"])
    _record_once(store, artifact=artifact, context_hash=context_hash, workspace=tmp_path / "workspace")
    claim_calls: list[object] = []

    class MissingLaunchAdapter(HarnessAdapter):
        def launch_command(self, _context: HarnessContext, args: list[str]) -> list[str]:
            return [str(tmp_path / "missing-harness-executable"), *args]

        def prepare_launch_environment(
            self,
            _context: HarnessContext,
            inherited: dict[str, str],
        ) -> dict[str, str]:
            return dict(inherited)

    monkeypatch.setattr(guard_runner_module, "detect_harness", lambda _harness, _context: detection)
    monkeypatch.setattr(guard_runner_module, "get_adapter", lambda _harness: MissingLaunchAdapter())
    monkeypatch.setattr(
        store,
        "claim_approval_reuse_decisions",
        lambda *_args, **_kwargs: claim_calls.append(object()) or True,
    )
    monkeypatch.setattr(
        guard_runner_module.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("an unverified launch identity must not launch"),
    )

    result = guard_runner_module.guard_run(
        "codex",
        HarnessContext(
            home_dir=tmp_path,
            workspace_dir=tmp_path / "workspace",
            guard_home=tmp_path / "guard-home",
        ),
        store,
        config,
        dry_run=False,
        passthrough_args=[],
    )

    assert claim_calls == []
    assert result["blocked"] is True
    assert result["launched"] is False
    assert result["approval_claim"] == {
        "status": "rejected",
        "reason_code": "approval_reuse_launch_identity_unverified",
        "artifact_ids": [artifact.artifact_id],
    }
    item = result["artifacts"][0]
    assert item["policy_action"] == "require-reapproval"
    assert item["approval_reuse_reason_code"] == "approval_reuse_launch_identity_unverified"
    assert item["policy_composition"]["claim_revalidation"] == "unverified"
    inventory = store.find_inventory_item(artifact.artifact_id)
    assert inventory is not None
    assert inventory["last_policy_action"] == "require-reapproval"
    assert inventory["last_approved_at"] is None
    receipt = store.list_receipts(harness="codex")[0]
    assert receipt["policy_decision"] == "require-reapproval"
    assert receipt["approval_source"] == "approval-reuse"
    assert receipt["scanner_evidence"][-1]["reason_code"] == "approval_reuse_launch_identity_unverified"
    assert (
        store.peek_local_once_approval(
            harness=artifact.harness,
            artifact_id=artifact.artifact_id,
            artifact_hash=context_hash,
            workspace=str(tmp_path / "workspace"),
            publisher=artifact.publisher,
            now="2026-07-17T00:01:00+00:00",
        )
        is not None
    )


def test_guard_run_atomic_claim_exception_is_persisted_without_error_disclosure_or_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    config = _config(tmp_path)
    store = GuardStore(config.guard_home)
    initial = evaluate_detection(detection, store, config, persist=False)
    context_hash = str(initial["artifacts"][0]["approval_context_hash"])
    _record_once(store, artifact=artifact, context_hash=context_hash, workspace=tmp_path / "workspace")
    raw_database_error = "raw sqlite detail: guard_local_once_approvals disk image is malformed"

    def raise_claim_error(*_args, **_kwargs) -> bool:
        raise sqlite3.OperationalError(raw_database_error)

    monkeypatch.setattr(guard_runner_module, "detect_harness", lambda _harness, _context: detection)
    monkeypatch.setattr(store, "claim_approval_reuse_decisions", raise_claim_error)
    monkeypatch.setattr(
        guard_runner_module.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("an exceptional approval claim must not launch"),
    )

    result = guard_runner_module.guard_run(
        "codex",
        HarnessContext(
            home_dir=tmp_path,
            workspace_dir=tmp_path / "workspace",
            guard_home=config.guard_home,
        ),
        store,
        config,
        dry_run=False,
        passthrough_args=[],
    )

    assert result["blocked"] is True
    assert result["launched"] is False
    assert result["launch_command"] == []
    assert result["approval_claim"]["reason_code"] == "approval_reuse_claim_failed"
    assert raw_database_error not in json.dumps(result, sort_keys=True, default=str)
    receipt = store.list_receipts(harness="codex")[0]
    assert receipt["policy_decision"] == "require-reapproval"
    assert receipt["scanner_evidence"][-1]["reason_code"] == "approval_reuse_claim_failed"


def test_guard_run_batch_claim_failure_consumes_no_saved_review_allow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_artifact = _artifact(tmp_path)
    second_artifact = replace(
        first_artifact,
        artifact_id="codex:project:consumer-review-second",
        name="consumer-review-second",
    )
    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(first_artifact.config_path,),
        artifacts=(first_artifact, second_artifact),
    )
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=tmp_path / "workspace")
    store = GuardStore(tmp_path / "guard-home")
    initial = evaluate_detection(detection, store, config, persist=False)
    context_hashes = {str(item["artifact_id"]): str(item["approval_context_hash"]) for item in initial["artifacts"]}
    for index, artifact in enumerate(detection.artifacts):
        _record_once(
            store,
            artifact=artifact,
            context_hash=context_hashes[artifact.artifact_id],
            workspace=tmp_path / "workspace",
            request_id=f"consumer-review-once-{index}",
        )
    claim_calls: list[tuple[object, ...]] = []

    def fail_batch_claim(decisions, **_kwargs) -> bool:
        claim_calls.append(tuple(decisions))
        return False

    monkeypatch.setattr(store, "claim_approval_reuse_decisions", fail_batch_claim)
    monkeypatch.setattr(guard_runner_module, "detect_harness", lambda _harness, _context: detection)
    monkeypatch.setattr(
        guard_runner_module.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("failed approval claim must not launch"),
    )

    result = guard_runner_module.guard_run(
        "codex",
        HarnessContext(
            home_dir=tmp_path,
            workspace_dir=tmp_path / "workspace",
            guard_home=tmp_path / "guard-home",
        ),
        store,
        config,
        dry_run=False,
        passthrough_args=[],
    )

    assert result["blocked"] is True
    assert result["launched"] is False
    assert result["approval_claim"]["reason_code"] == "approval_reuse_claim_failed"
    assert len(claim_calls) == 1
    assert len(claim_calls[0]) == 2
    for item in result["artifacts"]:
        assert item["policy_action"] == "require-reapproval"
        assert item["approval_reuse_status"] == "rejected"
        assert item["approval_reuse_reason_code"] == "approval_reuse_claim_failed"
        assert item["approval_reuse"]["action"] == "require-reapproval"
        assert item["approval_reuse"]["should_claim"] is False
        assert item["decision_v2_json"]["action"] == "ask"
        assert item["decision_v2_json"]["reason"] == "approval_reuse_claim_failed"
        assert item["policy_composition"]["final_action"] == "require-reapproval"
        assert item["policy_composition"]["claim_revalidation"] == "claim-failed"
        assert item["scanner_evidence"][-1]["reason_code"] == "approval_reuse_claim_failed"
    for artifact in detection.artifacts:
        inventory = store.find_inventory_item(artifact.artifact_id)
        assert inventory is not None
        assert inventory["last_policy_action"] == "require-reapproval"
        assert inventory["last_approved_at"] is None
        assert (
            store.peek_local_once_approval(
                harness=artifact.harness,
                artifact_id=artifact.artifact_id,
                artifact_hash=context_hashes[artifact.artifact_id],
                workspace=str(tmp_path / "workspace"),
                publisher=artifact.publisher,
                now="2026-07-17T00:01:00+00:00",
            )
            is not None
        )
    assert store.list_snapshots("codex") == {}
    receipts = store.list_receipts(harness="codex")
    assert {receipt["artifact_id"] for receipt in receipts} == {
        first_artifact.artifact_id,
        second_artifact.artifact_id,
    }
    for receipt in receipts:
        assert receipt["policy_decision"] == "require-reapproval"
        assert receipt["approval_source"] == "approval-reuse"
        assert receipt["scanner_evidence"][-1]["reason_code"] == "approval_reuse_claim_failed"


def test_fresh_trusted_request_override_allows_only_the_exact_current_reapproval(
    tmp_path: Path,
) -> None:
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    config = _config(tmp_path, action="require-reapproval")
    store = GuardStore(tmp_path / "guard-home")
    initial = evaluate_detection(detection, store, config, persist=False)
    context_hash = str(initial["artifacts"][0]["approval_context_hash"])

    result = evaluate_detection(
        detection,
        store,
        config,
        persist=True,
        trusted_request_overrides={artifact.artifact_id: context_hash},
    )
    item = result["artifacts"][0]
    receipt = store.list_receipts(limit=1)[0]

    assert result["blocked"] is False
    assert item["policy_action"] == "allow"
    assert item["policy_composition"]["current_action"] == "require-reapproval"
    assert item["policy_composition"]["trusted_request_override"] is True
    assert item["approval_reuse_reason_code"] == "approval_reuse_no_saved_decision"
    assert item["trusted_request_override"] == {
        "applied": True,
        "reason_code": "trusted_request_override_exact_context",
    }
    assert item["scanner_evidence"][-1]["reason_code"] == "trusted_request_override_exact_context"
    assert receipt["policy_decision"] == "allow"
    assert receipt["approval_source"] == "fresh-approval"


@pytest.mark.parametrize("terminal_action", ("sandbox-required", "block"))
def test_fresh_trusted_request_override_cannot_lower_terminal_current_action(
    tmp_path: Path,
    terminal_action: GuardAction,
) -> None:
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    config = _config(tmp_path, action=terminal_action)
    store = GuardStore(tmp_path / "guard-home")
    initial = evaluate_detection(detection, store, config, persist=False)
    context_hash = str(initial["artifacts"][0]["approval_context_hash"])

    result = evaluate_detection(
        detection,
        store,
        config,
        persist=False,
        trusted_request_overrides={artifact.artifact_id: context_hash},
    )
    item = result["artifacts"][0]

    assert result["blocked"] is True
    assert item["policy_action"] == terminal_action
    assert item["policy_composition"]["trusted_request_override"] is False
    assert item["trusted_request_override"]["applied"] is False


def test_fresh_trusted_request_override_rejects_changed_context_token(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    config = _config(tmp_path)
    store = GuardStore(tmp_path / "guard-home")
    initial = evaluate_detection(detection, store, config, persist=False)
    context_hash = str(initial["artifacts"][0]["approval_context_hash"])
    artifact_script = tmp_path / "workspace" / "consumer-review.js"
    artifact_script.write_text("console.log('changed');\n", encoding="utf-8")

    result = evaluate_detection(
        detection,
        store,
        config,
        persist=False,
        trusted_request_overrides={artifact.artifact_id: context_hash},
    )
    item = result["artifacts"][0]

    assert result["blocked"] is True
    assert item["policy_action"] == "review"
    assert item["approval_context_hash"] != context_hash
    assert item["policy_composition"]["trusted_request_override"] is False


@pytest.mark.parametrize(
    ("stronger_action", "reason_code"),
    (
        ("require-reapproval", "approval_reuse_reapproval_required"),
        ("sandbox-required", "approval_reuse_sandbox_required"),
        ("block", "approval_reuse_current_block"),
    ),
)
def test_matching_saved_allow_is_composed_non_consumingly_before_any_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stronger_action: GuardAction,
    reason_code: str,
) -> None:
    artifact = _artifact(tmp_path)
    store = GuardStore(tmp_path / "guard-home")

    def exact_saved_allow(*_args: object, **kwargs: object) -> dict[str, object]:
        assert kwargs["consume_one_shot"] is False
        return {
            "decision": {
                "action": "allow",
                "artifact_hash": kwargs["artifact_hash"],
                "decision_id": 777,
                "source": "approval-gate",
            },
            "ignored_local_integrity": None,
            "trust_status": {},
        }

    monkeypatch.setattr(store, "resolve_policy_decision_lookup_with_memory_pattern", exact_saved_allow)

    def reject_early_claim(*_args: object, **_kwargs: object) -> bool:
        raise AssertionError("strong current action must be composed before claim")

    monkeypatch.setattr(store, "claim_approval_reuse_decision", reject_early_claim)

    result = evaluate_detection(
        _detection(artifact),
        store,
        _config(tmp_path, action=stronger_action),
        persist=False,
    )
    item = result["artifacts"][0]

    assert item["policy_action"] == stronger_action
    assert item["approval_reuse_status"] == "rejected"
    assert item["approval_reuse_reason_code"] == reason_code


def test_evaluation_records_exact_saved_allow_without_claiming_before_launch(
    tmp_path: Path,
) -> None:
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    config = _config(tmp_path)
    store = GuardStore(tmp_path / "guard-home")
    initial = evaluate_detection(detection, store, config, persist=False)
    context_hash = str(initial["artifacts"][0]["approval_context_hash"])
    _record_once(
        store,
        artifact=artifact,
        context_hash=context_hash,
        workspace=tmp_path / "workspace",
    )

    preview = evaluate_detection(detection, store, config, persist=False)
    preview_item = preview["artifacts"][0]
    assert preview_item["policy_action"] == "allow"
    assert preview_item["approval_reuse_status"] == "accepted"
    assert (
        store.peek_local_once_approval(
            harness=artifact.harness,
            artifact_id=artifact.artifact_id,
            artifact_hash=context_hash,
            workspace=str(tmp_path / "workspace"),
            publisher=artifact.publisher,
            now="2026-07-17T00:01:00+00:00",
        )
        is not None
    )

    result = evaluate_detection(detection, store, config, persist=True)
    item = result["artifacts"][0]
    receipt = store.list_receipts(limit=1)[0]

    assert item["approval_context_hash"] == context_hash
    assert item["policy_action"] == "allow"
    assert item["approval_reuse_status"] == "accepted"
    assert item["approval_reuse_reason_code"] == "approval_reuse_accepted"
    assert item["policy_composition"] == {
        "configured_action": None,
        "current_action": "review",
        "saved_action": "allow",
        "saved_state_present": True,
        "scanner_action": item["verdict_action"],
        "scoring_recommendation": item["verdict_action"],
        "final_action": "allow",
        "trusted_request_override": False,
    }
    assert result["blocked"] is False
    assert receipt["policy_decision"] == "allow"
    assert receipt["approval_source"] == "saved-approval"
    assert receipt["scanner_evidence"][-1]["reason_code"] == "approval_reuse_accepted"
    assert artifact.artifact_id not in store.list_snapshots(artifact.harness)
    inventory = store.find_inventory_item(artifact.artifact_id)
    assert inventory is not None
    assert inventory["last_approved_at"] is None
    assert (
        store.peek_local_once_approval(
            harness=artifact.harness,
            artifact_id=artifact.artifact_id,
            artifact_hash=context_hash,
            workspace=str(tmp_path / "workspace"),
            publisher=artifact.publisher,
            now="2026-07-17T00:01:00+00:00",
        )
        is not None
    )


def test_changed_context_cannot_use_stale_claim_proof_to_finalize_persistence(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    config = _config(tmp_path)
    store = GuardStore(tmp_path / "guard-home")
    initial = evaluate_detection(detection, store, config, persist=False)
    old_context_hash = str(initial["artifacts"][0]["approval_context_hash"])
    _record_once(
        store,
        artifact=artifact,
        context_hash=old_context_hash,
        workspace=tmp_path / "workspace",
    )
    (tmp_path / "workspace" / "consumer-review.js").write_text(
        "console.log('changed after claim');\n",
        encoding="utf-8",
    )

    result = evaluate_detection(
        detection,
        store,
        config,
        persist=True,
        claimed_saved_approval_overrides={artifact.artifact_id: old_context_hash},
    )

    item = result["artifacts"][0]
    inventory = store.find_inventory_item(artifact.artifact_id)
    assert item["approval_context_hash"] != old_context_hash
    assert item["policy_action"] == "review"
    assert item["approval_reuse_status"] == "rejected"
    assert artifact.artifact_id not in store.list_snapshots(artifact.harness)
    assert inventory is not None
    assert inventory["last_approved_at"] is None


def test_exact_claim_proof_cannot_override_saved_block_visible_during_persistence(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    config = _config(tmp_path)
    store = GuardStore(tmp_path / "guard-home")
    initial = evaluate_detection(detection, store, config, persist=False)
    context_hash = str(initial["artifacts"][0]["approval_context_hash"])
    store.upsert_policy(
        PolicyDecision(
            harness=artifact.harness,
            scope="artifact",
            action="block",
            artifact_id=artifact.artifact_id,
            artifact_hash=context_hash,
            workspace=str(tmp_path / "workspace"),
            publisher=artifact.publisher,
            source="approval-gate",
        ),
        "2026-07-17T00:00:00+00:00",
    )

    result = evaluate_detection(
        detection,
        store,
        config,
        persist=True,
        claimed_saved_approval_overrides={artifact.artifact_id: context_hash},
    )

    item = result["artifacts"][0]
    inventory = store.find_inventory_item(artifact.artifact_id)
    assert item["approval_context_hash"] == context_hash
    assert item["policy_action"] == "block"
    assert item["approval_reuse_reason_code"] == "approval_reuse_saved_block"
    assert artifact.artifact_id not in store.list_snapshots(artifact.harness)
    assert inventory is not None
    assert inventory["last_approved_at"] is None


def test_retained_claim_proof_requires_fresh_exact_allow_during_persistence(
    tmp_path: Path,
) -> None:
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    config = _config(tmp_path)
    store = GuardStore(tmp_path / "guard-home")
    initial = evaluate_detection(detection, store, config, persist=False)
    context_hash = str(initial["artifacts"][0]["approval_context_hash"])

    result = evaluate_detection(
        detection,
        store,
        config,
        persist=True,
        retained_saved_approval_overrides={artifact.artifact_id: context_hash},
    )

    item = result["artifacts"][0]
    inventory = store.find_inventory_item(artifact.artifact_id)
    assert item["approval_context_hash"] == context_hash
    assert item["policy_action"] == "review"
    assert item["approval_reuse_reason_code"] == "approval_reuse_no_saved_decision"
    assert artifact.artifact_id not in store.list_snapshots(artifact.harness)
    assert inventory is not None
    assert inventory["last_approved_at"] is None


def _with_runtime_detector_telemetry(
    evaluation: dict[str, object],
    *,
    status: str,
    elapsed_ms: int,
    error_type: str | None = None,
) -> dict[str, object]:
    return {
        **evaluation,
        "runtime_detector_signals_v2": [],
        "runtime_detector_telemetry": [
            {
                "detector_id": "semantic.detector",
                "categories": ["execution", "bypass"],
                "status": status,
                "elapsed_ms": elapsed_ms,
                "error_type": error_type,
                "semantic_revision": "v1",
            }
        ],
        "runtime_detector_composition": {
            "action": "allow",
            "reason": "no detector signal",
            "downgraded": False,
            "upgraded": False,
        },
    }


def test_runtime_detector_context_excludes_only_elapsed_and_normalizes_semantics() -> None:
    context = guard_runner_module._runtime_detector_context(
        _with_runtime_detector_telemetry(
            {"blocked": False, "artifacts": []},
            status="ok",
            elapsed_ms=917,
        )
    )

    assert context is not None
    assert context["telemetry"] == [
        {
            "detector_id": "semantic.detector",
            "categories": ["bypass", "execution"],
            "status": "ok",
            "error_type": None,
            "semantic_revision": "v1",
        }
    ]


@pytest.mark.parametrize(
    ("postclaim_status", "postclaim_error_type"),
    (("timeout", None), ("error", "RuntimeError")),
    ids=("ok-to-timeout", "ok-to-error"),
)
def test_runtime_detector_telemetry_status_change_after_claim_prevents_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    postclaim_status: str,
    postclaim_error_type: str | None,
) -> None:
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    config = _config(tmp_path)
    store = GuardStore(config.guard_home)
    initial_base = evaluate_detection(detection, store, config, persist=False)
    initial_detector_evaluation = _with_runtime_detector_telemetry(
        initial_base,
        status="ok",
        elapsed_ms=1,
    )
    initial_detector_context = guard_runner_module._runtime_detector_context(initial_detector_evaluation)
    assert initial_detector_context is not None
    initial = evaluate_detection(
        detection,
        store,
        config,
        persist=False,
        runtime_detector_context=initial_detector_context,
    )
    context_hash = str(initial["artifacts"][0]["approval_context_hash"])
    _record_once(store, artifact=artifact, context_hash=context_hash, workspace=tmp_path / "workspace")
    detector_runs = iter((("ok", 12, None), (postclaim_status, 987, postclaim_error_type)))

    def detector_evaluation(evaluation, *_args):
        status, elapsed_ms, error_type = next(detector_runs)
        return _with_runtime_detector_telemetry(
            evaluation,
            status=status,
            elapsed_ms=elapsed_ms,
            error_type=error_type,
        )

    monkeypatch.setattr(guard_runner_module, "detect_harness", lambda _harness, _context: detection)
    monkeypatch.setattr(guard_runner_module, "_evaluation_with_detector_registry", detector_evaluation)
    monkeypatch.setattr(
        guard_runner_module.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("changed detector execution status must prevent launch"),
    )

    result = guard_runner_module.guard_run(
        "codex",
        HarnessContext(
            home_dir=tmp_path,
            workspace_dir=tmp_path / "workspace",
            guard_home=config.guard_home,
        ),
        store,
        config,
        dry_run=False,
        passthrough_args=[],
    )

    assert result["blocked"] is True
    assert result["launched"] is False
    assert result["approval_claim"]["reason_code"] == "approval_reuse_context_changed_after_claim"
    assert result["runtime_detector_telemetry"][0]["status"] == postclaim_status
    assert result["runtime_detector_telemetry"][0]["error_type"] == postclaim_error_type


def test_runtime_detector_unchanged_status_ignores_elapsed_ms_and_launches_after_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    config = _config(tmp_path)
    store = GuardStore(config.guard_home)
    initial_base = evaluate_detection(detection, store, config, persist=False)
    initial_detector_evaluation = _with_runtime_detector_telemetry(
        initial_base,
        status="ok",
        elapsed_ms=1,
    )
    initial_detector_context = guard_runner_module._runtime_detector_context(initial_detector_evaluation)
    assert initial_detector_context is not None
    initial = evaluate_detection(
        detection,
        store,
        config,
        persist=False,
        runtime_detector_context=initial_detector_context,
    )
    context_hash = str(initial["artifacts"][0]["approval_context_hash"])
    _record_once(store, artifact=artifact, context_hash=context_hash, workspace=tmp_path / "workspace")
    elapsed_values = iter((19, 991))

    def detector_evaluation(evaluation, *_args):
        return _with_runtime_detector_telemetry(
            evaluation,
            status="ok",
            elapsed_ms=next(elapsed_values),
        )

    launches: list[list[str]] = []

    def launch(command: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        launches.append(list(command))
        return subprocess.CompletedProcess(args=command, returncode=0)

    monkeypatch.setattr(guard_runner_module, "detect_harness", lambda _harness, _context: detection)
    monkeypatch.setattr(guard_runner_module, "_evaluation_with_detector_registry", detector_evaluation)
    monkeypatch.setattr(guard_runner_module.subprocess, "run", launch)

    result = guard_runner_module.guard_run(
        "codex",
        HarnessContext(
            home_dir=tmp_path,
            workspace_dir=tmp_path / "workspace",
            guard_home=config.guard_home,
        ),
        store,
        config,
        dry_run=False,
        passthrough_args=[],
    )

    assert result["blocked"] is False
    assert result["launched"] is True
    assert result["runtime_detector_telemetry"][0]["elapsed_ms"] == 991
    assert len(launches) == 1


def test_runtime_detector_signal_change_invalidates_exact_saved_approval(
    tmp_path: Path,
) -> None:
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    config = _config(tmp_path)
    store = GuardStore(tmp_path / "guard-home")
    first_detector_context = {
        "composition": {"action": "review", "reason": "persistence signal alpha"},
        "signals": [{"detector_id": "persistence", "signal_id": "alpha"}],
    }
    second_detector_context = {
        "composition": {"action": "review", "reason": "persistence signal beta"},
        "signals": [{"detector_id": "persistence", "signal_id": "beta"}],
    }
    first = evaluate_detection(
        detection,
        store,
        config,
        persist=False,
        runtime_detector_context=first_detector_context,
    )
    first_context_hash = str(first["artifacts"][0]["approval_context_hash"])
    _record_once(
        store,
        artifact=artifact,
        context_hash=first_context_hash,
        workspace=tmp_path / "workspace",
    )

    unchanged = evaluate_detection(
        detection,
        store,
        config,
        persist=False,
        runtime_detector_context=first_detector_context,
    )
    changed = evaluate_detection(
        detection,
        store,
        config,
        persist=False,
        runtime_detector_context=second_detector_context,
    )

    assert unchanged["artifacts"][0]["approval_context_hash"] == first_context_hash
    assert unchanged["artifacts"][0]["policy_action"] == "allow"
    assert changed["artifacts"][0]["approval_context_hash"] != first_context_hash
    assert changed["artifacts"][0]["policy_action"] == "review"
    assert changed["artifacts"][0]["approval_reuse_reason_code"] == ("approval_reuse_capability_changed")
    assert (
        store.peek_local_once_approval(
            harness=artifact.harness,
            artifact_id=artifact.artifact_id,
            artifact_hash=first_context_hash,
            workspace=str(tmp_path / "workspace"),
            publisher=artifact.publisher,
            now="2026-07-17T00:01:00+00:00",
        )
        is not None
    )


def test_changed_sandbox_context_rejects_review_allow_without_consuming_it(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    baseline_config = _config(tmp_path)
    store = GuardStore(tmp_path / "guard-home")
    initial = evaluate_detection(detection, store, baseline_config, persist=False)
    context_hash = str(initial["artifacts"][0]["approval_context_hash"])
    _record_once(
        store,
        artifact=artifact,
        context_hash=context_hash,
        workspace=tmp_path / "workspace",
    )
    changed_config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
        sandbox_analysis="strict",
    )

    result = evaluate_detection(detection, store, changed_config, persist=False)
    item = result["artifacts"][0]

    assert item["policy_action"] == "review"
    assert item["approval_reuse_status"] == "rejected"
    assert item["approval_reuse_reason_code"] == "approval_reuse_sandbox_changed"
    assert (
        store.peek_local_once_approval(
            harness=artifact.harness,
            artifact_id=artifact.artifact_id,
            artifact_hash=context_hash,
            workspace=str(tmp_path / "workspace"),
            publisher=artifact.publisher,
            now="2026-07-17T00:01:00+00:00",
        )
        is not None
    )


def test_changed_effective_workspace_rejects_review_allow_as_identity_change(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    baseline_config = _config(tmp_path)
    store = GuardStore(tmp_path / "guard-home")
    initial = evaluate_detection(detection, store, baseline_config, persist=False)
    context_hash = str(initial["artifacts"][0]["approval_context_hash"])
    _record_once(
        store,
        artifact=artifact,
        context_hash=context_hash,
        workspace=tmp_path / "workspace",
    )
    changed_config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "different-workspace",
    )

    result = evaluate_detection(detection, store, changed_config, persist=False)
    item = result["artifacts"][0]

    assert item["policy_action"] == "review"
    assert item["approval_reuse_status"] == "rejected"
    assert item["approval_reuse_reason_code"] == "approval_reuse_identity_changed"
    assert (
        store.peek_local_once_approval(
            harness=artifact.harness,
            artifact_id=artifact.artifact_id,
            artifact_hash=context_hash,
            workspace=str(tmp_path / "workspace"),
            publisher=artifact.publisher,
            now="2026-07-17T00:01:00+00:00",
        )
        is not None
    )


def test_changed_scanner_provenance_rejects_review_allow_as_capability_change(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    config = _config(tmp_path)
    store = GuardStore(tmp_path / "guard-home")
    initial = evaluate_detection(detection, store, config, persist=False)
    context_hash = str(initial["artifacts"][0]["approval_context_hash"])
    _record_once(
        store,
        artifact=artifact,
        context_hash=context_hash,
        workspace=tmp_path / "workspace",
    )
    store.cache_advisories(
        [
            {
                "id": "consumer-provenance-block",
                "publisher": artifact.publisher,
                "severity": "high",
                "action": "block",
                "headline": "Publisher trust changed after approval.",
            }
        ],
        "2026-07-17T00:01:00+00:00",
    )

    result = evaluate_detection(detection, store, config, persist=False)
    item = result["artifacts"][0]

    assert item["policy_action"] == "block"
    assert item["policy_composition"]["current_action"] == "block"
    assert item["policy_composition"]["scanner_action"] == "block"
    assert item["approval_reuse_status"] == "rejected"
    assert item["approval_reuse_reason_code"] == "approval_reuse_capability_changed"
    assert item["provenance"]["publisher_trust"] == "flagged"
    assert result["blocked"] is True
    assert (
        store.peek_local_once_approval(
            harness=artifact.harness,
            artifact_id=artifact.artifact_id,
            artifact_hash=context_hash,
            workspace=str(tmp_path / "workspace"),
            publisher=artifact.publisher,
            now="2026-07-17T00:02:00+00:00",
        )
        is not None
    )


def test_saved_block_remains_authoritative_after_current_review_is_computed(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    store = GuardStore(tmp_path / "guard-home")
    store.upsert_policy(
        PolicyDecision(
            harness=artifact.harness,
            scope="artifact",
            action="block",
            artifact_id=artifact.artifact_id,
            reason="intentional saved block",
        ),
        "2026-07-17T00:00:00+00:00",
    )

    result = evaluate_detection(detection, store, _config(tmp_path), persist=False)
    item = result["artifacts"][0]

    assert item["policy_composition"]["current_action"] == "review"
    assert item["policy_composition"]["saved_action"] == "block"
    assert item["policy_action"] == "block"
    assert item["approval_reuse_reason_code"] == "approval_reuse_saved_block"
    assert result["blocked"] is True


def test_consumer_current_allow_and_exact_allow_do_not_hide_tampered_broader_authority(
    tmp_path: Path,
) -> None:
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    store = GuardStore(tmp_path / "guard-home")
    config = _config(tmp_path, action="allow")
    initial = evaluate_detection(detection, store, config, persist=False)
    initial_item = initial["artifacts"][0]
    context_hash = str(initial_item["approval_context_hash"])
    assert initial_item["policy_composition"]["current_action"] == "allow"
    approval_id = _record_once(
        store,
        artifact=artifact,
        context_hash=context_hash,
        workspace=tmp_path / "workspace",
        request_id="consumer-current-allow-integrity-collision",
    )
    store.upsert_policy(
        PolicyDecision(
            harness=artifact.harness,
            scope="global",
            action="block",
            reason="tampered broader authority must not be ignored",
            source="manual",
        ),
        "2026-07-17T00:01:00+00:00",
    )
    broader_block = next(
        item
        for item in store.list_policy_decisions(artifact.harness)
        if item["scope"] == "global" and item["action"] == "block"
    )
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "update policy_decisions set payload_mac = ? where decision_id = ?",
            ("00", broader_block["decision_id"]),
        )

    result = evaluate_detection(detection, store, config, persist=False)
    item = result["artifacts"][0]
    with sqlite3.connect(store.path) as connection:
        claimed_at = connection.execute(
            "select claimed_at from guard_local_once_approvals where approval_id = ?",
            (approval_id,),
        ).fetchone()[0]

    assert item["policy_composition"]["current_action"] == "allow"
    assert item["policy_composition"]["saved_action"] == "allow"
    assert item["policy_action"] == "require-reapproval"
    assert item["approval_reuse_status"] == "rejected"
    assert item["approval_reuse_reason_code"] == "approval_reuse_integrity_failure"
    assert result["blocked"] is True
    assert claimed_at is None


def test_consumer_current_allow_detects_tampered_block_moved_out_of_exact_lookup(
    tmp_path: Path,
) -> None:
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    store = GuardStore(tmp_path / "guard-home")
    config = _config(tmp_path, action="allow")
    initial_item = evaluate_detection(detection, store, config, persist=False)["artifacts"][0]
    current_context = str(initial_item["approval_context_hash"])
    store.upsert_policy(
        PolicyDecision(
            harness=artifact.harness,
            scope="artifact",
            action="block",
            artifact_id=artifact.artifact_id,
            artifact_hash=current_context,
            reason="signed block moved by local database tampering",
            source="manual",
        ),
        "2026-07-17T00:01:00+00:00",
    )
    moved_context = build_approval_context_token(
        identity={"artifact_id": artifact.artifact_id},
        content={"artifact_hash": "tampered"},
        capabilities={},
        policy={},
        sandbox={},
    )
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            """
            update policy_decisions
            set action = 'allow', artifact_hash = ?
            where artifact_id = ? and action = 'block'
            """,
            (moved_context, artifact.artifact_id),
        )

    item = evaluate_detection(detection, store, config, persist=False)["artifacts"][0]

    assert item["policy_composition"]["current_action"] == "allow"
    assert item["policy_action"] == "require-reapproval"
    assert item["approval_reuse_status"] == "rejected"
    assert item["approval_reuse_reason_code"] == "approval_reuse_integrity_failure"


def test_consumer_current_allow_ignores_tampered_nonmatching_local_row(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    store = GuardStore(tmp_path / "guard-home")
    config = _config(tmp_path, action="allow")
    unrelated_context = build_approval_context_token(
        identity={"artifact_id": "codex:project:unrelated"},
        content={"artifact_hash": "unrelated"},
        capabilities={},
        policy={},
        sandbox={},
    )
    store.upsert_policy(
        PolicyDecision(
            harness=artifact.harness,
            scope="artifact",
            action="block",
            artifact_id="codex:project:unrelated",
            artifact_hash=unrelated_context,
            reason="unrelated signed authority",
            source="manual",
        ),
        "2026-07-17T00:01:00+00:00",
    )
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            """
            update policy_decisions
            set action = 'allow', artifact_hash = 'guard-approval-context:v1:tampered'
            where artifact_id = 'codex:project:unrelated'
            """
        )

    item = evaluate_detection(detection, store, config, persist=False)["artifacts"][0]

    assert item["policy_composition"]["current_action"] == "allow"
    assert item["policy_action"] == "allow"
    assert item["approval_reuse_reason_code"] == "approval_reuse_no_saved_decision"


@pytest.mark.parametrize("queued_action", ("review", "require-reapproval"))
def test_approval_queue_persists_exact_v1_context_instead_of_legacy_content_hash(
    tmp_path: Path,
    queued_action: GuardAction,
) -> None:
    artifact = _artifact(tmp_path)
    detection = _detection(artifact)
    store = GuardStore(tmp_path / "guard-home")
    config = _config(tmp_path, action=queued_action)
    evaluation = evaluate_detection(detection, store, config, persist=False)

    queued = queue_blocked_approvals(
        detection=detection,
        evaluation=evaluation,
        store=store,
        approval_center_url="http://127.0.0.1:4455",
    )

    assert len(queued) == 1
    assert queued[0]["policy_action"] == queued_action
    assert queued[0]["artifact_hash"] == evaluation["artifacts"][0]["approval_context_hash"]
    assert parse_approval_context_token(queued[0]["artifact_hash"]) is not None
    assert queued[0]["artifact_hash"] != evaluation["artifacts"][0]["artifact_hash"]
    assert queued[0]["workspace"] == str((tmp_path / "workspace").resolve())
