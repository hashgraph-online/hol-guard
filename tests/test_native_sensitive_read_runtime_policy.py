"""Actual runtime evaluator keeps sensitive-read risk and configured floors distinct."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli.commands_hook_runtime_eval import _evaluate_runtime_artifact_hook
from codex_plugin_scanner.guard.cli.commands_support_hook_payload import _hook_action_envelope, _normalize_hook_payload
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_sensitive_read_sources import FIXTURE, produce_sensitive_read


def _enroll_control_authority(store: GuardStore, monkeypatch: pytest.MonkeyPatch):
    from codex_plugin_scanner.guard.approval_gate import update_settings
    from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
    from tests.test_guard_extension_control_authority import _PASSWORD, MemorySecretStore, _enroll

    secrets = MemorySecretStore()
    store._extension_control_authority_secret_store = secrets
    update_settings(
        store.guard_home,
        {
            "enabled": True,
            "new_password": _PASSWORD,
            "confirm_password": _PASSWORD,
            "cooldown_seconds": 0,
        },
    )
    # Fixture-only terminal confirmation and secret backend; actual signed
    # enrollment, persisted authority, and runtime verification stay in use.
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._require_local_terminal_confirmation",
        lambda _enrollment: None,
    )
    assert _enroll(store).health is AuthorityHealth.PROTECTED
    return secrets


@pytest.mark.parametrize(
    ("scope", "configured", "expected"),
    [
        ("default", "allow", "require-reapproval"),
        ("harness", "allow", "require-reapproval"),
        ("harness", "review", "require-reapproval"),
        ("artifact", "allow", "require-reapproval"),
        ("artifact", "block", "block"),
        ("artifact", "sandbox-required", "sandbox-required"),
        ("risk", "allow", "allow"),
        ("risk", "review", "review"),
        ("risk", "block", "block"),
        ("payload", "block", "block"),
    ],
)
def test_actual_runtime_sensitive_read_keeps_configured_and_intrinsic_floors(
    tmp_path: Path, scope: str, configured: GuardAction, expected: GuardAction
):
    case = json.loads(FIXTURE.read_text())["cases"][0]
    artifact = produce_sensitive_read(case)
    workspace = Path(case["source"]["cwd"])
    home = Path(case["source"]["home_dir"])
    payload = _normalize_hook_payload(case["payload"], harness="codex")
    if scope == "payload":
        payload["policy_action"] = configured
    action = _hook_action_envelope(harness="codex", payload=payload, home_dir=home, workspace=workspace)
    assert action is not None and action.action_type == "file_read"
    store = GuardStore(tmp_path / "guard")
    config = GuardConfig(
        guard_home=store.guard_home,
        workspace=workspace,
        mode="enforce",
        default_action="allow",
        harness_actions={"codex": configured} if scope == "harness" else {},
        artifact_actions={artifact.artifact_id: configured} if scope == "artifact" else {},
        risk_actions={"local_secret_read": configured} if scope == "risk" else {},
    )
    result = _evaluate_runtime_artifact_hook(
        argparse.Namespace(harness="codex", policy_action=None, json=True),
        action_envelope=action,
        config=config,
        context=HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=store.guard_home),
        data_flow_signals=(),
        guard_home=store.guard_home,
        payload=payload,
        runtime_artifact=artifact,
        runtime_workspace=workspace,
        store=store,
    )
    assert not isinstance(result, int)
    assert result.policy_action == expected
    approval_reuse = result.response_payload["approval_reuse"]
    assert isinstance(approval_reuse, dict)
    assert approval_reuse["reason_code"] == "approval_reuse_no_saved_decision"


def test_original_sensitive_read_python_outer_hook_queues_local_reapproval(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
):
    from codex_plugin_scanner.guard.cli import commands_hook_runtime_review as runtime_review
    from tests.test_exact_command_hook_policy import _outer
    from tests.test_guard_review_policy_memory_command import _store

    def unavailable_daemon(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("Synthetic daemon unavailability")

    # Only the daemon boundary is unavailable. The actual Python hook, producer,
    # evaluation, local queue and durable request run unchanged. This is not a
    # native, installed-entrypoint or Cloud delivery acceptance claim.
    monkeypatch.setattr(runtime_review, "load_guard_surface_daemon_client", unavailable_daemon)
    monkeypatch.setattr(runtime_review, "schedule_guard_daemon_ensure", lambda *_args, **_kwargs: "http://localhost:1")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = _store(tmp_path)
    _enroll_control_authority(store, monkeypatch)
    rc, output = _outer(
        capsys,
        store,
        workspace,
        "",
        harness="codex",
        extra_payload={
            "tool_name": "Read",
            "tool_input": {"file_path": "/workspace/release-gate-project/authorization-recovery/.npmrc"},
        },
    )
    assert rc == 1 and output["policy_action"] == "require-reapproval"
    requests = store.list_approval_requests()
    assert len(requests) == 1
    assert requests[0]["policy_action"] == "require-reapproval"
    artifact_id = requests[0]["artifact_id"]
    assert isinstance(artifact_id, str) and ":file-read:" in artifact_id


@pytest.mark.parametrize("failure", ["unavailable", "tampered"])
def test_original_sensitive_read_refuses_unavailable_or_tampered_control_authority(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
):
    from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
    from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
    from tests.test_exact_command_hook_policy import _outer
    from tests.test_guard_review_policy_memory_command import _store

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = _store(tmp_path)
    secrets = _enroll_control_authority(store, monkeypatch)
    if failure == "unavailable":
        secrets.available = False
    else:
        with store._connect() as connection:
            connection.execute(
                "update extension_control_authority_snapshot set snapshot_mac = ? where singleton = 1",
                ("synthetic-invalid-mac",),
            )
    authority = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    assert authority.health is not AuthorityHealth.PROTECTED
    rc, output = _outer(
        capsys,
        store,
        workspace,
        "",
        harness="codex",
        extra_payload={
            "tool_name": "Read",
            "tool_input": {"file_path": "/workspace/release-gate-project/authorization-recovery/.npmrc"},
        },
    )
    assert rc == 1 and output["policy_action"] == "block"
    assert store.list_approval_requests() == []
