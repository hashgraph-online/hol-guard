"""Current-policy-first regressions for generic hooks and stdio secret reads."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import commands_support as guard_commands_module
from codex_plugin_scanner.guard.cli.commands_hook_generic import (
    _generic_hook_approval_reuse,
    _generic_hook_payload_digest,
)
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.consumer import artifact_hash
from codex_plugin_scanner.guard.models import GuardAction, GuardArtifact, PolicyDecision
from codex_plugin_scanner.guard.proxy._env import _build_scrubbed_env
from codex_plugin_scanner.guard.proxy.stdio import (
    StdioGuardProxy,
    _sensitive_read_current_action,
    build_sensitive_read_approval_hash,
)
from codex_plugin_scanner.guard.runtime.approval_context import (
    APPROVAL_CONTEXT_TOKEN_PREFIX,
    build_configured_environment_hash,
    build_runtime_launch_identity,
)
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    build_file_read_request_artifact,
    extract_sensitive_file_read_request,
)
from codex_plugin_scanner.guard.store import GuardStore

_GENERIC_HARNESS = "generic-test"
_GENERIC_ARTIFACT_ID = "generic-test:project:opaque-request"


def test_generic_hook_integrity_warning_does_not_hide_separate_valid_saved_block(tmp_path: Path) -> None:
    reuse, saved_present = _generic_hook_approval_reuse(
        artifact_hash="guard-approval-context:v1:current",
        artifact_id=_GENERIC_ARTIFACT_ID,
        current_action="review",
        decision={"action": "block", "artifact_hash": None},
        harness=_GENERIC_HARNESS,
        ignored_integrity={"integrity_status": "tampered"},
        publisher=None,
        runtime_workspace=tmp_path,
        store=GuardStore(tmp_path / "guard-home"),
    )

    assert saved_present is True
    assert reuse.action == "block"
    assert reuse.saved_action == "block"
    assert reuse.reason_code == "approval_reuse_integrity_failure"


def _generic_payload() -> dict[str, object]:
    return {
        "artifact_id": _GENERIC_ARTIFACT_ID,
        "artifact_name": "opaque request",
        "hook_event_name": "OpaqueHookEvent",
        "source_scope": "project",
        "tool_name": "opaque_tool",
        "tool_input": {"target": "unchanged"},
    }


def test_generic_hook_payload_digest_ignores_delivery_ids_but_keeps_nested_action_ids() -> None:
    first = {
        **_generic_payload(),
        "requestId": "request-first",
        "session_id": "session-first",
        "timestamp": "2026-07-17T00:00:00Z",
        "toolUseId": "tool-first",
    }
    retried = {
        **_generic_payload(),
        "request_id": "request-second",
        "sessionId": "session-second",
        "timestamp": "2026-07-17T00:01:00Z",
        "tool_use_id": "tool-second",
    }
    changed_argument = {
        **retried,
        "tool_input": {"target": "unchanged", "request_id": "action-argument"},
    }

    assert _generic_hook_payload_digest(first) == _generic_hook_payload_digest(retried)
    assert _generic_hook_payload_digest(retried) != _generic_hook_payload_digest(changed_argument)


def _run_generic_hook(
    *,
    capsys: pytest.CaptureFixture[str],
    config: GuardConfig,
    payload: dict[str, object],
    store: GuardStore,
    workspace: Path,
    post_claim_revalidator: Callable[[str], int | None] | None = None,
) -> tuple[int, dict[str, object]]:
    args = argparse.Namespace(
        artifact_id=None,
        artifact_name=None,
        harness=_GENERIC_HARNESS,
        json=True,
        policy_action=None,
    )
    rc = guard_commands_module._run_hook_generic_payload(
        args,
        action_envelope=None,
        config=config,
        home_dir=workspace.parent,
        payload=payload,
        runtime_workspace=workspace,
        store=store,
        post_claim_revalidator=post_claim_revalidator,
    )
    output = json.loads(capsys.readouterr().out)
    assert isinstance(output, dict)
    return rc, output


def _record_generic_once_allow(
    store: GuardStore,
    *,
    artifact_hash_value: str,
    request_id: str,
    workspace: Path,
) -> str:
    approval_id = store.record_local_once_approval(
        request_id=request_id,
        harness=_GENERIC_HARNESS,
        artifact_id=_GENERIC_ARTIFACT_ID,
        artifact_hash=artifact_hash_value,
        workspace=str(workspace),
        publisher=None,
        action="allow",
        created_at="2026-07-17T00:00:00+00:00",
        expires_at="2099-07-17T00:00:00+00:00",
    )
    assert approval_id is not None
    return approval_id


def test_generic_hook_exact_review_approval_uses_v1_context_and_late_claim(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        default_action="review",
    )
    payload = {
        **_generic_payload(),
        "request_id": "request-first",
        "session_id": "session-first",
        "timestamp": "2026-07-17T00:00:00Z",
        "tool_use_id": "tool-first",
    }

    first_rc, first_output = _run_generic_hook(
        capsys=capsys,
        config=config,
        payload=payload,
        store=store,
        workspace=workspace,
    )
    assert first_rc == 1
    assert first_output["policy_action"] == "review"
    context_token = str(store.list_receipts(limit=1)[0]["artifact_hash"])
    assert context_token.startswith(APPROVAL_CONTEXT_TOKEN_PREFIX)
    approval_id = _record_generic_once_allow(
        store,
        artifact_hash_value=context_token,
        request_id="generic-exact-review",
        workspace=workspace,
    )

    second_rc, second_output = _run_generic_hook(
        capsys=capsys,
        config=config,
        payload={
            **payload,
            "request_id": "request-retry",
            "session_id": "session-retry",
            "timestamp": "2026-07-17T00:01:00Z",
            "tool_use_id": "tool-retry",
        },
        store=store,
        workspace=workspace,
    )

    assert second_rc == 0
    assert second_output["policy_action"] == "allow"
    assert second_output["approval_reuse"]["reason_code"] == "approval_reuse_accepted"
    assert second_output["policy_composition"]["current_composed_action"] == "review"
    assert second_output["policy_composition"]["authoritative_action"] == "allow"
    assert (
        store.resolve_policy_decision(
            _GENERIC_HARNESS,
            _GENERIC_ARTIFACT_ID,
            context_token,
            str(workspace),
            consume_one_shot=False,
        )
        is None
    )
    claim_events = store.list_events(event_name="approval.local_once_applied")
    assert len(claim_events) == 1
    assert claim_events[0]["payload"]["approval_id"] == approval_id
    receipt = store.list_receipts(limit=1)[0]
    assert receipt["policy_decision"] == "allow"
    assert receipt["artifact_hash"] == context_token
    evidence = receipt["scanner_evidence"]
    assert isinstance(evidence, list)
    assert {item["source"] for item in evidence if isinstance(item, dict)} >= {
        "approval_reuse",
        "policy_composition",
    }


def test_generic_hook_rebuilds_current_policy_after_atomic_claim(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    artifact_actions: dict[str, GuardAction] = {}
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        default_action="review",
        artifact_actions=artifact_actions,
    )
    payload = _generic_payload()
    _run_generic_hook(
        capsys=capsys,
        config=config,
        payload=payload,
        store=store,
        workspace=workspace,
    )
    context_token = str(store.list_receipts(limit=1)[0]["artifact_hash"])
    _record_generic_once_allow(
        store,
        artifact_hash_value=context_token,
        request_id="generic-post-claim-policy-change",
        workspace=workspace,
    )
    original_claim = store.claim_approval_reuse_decision

    def claim_then_block(decision: object, *, now: str | None = None) -> bool:
        claimed = original_claim(decision, now=now)
        if claimed:
            artifact_actions[_GENERIC_ARTIFACT_ID] = "block"
        return claimed

    monkeypatch.setattr(store, "claim_approval_reuse_decision", claim_then_block)

    rc, output = _run_generic_hook(
        capsys=capsys,
        config=config,
        payload=payload,
        store=store,
        workspace=workspace,
    )

    assert rc == 1
    assert output["policy_action"] == "block"
    assert output["policy_composition"]["current_composed_action"] == "block"
    assert output["policy_composition"]["authoritative_action"] == "block"
    assert output["approval_reuse"]["status"] == "rejected"
    assert output["approval_reuse"]["reason_code"] == ("approval_reuse_context_changed_after_claim")
    assert store.list_receipts(limit=1)[0]["policy_decision"] == "block"


def test_generic_hook_missing_post_claim_context_fails_closed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        default_action="review",
    )
    payload = _generic_payload()
    _run_generic_hook(
        capsys=capsys,
        config=config,
        payload=payload,
        store=store,
        workspace=workspace,
    )
    context_token = str(store.list_receipts(limit=1)[0]["artifact_hash"])
    _record_generic_once_allow(
        store,
        artifact_hash_value=context_token,
        request_id="generic-missing-post-claim-context",
        workspace=workspace,
    )

    rc, output = _run_generic_hook(
        capsys=capsys,
        config=config,
        payload=payload,
        store=store,
        workspace=workspace,
        post_claim_revalidator=lambda _artifact_hash: None,
    )

    assert rc == 1
    assert output["policy_action"] == "require-reapproval"
    assert output["approval_reuse"]["reason_code"] == ("approval_reuse_context_changed_after_claim")


@pytest.mark.parametrize("block_source", ["config", "payload"])
def test_generic_hook_saved_allow_never_lowers_new_current_block(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    block_source: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    review_config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        default_action="review",
    )
    original_payload = _generic_payload()
    _run_generic_hook(
        capsys=capsys,
        config=review_config,
        payload=original_payload,
        store=store,
        workspace=workspace,
    )
    approved_token = str(store.list_receipts(limit=1)[0]["artifact_hash"])
    _record_generic_once_allow(
        store,
        artifact_hash_value=approved_token,
        request_id=f"generic-stale-{block_source}",
        workspace=workspace,
    )
    current_config = (
        replace(review_config, artifact_actions={_GENERIC_ARTIFACT_ID: "block"})
        if block_source == "config"
        else review_config
    )
    current_payload = {**original_payload, "policy_action": "block"} if block_source == "payload" else original_payload

    rc, output = _run_generic_hook(
        capsys=capsys,
        config=current_config,
        payload=current_payload,
        store=store,
        workspace=workspace,
    )

    assert rc == 1
    assert output["policy_action"] == "block"
    assert output["policy_composition"]["current_composed_action"] == "block"
    assert output["policy_composition"]["authoritative_action"] == "block"
    assert output["approval_reuse"]["status"] == "rejected"
    assert store.list_receipts(limit=1)[0]["policy_decision"] == "block"
    assert store.list_events(event_name="approval.policy_reuse_applied") == []
    assert (
        store.resolve_policy_decision(
            _GENERIC_HARNESS,
            _GENERIC_ARTIFACT_ID,
            approved_token,
            str(workspace),
            consume_one_shot=False,
        )
        is not None
    )


@pytest.mark.parametrize(
    ("saved_action", "expected_action", "expected_reason", "expected_rc"),
    [
        ("allow", "review", "approval_reuse_content_changed", 1),
        ("block", "block", "approval_reuse_saved_block", 1),
    ],
)
def test_generic_hook_legacy_allow_fails_closed_but_legacy_block_is_preserved(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    saved_action: GuardAction,
    expected_action: GuardAction,
    expected_reason: str,
    expected_rc: int,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        default_action="review",
    )
    legacy_hash = "sha256:legacy-generic-hook"
    payload = {**_generic_payload(), "artifact_hash": legacy_hash}
    store.upsert_policy(
        PolicyDecision(
            harness=_GENERIC_HARNESS,
            scope="artifact",
            action=saved_action,
            artifact_id=_GENERIC_ARTIFACT_ID,
            artifact_hash=legacy_hash,
            source="local",
        ),
        "2026-07-17T00:00:00+00:00",
    )

    rc, output = _run_generic_hook(
        capsys=capsys,
        config=config,
        payload=payload,
        store=store,
        workspace=workspace,
    )

    assert rc == expected_rc
    assert output["policy_action"] == expected_action
    assert output["approval_reuse"]["reason_code"] == expected_reason
    receipt = store.list_receipts(limit=1)[0]
    assert receipt["policy_decision"] == expected_action
    assert str(receipt["artifact_hash"]).startswith(APPROVAL_CONTEXT_TOKEN_PREFIX)


def test_generic_hook_exact_v1_allow_cannot_hide_matching_legacy_block(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        default_action="review",
    )
    legacy_hash = "sha256:legacy-generic-block"
    payload = {**_generic_payload(), "artifact_hash": legacy_hash}
    _run_generic_hook(
        capsys=capsys,
        config=config,
        payload=payload,
        store=store,
        workspace=workspace,
    )
    context_token = str(store.list_receipts(limit=1)[0]["artifact_hash"])
    for action, digest in (("allow", context_token), ("block", legacy_hash)):
        store.upsert_policy(
            PolicyDecision(
                harness=_GENERIC_HARNESS,
                scope="artifact",
                action=action,
                artifact_id=_GENERIC_ARTIFACT_ID,
                artifact_hash=digest,
                source="local",
            ),
            "2026-07-17T00:00:00+00:00",
        )

    rc, output = _run_generic_hook(
        capsys=capsys,
        config=config,
        payload=payload,
        store=store,
        workspace=workspace,
    )

    assert rc == 1
    assert output["policy_action"] == "block"
    assert output["approval_reuse"]["reason_code"] == "approval_reuse_saved_block"
    assert store.list_receipts(limit=1)[0]["policy_decision"] == "block"


def _sensitive_read_artifact(workspace: Path, *, publisher: str | None = None) -> GuardArtifact:
    request = extract_sensitive_file_read_request("read_file", {"path": ".env"}, cwd=workspace)
    assert request is not None
    artifact = build_file_read_request_artifact(
        harness="codex",
        request=request,
        config_path=str(workspace / ".mcp.json"),
        source_scope="project",
    )
    return replace(artifact, publisher=publisher) if publisher is not None else artifact


def _marker_child_command(marker: Path) -> list[str]:
    return [
        sys.executable,
        "-u",
        "-c",
        "\n".join(
            (
                "import json, pathlib, sys",
                "for line in sys.stdin:",
                "    message = json.loads(line)",
                f"    pathlib.Path({str(marker)!r}).write_text(json.dumps(message), encoding='utf-8')",
                "    print(json.dumps({'jsonrpc': '2.0', 'id': message.get('id'), 'result': {'ok': True}}))",
                "    sys.stdout.flush()",
            )
        ),
    ]


def _sensitive_read_message() -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": ".env"}},
    }


def _save_sensitive_read_policy(
    store: GuardStore,
    *,
    action: GuardAction,
    artifact: GuardArtifact,
    config: GuardConfig,
    workspace: Path,
    command: list[str],
) -> str:
    current_action = _sensitive_read_current_action(config, artifact=artifact, harness="codex")
    launch_env = _build_scrubbed_env()
    context_token = build_sensitive_read_approval_hash(
        artifact,
        config=config,
        cwd=workspace,
        current_action=current_action,
        server_launch_identity=build_runtime_launch_identity(
            command[0],
            args=command[1:],
            structured_command=True,
            cwd=workspace,
            launch_env=launch_env,
        ),
        configured_env_values_hash=build_configured_environment_hash(
            launch_env,
            configured_keys=(),
        ),
    )
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action=action,
            artifact_id=artifact.artifact_id,
            artifact_hash=context_token,
            source="local",
        ),
        "2026-07-17T00:00:00+00:00",
    )
    return context_token


@pytest.mark.parametrize("override_scope", ["artifact", "harness", "publisher"])
def test_sensitive_read_context_binds_exact_configured_override(
    tmp_path: Path,
    override_scope: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    publisher = "trusted-publisher" if override_scope == "publisher" else None
    artifact = _sensitive_read_artifact(workspace, publisher=publisher)
    base_config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        security_level="custom",
        risk_actions={"local_secret_read": "review"},
    )
    changed_kwargs: dict[str, object]
    if override_scope == "artifact":
        changed_kwargs = {"artifact_actions": {artifact.artifact_id: "block"}}
    elif override_scope == "harness":
        changed_kwargs = {"harness_actions": {"codex": "block"}}
    else:
        changed_kwargs = {"publisher_actions": {"trusted-publisher": "block"}}
    changed_config = replace(base_config, **changed_kwargs)
    base_action = _sensitive_read_current_action(base_config, artifact=artifact, harness="codex")
    changed_action = _sensitive_read_current_action(changed_config, artifact=artifact, harness="codex")

    base_token = build_sensitive_read_approval_hash(
        artifact,
        config=base_config,
        cwd=workspace,
        current_action=base_action,
    )
    changed_token = build_sensitive_read_approval_hash(
        artifact,
        config=changed_config,
        cwd=workspace,
        current_action=changed_action,
    )

    assert base_action == "review"
    assert changed_action == "block"
    assert base_token != changed_token


def test_sensitive_read_exact_allow_overrides_global_block_before_independent_risk_review(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifact = _sensitive_read_artifact(workspace)
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        default_action="block",
        artifact_actions={artifact.artifact_id: "allow"},
        risk_actions={"local_secret_read": "review"},
    )

    action = _sensitive_read_current_action(config, artifact=artifact, harness="codex")

    assert action == "review"


def test_sensitive_read_risk_block_outranks_exact_allow(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifact = _sensitive_read_artifact(workspace)
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        default_action="block",
        artifact_actions={artifact.artifact_id: "allow"},
        risk_actions={"local_secret_read": "block"},
    )

    action = _sensitive_read_current_action(config, artifact=artifact, harness="codex")

    assert action == "block"


def test_stdio_sensitive_read_old_allow_cannot_survive_new_exact_artifact_block(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    artifact = _sensitive_read_artifact(workspace)
    review_config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        security_level="custom",
        risk_actions={"local_secret_read": "review"},
    )
    marker = tmp_path / "must-not-forward.json"
    command = _marker_child_command(marker)
    _save_sensitive_read_policy(
        store,
        action="allow",
        artifact=artifact,
        config=review_config,
        workspace=workspace,
        command=command,
    )
    block_config = replace(review_config, artifact_actions={artifact.artifact_id: "block"})
    proxy = StdioGuardProxy(
        command=command,
        cwd=workspace,
        guard_store=store,
        guard_config=block_config,
        approval_center_url="http://127.0.0.1:4455",
        harness="codex",
    )

    result = proxy.run_session([_sensitive_read_message()])

    assert result["responses"][0]["error"]["code"] == -32001
    assert marker.exists() is False
    event = result["events"][0]
    assert event["decision"] == "block"
    assert event["approval_reuse_status"] == "rejected"
    assert store.list_receipts(limit=1)[0]["policy_decision"] == "block"
    assert "approval_requests" not in event
    assert store.list_approval_requests(limit=None) == []


def test_stdio_sensitive_read_old_allow_cannot_survive_new_default_block(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    artifact = _sensitive_read_artifact(workspace)
    review_config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        default_action="review",
        security_level="custom",
        risk_actions={"local_secret_read": "review"},
    )
    marker = tmp_path / "must-not-forward.json"
    command = _marker_child_command(marker)
    reviewed_hash = _save_sensitive_read_policy(
        store,
        action="allow",
        artifact=artifact,
        config=review_config,
        workspace=workspace,
        command=command,
    )
    block_config = replace(review_config, default_action="block")
    launch_env = _build_scrubbed_env()
    blocked_hash = build_sensitive_read_approval_hash(
        artifact,
        config=block_config,
        cwd=workspace,
        current_action="block",
        server_launch_identity=build_runtime_launch_identity(
            command[0],
            args=command[1:],
            structured_command=True,
            cwd=workspace,
            launch_env=launch_env,
        ),
        configured_env_values_hash=build_configured_environment_hash(
            launch_env,
            configured_keys=(),
        ),
    )
    proxy = StdioGuardProxy(
        command=command,
        cwd=workspace,
        guard_store=store,
        guard_config=block_config,
        approval_center_url="http://127.0.0.1:4455",
        harness="codex",
    )

    result = proxy.run_session([_sensitive_read_message()])

    assert reviewed_hash != blocked_hash
    assert result["responses"][0]["error"]["code"] == -32001
    assert marker.exists() is False
    event = result["events"][0]
    assert event["approval_reuse_reason_code"] == "approval_reuse_policy_changed"
    assert store.list_receipts(limit=1)[0]["policy_decision"] == "block"
    assert "approval_requests" not in event
    assert store.list_approval_requests(limit=None) == []


@pytest.mark.parametrize("terminal_action", ["block", "sandbox-required"])
def test_stdio_sensitive_read_fresh_terminal_action_never_queues_approval(
    tmp_path: Path,
    terminal_action: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    artifact = _sensitive_read_artifact(workspace)
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        security_level="custom",
        artifact_actions={artifact.artifact_id: terminal_action},
        risk_actions={"local_secret_read": "review"},
    )
    marker = tmp_path / "must-not-forward.json"
    proxy = StdioGuardProxy(
        command=_marker_child_command(marker),
        cwd=workspace,
        guard_store=store,
        guard_config=config,
        approval_center_url="http://127.0.0.1:4455",
        harness="codex",
    )

    result = proxy.run_session([_sensitive_read_message()])

    assert result["responses"][0]["error"]["code"] == -32001
    assert marker.exists() is False
    event = result["events"][0]
    assert event["approval_reuse_reason_code"] == "approval_reuse_no_saved_decision"
    assert "approval_requests" not in event
    assert store.list_approval_requests(limit=None) == []
    assert store.list_receipts(limit=1)[0]["policy_decision"] == terminal_action


def test_stdio_sensitive_read_exact_saved_block_is_terminal_and_not_reapprovable(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        security_level="custom",
        risk_actions={"local_secret_read": "review"},
    )
    artifact = _sensitive_read_artifact(workspace)
    marker = tmp_path / "must-not-forward.json"
    command = _marker_child_command(marker)
    _save_sensitive_read_policy(
        store,
        action="block",
        artifact=artifact,
        config=config,
        workspace=workspace,
        command=command,
    )
    proxy = StdioGuardProxy(
        command=command,
        cwd=workspace,
        guard_store=store,
        guard_config=config,
        approval_center_url="http://127.0.0.1:4455",
        harness="codex",
    )

    result = proxy.run_session([_sensitive_read_message()])

    assert result["responses"][0]["error"]["code"] == -32001
    assert marker.exists() is False
    event = result["events"][0]
    assert event["approval_reuse_reason_code"] == "approval_reuse_saved_block"
    assert event["terminal_saved_block"] is True
    assert "approval_requests" not in event
    assert store.list_approval_requests() == []
    assert store.list_receipts(limit=1)[0]["policy_decision"] == "block"


def test_stdio_sensitive_read_valid_saved_block_remains_terminal_with_separate_integrity_warning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        security_level="custom",
        risk_actions={"local_secret_read": "review"},
    )
    marker = tmp_path / "must-not-forward.json"
    proxy = StdioGuardProxy(
        command=_marker_child_command(marker),
        cwd=workspace,
        guard_store=store,
        guard_config=config,
        approval_center_url="http://127.0.0.1:4455",
        harness="codex",
    )

    monkeypatch.setattr(
        store,
        "resolve_policy_decision_lookup",
        lambda *_args, **_kwargs: {
            "decision": {
                "action": "block",
                "artifact_hash": None,
                "decision_id": 1,
                "source": "local",
            },
            "ignored_local_integrity": {
                "decision_id": 2,
                "integrity_status": "tampered",
                "source": "local",
            },
            "trust_status": {},
        },
    )

    result = proxy.run_session([_sensitive_read_message()])

    assert result["responses"][0]["error"]["code"] == -32001
    assert marker.exists() is False
    event = result["events"][0]
    assert event["approval_reuse_reason_code"] == "approval_reuse_integrity_failure"
    assert event["terminal_saved_block"] is True
    assert "approval_requests" not in event
    assert store.list_approval_requests() == []
    assert store.list_receipts(limit=1)[0]["policy_decision"] == "block"


def test_stdio_sensitive_read_current_review_still_queues_approval(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        security_level="custom",
        risk_actions={"local_secret_read": "review"},
    )
    marker = tmp_path / "must-not-forward.json"
    proxy = StdioGuardProxy(
        command=_marker_child_command(marker),
        cwd=workspace,
        guard_store=store,
        guard_config=config,
        approval_center_url="http://127.0.0.1:4455",
        harness="codex",
    )

    result = proxy.run_session([_sensitive_read_message()])

    assert result["responses"][0]["error"]["code"] == -32001
    assert marker.exists() is False
    event = result["events"][0]
    assert event["approval_reuse_reason_code"] == "approval_reuse_no_saved_decision"
    assert len(event["approval_requests"]) == 1
    assert store.list_approval_requests(limit=1)[0]["policy_action"] == "require-reapproval"


def test_stdio_sensitive_read_unchanged_exact_one_shot_is_claimed_and_forwarded(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    artifact = _sensitive_read_artifact(workspace)
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        security_level="custom",
        risk_actions={"local_secret_read": "review"},
    )
    marker = tmp_path / "unchanged-one-shot-forwarded.json"
    command = _marker_child_command(marker)
    launch_env = _build_scrubbed_env()
    context_token = build_sensitive_read_approval_hash(
        artifact,
        config=config,
        cwd=workspace,
        current_action="review",
        server_launch_identity=build_runtime_launch_identity(
            command[0],
            args=command[1:],
            structured_command=True,
            cwd=workspace,
            launch_env=launch_env,
        ),
        configured_env_values_hash=build_configured_environment_hash(
            launch_env,
            configured_keys=(),
        ),
    )
    approval_id = store.record_local_once_approval(
        request_id="stdio-unchanged-one-shot",
        harness="codex",
        artifact_id=artifact.artifact_id,
        artifact_hash=context_token,
        workspace=str(workspace),
        publisher=artifact.publisher,
        action="allow",
        created_at="2026-07-17T00:00:00+00:00",
        expires_at="2099-07-17T00:00:00+00:00",
    )
    assert approval_id is not None
    proxy = StdioGuardProxy(
        command=command,
        cwd=workspace,
        guard_store=store,
        guard_config=config,
        approval_center_url="http://127.0.0.1:4455",
        harness="codex",
        current_config_provider=lambda: config,
    )

    result = proxy.run_session([_sensitive_read_message()])

    assert marker.exists() is True
    assert result["responses"][0]["result"]["ok"] is True
    assert result["events"][0]["decision"] == "forward"
    assert result["events"][0]["approval_reuse_reason_code"] == "approval_reuse_accepted"
    claim_events = store.list_events(event_name="approval.local_once_applied")
    assert len(claim_events) == 1
    assert claim_events[0]["payload"]["approval_id"] == approval_id
    assert store.list_receipts(limit=1)[0]["policy_decision"] == "allow"


def test_stdio_sensitive_read_rebuilds_current_authority_after_exact_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    artifact = _sensitive_read_artifact(workspace)
    review_config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        security_level="custom",
        risk_actions={"local_secret_read": "review"},
    )
    block_config = replace(
        review_config,
        artifact_actions={artifact.artifact_id: "block"},
    )
    current_config = [review_config]
    marker = tmp_path / "postclaim-sensitive-read-must-not-forward.json"
    command = _marker_child_command(marker)
    launch_env = _build_scrubbed_env()
    context_token = build_sensitive_read_approval_hash(
        artifact,
        config=review_config,
        cwd=workspace,
        current_action="review",
        server_launch_identity=build_runtime_launch_identity(
            command[0],
            args=command[1:],
            structured_command=True,
            cwd=workspace,
            launch_env=launch_env,
        ),
        configured_env_values_hash=build_configured_environment_hash(
            launch_env,
            configured_keys=(),
        ),
    )
    approval_id = store.record_local_once_approval(
        request_id="stdio-postclaim-freshness",
        harness="codex",
        artifact_id=artifact.artifact_id,
        artifact_hash=context_token,
        workspace=str(workspace),
        publisher=artifact.publisher,
        action="allow",
        created_at="2026-07-17T00:00:00+00:00",
        expires_at="2099-07-17T00:00:00+00:00",
    )
    assert approval_id is not None
    proxy = StdioGuardProxy(
        command=command,
        cwd=workspace,
        guard_store=store,
        guard_config=review_config,
        approval_center_url="http://127.0.0.1:4455",
        harness="codex",
        current_config_provider=lambda: current_config[0],
    )
    real_claim = store.claim_approval_reuse_decision

    def claim_then_tighten_policy(decision: dict[str, object]) -> bool:
        claimed = real_claim(decision)
        if claimed:
            current_config[0] = block_config
        return claimed

    monkeypatch.setattr(store, "claim_approval_reuse_decision", claim_then_tighten_policy)

    result = proxy.run_session([_sensitive_read_message()])

    assert marker.exists() is False
    assert result["responses"][0]["error"]["code"] == -32001
    event = result["events"][0]
    assert event["decision"] == "block"
    assert event["approval_reuse_reason_code"] == "approval_reuse_policy_changed"
    assert "approval_requests" not in event
    claim_events = store.list_events(event_name="approval.local_once_applied")
    assert len(claim_events) == 1
    assert claim_events[0]["payload"]["approval_id"] == approval_id
    assert store.list_receipts(limit=1)[0]["policy_decision"] == "block"


def test_stdio_sensitive_read_fails_closed_when_postclaim_config_refresh_fails(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        security_level="custom",
        risk_actions={"local_secret_read": "review"},
    )
    artifact = _sensitive_read_artifact(workspace)
    marker = tmp_path / "config-refresh-failure-must-not-forward.json"
    command = _marker_child_command(marker)
    _save_sensitive_read_policy(
        store,
        action="allow",
        artifact=artifact,
        config=config,
        workspace=workspace,
        command=command,
    )

    def unavailable_config() -> GuardConfig:
        raise OSError("current config unavailable")

    proxy = StdioGuardProxy(
        command=command,
        cwd=workspace,
        guard_store=store,
        guard_config=config,
        approval_center_url="http://127.0.0.1:4455",
        harness="codex",
        current_config_provider=unavailable_config,
    )

    result = proxy.run_session([_sensitive_read_message()])

    assert marker.exists() is False
    assert result["responses"][0]["error"]["code"] == -32001
    event = result["events"][0]
    assert event["decision"] == "block"
    assert event["approval_reuse_reason_code"] == "approval_reuse_current_config_refresh_failed"
    assert len(event["approval_requests"]) == 1
    approval_evidence = event["approval_requests"][0]["scanner_evidence"]
    assert approval_evidence[-1] == {
        "source": "approval_reuse",
        "status": "rejected",
        "reason_code": "approval_reuse_current_config_refresh_failed",
        "effective_action": "require-reapproval",
    }
    receipt = store.list_receipts(limit=1)[0]
    assert receipt["policy_decision"] == "require-reapproval"
    assert receipt["scanner_evidence"][-1] == approval_evidence[-1]


def test_stdio_invalidated_saved_allow_with_current_review_never_reaches_child(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(tmp_path / "guard-home")
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        security_level="custom",
        risk_actions={"local_secret_read": "review"},
    )
    artifact = _sensitive_read_artifact(workspace)
    marker = tmp_path / "must-not-forward.json"
    reviewed_command = _marker_child_command(marker)
    _save_sensitive_read_policy(
        store,
        action="allow",
        artifact=artifact,
        config=config,
        workspace=workspace,
        command=reviewed_command,
    )
    current_command = [*reviewed_command[:-1], f"{reviewed_command[-1]}\n# identity changed after review"]
    proxy = StdioGuardProxy(
        command=current_command,
        cwd=workspace,
        guard_store=store,
        guard_config=config,
        approval_center_url="http://127.0.0.1:4455",
        harness="codex",
    )

    result = proxy.run_session([_sensitive_read_message()])

    assert result["responses"][0]["error"]["code"] == -32001
    assert marker.exists() is False
    event = result["events"][0]
    assert event["decision"] == "block"
    assert event["approval_reuse_status"] == "rejected"
    assert event["approval_reuse_reason_code"] == "approval_reuse_identity_changed"
    assert len(event["approval_requests"]) == 1
    assert store.list_receipts(limit=1)[0]["policy_decision"] == "require-reapproval"


def test_sensitive_read_legacy_artifact_digest_is_not_approval_authority(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifact = _sensitive_read_artifact(workspace)
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        security_level="custom",
        risk_actions={"local_secret_read": "review"},
    )

    context_token = build_sensitive_read_approval_hash(
        artifact,
        config=config,
        cwd=workspace,
        current_action="review",
    )

    assert context_token.startswith(APPROVAL_CONTEXT_TOKEN_PREFIX)
    assert context_token != artifact_hash(artifact)
