"""Daemon native reviews offer and honor a stable exact-action "Always" decision."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.approval_scope_support import request_scope_contract
from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.daemon.hook_native_saved_approval import (
    EXACT_ACTION_CONTEXT_TOKEN_KEY,
    native_exact_action_token,
    native_saved_decision_response,
)
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.native_decision_receipt import canonical_receipt_bytes
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_command_observations import _edge, _observations, _receipt

_HARNESS = "claude-code"
_ARTIFACT_ID = "claude-code:native-review:Bash"


def _write_executable(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!/bin/sh\n# {body}\n", encoding="utf-8")
    path.chmod(0o755)


def _wrangler_workspace(root: Path, monkeypatch: pytest.MonkeyPatch, *, version: str = "4.1.0") -> Path:
    workspace = root / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "package.json").write_text('{"name":"demo","devDependencies":{"wrangler":"^4.0.0"}}\n')
    package = workspace / "node_modules" / "wrangler"
    package.mkdir(parents=True, exist_ok=True)
    (package / "package.json").write_text(json.dumps({"name": "wrangler", "version": version}))
    _write_executable(package / "bin" / "wrangler.js", "wrangler")
    link = workspace / "node_modules" / ".bin" / "wrangler"
    link.parent.mkdir(parents=True, exist_ok=True)
    if not link.is_symlink():
        link.symlink_to(Path("..") / "wrangler" / "bin" / "wrangler.js")
    manager_dir = root / "manager-bin"
    for name in ("npx", "bunx"):
        _write_executable(manager_dir / name, name)
    monkeypatch.setenv("PATH", os.pathsep.join((str(manager_dir), "/usr/bin", "/bin")))
    return workspace.resolve()


def _verdict(**overrides: object) -> tuple[dict[str, Any], dict[str, Any]]:
    observations = _observations()
    result = _edge(observations)["result"]
    result.update(minimum_action="review", action={"action_type": "unknown"})
    result.update(overrides)
    receipt = _receipt(observations)
    return result, receipt


def _token(
    command: str,
    workspace: Path,
    *,
    result: dict[str, Any] | None = None,
    receipt: dict[str, Any] | None = None,
    payload_extra: dict[str, object] | None = None,
) -> str | None:
    default_result, default_receipt = _verdict()
    payload = {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(workspace)}
    payload.update(payload_extra or {})
    return native_exact_action_token(
        harness=_HARNESS,
        tool_name="Bash",
        payload=payload,
        native_result=result or default_result,
        native_receipt=receipt or default_receipt,
        workspace=workspace,
        home_dir=workspace.parent / "home",
    )


def test_token_is_stable_across_sessions_and_binds_the_installed_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    workspace = _wrangler_workspace(tmp_path, monkeypatch)
    first = _token("npx wrangler --version", workspace, payload_extra={"session_id": "a", "tool_use_id": "1"})
    assert first is not None
    assert first == _token("npx wrangler --version", workspace, payload_extra={"session_id": "b", "tool_use_id": "2"})
    assert first != _token("npx wrangler whoami", workspace)
    assert first != _token("bunx wrangler --version", workspace)

    _wrangler_workspace(tmp_path, monkeypatch, version="4.2.0")
    assert _token("npx wrangler --version", workspace) not in {None, first}


def test_token_changes_when_native_rules_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    workspace = _wrangler_workspace(tmp_path, monkeypatch)
    result, receipt = _verdict()
    changed_result = copy.deepcopy(result)
    changed_receipt = copy.deepcopy(receipt)
    for value in (changed_result["command_extensions"]["binding"], changed_receipt["command_extensions"]):
        value["control_revision"] += 1
    identity = {
        **{key: value for key, value in changed_receipt.items() if key not in {"authority", "decision_id"}},
        "schema": "guard-native-hook-decision-identity.v1",
    }
    changed_receipt["decision_id"] = hashlib.sha256(
        json.dumps(identity, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()
    original = _token("git status", workspace, result=result, receipt=receipt)
    assert original is not None
    assert _token("git status", workspace, result=changed_result, receipt=changed_receipt) not in {None, original}


@pytest.mark.parametrize(
    "command",
    [
        "npx -y wrangler@latest --version",
        "npx wrangler@3.0.0 --version",
        "npx create-cloudflare",
        "npm run build",
        "bash deploy.sh",
        "node script.js",
        "sed -f program.sed input.txt",
    ],
)
def test_unbound_code_stays_once_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path, command: str
) -> None:
    workspace = _wrangler_workspace(tmp_path, monkeypatch)
    assert _token(command, workspace) is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"policy_action": "block"},
        {"minimum_action": "block"},
        {"minimum_action": "sandbox-required"},
        {"action": {"action_type": "guard_control"}},
        {"action": {"action_type": "package"}},
    ],
)
def test_non_overridable_verdicts_never_offer_always(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path, overrides: dict[str, object]
) -> None:
    workspace = _wrangler_workspace(tmp_path, monkeypatch)
    result, receipt = _verdict(**overrides)
    assert _token("npx wrangler --version", workspace, result=result, receipt=receipt) is None


def test_receipt_without_policy_binding_stays_once_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    workspace = _wrangler_workspace(tmp_path, monkeypatch)
    result, _ = _verdict()
    result.pop("command_extensions")
    assert _token("git status", workspace, result=result, receipt=_receipt(None)) is None


def _save(store: GuardStore, token: str, action: str, **fields: object) -> None:
    store.upsert_policy(
        PolicyDecision(
            harness=_HARNESS,
            scope="artifact",
            action=action,
            artifact_id=_ARTIFACT_ID,
            artifact_hash=token,
            source=str(fields.pop("source", "approval-gate")),
            **fields,
        ),
        "2026-10-08T00:00:00+00:00",
    )


def test_saved_allow_reuses_only_overridable_reviews(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    workspace = _wrangler_workspace(tmp_path, monkeypatch)
    store = GuardStore(tmp_path / "guard-home")
    token = _token("npx wrangler --version", workspace)
    assert token is not None
    result, _ = _verdict()
    kwargs = {"harness": _HARNESS, "artifact_id": _ARTIFACT_ID, "workspace": workspace}
    assert native_saved_decision_response(store, token=token, native_result=result, **kwargs) is None

    _save(store, token, "allow")
    allowed = native_saved_decision_response(store, token=token, native_result=result, **kwargs)
    assert allowed is not None and allowed["approval_reuse_status"] == "accepted"
    assert allowed["policy_action"] == "allow"
    blocked_verdict, _ = _verdict(policy_action="block", minimum_action="block")
    assert native_saved_decision_response(store, token=token, native_result=blocked_verdict, **kwargs) is None
    assert native_saved_decision_response(store, token=token + "x", native_result=result, **kwargs) is None


def test_saved_block_blocks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path) -> None:
    workspace = _wrangler_workspace(tmp_path, monkeypatch)
    store = GuardStore(tmp_path / "guard-home")
    token = _token("npx wrangler --version", workspace)
    assert token is not None
    _save(store, token, "block")
    result, _ = _verdict()
    response = native_saved_decision_response(
        store, harness=_HARNESS, token=token, artifact_id=_ARTIFACT_ID, native_result=result, workspace=workspace
    )
    assert response is not None
    assert response["approval_reuse_status"] == "blocked"
    assert response["policy_action"] == "block"
    assert response["reason_code"] == "saved_exact_action_block"


def _hook_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, result: dict[str, Any], receipt: dict[str, Any]
) -> tuple[HookWorker, GuardStore]:
    from codex_plugin_scanner.guard.config import update_guard_settings

    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.hook_worker.native_mode", lambda: "auto")

    def review_raw_hook_native(*_args: object, **_kwargs: object) -> dict[str, object]:
        bound_receipt = copy.deepcopy(receipt)
        bound_receipt["decision_id"] = hashlib.sha256(canonical_receipt_bytes(bound_receipt)).hexdigest()
        return {
            "schema": "guard-hook-edge-result.v2",
            "authority": "rust",
            "harness": _HARNESS,
            "event_name": "PreToolUse",
            "payload_kind": "inline",
            "result": {
                "schema": "guard-pre-tool-result.v1",
                "version": 1,
                "authority": "rust",
                "reason": "HOL Guard requires review before this command can execute.",
                **copy.deepcopy(result),
            },
            "receipt": bound_receipt,
        }

    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native", review_raw_hook_native)
    store = GuardStore(tmp_path / "guard-home")
    update_guard_settings(store.guard_home, {"blocked_request_mode": "ask"})
    store.upsert_runtime_state(
        session_id="native-review",
        daemon_host="127.0.0.1",
        daemon_port=4781,
        started_at="2026-09-05T00:00:00+00:00",
        last_heartbeat_at="2026-09-05T00:00:00+00:00",
    )
    return HookWorker(store=store), store


def test_native_review_offers_and_honors_always_for_local_wrangler(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    workspace = _wrangler_workspace(tmp_path, monkeypatch)
    result, receipt = _verdict()
    worker, store = _hook_worker(tmp_path, monkeypatch, result, receipt)

    def review(session_id: str) -> dict[str, object]:
        return worker.review_http_payload(
            payload={
                "hook_event_name": "PreToolUse",
                "session_id": session_id,
                "tool_use_id": f"tool-{session_id}",
                "tool_name": "Bash",
                "tool_input": {"command": "npx wrangler --version"},
                "cwd": str(workspace),
            },
            params={},
            default_harness=_HARNESS,
            home_dir=tmp_path / "home",
            guard_home=tmp_path / "guard-home",
            workspace=workspace,
        )

    first = review("first")
    assert first["policy_action"] == "review"
    request_id = first["approval_request_id"]
    assert isinstance(request_id, str)
    row = store.get_approval_request(request_id)
    assert row is not None
    envelope = row["action_envelope_json"]
    assert isinstance(envelope, dict) and isinstance(envelope.get(EXACT_ACTION_CONTEXT_TOKEN_KEY), str)
    contract = request_scope_contract(row)
    assert contract.exact_action_persistence_eligible is True
    assert "artifact" in contract.to_dict()["allowed_scopes_by_action"]["allow"]

    apply_approval_resolution(
        store=store,
        request_id=request_id,
        action="allow",
        scope="artifact",
        workspace=str(workspace),
        reason="always allow",
        persist_policy=True,
        scope_contract_version=row["scope_contract_version"],
        scope_contract_digest=row["scope_contract_digest"],
    )
    saved = [item for item in store.list_policy_decisions() if item["expires_at"] is None]
    assert [item["artifact_hash"] for item in saved] == [envelope[EXACT_ACTION_CONTEXT_TOKEN_KEY]]

    second = review("second")
    assert second["policy_action"] == "allow"
    assert second["approval_reuse_status"] == "accepted"
    third = review("third")
    assert third["approval_reuse_status"] == "accepted"
