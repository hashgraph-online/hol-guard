"""Daemon native reviews offer and honor a stable exact-action "Always" decision."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.approval_scope_support import request_scope_contract
from codex_plugin_scanner.guard.approvals import apply_approval_resolution
from codex_plugin_scanner.guard.daemon.hook_native_exact_action import native_exact_action, native_launch_evidence
from codex_plugin_scanner.guard.daemon.hook_native_saved_approval import (
    EXACT_ACTION_CONTEXT_TOKEN_KEY,
    native_saved_decision_response,
)
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.models import GuardAction, PolicyDecision
from codex_plugin_scanner.guard.native_decision_receipt import canonical_receipt_bytes
from codex_plugin_scanner.guard.store import GuardStore
from tests import native_launch_evidence_helpers
from tests.native_launch_evidence_helpers import _inventory, _permission
from tests.test_native_command_observations import _edge, _observations, _receipt

_HARNESS = "claude-code"
_ARTIFACT_ID = "claude-code:native-pretool:Bash"


@pytest.fixture(autouse=True)
def _native_package_intent(package_intent_native):
    """Resolve runner local bins through the resident package-intent authority."""

    return package_intent_native


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
        # Keep the manager's source type explicit after canonical resolution.
        # A bare launcher-named file is intentionally not a code proof.
        _write_executable(manager_dir / f"{name}.sh", name)
        manager = manager_dir / name
        if not manager.is_symlink():
            manager.symlink_to(f"{name}.sh")
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
    payload: dict[str, object] = {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(workspace)}
    payload.update(payload_extra or {})
    return native_exact_action(
        harness=_HARNESS,
        tool_name="Bash",
        payload=payload,
        native_result=result or default_result,
        native_receipt=receipt or default_receipt,
        workspace=workspace,
        home_dir=workspace.parent / "home",
    )[0]


def test_inventory_is_stable_across_sessions_and_observes_the_installed_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    workspace = _wrangler_workspace(tmp_path, monkeypatch)
    first = _inventory("npx wrangler --version", workspace, payload_extra={"session_id": "a", "tool_use_id": "1"})
    assert first is not None, native_launch_evidence_helpers.LAST_UNAVAILABLE_REASON
    assert first == _inventory(
        "npx wrangler --version", workspace, payload_extra={"session_id": "b", "tool_use_id": "2"}
    )
    assert first != _inventory("npx wrangler whoami", workspace)
    assert first != _inventory("bunx wrangler --version", workspace)

    _wrangler_workspace(tmp_path, monkeypatch, version="4.2.0")
    assert _inventory("npx wrangler --version", workspace) not in {None, first}


def test_camel_case_harness_payload_offers_the_same_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    # ZCode, Devin and Grok send ``toolInput``; the daemon receives that shape unchanged.
    workspace = _wrangler_workspace(tmp_path, monkeypatch)
    expected = _inventory("npx wrangler --version", workspace)
    assert expected is not None, native_launch_evidence_helpers.LAST_UNAVAILABLE_REASON
    result, receipt = _verdict()
    camel, _reason = native_launch_evidence(
        harness=_HARNESS,
        tool_name="Bash",
        payload={
            "toolName": "run_terminal_command",
            "toolInput": {"command": "npx wrangler --version"},
            "cwd": str(workspace),
        },
        native_result=result,
        native_receipt=receipt,
        workspace=workspace,
        home_dir=workspace.parent / "home",
    )
    assert camel is not None and camel["inventory_sha256"] == expected
    token, reason = _permission("npx wrangler --version", workspace)
    assert token is not None and reason is None
    assert not _proven("npx wrangler --version", workspace)


@pytest.mark.parametrize(
    "command",
    [
        "npx wrangler --version",
        "npx --package wrangler wrangler --version",
        "node scripts/report.mjs",
        "node -e 1",
        "python3 report.py",
        "python3 -c 1",
    ],
)
def test_unowned_script_launch_keeps_the_review_command_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path, command: str
) -> None:
    """Off the execution-owner route the review keeps both approval choices.

    This harness has no route that can hold a script to the bytes the user saw,
    so withholding the token would leave the review with neither Allow once nor
    Always allow (``docs/guard/approval-invariant.md``). The approval binds the
    command text, which is not a proof of what the script contains.
    """

    workspace = _wrangler_workspace(tmp_path, monkeypatch)
    token, reason = _permission(command, workspace)
    assert token is not None and reason is None
    assert not _proven(command, workspace)
    result, receipt = _verdict(policy_action="block", minimum_action="block")
    assert _permission(command, workspace, result=result, receipt=receipt) == (None, "non_overridable")


def _changed_rules(result: dict[str, Any], receipt: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    changed_result = copy.deepcopy(result)
    changed_receipt = copy.deepcopy(receipt)
    for value in (changed_result["command_extensions"]["binding"], changed_receipt["command_extensions"]):
        value["control_revision"] += 1
    identity = {
        **{
            key: value
            for key, value in changed_receipt.items()
            if key not in {"authority", "decision_id", "review_anchor_digest"}
        },
        "schema": "guard-native-hook-decision-identity.v1",
    }
    changed_receipt["decision_id"] = hashlib.sha256(
        json.dumps(identity, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()
    return changed_result, changed_receipt


def _proven(command: str, workspace: Path) -> bool:
    """Whether Guard proved what ``command`` runs, rather than hashing the command.

    A command-hash fallback binds only the command, so a rule change leaves it
    as it was. A review with no token at all proved nothing either.
    """

    result, receipt = _verdict()
    first, reason = _permission(command, workspace, result=result, receipt=receipt)
    if first is None:
        assert reason is not None, command
        return False
    changed_result, changed_receipt = _changed_rules(result, receipt)
    return first != _token(command, workspace, result=changed_result, receipt=changed_receipt)


def test_token_changes_when_native_rules_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    workspace = _wrangler_workspace(tmp_path, monkeypatch)
    result, receipt = _verdict()
    changed_result, changed_receipt = _changed_rules(result, receipt)
    original = _token("cat package.json", workspace, result=result, receipt=receipt)
    assert original is not None
    assert _token("cat package.json", workspace, result=changed_result, receipt=changed_receipt) not in {None, original}


def _node_script(workspace: Path) -> Path:
    library = workspace / "scripts" / "lib"
    library.mkdir(parents=True, exist_ok=True)
    (workspace / "scripts" / "report.mjs").write_text(
        "import path from 'node:path';\nimport { total } from './lib/sum.mjs';\nconsole.log(total([1, 2]), path.sep);\n"
    )
    (library / "sum.mjs").write_text("export const total = (xs) => xs.length;\n")
    return library / "sum.mjs"


def test_node_script_inventory_observes_the_code_it_imports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    workspace = _wrangler_workspace(tmp_path, monkeypatch)
    # A native binary: a script-backed `node` has no native runtime inventory.
    node = tmp_path / "manager-bin" / "node"
    shutil.copyfile("/bin/echo", node)
    node.chmod(0o755)
    imported = _node_script(workspace)
    first = _inventory("node scripts/report.mjs", workspace)
    assert first is not None
    assert _inventory("node scripts/report.mjs", workspace) == first
    assert _inventory("node scripts/report.mjs --dry-run", workspace) not in {None, first}

    imported.write_text("export const total = () => 0;\n")
    assert _inventory("node scripts/report.mjs", workspace) not in {None, first}

    # Code Guard cannot follow is approved by its command alone.
    imported.write_text("import { execSync } from 'node:child_process';\nexport const total = () => execSync('id');\n")
    assert _inventory("node scripts/report.mjs", workspace) is None
    assert not _proven("node scripts/report.mjs", workspace)
    imported.write_text("export const total = () => 0;\n")
    assert _inventory("node -e 1", workspace) is None
    assert not _proven("node -e 1", workspace)
    assert _inventory("cd scripts && node report.mjs", workspace) is None
    assert not _proven("cd scripts && node report.mjs", workspace)
    monkeypatch.setenv("NODE_OPTIONS", "--require ./preload.js")
    assert _inventory("node scripts/report.mjs", workspace) is None
    assert not _proven("node scripts/report.mjs", workspace)


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
        "sed -n '1e ./build.sh' notes.txt",
        "terraform apply",
        "pytest tests/",
        "R -f analysis.R",
        "ansible-playbook play.yml",
    ],
)
def test_unbound_code_falls_back_to_the_command_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path, command: str
) -> None:
    # Guard cannot prove what these run, yet every review offers Always allow:
    # the approval binds to the command itself (docs/guard/approval-invariant.md).
    workspace = _wrangler_workspace(tmp_path, monkeypatch)
    assert not _proven(command, workspace)
    token = _token(command, workspace)
    assert token == _token(command, workspace, payload_extra={"session_id": "b", "tool_use_id": "2"})
    assert token != _token(command + " --verbose", workspace)


@pytest.mark.parametrize(
    "overrides",
    [
        {"policy_action": "block"},
        {"minimum_action": "block"},
        {"minimum_action": "sandbox-required"},
    ],
)
def test_non_overridable_verdicts_never_offer_always(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path, overrides: dict[str, object]
) -> None:
    workspace = _wrangler_workspace(tmp_path, monkeypatch)
    result, receipt = _verdict(**overrides)
    assert _token("npx wrangler --version", workspace, result=result, receipt=receipt) is None


@pytest.mark.parametrize("action_type", ["guard_control", "guard-control-operation", "package"])
def test_guard_control_and_package_reviews_offer_always(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path, action_type: str
) -> None:
    workspace = _wrangler_workspace(tmp_path, monkeypatch)
    result, receipt = _verdict(action={"action_type": action_type})
    assert _token("npx wrangler --version", workspace, result=result, receipt=receipt) is not None


def test_receipt_without_policy_binding_still_offers_always(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    workspace = _wrangler_workspace(tmp_path, monkeypatch)
    result, _ = _verdict()
    result.pop("command_extensions")
    token = _token("cat package.json", workspace, result=result, receipt=_receipt(None))
    assert token is not None
    assert token != _token("cat package.json -n", workspace, result=result, receipt=_receipt(None))


def _save(store: GuardStore, token: str, action: GuardAction, **fields: Any) -> None:
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


def test_saved_allow_reuses_every_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    workspace = _wrangler_workspace(tmp_path, monkeypatch)
    store = GuardStore(tmp_path / "guard-home")
    token = _token("cat package.json", workspace)
    assert token is not None
    result, _ = _verdict()
    kwargs: dict[str, Any] = {"harness": _HARNESS, "artifact_id": _ARTIFACT_ID, "workspace": workspace}
    assert native_saved_decision_response(store, token=token, native_result=result, **kwargs) is None

    _save(store, token, "allow")
    allowed = native_saved_decision_response(store, token=token, native_result=result, **kwargs)
    assert allowed is not None and allowed["approval_reuse_status"] == "accepted"
    assert allowed["policy_action"] == "allow"
    blocked_verdict, _ = _verdict(policy_action="block", minimum_action="block")
    assert native_saved_decision_response(store, token=token, native_result=blocked_verdict, **kwargs) is None
    for action_type in ("guard_control", "package"):
        control_verdict, _ = _verdict(action={"action_type": action_type})
        reused = native_saved_decision_response(store, token=token, native_result=control_verdict, **kwargs)
        assert reused is not None and reused["approval_reuse_status"] == "accepted"
    assert native_saved_decision_response(store, token=token + "x", native_result=result, **kwargs) is None


def test_unsaved_token_skips_the_integrity_refreshing_lookup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    workspace = _wrangler_workspace(tmp_path, monkeypatch)
    store = GuardStore(tmp_path / "guard-home")
    token = _token("cat package.json", workspace)
    assert token is not None
    _save(store, token + "-other", "allow")

    def _unexpected_lookup(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("full policy lookup ran without a matching exact decision")

    monkeypatch.setattr(store, "resolve_policy_decision_lookup", _unexpected_lookup)
    result, _ = _verdict()
    assert (
        native_saved_decision_response(
            store, harness=_HARNESS, token=token, artifact_id=_ARTIFACT_ID, native_result=result, workspace=workspace
        )
        is None
    )


def test_saved_block_blocks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path) -> None:
    workspace = _wrangler_workspace(tmp_path, monkeypatch)
    store = GuardStore(tmp_path / "guard-home")
    token = _token("cat package.json", workspace)
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


def test_native_review_offers_and_honors_always_for_native_file_read(
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
                "tool_input": {"command": "cat package.json"},
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
    assert "artifact" in contract.allow_scopes
    version, digest = row["scope_contract_version"], row["scope_contract_digest"]
    assert isinstance(version, str) and isinstance(digest, str)

    apply_approval_resolution(
        store=store,
        request_id=request_id,
        action="allow",
        scope="artifact",
        workspace=str(workspace),
        reason="always allow",
        persist_policy=True,
        scope_contract_version=version,
        scope_contract_digest=digest,
    )
    saved = [item for item in store.list_policy_decisions() if item["expires_at"] is None]
    assert [item["artifact_hash"] for item in saved] == [envelope[EXACT_ACTION_CONTEXT_TOKEN_KEY]]

    second = review("second")
    assert second["policy_action"] == "allow"
    assert second["approval_reuse_status"] == "accepted"
    third = review("third")
    assert third["approval_reuse_status"] == "accepted"


@pytest.mark.parametrize("persist", [False, True])
def test_unbound_script_review_can_grant_once_or_command_bound_persistence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path, persist: bool
) -> None:
    workspace = _wrangler_workspace(tmp_path, monkeypatch)
    result, receipt = _verdict()
    worker, store = _hook_worker(tmp_path, monkeypatch, result, receipt)
    response = worker.review_http_payload(
        payload={
            "hook_event_name": "PreToolUse",
            "session_id": "unbound-script",
            "tool_use_id": "unbound-tool",
            "tool_name": "Bash",
            "tool_input": {"command": "npx wrangler --version"},
            "cwd": str(workspace),
        },
        params={},
        default_harness=_HARNESS,
        home_dir=tmp_path / "home",
        guard_home=store.guard_home,
        workspace=workspace,
    )
    assert response["policy_action"] == "review"
    rows = store.list_approval_requests(status="pending")
    assert len(rows) == 1
    row = rows[0]
    envelope = row["action_envelope_json"]
    assert isinstance(envelope, dict)
    assert isinstance(envelope.get(EXACT_ACTION_CONTEXT_TOKEN_KEY), str)
    assert envelope.get("once_only_reason") is None
    contract = request_scope_contract(row)
    assert contract.can_run_once and contract.can_persist_exact_version
    assert "artifact" in contract.allow_scopes
    request_id, version, digest = row["request_id"], row["scope_contract_version"], row["scope_contract_digest"]
    assert isinstance(request_id, str) and isinstance(version, str) and isinstance(digest, str)
    resolved = apply_approval_resolution(
        store=store,
        request_id=request_id,
        action="allow",
        scope="artifact",
        workspace=str(workspace),
        reason="test command-bound approval",
        persist_policy=persist,
        scope_contract_version=version,
        scope_contract_digest=digest,
    )
    assert resolved["status"] == "resolved"
    assert bool(store.list_policy_decisions()) is persist


def test_native_review_derives_the_exact_action_token_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    """The saved lookup and the queued request share one derivation of the same token."""
    from codex_plugin_scanner.guard.daemon import hook_native_review_approval, hook_native_saved_approval

    workspace = _wrangler_workspace(tmp_path, monkeypatch)
    result, receipt = _verdict()
    worker, store = _hook_worker(tmp_path, monkeypatch, result, receipt)
    calls: list[str | None] = []
    real = hook_native_saved_approval.native_exact_action

    def counting(**kwargs: Any) -> tuple[str | None, str | None]:
        decision = real(**kwargs)
        calls.append(decision[0])
        return decision

    monkeypatch.setattr(hook_native_review_approval, "native_exact_action", counting)
    monkeypatch.setattr(hook_native_saved_approval, "native_exact_action", counting)
    payload: dict[str, object] = {
        "hook_event_name": "PreToolUse",
        "session_id": "once",
        "tool_use_id": "tool-once",
        "tool_name": "Bash",
        "tool_input": {"command": "cat package.json"},
        "cwd": str(workspace),
    }
    response = worker.review_http_payload(
        payload=payload,
        params={},
        default_harness=_HARNESS,
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
    )
    assert response["policy_action"] == "review"
    assert len(calls) == 1
    request_id = response["approval_request_id"]
    assert isinstance(request_id, str)
    row = store.get_approval_request(request_id)
    assert row is not None
    envelope = row["action_envelope_json"]
    assert isinstance(envelope, dict)
    stored = envelope[EXACT_ACTION_CONTEXT_TOKEN_KEY]
    assert stored == calls[0]
    assert stored == _token("cat package.json", workspace, payload_extra={"session_id": "other"})


def test_precomputed_token_binds_the_saved_decision_lookup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    """A supplied token (including None) replaces derivation inside the saved review lookup."""
    from codex_plugin_scanner.guard.daemon import hook_native_saved_approval
    from codex_plugin_scanner.guard.daemon.hook_native_saved_approval import native_saved_review_response

    workspace = _wrangler_workspace(tmp_path, monkeypatch)
    result, receipt = _verdict()
    store = GuardStore(tmp_path / "guard-home")
    monkeypatch.setattr(
        hook_native_saved_approval,
        "native_exact_action",
        lambda **_kwargs: pytest.fail("a precomputed token must not be re-derived"),
    )
    kwargs: dict[str, Any] = {
        "harness": _HARNESS,
        "tool_name": "Bash",
        "artifact_id": _ARTIFACT_ID,
        "payload": {"tool_name": "Bash", "tool_input": {"command": "cat package.json"}, "cwd": str(workspace)},
        "native_result": result,
        "native_receipt": receipt,
        "workspace": workspace,
        "home_dir": tmp_path / "home",
    }
    assert native_saved_review_response(store, precomputed_token=None, **kwargs) is None
    token = "a" * 64
    _save(store, token, "block")
    blocked = native_saved_review_response(store, precomputed_token=token, **kwargs)
    assert blocked is not None and blocked["reason_code"] == "saved_exact_action_block"


def _local_bin(workspace: Path, package: str, name: str) -> None:
    root = workspace / "node_modules" / package
    (root / "package.json").parent.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(json.dumps({"name": package, "version": "1.0.0"}))
    _write_executable(root / "bin" / f"{name}.js", name)
    link = workspace / "node_modules" / ".bin" / name
    if not link.is_symlink():
        link.symlink_to(Path("..") / package / "bin" / f"{name}.js")


@pytest.mark.parametrize(
    "command",
    [
        "npx --package=wrangler@3 wrangler --version",
        "npx -p wrangler@3 wrangler --version",
        "npx --call 'wrangler --version'",
        "npx --prefix /tmp wrangler --version",
        "npx tsx script.ts",
        "awk -f program.awk input.txt",
        "awk '{ print }' input.txt",
        "git -c alias.x=!./payload x",
        "git push origin main",
        "find . -name '*.txt' -exec ./payload {} ;",
        "xargs ./payload",
    ],
)
def test_selectors_interpreters_and_code_loaders_bind_only_the_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path, command: str
) -> None:
    workspace = _wrangler_workspace(tmp_path, monkeypatch)
    _local_bin(workspace, "tsx", "tsx")
    (workspace / "script.ts").write_text("console.log(1)\n")
    assert not _proven(command, workspace)


def test_token_binds_file_operand_contents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    workspace = _wrangler_workspace(tmp_path, monkeypatch)
    notes = workspace / "notes.txt"
    notes.write_text("first\n")
    original = _token("cat notes.txt", workspace)
    assert original is not None
    assert original == _token("cat notes.txt", workspace)
    notes.write_text("second\n")
    assert _token("cat notes.txt", workspace) not in {None, original}


def test_unreadable_saved_decision_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    import sqlite3

    workspace = _wrangler_workspace(tmp_path, monkeypatch)
    store = GuardStore(tmp_path / "guard-home")
    token = _token("cat package.json", workspace)
    assert token is not None
    _save(store, token, "block")

    def _broken_lookup(*_args: object, **_kwargs: object) -> None:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(store, "resolve_policy_decision_lookup", _broken_lookup)
    result, _ = _verdict()
    response = native_saved_decision_response(
        store, harness=_HARNESS, token=token, artifact_id=_ARTIFACT_ID, native_result=result, workspace=workspace
    )
    assert response is not None
    assert response["policy_action"] == "block"
    assert response["reason_code"] == "saved_exact_action_unreadable"


def test_saved_block_wins_over_a_pending_once_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native_context_digest: Path
) -> None:
    from codex_plugin_scanner.guard.daemon import hook_native_review_approval

    workspace = _wrangler_workspace(tmp_path, monkeypatch)
    store = GuardStore(tmp_path / "guard-home")
    token = _token("cat package.json", workspace)
    assert token is not None
    _save(store, token, "block")
    monkeypatch.setattr(hook_native_review_approval, "native_review_claimed_allow", lambda *_a, **_k: True)
    monkeypatch.setattr(hook_native_review_approval, "native_review_matching_allow", lambda *_a, **_k: True)
    result, receipt = _verdict()
    response = hook_native_review_approval.pause_native_pre_tool_for_approval(
        store,
        harness=_HARNESS,
        payload={"tool_name": "Bash", "tool_input": {"command": "cat package.json"}, "cwd": str(workspace)},
        native_result=result,
        native_receipt=receipt,
        workspace=workspace,
        guard_home=tmp_path / "guard-home",
        home_dir=workspace.parent / "home",
        claimed_saved_allow_hash="once-hash",
    )
    assert response["policy_action"] == "block"
    assert response["approval_reuse_status"] == "blocked"
