from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Condition

import pytest

from codex_plugin_scanner.guard.approval_gate import update_settings
from codex_plugin_scanner.guard.approval_scope_support import request_scope_contract
from codex_plugin_scanner.guard.cli.commands_support_runtime_resolution import _copilot_runtime_tool_call
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiError, LocalCliApiService
from codex_plugin_scanner.guard.mcp_tool_calls import build_tool_call_artifact, build_tool_call_hash, evaluate_tool_call
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_inputs import NativePolicySnapshotPublisherInputs
from codex_plugin_scanner.guard.runtime.composio_discovery import ComposioActionSchema
from codex_plugin_scanner.guard.runtime.custom_extension_continuity import record_local_custom_extension_mutation
from codex_plugin_scanner.guard.runtime.observed_mcp_tools import observed_mcp_tool
from codex_plugin_scanner.guard.store import GuardStore

_TIME = "2026-09-27T12:00:00Z"
_TOOL = "mcp__codex_apps__composio__composio_search_tools"
_BATCH = "mcp__codex_apps__composio__composio_multi_execute_tool"


def _setup(tmp_path: Path):
    store = GuardStore(tmp_path / "home")
    source = observed_mcp_tool("codex", _TOOL)
    assert source is not None
    cli_id = store.record_composio_discovery(
        source, (ComposioActionSchema("slack", "SLACK_SEND_MESSAGE", "Send", {"type": "object"}, True),), seen_at=_TIME
    )
    return store, source, cli_id


def test_copilot_composio_artifact_binds_current_provider_authority(tmp_path: Path):
    store, _, _ = _setup(tmp_path)
    authority_hash = store.read_mcp_provider_authority_hash()
    assert authority_hash is not None
    resolved = _copilot_runtime_tool_call(
        payload={"tool_name": "composio/COMPOSIO_MULTI_EXECUTE_TOOL", "tool_input": {"tools": []}},
        home_dir=tmp_path,
        workspace=None,
        store=store,
    )
    assert resolved is not None
    assert resolved[0].metadata["mcp_provider_catalog_hash"] == authority_hash
    unrelated = _copilot_runtime_tool_call(
        payload={"tool_name": "other/read", "tool_input": {}},
        home_dir=tmp_path,
        workspace=None,
        store=store,
    )
    assert unrelated is not None
    assert "mcp_provider_catalog_hash" not in unrelated[0].metadata


def _save(store, source, state="allowed", updates=(("SLACK_SEND_MESSAGE", "block", 1),)):
    return record_local_custom_extension_mutation(
        store,
        identity=source.identity,
        state=state,
        expected_revision=store.read_local_cli_revision(),
        command_states={},
        provider_updates=updates,
        now=_TIME,
    )


def test_protected_transaction_saves_deny_and_native_choice_without_granting_allow(tmp_path: Path):
    store, source, cli_id = _setup(tmp_path)
    assert _save(store, source) == 1
    assert store.read_local_mcp_provider_actions(cli_id)["actions"][0]["permission_state"] == "block"
    choices = store.read_mcp_provider_choices()
    assert list(choices.values()) == ["block"]
    inputs = NativePolicySnapshotPublisherInputs()
    inputs.guard_home = store.guard_home
    inputs.store = store
    inputs._condition = Condition()
    inputs._workspace_paths = set()
    assert inputs._compiled_effective_policy()["mcp_provider_actions"] == choices
    # Saving unrelated outer choices must preserve the inner restriction.
    _save(store, source, updates=())
    assert store.read_mcp_provider_choices() == choices
    _save(store, source, state="unset", updates=())
    assert store.read_mcp_provider_choices() == {}


def test_metadata_revision_conflict_rolls_back_parent_and_provider_authority(tmp_path: Path):
    store, source, _ = _setup(tmp_path)
    store.record_composio_discovery(
        source,
        (ComposioActionSchema("slack", "SLACK_SEND_MESSAGE", "Send", {"type": "object", "required": ["text"]}, True),),
        seen_at=_TIME,
    )
    with pytest.raises(ValueError, match="provider_action_revision_conflict"):
        _save(store, source)
    assert store.read_local_cli_revision() == 0
    assert store.read_mcp_provider_choices() == {}


def test_metadata_changes_do_not_erase_deny(tmp_path: Path):
    store, source, cli_id = _setup(tmp_path)
    _save(store, source)
    store.record_composio_discovery(
        source,
        (
            ComposioActionSchema(
                "slack", "SLACK_SEND_MESSAGE", "Changed", {"type": "object", "required": ["text"]}, True
            ),
        ),
        seen_at=_TIME,
    )
    action = store.read_local_mcp_provider_actions(cli_id)["actions"][0]
    assert (action["permission_state"], action["revision"]) == ("block", 2)


def test_paged_inventory_rejects_metadata_and_permission_changes(tmp_path: Path):
    store, source, cli_id = _setup(tmp_path)
    first = store.read_local_mcp_provider_actions(cli_id, limit=1)
    token = first["catalog_token"]
    assert store.read_local_mcp_provider_actions(cli_id, expected_token=token)["catalog_token"] == token
    _save(store, source)
    with pytest.raises(ValueError, match="provider_catalog_changed"):
        store.read_local_mcp_provider_actions(cli_id, expected_token=token)
    next_token = store.read_local_mcp_provider_actions(cli_id)["catalog_token"]
    store.record_composio_discovery(
        source,
        (ComposioActionSchema("slack", "SLACK_SEND_MESSAGE", "Display changed", {"type": "object"}, True),),
        seen_at=_TIME,
    )
    with pytest.raises(ValueError, match="provider_catalog_changed"):
        store.read_local_mcp_provider_actions(cli_id, expected_token=next_token)


def test_action_api_requires_real_approval_proof_and_rejects_unverified_allow(tmp_path: Path):
    store, source, cli_id = _setup(tmp_path)
    service = LocalCliApiService(store=store)
    password = "synthetic-provider-test-password"
    update_settings(
        store.guard_home,
        {
            "enabled": True,
            "new_password": password,
            "confirm_password": password,
            "cooldown_seconds": 0,
        },
    )
    payload = {
        "cli_id": cli_id,
        "identity_hash": source.identity.identity_hash,
        "name": source.identity.name,
        "kind": source.identity.kind,
        "state": "allowed",
        "previous_revision": 0,
        "session_nonce": "synthetic-provider-action-nonce",
        "provider_actions": [{"tool_slug": "SLACK_SEND_MESSAGE", "state": "block", "revision": 1}],
    }
    with pytest.raises(LocalCliApiError):
        service.apply(payload)
    assert store.read_mcp_provider_choices() == {}
    result = service.apply({**payload, "approval_password": password})
    assert result["revision"] == 1
    assert set(store.read_mcp_provider_choices().values()) == {"block"}
    with pytest.raises(LocalCliApiError) as error:
        service.apply(
            {
                **payload,
                "provider_actions": [
                    {"tool_slug": "SLACK_SEND_MESSAGE", "state": "allow", "revision": 1},
                ],
                "approval_password": password,
            }
        )
    assert error.value.code == "invalid_provider_actions"
    assert store.read_local_cli_revision() == 1


def test_python_execution_evaluator_honors_saved_inner_deny_before_outer_review(tmp_path: Path):
    store, source, _ = _setup(tmp_path)
    _save(store, source)
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="composio",
        tool_name=_BATCH,
        source_scope="host",
        config_path="",
        transport="observed",
        server_identity=source.server_identity,
    )
    config = GuardConfig(guard_home=store.guard_home, workspace=None, mode="prompt")
    args = {
        "tools": [
            {"tool_slug": "SLACK_SEARCH_MESSAGES", "arguments": {}},
            {"tool_slug": "SLACK_SEND_MESSAGE", "arguments": {}, "account": "unverified-other-account"},
        ]
    }
    result = evaluate_tool_call(
        store=store,
        config=config,
        artifact=artifact,
        artifact_hash=build_tool_call_hash(artifact, args, workspace=None, config=config),
        arguments=args,
        claim_saved_approval=False,
    )
    assert (result.action, result.source) == ("block", "composio-action-deny")


def test_provider_schema_binding_changes_hash_and_rejects_stale_execution_context(tmp_path: Path):
    store, source, _ = _setup(tmp_path)
    config = GuardConfig(guard_home=store.guard_home, workspace=None, mode="prompt")
    args = {"tools": [{"tool_slug": "SLACK_SEND_MESSAGE", "arguments": {}}]}

    def artifact():
        return build_tool_call_artifact(
            harness="codex",
            server_name="composio",
            tool_name=_BATCH,
            source_scope="host",
            config_path="",
            transport="observed",
            server_identity=source.server_identity,
            provider_catalog_hash=store.read_mcp_provider_authority_hash(),
        )

    original = artifact()
    old_hash = build_tool_call_hash(original, args, workspace=None, config=config)
    old_provider_hash = store.read_mcp_provider_authority_hash()
    store.record_composio_discovery(
        source,
        (ComposioActionSchema("slack", "SLACK_SEND_MESSAGE", "Cosmetic description", {"type": "object"}, True),),
        seen_at=_TIME,
    )
    assert store.read_mcp_provider_authority_hash() == old_provider_hash
    assert build_tool_call_hash(artifact(), args, workspace=None, config=config) == old_hash
    store.record_composio_discovery(
        source,
        (
            ComposioActionSchema(
                "slack", "SLACK_SEND_MESSAGE", "Cosmetic description", {"type": "object", "required": ["text"]}, True
            ),
        ),
        seen_at=_TIME,
    )
    stale = evaluate_tool_call(
        store=store,
        config=config,
        artifact=original,
        artifact_hash=old_hash,
        arguments=args,
        claim_saved_approval=False,
    )
    assert (stale.action, stale.source) == ("require-reapproval", "composio-schema-reapproval")
    fresh = artifact()
    assert build_tool_call_hash(fresh, args, workspace=None, config=config) != old_hash
    # Metadata revisions never invent or advance a user grant.
    assert store.read_local_cli_revision() == 0 and store.read_mcp_provider_choices() == {}


@pytest.mark.parametrize("one_shot", [False, True])
def test_unverified_account_profile_accepts_only_single_use_wrapper_approval(tmp_path: Path, one_shot: bool):
    store, source, _ = _setup(tmp_path)
    config = GuardConfig(guard_home=store.guard_home, workspace=None, mode="prompt")
    args = {"tools": [{"tool_slug": "SLACK_SEND_MESSAGE", "arguments": {}}]}
    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="composio",
        tool_name=_BATCH,
        source_scope="host",
        config_path="",
        transport="observed",
        server_identity=source.server_identity,
        provider_catalog_hash=store.read_mcp_provider_authority_hash(),
    )
    digest = build_tool_call_hash(artifact, args, workspace=None, config=config)
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=artifact.artifact_id,
            artifact_hash=digest,
            source="approval-gate",
            expires_at=(datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat() if one_shot else None,
        ),
        _TIME,
    )
    result = evaluate_tool_call(
        store=store,
        config=config,
        artifact=artifact,
        artifact_hash=digest,
        arguments=args,
        claim_saved_approval=False,
    )
    assert result.action == ("allow" if one_shot else "review")
    if not one_shot:
        assert result.approval_reuse_reason_code == "approval_reuse_provider_account_unverified"


def test_unverified_wrapper_scope_contract_offers_once_without_claiming_account_binding():
    request = {
        "artifact_type": "tool_action_request",
        "artifact_name": _BATCH,
        "artifact_id": "codex:runtime:tool-action:fixture",
        "artifact_hash": "a" * 64,
        "policy_action": "review",
        "workspace": "/synthetic/project",
        "raw_command_text": "tool:" + _BATCH,
    }
    contract = request_scope_contract(request)
    assert contract.allow_scopes == ("artifact",)
    assert contract.recommended_allow_scope == "artifact"
    assert not contract.exact_action_persistence_eligible
    assert "provider_account_unverified_once_only" in contract.restrictions
    assert (
        "provider_account_unverified_once_only"
        not in request_scope_contract(
            {
                **request,
                "artifact_name": _TOOL,
                "raw_command_text": "tool:" + _TOOL,
            }
        ).restrictions
    )
