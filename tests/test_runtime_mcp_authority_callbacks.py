"""Real-stdio security regression; no inactive adapter is installed."""

from __future__ import annotations

import json
import os
from copy import deepcopy
from dataclasses import replace

import pytest

from codex_plugin_scanner.guard import mcp_tool_calls as calls
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.mcp_authority_binding import (
    UnsupportedAuthorityValueError,
    capture_authority_binding,
    exact_authority_digest,
    use_mcp_authority_check,
)
from codex_plugin_scanner.guard.proxy import framing, runtime_mcp
from codex_plugin_scanner.guard.proxy.tool_call_binding import current_tool_call_binding

from .test_mcp_owned_preparation_pilot import _session


def test_local_grant_mutation_cannot_reach_later_saved_lookup_or_child(tmp_path, monkeypatch):
    proxy, messages, marker = _session(tmp_path)
    proxy.config = replace(proxy.config, artifact_actions={})
    trace = []
    original_override = GuardConfig.resolve_action_override
    original_grant = proxy.store.read_local_mcp_grant
    original_saved = proxy.store.resolve_policy_decision_lookup_with_memory_pattern

    def policy(config, *args, **kwargs):
        trace.append("policy")
        return original_override(config, *args, **kwargs)

    def grant(*args, **kwargs):
        result = original_grant(*args, **kwargs)
        proxy.config.artifact_actions["codex:runtime:project:synthetic:safe_echo"] = "block"
        trace.append("grant_changed_current_policy_to_block")
        return result

    def saved(*args, **kwargs):
        trace.append("later_saved_lookup")
        return original_saved(*args, **kwargs)

    monkeypatch.setattr(GuardConfig, "resolve_action_override", policy)
    monkeypatch.setattr(proxy.store, "read_local_mcp_grant", grant)
    monkeypatch.setattr(proxy.store, "resolve_policy_decision_lookup_with_memory_pattern", saved)
    result = proxy.run_session(messages)
    (tmp_path / "callback-witness.json").write_text(
        json.dumps(
            {
                "trace": trace,
                "child_received": marker.exists(),
                "last_event": result["events"][-1],
                "current_action": proxy.config.artifact_actions["codex:runtime:project:synthetic:safe_echo"],
                "production_default": True,
                "inactive_prototype_installed": False,
            },
            indent=2,
        )
        + "\n"
    )

    assert trace[:3] == ["policy", "policy", "grant_changed_current_policy_to_block"]
    assert "later_saved_lookup" not in trace
    assert not marker.exists()
    assert result["events"][-1]["session_terminal"] is True


def test_unchanged_policy_callbacks_keep_original_order_and_child_bytes(tmp_path, monkeypatch):
    proxy, messages, marker = _session(tmp_path)
    trace = []
    original_override = GuardConfig.resolve_action_override
    original_grant = proxy.store.read_local_mcp_grant
    original_saved = proxy.store.resolve_policy_decision_lookup_with_memory_pattern
    original_package = proxy._package_request_artifact
    original_drain = proxy._drain_and_validate_catalog_authority

    def policy(config, *args, **kwargs):
        trace.append("policy")
        return original_override(config, *args, **kwargs)

    def grant(*args, **kwargs):
        trace.append("local_grant")
        return original_grant(*args, **kwargs)

    def saved(*args, **kwargs):
        trace.append("saved_lookup")
        return original_saved(*args, **kwargs)

    def package(*args, **kwargs):
        trace.append("package_classifier")
        return original_package(*args, **kwargs)

    def drain(**kwargs):
        if kwargs.get("quiet_seconds") == 0.005:
            trace.append("quiet_5ms")
        return original_drain(**kwargs)

    monkeypatch.setattr(GuardConfig, "resolve_action_override", policy)
    monkeypatch.setattr(proxy.store, "read_local_mcp_grant", grant)
    monkeypatch.setattr(proxy.store, "resolve_policy_decision_lookup_with_memory_pattern", saved)
    monkeypatch.setattr(proxy, "_package_request_artifact", package)
    monkeypatch.setattr(proxy, "_drain_and_validate_catalog_authority", drain)
    result = proxy.run_session(messages)
    assert trace == ["policy", "policy", "local_grant", "saved_lookup", "package_classifier", "quiet_5ms"]
    assert json.loads(marker.read_text()) == messages[-1]
    assert result["responses"][-1]["result"]["content"][0]["text"] == "forwarded"


@pytest.mark.parametrize(
    "stage",
    [
        "hash_policy",
        "current_policy",
        "browser_context",
        "saved_lookup",
        "validation",
        "package_classifier",
        "quiet",
        "writer",
    ],
)
def test_authority_changes_stop_at_the_next_boundary(tmp_path, monkeypatch, stage):
    proxy, messages, marker = _session(tmp_path)
    proxy.config = replace(proxy.config, artifact_actions={})
    trace = []
    changed = []
    original_policy = GuardConfig.resolve_action_override
    original_context = calls._browser_runtime_exact_match_context
    original_saved = proxy.store.resolve_policy_decision_lookup_with_memory_pattern
    original_validation = proxy.store.approval_reuse_validation_reason
    original_package = proxy._package_request_artifact
    original_drain = proxy._drain_and_validate_catalog_authority
    original_write = proxy._write_message

    def mutate():
        proxy.config.artifact_actions["codex:runtime:project:synthetic:safe_echo"] = "block"
        changed.append(True)
        trace.append("changed")

    def policy(config, *args, **kwargs):
        trace.append("policy")
        result = original_policy(config, *args, **kwargs)
        if stage == ("hash_policy" if trace.count("policy") == 1 else "current_policy"):
            mutate()
        return result

    def context(*args, **kwargs):
        result = original_context(*args, **kwargs)
        if stage == "browser_context":
            mutate()
        return result

    def saved(*args, **kwargs):
        trace.append("saved")
        result = original_saved(*args, **kwargs)
        if stage == "saved_lookup":
            mutate()
        return result

    def validation(*args, **kwargs):
        trace.append("validation")
        result = original_validation(*args, **kwargs)
        if stage == "validation":
            mutate()
        return result

    def package(*args, **kwargs):
        trace.append("package")
        result = original_package(*args, **kwargs)
        if stage == "package_classifier":
            mutate()
        return result

    def drain(**kwargs):
        result = original_drain(**kwargs)
        if stage == "quiet" and kwargs.get("quiet_seconds") == 0.005:
            mutate()
        return result

    def write(stream, message, **kwargs):
        if stage == "writer" and message.get("method") == "tools/call":
            mutate()
        return original_write(stream, message, **kwargs)

    monkeypatch.setattr(GuardConfig, "resolve_action_override", policy)
    monkeypatch.setattr(calls, "_browser_runtime_exact_match_context", context)
    monkeypatch.setattr(proxy.store, "resolve_policy_decision_lookup_with_memory_pattern", saved)
    monkeypatch.setattr(proxy.store, "approval_reuse_validation_reason", validation)
    monkeypatch.setattr(proxy, "_package_request_artifact", package)
    monkeypatch.setattr(proxy, "_drain_and_validate_catalog_authority", drain)
    monkeypatch.setattr(proxy, "_write_message", write)
    result = proxy.run_session(messages)
    assert changed == [True]
    assert trace[-1] == "changed"
    assert not marker.exists()
    assert result["events"][-1]["reason_code"] == "tool_call_authority_changed"
    assert result["events"][-1]["session_terminal"] is True


@pytest.mark.parametrize(
    "mutation",
    [
        "original_arguments",
        "owned_arguments",
        "artifact_metadata",
        "artifact_private",
        "equal_config_owner",
        "effective_cwd",
        "catalog_epoch",
        "catalog_sibling",
        "command",
    ],
)
def test_grant_callback_binds_every_authority_input(tmp_path, monkeypatch, mutation):
    proxy, messages, marker = _session(tmp_path)
    if mutation == "effective_cwd":
        proxy.context = replace(proxy.context, workspace_dir=None)
        proxy.config = replace(proxy.config, workspace=None)
        first = tmp_path / "first"
        second = tmp_path / "second"
        first.mkdir()
        second.mkdir()
        monkeypatch.chdir(first)
    original_evaluate = proxy._evaluate_tool_call_authority
    original_grant = proxy.store.read_local_mcp_grant
    artifacts = []

    def evaluate(**kwargs):
        artifacts.append(kwargs["artifact"])
        return original_evaluate(**kwargs)

    def grant(*args, **kwargs):
        result = original_grant(*args, **kwargs)
        if mutation == "original_arguments":
            messages[-1]["params"]["arguments"]["text"] = "changed"
        elif mutation == "owned_arguments":
            current_tool_call_binding().owned_message["params"]["arguments"]["text"] = "changed"
        elif mutation == "artifact_metadata":
            artifacts[0].metadata["tool_description"] = "changed"
        elif mutation == "artifact_private":
            artifacts[0].runtime_private_metadata["private"] = "changed"
        elif mutation == "equal_config_owner":
            proxy.config = replace(proxy.config)
        elif mutation == "effective_cwd":
            os.chdir(second)
        elif mutation == "catalog_epoch":
            proxy._tool_catalog_generation += 1
        elif mutation == "catalog_sibling":
            proxy._tool_catalog["new-sibling"] = {"inputSchema": {"type": "object"}}
        else:
            proxy.command.append("changed")
        return result

    def saved(*args, **kwargs):
        pytest.fail("a changed authority reached a later saved lookup")

    monkeypatch.setattr(proxy, "_evaluate_tool_call_authority", evaluate)
    monkeypatch.setattr(proxy.store, "read_local_mcp_grant", grant)
    monkeypatch.setattr(proxy.store, "resolve_policy_decision_lookup_with_memory_pattern", saved)
    result = proxy.run_session(messages)
    assert not marker.exists()
    assert result["events"][-1]["reason_code"] in {"tool_call_authority_changed", "tool_call_request_changed"}
    assert result["events"][-1]["session_terminal"] is True


def test_nested_preparation_cannot_replace_the_selected_outer_artifact(tmp_path, monkeypatch):
    proxy, messages, marker = _session(tmp_path)
    original_evaluate = proxy._evaluate_tool_call_authority
    artifacts = []
    nested = []

    def evaluate(**kwargs):
        artifacts.append(kwargs["artifact"])
        return original_evaluate(**kwargs)

    def package(*, tool_name, arguments):
        nested.append(proxy._resolve_tool_call_authority(tool_name="nested", arguments=arguments))
        artifacts[0].runtime_private_metadata["changed_outer"] = True
        return None

    monkeypatch.setattr(proxy, "_evaluate_tool_call_authority", evaluate)
    monkeypatch.setattr(proxy, "_package_request_artifact", package)
    result = proxy.run_session(messages)
    assert len(nested) == 1
    assert len(artifacts) == 2
    assert not marker.exists()
    assert result["events"][-1]["reason_code"] == "tool_call_authority_changed"


def test_private_evaluator_owned_artifact_is_bound_through_the_write(tmp_path, monkeypatch):
    proxy, messages, marker = _session(tmp_path)
    original_evaluate = proxy._evaluate_tool_call_authority
    consumed = []
    original_drain = proxy._drain_and_validate_catalog_authority

    def evaluate(**kwargs):
        artifact, artifact_hash, decision = original_evaluate(**kwargs)
        owned = replace(artifact, metadata=deepcopy(artifact.metadata), runtime_private_metadata={})
        consumed.append(owned)
        return owned, artifact_hash, decision

    def drain(**kwargs):
        result = original_drain(**kwargs)
        if kwargs.get("quiet_seconds") == 0.005:
            consumed[0].runtime_private_metadata["changed"] = True
        return result

    monkeypatch.setattr(proxy, "_evaluate_tool_call_authority", evaluate)
    monkeypatch.setattr(proxy, "_drain_and_validate_catalog_authority", drain)
    result = proxy.run_session(messages)
    assert len(consumed) == 1
    assert not marker.exists()
    assert result["events"][-1]["reason_code"] == "tool_call_authority_changed"


def test_unsupported_artifact_inside_proxy_never_drops_the_guard(tmp_path, monkeypatch):
    proxy, messages, marker = _session(tmp_path)
    original_artifact = runtime_mcp.build_tool_call_artifact
    callbacks = []

    class Hostile(dict):
        def items(self):
            callbacks.append("items")
            raise AssertionError

    def artifact(*args, **kwargs):
        result = original_artifact(*args, **kwargs)
        result.runtime_private_metadata["unsupported"] = Hostile(value="private")
        return result

    monkeypatch.setattr(runtime_mcp, "build_tool_call_artifact", artifact)
    result = proxy.run_session(messages)
    assert callbacks == []
    assert not marker.exists()
    assert result["events"][-1]["reason_code"] == "tool_call_authority_changed"


def test_authority_mutation_after_completed_write_does_not_veto_success(tmp_path, monkeypatch):
    proxy, messages, marker = _session(tmp_path)
    proxy.config = replace(proxy.config, artifact_actions={})
    original = framing._write_encoded_line
    completed = []

    def write(stream, data, **kwargs):
        result = original(stream, data, **kwargs)
        if json.loads(data).get("method") == "tools/call":
            proxy.config.artifact_actions["codex:runtime:project:synthetic:safe_echo"] = "block"
            completed.append(True)
        return result

    monkeypatch.setattr(framing, "_write_encoded_line", write)
    result = proxy.run_session(messages)
    assert completed == [True]
    assert json.loads(marker.read_text()) == messages[-1]
    assert result["responses"][-1]["result"]["content"][0]["text"] == "forwarded"


def test_temporary_grant_mutation_stops_before_the_next_selector(tmp_path, monkeypatch):
    proxy, messages, marker = _session(tmp_path, action="review")
    proxy.config = replace(proxy.config, artifact_actions={})
    trace = []
    original_lookup = proxy.store.resolve_policy_decision_lookup

    def lookup(*args, **kwargs):
        trace.append(args[1])
        result = original_lookup(*args, **kwargs)
        proxy.config.artifact_actions["codex:runtime:project:synthetic:safe_echo"] = "block"
        return result

    # Two selectors make a later store callback observable even when the first
    # has no match; production grant lookup and proxy forwarding stay active.
    monkeypatch.setattr(calls, "runtime_grant_selectors", lambda *_args, **_kwargs: ("first", "second"))
    monkeypatch.setattr(proxy.store, "resolve_policy_decision_lookup", lookup)
    result = proxy.run_session(messages)
    assert trace == ["first"]
    assert not marker.exists()
    assert result["events"][-1]["reason_code"] == "tool_call_authority_changed"


def test_claim_disposition_mutation_cannot_reach_a_claim_or_child(tmp_path, monkeypatch):
    proxy, messages, marker = _session(tmp_path, action="review")
    proxy.config = replace(proxy.config, artifact_actions={})
    trace = []

    def lookup(*args, **kwargs):
        trace.append("saved_lookup")
        return {
            "decision": {"action": "allow", "artifact_hash": kwargs["artifact_hash"]},
            "ignored_local_integrity": None,
        }

    def disposition(*args, **kwargs):
        trace.append("disposition")
        proxy.config.artifact_actions["codex:runtime:project:synthetic:safe_echo"] = "block"
        return "retained"

    def claim(*args, **kwargs):
        pytest.fail("a mutated preparation reached a saved approval claim")

    monkeypatch.setattr(proxy.store, "resolve_policy_decision_lookup_with_memory_pattern", lookup)
    monkeypatch.setattr(proxy.store, "approval_reuse_claim_disposition", disposition)
    monkeypatch.setattr(proxy.store, "claim_approval_reuse_decisions", claim)
    result = proxy.run_session(messages)
    assert trace == ["saved_lookup", "disposition"]
    assert not marker.exists()
    assert result["events"][-1]["reason_code"] == "tool_call_authority_changed"


def test_artifact_construction_cannot_bless_an_earlier_catalog_snapshot(tmp_path, monkeypatch):
    proxy, messages, marker = _session(tmp_path)
    original_artifact = runtime_mcp.build_tool_call_artifact
    constructed = []

    def artifact(*args, **kwargs):
        result = original_artifact(*args, **kwargs)
        constructed.append(result)
        proxy._tool_catalog_generation += 1
        proxy._tool_catalog["new-sibling"] = {"inputSchema": {"type": "object"}}
        return result

    def evaluate(**kwargs):
        pytest.fail("an artifact built across a catalog mutation reached evaluation")

    monkeypatch.setattr(runtime_mcp, "build_tool_call_artifact", artifact)
    monkeypatch.setattr(proxy, "_evaluate_tool_call_authority", evaluate)
    result = proxy.run_session(messages)
    assert len(constructed) == 1
    assert not marker.exists()
    assert result["events"][-1]["reason_code"] == "tool_call_authority_changed"


def test_contribution_authority_callback_cannot_reach_later_tool_state(monkeypatch):
    from codex_plugin_scanner.guard.runtime import mcp_server_grants

    from .test_guard_mcp_server_grants import _artifact, _AuthorityStore, _identity

    artifact = _artifact(_identity(), "write_file")
    store = _AuthorityStore()
    original_read = store.read_extension_control_authority_for_registry
    binding = capture_authority_binding(
        values=lambda: artifact, owners=lambda: (artifact,), changed=lambda: ValueError("changed")
    )
    reached = []

    def read(registry):
        result = original_read(registry)
        reached.append("authority_read")
        artifact.metadata["changed"] = True
        return result

    def state(*args, **kwargs):
        pytest.fail("a changed contribution authority reached tool-state selection")

    monkeypatch.setattr(store, "read_extension_control_authority_for_registry", read)
    monkeypatch.setattr(mcp_server_grants, "mcp_tool_state", state)
    with use_mcp_authority_check(binding.check), pytest.raises(ValueError, match="changed"):
        mcp_server_grants.apply_contributed_mcp_decision(store, artifact, "review")
    assert reached == ["authority_read"]


def test_authority_digest_rejects_hostile_metaclasses_without_callbacks():
    callbacks = []

    class HostileMeta(type):
        def __eq__(cls, other):
            callbacks.append("equality")
            return True

    class Hostile(metaclass=HostileMeta):
        def __str__(self):
            callbacks.append("string")
            raise AssertionError

    with pytest.raises(UnsupportedAuthorityValueError):
        exact_authority_digest(Hostile())
    assert callbacks == []


@pytest.mark.parametrize(
    ("first", "second"), [(True, 1), (1, 1.0), (0.0, -0.0), ([], ()), ({"a": 1, "b": 2}, {"b": 2, "a": 1})]
)
def test_authority_digest_preserves_scalar_types_and_input_order(first, second):
    assert exact_authority_digest(first) != exact_authority_digest(second)


def test_default_evaluator_keeps_public_aliases_and_three_private_preparation_calls(tmp_path, monkeypatch):
    proxy, messages, marker = _session(tmp_path)
    trace = []
    original_hash = runtime_mcp.build_tool_call_hash
    original_evaluate = runtime_mcp.evaluate_tool_call
    original_check = proxy._check_tool_call_preparation

    def build(*args, **kwargs):
        trace.append("public_hash")
        return original_hash(*args, **kwargs)

    def evaluate(**kwargs):
        trace.append("public_evaluate")
        return original_evaluate(**kwargs)

    def check():
        trace.append("private_prepare")
        return original_check()

    monkeypatch.setattr(runtime_mcp, "build_tool_call_hash", build)
    monkeypatch.setattr(runtime_mcp, "evaluate_tool_call", evaluate)
    monkeypatch.setattr(proxy, "_check_tool_call_preparation", check)
    result = proxy.run_session(messages)
    assert trace == [
        "private_prepare",
        "public_hash",
        "private_prepare",
        "public_evaluate",
        "private_prepare",
        "private_prepare",
    ]
    assert json.loads(marker.read_text()) == messages[-1]
    assert result["responses"][-1]["result"]["content"][0]["text"] == "forwarded"


def test_private_composer_check_cannot_replace_active_proxy_authority(tmp_path, monkeypatch):
    proxy, messages, marker = _session(tmp_path)
    proxy.config = replace(proxy.config, artifact_actions={})
    original_grant = proxy.store.read_local_mcp_grant
    private_checks = []

    def evaluate(**kwargs):
        current = calls._evaluate_current_tool_call(
            config=kwargs["config"],
            artifact=kwargs["artifact"],
            arguments=kwargs["arguments"],
        )
        return calls._evaluate_tool_call_with_current(
            **kwargs,
            current=current,
            authority_check=lambda: private_checks.append(True),
        )

    def grant(*args, **kwargs):
        result = original_grant(*args, **kwargs)
        proxy.config.artifact_actions["codex:runtime:project:synthetic:safe_echo"] = "block"
        return result

    def saved(*args, **kwargs):
        pytest.fail("an optional private check hid a changed proxy authority")

    monkeypatch.setattr(runtime_mcp, "evaluate_tool_call", evaluate)
    monkeypatch.setattr(proxy.store, "read_local_mcp_grant", grant)
    monkeypatch.setattr(proxy.store, "resolve_policy_decision_lookup_with_memory_pattern", saved)
    result = proxy.run_session(messages)
    assert private_checks
    assert not marker.exists()
    assert result["events"][-1]["reason_code"] == "tool_call_authority_changed"


@pytest.mark.parametrize("guard_active", [True, False], ids=["mcp_guard", "direct_helper_compatibility"])
def test_package_saved_lookup_mutation_stops_before_next_workspace(tmp_path, monkeypatch, guard_active):
    from types import SimpleNamespace

    from codex_plugin_scanner.guard import local_supply_chain

    from .test_guard_mcp_package_proxy_phase14 import _runtime_package_artifact

    proxy, _messages, _marker = _session(tmp_path)
    artifact = _runtime_package_artifact(proxy.context)
    binding = capture_authority_binding(
        values=lambda: artifact, owners=lambda: (artifact,), changed=lambda: ValueError("changed")
    )
    trace = []

    def lookup(*args, **kwargs):
        trace.append(("lookup", args[3]))
        artifact.runtime_private_metadata["changed"] = True
        return {"decision": None, "ignored_local_integrity": None}

    def validation(*args, **kwargs):
        trace.append(("validation", args[3]))
        return None

    monkeypatch.setattr(
        local_supply_chain,
        "_package_policy_workspace_candidates",
        lambda **_kwargs: ("first-workspace", "second-workspace"),
    )
    monkeypatch.setattr(proxy.store, "resolve_policy_decision_lookup", lookup)
    monkeypatch.setattr(proxy.store, "approval_reuse_validation_reason", validation)

    def resolve():
        return local_supply_chain._resolve_stored_package_policy_override(
            SimpleNamespace(policy_action="warn"),
            store=proxy.store,
            artifact=artifact,
            artifact_hash="synthetic-hash",
            workspace_dir=tmp_path,
            now="2026-09-18T00:00:00Z",
            claim_saved_approval=False,
        )

    if guard_active:
        with use_mcp_authority_check(binding.check), pytest.raises(ValueError, match="changed"):
            resolve()
        assert trace == [("lookup", "first-workspace")]
    else:
        resolve()
        assert trace == [
            ("lookup", "first-workspace"),
            ("lookup", "second-workspace"),
            ("validation", "first-workspace"),
            ("validation", "second-workspace"),
        ]
