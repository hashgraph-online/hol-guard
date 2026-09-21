"""Request-local reuse must not survive a change to arguments or authority."""

from __future__ import annotations

import sys
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import mcp_tool_calls as calls
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.proxy import CodexMcpGuardProxy
from codex_plugin_scanner.guard.store import GuardStore


def _artifact(tool="summarize"):
    return calls.build_tool_call_artifact(
        harness="codex",
        server_name="synthetic",
        tool_name=tool,
        source_scope="project",
        config_path=".mcp.json",
        transport="stdio",
        tool_schema={"type": "object", "properties": {"text": {"type": "string"}}},
        tool_description="Summarize text.",
        server_fingerprint={"tool_catalog_fingerprint": "initial", "configured_env_values_hash": "initial"},
    )


def _count_categories(monkeypatch):
    original = calls.tool_call_risk_categories
    seen = []

    def counted(artifact, arguments):
        seen.append((artifact, arguments))
        return original(artifact, arguments)

    monkeypatch.setattr(calls, "tool_call_risk_categories", counted)
    return seen


def _hash(config, artifact, arguments, facts=None):
    return calls.build_tool_call_hash(artifact, arguments, workspace=config.workspace, config=config, risk_facts=facts)


def test_one_analysis_supplies_unchanged_hash_and_complete_current_policy(tmp_path, monkeypatch):
    artifact = _artifact("run_terminal_command")
    arguments = {"command": "cat .env", "nested": [False, 7, 3.0, None]}
    config = GuardConfig(guard_home=tmp_path, workspace=tmp_path)
    store = GuardStore(tmp_path)
    expected_hash = _hash(config, artifact, arguments)
    expected = calls.evaluate_tool_call(
        store=store,
        config=config,
        artifact=artifact,
        artifact_hash=expected_hash,
        arguments=arguments,
        claim_saved_approval=False,
    )
    seen = _count_categories(monkeypatch)
    facts = calls.prepare_tool_call_risk_facts(artifact, arguments)
    assert facts is not None
    assert _hash(config, artifact, arguments, facts) == expected_hash
    actual = calls.evaluate_tool_call(
        store=store,
        config=config,
        artifact=artifact,
        artifact_hash=expected_hash,
        arguments=arguments,
        claim_saved_approval=False,
        risk_facts=facts,
    )
    assert actual == expected
    assert len(seen) == 1
    assert seen[0][0].metadata is not artifact.metadata
    assert seen[0][1] is not arguments


def test_retained_default_derives_facts_at_both_authority_consumers(tmp_path, monkeypatch):
    context = HarnessContext(home_dir=tmp_path, workspace_dir=tmp_path, guard_home=tmp_path / "guard")
    proxy = CodexMcpGuardProxy(
        server_name="synthetic",
        command=[sys.executable, "-u", "-c", ""],
        context=context,
        store=GuardStore(context.guard_home),
        config=GuardConfig(guard_home=context.guard_home, workspace=tmp_path),
        source_scope="project",
        config_path=".mcp.json",
    )
    proxy._tool_catalog["run_terminal_command"] = {
        "name": "run_terminal_command",
        "description": "Run a terminal command.",
        "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}},
    }
    proxy._tool_catalog_state = "complete"
    seen = _count_categories(monkeypatch)
    monkeypatch.setattr(
        calls,
        "prepare_tool_call_risk_facts",
        lambda *_args, **_kwargs: pytest.fail("Unselected facts experiment entered the runtime default"),
    )
    arguments = {"command": "echo hello"}
    first = proxy._resolve_tool_call_authority(tool_name="run_terminal_command", arguments=arguments)
    assert len(seen) == 2
    second = proxy._resolve_tool_call_authority(tool_name="run_terminal_command", arguments=arguments)
    assert len(seen) == 4
    assert second == first
    arguments["command"] = "cat .env"
    changed = proxy._resolve_tool_call_authority(tool_name="run_terminal_command", arguments=arguments)
    assert len(seen) == 6
    assert changed.artifact_hash != first.artifact_hash
    assert "secret_access" in changed.decision.risk_categories
    assert not hasattr(changed, "risk_facts")


@pytest.mark.parametrize(
    "mutation",
    ["arguments", "schema", "description", "catalog", "environment", "server_identity", "tool_identity", "private"],
)
def test_changed_inputs_reject_prepared_facts_and_match_uncached_policy(tmp_path, monkeypatch, mutation):
    artifact = _artifact()
    arguments = {"nested": {"text": "ordinary text"}}
    config = GuardConfig(guard_home=tmp_path, workspace=tmp_path)
    facts = calls.prepare_tool_call_risk_facts(artifact, arguments)
    assert facts is not None
    if mutation == "arguments":
        arguments["nested"]["text"] = "cat .env"
    elif mutation == "schema":
        artifact.metadata["tool_schema"]["properties"]["command"] = {"type": "string"}
    elif mutation == "description":
        artifact.metadata["tool_description"] = "Execute commands and read secrets."
    elif mutation in {"catalog", "environment"}:
        key = "tool_catalog_fingerprint" if mutation == "catalog" else "configured_env_values_hash"
        artifact.metadata["server_fingerprint"][key] = "changed"
    elif mutation == "server_identity":
        artifact.metadata["mcp_server_identity"] = {"identity_hash": "changed"}
    elif mutation == "tool_identity":
        artifact.metadata["mcp_tool_identity"]["identity_hash"] = "changed"
    else:
        artifact.runtime_private_metadata["request_binding"] = "changed"
    expected_hash = _hash(config, artifact, arguments)
    expected = calls._evaluate_current_tool_call(config=config, artifact=artifact, arguments=arguments)
    seen = _count_categories(monkeypatch)
    assert _hash(config, artifact, arguments, facts) == expected_hash
    actual = calls._evaluate_current_tool_call(config=config, artifact=artifact, arguments=arguments, risk_facts=facts)
    assert actual == expected
    assert len(seen) == 2


def test_preparation_owns_inputs_before_analysis_can_observe_mutation(tmp_path, monkeypatch):
    artifact = _artifact()
    arguments = {"nested": {"text": "ordinary text"}}
    original = calls.tool_call_risk_categories

    def mutate_original(owned_artifact, owned_arguments):
        arguments["nested"]["text"] = "cat .env"
        artifact.metadata["tool_description"] = "Read secrets."
        assert owned_arguments["nested"]["text"] == "ordinary text"
        assert owned_artifact.metadata["tool_description"] == "Summarize text."
        return original(owned_artifact, owned_arguments)

    monkeypatch.setattr(calls, "tool_call_risk_categories", mutate_original)
    facts = calls.prepare_tool_call_risk_facts(artifact, arguments)
    assert facts is not None and "secret_access" not in facts.categories
    monkeypatch.setattr(calls, "tool_call_risk_categories", original)
    config = GuardConfig(guard_home=tmp_path, workspace=tmp_path)
    assert _hash(config, artifact, arguments, facts) == _hash(config, artifact, arguments)
    decision = calls._evaluate_current_tool_call(
        config=config, artifact=artifact, arguments=arguments, risk_facts=facts
    )
    assert "secret_access" in decision.risk_categories


@pytest.mark.parametrize("consumer", ["hash", "policy"])
def test_matching_consumer_uses_owned_copy_after_alias_changes(tmp_path, monkeypatch, consumer):
    artifact = _artifact("run_terminal_command")
    arguments = {"command": "echo hello"}
    config = GuardConfig(guard_home=tmp_path, workspace=tmp_path)
    facts = calls.prepare_tool_call_risk_facts(artifact, arguments)
    expected_hash = _hash(config, artifact, arguments)
    expected_policy = calls._evaluate_current_tool_call(config=config, artifact=artifact, arguments=arguments)
    original = calls._matching_tool_call_risk_snapshot

    def mutate_after_matching(current_artifact, current_arguments, current_facts):
        result = original(current_artifact, current_arguments, current_facts)
        assert result is not None
        arguments["command"] = "cat .env"
        artifact.metadata["tool_description"] = "Read secrets."
        return result

    monkeypatch.setattr(calls, "_matching_tool_call_risk_snapshot", mutate_after_matching)
    if consumer == "hash":
        assert _hash(config, artifact, arguments, facts) == expected_hash
    else:
        assert (
            calls._evaluate_current_tool_call(config=config, artifact=artifact, arguments=arguments, risk_facts=facts)
            == expected_policy
        )


def test_current_policy_callback_mutation_cannot_reuse_old_facts(tmp_path, monkeypatch):
    artifact = _artifact("run_terminal_command")
    arguments = {"command": "echo hello"}
    config = GuardConfig(guard_home=tmp_path, workspace=tmp_path)
    facts = calls.prepare_tool_call_risk_facts(artifact, arguments)
    original = GuardConfig.resolve_action_override

    def mutate_then_resolve(self, *args, **kwargs):
        arguments["command"] = "cat .env"
        return original(self, *args, **kwargs)

    monkeypatch.setattr(GuardConfig, "resolve_action_override", mutate_then_resolve)
    seen = _count_categories(monkeypatch)
    actual = calls._evaluate_current_tool_call(config=config, artifact=artifact, arguments=arguments, risk_facts=facts)
    assert "secret_access" in actual.risk_categories
    assert len(seen) == 1
    assert actual == calls._evaluate_current_tool_call(config=config, artifact=artifact, arguments=arguments)


@pytest.mark.parametrize("action", ["allow", "warn", "review", "block"])
def test_policy_and_browser_context_stay_fresh_and_preserve_order(tmp_path, action):
    artifact = _artifact("browser_click")
    artifact.metadata.update(
        {
            "browser_current_page_url": "https://example.invalid/form",
            "server_args": ["--isolated"],
            "tool_schema": {
                "type": "object",
                "properties": {"password": {"type": "string"}, "element": {"type": "string"}},
            },
        }
    )
    arguments = {"element": "submit", "ref": "fixture", "password": "synthetic-private-value"}
    facts = calls.prepare_tool_call_risk_facts(artifact, arguments)
    assert facts is not None
    config = GuardConfig(guard_home=tmp_path, workspace=tmp_path, default_action=action)
    for current in (config, replace(config, default_action="block")):
        assert _hash(current, artifact, arguments, facts) == _hash(current, artifact, arguments)
        assert calls._evaluate_current_tool_call(
            config=current, artifact=artifact, arguments=arguments, risk_facts=facts
        ) == calls._evaluate_current_tool_call(config=current, artifact=artifact, arguments=arguments)
    reordered = dict(reversed(list(arguments.items())))
    assert calls._matching_tool_call_risk_snapshot(artifact, reordered, facts) is None
    artifact.metadata["browser_current_page_url"] = "https://other.invalid/login"
    artifact.metadata["server_args"] = ["--shared"]
    assert calls._matching_tool_call_risk_snapshot(artifact, arguments, facts) is None
    assert _hash(config, artifact, arguments, facts) == _hash(config, artifact, arguments)


@pytest.mark.parametrize(
    "first,second",
    [
        (True, 1),
        (False, 0),
        (1, 1.0),
        (0.0, -0.0),
        (1.0, "0x1.0000000000000p+0"),
        (1, "1"),
        ([], {}),
        ([1], (1,)),
        ([[1], 2], [1, [2]]),
        ({"a": ["b"]}, {"b": ["a"]}),
        ({"a": 1, "b": 2}, {"b": 2, "a": 1}),
        ({"1": "text"}, {1: "text"}),
    ],
)
def test_snapshot_does_not_conflate_json_types(first, second):
    artifact = _artifact()
    facts = calls.prepare_tool_call_risk_facts(artifact, {"value": first})
    assert facts is not None
    assert calls._matching_tool_call_risk_snapshot(artifact, {"value": second}, facts) is None


def test_structural_binding_shares_immutable_text_but_owns_nested_containers():
    artifact = _artifact()
    text = "\u20ac" * 8192
    arguments = {"nested": [{"text": text}, [True, False, None, 7, -0.0]]}
    first = calls._tool_call_risk_snapshot(artifact, arguments)
    second = calls._tool_call_risk_snapshot(artifact, deepcopy(arguments))
    assert first is not None and second is not None
    assert first[0] == second[0]
    assert type(first[0][0]) is bytes and type(first[0][1]) is tuple
    assert any(leaf is text for leaf in first[0][1])
    assert first[2] is not arguments
    assert first[2]["nested"][0] is not arguments["nested"][0]
    assert first[2]["nested"][0]["text"] is text
    arguments["nested"][0]["text"] = "changed"
    assert calls._tool_call_risk_snapshot(artifact, arguments)[0] != first[0]


def test_large_cardinality_binding_has_no_per_scalar_tagged_containers():
    artifact = _artifact()
    values = [0] * 65536
    empty = calls._tool_call_risk_snapshot(artifact, {"values": []})
    full = calls._tool_call_risk_snapshot(artifact, {"values": values})
    assert empty is not None and full is not None
    assert len(full[0][0]) - len(empty[0][0]) == len(values)
    assert len(full[0][1]) - len(empty[0][1]) == len(values)
    assert all(type(value) in (str, int) for value in full[0][1])
    assert full[2]["values"] == values and full[2]["values"] is not values


def test_artifact_tuple_arguments_and_fixed_fields_enter_structural_binding():
    artifact = replace(_artifact(), args=("--first", "--second"))
    facts = calls.prepare_tool_call_risk_facts(artifact, {})
    assert facts is not None
    reordered = replace(artifact, args=tuple(reversed(artifact.args)))
    assert calls._matching_tool_call_risk_snapshot(reordered, {}, facts) is None
    assert calls._matching_tool_call_risk_snapshot(replace(artifact, args=["--first", "--second"]), {}, facts) is None
    assert calls._matching_tool_call_risk_snapshot(replace(artifact, config_path="changed"), {}, facts) is None


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), ("text",), {1: "text"}])
def test_unsupported_shapes_preserve_uncached_hash_and_policy(tmp_path, value):
    artifact = _artifact()
    arguments = {"value": value}
    assert calls.prepare_tool_call_risk_facts(artifact, arguments) is None
    old_facts = calls.prepare_tool_call_risk_facts(artifact, {"value": "text"})
    config = GuardConfig(guard_home=tmp_path, workspace=tmp_path)
    assert _hash(config, artifact, arguments, old_facts) == _hash(config, artifact, arguments)
    assert calls._evaluate_current_tool_call(
        config=config, artifact=artifact, arguments=arguments, risk_facts=old_facts
    ) == calls._evaluate_current_tool_call(config=config, artifact=artifact, arguments=arguments)


def test_custom_containers_cycles_and_private_objects_never_get_cached(tmp_path):
    class CustomDict(dict):
        def items(self):
            raise AssertionError("snapshot must not invoke custom methods")

    class CustomStr(str):
        pass

    artifact = _artifact()
    for arguments in (CustomDict(value="text"), {"value": CustomStr("text")}):
        assert calls.prepare_tool_call_risk_facts(artifact, arguments) is None
    cycle = {}
    cycle["cycle"] = cycle
    assert calls.prepare_tool_call_risk_facts(artifact, cycle) is None
    config = GuardConfig(guard_home=tmp_path, workspace=tmp_path)
    with pytest.raises(ValueError, match="Circular reference"):
        _hash(config, artifact, cycle)
    artifact.runtime_private_metadata["request"] = object()
    assert calls.prepare_tool_call_risk_facts(artifact, {}) is None


def test_facts_are_immutable_private_and_detached():
    artifact = _artifact()
    arguments = {"text": "synthetic-private-value"}
    facts = calls.prepare_tool_call_risk_facts(artifact, arguments)
    assert facts is not None
    assert "synthetic-private-value" not in repr(facts)
    with pytest.raises(FrozenInstanceError):
        facts.categories = ()
    before = deepcopy(arguments)
    owned = calls._matching_tool_call_risk_snapshot(artifact, arguments, facts)
    assert owned is not None and owned[1] == before
    owned[1]["text"] = "changed copy"
    assert arguments == before
    assert calls._matching_tool_call_risk_snapshot(artifact, arguments, facts) is not None


def test_one_risk_analysis_per_decision_and_fresh_analysis_after_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = calls.build_tool_call_artifact(
        harness="codex",
        server_name="synthetic",
        tool_name="run_terminal_command",
        source_scope="project",
        config_path=".mcp.json",
        transport="stdio",
    )
    config = GuardConfig(guard_home=tmp_path, workspace=tmp_path)
    original = calls._tool_call_risk_category_set
    analyses = 0

    def counted(artifact, arguments):
        nonlocal analyses
        analyses += 1
        return original(artifact, arguments)

    monkeypatch.setattr(calls, "_tool_call_risk_category_set", counted)
    safe = calls._evaluate_current_tool_call(config=config, artifact=artifact, arguments={"command": "echo hello"})
    assert analyses == 1
    assert "command_execution" in safe.risk_categories
    assert "secret_access" not in safe.risk_categories
    changed = calls._evaluate_current_tool_call(config=config, artifact=artifact, arguments={"command": "cat .env"})
    assert analyses == 2
    assert "secret_access" in changed.risk_categories
    assert "sensitive local files or secrets" in changed.summary
    assert changed.action != "allow"
