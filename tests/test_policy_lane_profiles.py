"""Check complete selector projection and unavailable native admission."""

from __future__ import annotations

from dataclasses import replace
from itertools import combinations, product
from typing import cast

import pytest

from codex_plugin_scanner.guard.policy_capability_inventory import local_row_projection_capabilities
from codex_plugin_scanner.guard.policy_document import GuardPolicyDocument
from codex_plugin_scanner.guard.policy_document_compile import compile_policy_document
from codex_plugin_scanner.guard.policy_document_types import PolicyCompilationError
from codex_plugin_scanner.guard.policy_lane_capabilities import (
    GENERIC_LANE,
    NATIVE_DEFAULTS_LANE,
    NATIVE_SCOPED_LANE,
    command_evaluator_document,
    published_runtime_lane_profiles,
    source_runtime_lane_observation,
    validate_policy_runtime_lane,
)

SELECTORS: dict[str, object] = {
    "artifacts": ["shell:echo"],
    "harnesses": ["codex"],
    "publishers": ["synthetic"],
    "tools": ["shell"],
    "workspaces": ["/synthetic/workspace"],
    "exactCommand": {"contractVersion": "guard.exact-command.v1", "sha256": "a" * 64},
}
SUBSETS = tuple(keys for size in range(7) for keys in combinations(SELECTORS, size))


def document(match: dict[str, object] | None = None) -> GuardPolicyDocument:
    return GuardPolicyDocument.from_mapping(
        {
            "apiVersion": "guard.hashgraphonline.com/v1alpha1",
            "kind": "GuardPolicy",
            "metadata": {"id": "synthetic-profile", "name": "Synthetic profile", "revision": 1},
            "spec": {
                "defaults": {"mode": "prompt"},
                "rules": [
                    {
                        "id": "rule-a",
                        "enabled": True,
                        "effect": "block",
                        "match": {} if match is None else match,
                        "lifetime": {"mode": "permanent"},
                        "provenance": {"source": "import", "createdAt": "2026-09-18T00:00:00Z"},
                    }
                ],
            },
        }
    )


@pytest.mark.parametrize(
    ("keys", "effect", "lifetime"), product(SUBSETS, ("allow", "block", "review"), ("permanent", "until"))
)
def test_inventory_matches_actual_compiler_for_every_combination(
    keys: tuple[str, ...], effect: str, lifetime: str
) -> None:
    source = document({key: SELECTORS[key] for key in keys})
    rule = source.rules[0]
    source = replace(
        source,
        rules=(
            replace(
                rule,
                effect=effect,
                lifetime=replace(
                    rule.lifetime,
                    mode=lifetime,
                    expires_at="2030-01-01T00:00:00Z" if lifetime == "until" else None,
                ),
            ),
        ),
    )
    profile = local_row_projection_capabilities()
    published = cast(list[list[str]], profile["supported_match_combinations"])
    supported = frozenset(keys) in {frozenset(item) for item in published}
    if not supported:
        with pytest.raises(PolicyCompilationError):
            compile_policy_document(source)
        return
    rows = compile_policy_document(source)
    assert len(rows) == 1
    decision = rows[0].decision
    assert decision.action == effect
    if "artifacts" in keys:
        assert decision.artifact_id == "shell:echo"
    if "harnesses" in keys:
        assert decision.harness == "codex"
    if "publishers" in keys:
        assert decision.publisher == "synthetic"
    if "workspaces" in keys:
        assert decision.workspace == "/synthetic/workspace"
    if "tools" in keys:
        assert decision.artifact_id == "family:tool-action"
    if "exactCommand" in keys:
        assert decision.exact_command_sha256 == "a" * 64
    if lifetime == "until":
        assert decision.expires_at == "2030-01-01T00:00:00Z"


@pytest.mark.parametrize("artifact", ["*", "family:tool-action", "family:shell"])
def test_exact_command_never_becomes_a_family_or_global_rule(artifact: str) -> None:
    with pytest.raises(PolicyCompilationError):
        compile_policy_document(document({"artifacts": [artifact], "exactCommand": SELECTORS["exactCommand"]}))


def test_diagnostics_preserve_each_offending_rule() -> None:
    first = document({"paths": ["/synthetic/path"]}).rules[0]
    second = document({"domains": ["invalid.example"]}).rules[0]
    result = validate_policy_runtime_lane(
        replace(document(), rules=(first, replace(second, id="rule-b"))), GENERIC_LANE
    )
    assert not result["valid"]
    assert [item["rule_id"] for item in result["rule_diagnostics"]] == ["rule-a", "rule-b"]
    assert all(item["code"] == "unsupported_policy_match" for item in result["rule_diagnostics"])


def test_managed_diagnostics_preserve_each_enabled_rule_and_root() -> None:
    rule = replace(document().rules[0], extensions=(("x-hol-extension-targets", "[]"),))
    source = replace(
        document(),
        rules=(
            rule,
            replace(rule, id="rule-b"),
            replace(rule, id="disabled", enabled=False),
            replace(rule, id="ignored", effect="ignore"),
        ),
        extensions=(("x-hol-extension-controls", "{}"),),
    )
    result = validate_policy_runtime_lane(source, GENERIC_LANE)
    assert not result["valid"]
    assert [item["rule_id"] for item in result["rule_diagnostics"]] == ["rule-a", "rule-b", None]
    assert result["rule_diagnostics"][-1]["field_path"] == "$.x-hol-extension-controls"


@pytest.mark.parametrize("lane", [NATIVE_DEFAULTS_LANE, NATIVE_SCOPED_LANE])
def test_native_lane_cannot_admit_generic_rules_from_static_shape(lane: str) -> None:
    result = validate_policy_runtime_lane(document({"artifacts": ["shell:echo"]}), lane)
    assert not result["valid"]
    assert result["activation_evidence"] == "not_evaluated"
    assert result["rule_diagnostics"][0]["rule_id"] == "rule-a"


def test_empty_native_scoped_profile_still_requires_negotiation() -> None:
    result = validate_policy_runtime_lane(replace(document(), rules=()), NATIVE_SCOPED_LANE)
    assert not result["valid"]
    assert result["rule_diagnostics"][0]["code"] == "native_lane_unnegotiated"


def test_profiles_are_fresh_and_cannot_infer_activation_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOL_GUARD_NATIVE_RUNTIME", "1")
    monkeypatch.setenv("HOL_GUARD_RUNTIME_ENGINE", "oracle")
    first = published_runtime_lane_profiles()
    first["lanes"] = {}
    second = published_runtime_lane_profiles()
    assert second["lanes"]
    assert second["activation_evidence"] == "not_evaluated"
    observation = source_runtime_lane_observation()
    assert observation["selectedLane"] is None
    assert observation["readiness"] == "unavailable"
    expression = cast(dict[str, object], second["command_expression_projection"])
    assert expression["authenticated_application"] == "unsupported"


def test_command_expression_is_evaluator_only_for_generic_admission() -> None:
    source = document(
        {
            "commands": {
                "combinator": "any",
                "conditions": [{"field": "command", "operator": "exact", "value": "echo ok"}],
            }
        }
    )
    result = validate_policy_runtime_lane(source, GENERIC_LANE)
    assert not result["valid"]
    assert result["rule_diagnostics"][0]["code"] == "command_expression_requires_guard_3_1_runtime"


def test_unknown_lane_fails_explicitly() -> None:
    with pytest.raises(ValueError, match="unsupported_runtime_lane"):
        validate_policy_runtime_lane(document(), "unrecognized")


def test_aggregate_fanout_cannot_hide_behind_per_rule_validation() -> None:
    rule = document(
        {
            "artifacts": [f"shell:item-{index}" for index in range(100)],
            "harnesses": [f"harness-{index}" for index in range(60)],
        }
    ).rules[0]
    source = replace(document(), rules=(rule, replace(rule, id="rule-b")))
    result = validate_policy_runtime_lane(source, GENERIC_LANE)
    assert not result["valid"]
    assert result["rule_diagnostics"][0]["code"] == "policy_compilation_limit"
    assert result["rule_diagnostics"][0]["rule_id"] == "rule-b"


def test_native_content_context_is_not_a_ready_generic_projection() -> None:
    rule = document({"artifacts": ["shell:echo"]}).rules[0]
    source = replace(
        document(),
        rules=(replace(rule, extensions=(("x-hol-local", '{"artifactHash":"synthetic-context"}'),)),),
    )
    result = validate_policy_runtime_lane(source, NATIVE_SCOPED_LANE)
    assert not result["valid"]
    assert result["rule_diagnostics"][0]["code"] == "native_content_context_unsupported"


@pytest.mark.parametrize("lane", [GENERIC_LANE, NATIVE_DEFAULTS_LANE, NATIVE_SCOPED_LANE])
def test_network_authority_cannot_be_projected_to_a_different_lane(lane: str) -> None:
    source = replace(document(), spec_extensions=(("networkPolicy", '{"schemaVersion":"guard.network-policy.v1"}'),))
    result = validate_policy_runtime_lane(source, lane)
    assert not result["valid"]
    assert result["rule_diagnostics"][0]["code"] == "network_policy_requires_separate_runtime"
    assert result["rule_diagnostics"][0]["field_path"] == "$.spec.networkPolicy"


def test_direct_command_projection_cannot_discard_network_authority() -> None:
    source = replace(document(), spec_extensions=(("networkPolicy", '{"schemaVersion":"guard.network-policy.v1"}'),))
    with pytest.raises(PolicyCompilationError, match="network_policy_requires_separate_runtime"):
        command_evaluator_document(source)
