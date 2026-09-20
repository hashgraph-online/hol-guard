"""Complete pure projection evidence; no active consumer or signature claim."""

from __future__ import annotations

import copy
import json
from dataclasses import FrozenInstanceError

import pytest

from codex_plugin_scanner.guard.policy_command_projection import (
    CanonicalCommandProjection,
    project_canonical_command_policy,
)
from codex_plugin_scanner.guard.policy_document import GuardPolicyDocument, policy_document_digest
from codex_plugin_scanner.guard.policy_document_compile import compile_policy_document
from codex_plugin_scanner.guard.policy_document_types import PolicyCompilationError
from codex_plugin_scanner.guard.policy_document_yaml import parse_policy_document_yaml
from codex_plugin_scanner.guard.policy_lane_capabilities import source_runtime_lane_observation
from codex_plugin_scanner.guard.policy_publication_binding import PolicyPublicationBinding

WORKSPACE = "11111111-1111-4111-8111-111111111111"
TARGET = "22222222-2222-4222-8222-222222222222"
LOCAL_INSTALLATION = "local-machine-source"
PUBLICATION = PolicyPublicationBinding(42, "sha256:" + "b" * 64, LOCAL_INSTALLATION)


def expression() -> dict[str, object]:
    return {
        "combinator": "all",
        "conditions": [
            {"field": "command", "operator": "startsWith", "value": "printf", "caseSensitive": True},
            {"field": "command", "operator": "endsWith", "value": "fixture", "caseSensitive": False},
        ],
    }


def rule(rule_id: str = "expression", **overrides: object) -> dict[str, object]:
    result: dict[str, object] = {
        "id": rule_id,
        "enabled": True,
        "effect": "block",
        "match": {"commands": expression()},
        "lifetime": {"mode": "permanent", "expiresAt": None},
        "provenance": {"source": "builder", "createdAt": "2026-09-18T00:00:00Z"},
    }
    result.update(overrides)
    return result


def mapping(*rules: dict[str, object]) -> dict[str, object]:
    return {
        "apiVersion": "guard.hashgraphonline.com/v1alpha1",
        "kind": "GuardPolicy",
        "metadata": {"id": "expression-policy", "name": "Expression fixture", "revision": 8},
        "spec": {"defaults": {"mode": "enforce"}, "rules": list(rules or (rule(),))},
    }


def document(value: dict[str, object] | None = None) -> GuardPolicyDocument:
    return parse_policy_document_yaml(json.dumps(value or mapping()))


def project(value: dict[str, object] | None = None, *, target_device_id: str = TARGET) -> CanonicalCommandProjection:
    return project_canonical_command_policy(
        document(value),
        publication=PUBLICATION,
        workspace_id=WORKSPACE,
        target_device_id=target_device_id,
    )


def test_projection_retains_original_complete_expression_identity_and_no_activation():
    value = document()
    result = project()
    assert result.source.policy_version == "8"
    assert result.source.publication.bundle_version == 42
    assert result.source.publication.bundle_hash == "sha256:" + "b" * 64
    assert result.source.payload_hash == "sha256:" + policy_document_digest(value)
    assert result.source.workspace_id == WORKSPACE
    assert result.source.target_device_id == TARGET
    assert result.source.publication.installation_id == LOCAL_INSTALLATION
    assert result.rows[0].expression == value.rules[0].match.command_expression
    assert result.rows[0].identity.publication == PUBLICATION
    assert result.rows[0].identity.to_dict() == {
        "policyId": "expression-policy",
        "ruleId": "expression",
        "policyVersion": "8",
    }
    assert source_runtime_lane_observation()["selectedLane"] is None
    assert source_runtime_lane_observation()["readiness"] == "unavailable"
    with pytest.raises(PolicyCompilationError, match="command_expression_requires_guard_3_1_runtime"):
        compile_policy_document(value)


def test_existing_selector_compiler_retains_the_complete_and_product_and_expiry():
    expires = "2026-09-18T04:01:02.123Z"
    raw = mapping(
        rule(
            match={
                "commands": expression(),
                "harnesses": ["codex", "claude-code"],
                "artifacts": ["tool-action:shell:a", "tool-action:shell:b"],
                "workspaces": ["/synthetic/project"],
                "exactCommand": {"contractVersion": "guard.exact-command.v1", "sha256": "c" * 64},
            },
            lifetime={"mode": "until", "expiresAt": expires},
        )
    )
    before = copy.deepcopy(raw)
    result = project(raw)
    assert raw == before
    assert len(result.rows) == 4
    assert {(row.selector.harness, row.selector.artifact_id) for row in result.rows} == {
        ("codex", "tool-action:shell:a"),
        ("codex", "tool-action:shell:b"),
        ("claude-code", "tool-action:shell:a"),
        ("claude-code", "tool-action:shell:b"),
    }
    for row in result.rows:
        assert row.selector.workspace == "/synthetic/project"
        assert row.selector.exact_command_sha256 == "c" * 64
        assert row.selector.expires_at == expires
        assert row.selector.scope == "workspace"
        assert row.selector.owner == "expression"
        assert row.expression == document(raw).rules[0].match.command_expression


@pytest.mark.parametrize("selector", ["shell", "tool-action"])
def test_tool_family_uses_the_existing_compiler_without_a_second_alias_map(selector):
    result = project(mapping(rule(match={"commands": expression(), "tools": [selector]})))
    assert result.rows[0].selector.artifact_id == "family:tool-action"
    assert result.rows[0].selector.scope == "harness"


def test_publisher_selector_and_harness_remain_conjunctive():
    result = project(
        mapping(
            rule(
                match={
                    "commands": expression(),
                    "publishers": ["synthetic-publisher"],
                    "harnesses": ["codex"],
                }
            )
        )
    )
    row = result.rows[0]
    assert row.selector.publisher == "synthetic-publisher"
    assert row.selector.harness == "codex"
    assert row.selector.scope == "publisher"


def test_every_mixed_rule_has_a_disposition_including_inert_and_foreign_targets():
    raw = mapping(
        rule("expression"),
        rule("generic", match={"harnesses": ["codex"]}, effect="review"),
        rule("disabled", enabled=False, match={"paths": ["/unsupported"]}),
        rule("ignored", effect="ignore"),
        rule("foreign", match={"commands": expression(), "devices": ["other-target"]}),
    )
    result = project(raw)
    assert [row.identity.rule_id for row in result.rule_dispositions] == [
        "expression",
        "generic",
        "disabled",
        "ignored",
        "foreign",
    ]
    assert [row.kind for row in result.rule_dispositions] == [
        "expression",
        "generic",
        "inert",
        "inert",
        "expression",
    ]
    assert len(result.rows) == sum(row.row_count for row in result.rule_dispositions) == 3
    assert result.rows[1].expression is None
    assert result.rows[2].applicable_to_target is False
    assert result.rows[2].device_selectors == ("other-target",)
    assert result.rule_dispositions[-1].applicable_to_target is False


def test_delivery_target_never_matches_the_separate_local_source_identity():
    raw = mapping(rule(match={"commands": expression(), "devices": [TARGET]}))
    assert project(raw).rows[0].applicable_to_target is True
    assert project(raw, target_device_id=LOCAL_INSTALLATION).rows[0].applicable_to_target is False
    reverse = mapping(rule(match={"commands": expression(), "devices": [LOCAL_INSTALLATION]}))
    assert project(reverse).rows[0].applicable_to_target is False


@pytest.mark.parametrize(
    "field",
    [
        "actors",
        "agents",
        "domains",
        "environments",
        "locations",
        "mcps",
        "packages",
        "paths",
        "repositories",
        "secretTypes",
        "skills",
        "operations",
        "browserProfiles",
    ],
)
def test_no_command_expression_can_drop_an_unsupported_selector(field):
    raw = mapping(
        rule(match={"commands": expression(), field: ["isolated" if field == "browserProfiles" else "synthetic"]})
    )
    with pytest.raises(PolicyCompilationError, match="command_selector_unsupported"):
        project(raw)


def test_an_unsupported_foreign_target_rule_still_refuses_the_complete_projection():
    raw = mapping(
        rule(),
        rule(
            "foreign",
            match={
                "commands": expression(),
                "devices": ["other-target"],
                "paths": ["/synthetic"],
            },
        ),
    )
    with pytest.raises(PolicyCompilationError, match="command_selector_unsupported"):
        project(raw)


@pytest.mark.parametrize("mode", ["once", "session", "project", "machine", "workspace", "team"])
def test_unimplemented_lifetime_cannot_become_permanent(mode):
    with pytest.raises(PolicyCompilationError, match="unsupported_policy_lifetime"):
        project(mapping(rule(lifetime={"mode": mode, "expiresAt": None})))


@pytest.mark.parametrize(
    "location,key,expected",
    [
        ("rule", "x-hol-local", "command_rule_extension_unsupported"),
        ("rule", "x-hol-extension-targets", "managed_rule_requires_separate_runtime"),
        ("match", "x-synthetic-selector", "command_selector_unsupported"),
        ("lifetime", "x-synthetic-lifetime", "command_lifetime_extension_unsupported"),
        ("root", "x-hol-extension-controls", "managed_policy_requires_separate_runtime"),
        ("root", "x-synthetic-authority", "command_source_extension_unsupported"),
        ("spec", "x-synthetic-authority", "command_source_extension_unsupported"),
        ("defaults", "x-synthetic-authority", "command_default_extension_unsupported"),
    ],
)
def test_unconsumed_authority_extensions_are_refused_as_a_whole(location, key, expected):
    raw = mapping()
    spec = raw["spec"]
    assert isinstance(spec, dict)
    rules = spec["rules"]
    assert isinstance(rules, list)
    first = rules[0]
    assert isinstance(first, dict)
    targets = {
        "root": raw,
        "spec": spec,
        "defaults": spec["defaults"],
        "rule": first,
        "match": first["match"],
        "lifetime": first["lifetime"],
    }
    target = targets[location]
    assert isinstance(target, dict)
    target[key] = {}
    with pytest.raises(PolicyCompilationError, match=expected):
        project(raw)


def test_retained_network_authority_is_never_silently_removed():
    from dataclasses import replace

    value = replace(document(), spec_extensions=(("networkPolicy", "{}"),))
    with pytest.raises(PolicyCompilationError, match="network_policy_requires_separate_runtime"):
        project_canonical_command_policy(
            value,
            publication=PUBLICATION,
            workspace_id=WORKSPACE,
            target_device_id=TARGET,
        )


def test_whole_document_row_bound_is_checked_after_selector_fanout():
    raw = mapping(
        rule(
            match={
                "commands": expression(),
                "harnesses": [f"h{i}" for i in range(17)],
                "artifacts": [f"artifact:{i}" for i in range(17)],
            }
        )
    )
    with pytest.raises(PolicyCompilationError, match="command_projection_row_limit"):
        project(raw)


def test_output_is_immutable_and_source_digest_changes_with_a_restriction():
    first = project()
    raw = mapping(rule(match={"commands": expression(), "harnesses": ["codex"]}))
    second = project(raw)
    assert first.source.payload_hash != second.source.payload_hash
    frozen_field = "applicable_to_target"
    with pytest.raises(FrozenInstanceError):
        setattr(first.rows[0], frozen_field, False)
