"""Pure row association checks; signed admission and native execution are separate."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, replace
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.native_command_row_association import materialize_native_command_source_rows
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.policy_command_projection import project_canonical_command_policy
from codex_plugin_scanner.guard.policy_document_types import PolicyCompilationError
from codex_plugin_scanner.guard.policy_document_yaml import parse_policy_document_yaml
from codex_plugin_scanner.guard.policy_publication_binding import PolicyPublicationBinding

TARGET = "22222222-2222-4222-8222-222222222222"
OTHER = "33333333-3333-4333-8333-333333333333"
WORKSPACE = "11111111-1111-4111-8111-111111111111"
LOCAL = "local-installation-source"
AT = "2026-09-18T00:00:00.123456+00:00"


def expression(value="printf fixture", operator="exact", case=True):
    return {
        "combinator": "all",
        "conditions": [{"field": "command", "operator": operator, "value": value, "caseSensitive": case}],
    }


def rule(name, *, command=True, target=TARGET, expiry="2030-01-01T00:00:00Z", value="printf fixture", **kwargs):
    return {
        "id": name,
        "enabled": True,
        "effect": "block",
        "match": {
            **({"commands": expression(value, **kwargs)} if command else {}),
            "devices": [target],
            "harnesses": ["codex"],
            "artifacts": ["tool-action:shell:fixture"],
            "workspaces": ["/synthetic/project"],
            "exactCommand": {"contractVersion": "guard.exact-command.v1", "sha256": "c" * 64},
        },
        "lifetime": {"mode": "until", "expiresAt": expiry},
        "provenance": {"source": "builder", "createdAt": "2026-09-18T00:00:00Z"},
    }


def projection(*rules):
    raw = {
        "apiVersion": "guard.hashgraphonline.com/v1alpha1",
        "kind": "GuardPolicy",
        "metadata": {"id": "expression-policy", "name": "Synthetic", "revision": 8},
        "spec": {"defaults": {"mode": "enforce"}, "rules": list(rules)},
    }
    return project_canonical_command_policy(
        parse_policy_document_yaml(json.dumps(raw)),
        publication=PolicyPublicationBinding(42, "sha256:" + "b" * 64, LOCAL),
        workspace_id=WORKSPACE,
        target_device_id=TARGET,
    )


def normalize(decision: PolicyDecision):
    return decision.artifact_id, decision.artifact_hash, decision.workspace, decision.publisher


def materialize(projected, target=TARGET, at=AT):
    return materialize_native_command_source_rows(
        projected, target_device_id=target, normalize_keys=normalize, materialized_at=at
    )


def test_full_selectors_source_and_expression_remain_bound_after_remap():
    projected = projection(rule("expression"))
    source = materialize(projected)
    assert source.projection is projected
    item = source.rows[0]
    bound = item.bind_snapshot_row_id(73)
    assert bound.row.decision_id == 73
    assert bound.row.harness == "codex"
    assert bound.row.artifact_id == "tool-action:shell:fixture"
    assert bound.row.workspace == "/synthetic/project"
    assert bound.row.exact_command_sha256 == "c" * 64
    assert bound.row.updated_at_us == 1789689600123456
    assert bound.row.expires_at_ms == 1893456000000
    assert bound.identity.rule_id == "expression"
    assert bound.identity.policy_version == "8"
    assert bound.source.publication.bundle_version == 42
    assert bound.source.publication.installation_id == LOCAL
    assert bound.source.target_device_id == TARGET
    assert bound.expression_mapping() == {"decision_id": 73, "expression": expression()}
    assert "decision_id" not in item.source_mapping()


def test_reordering_and_expiry_filter_keep_original_expression_association():
    result = materialize(
        projection(
            rule("later", value="printf z"),
            rule("generic", command=False),
            rule("expired", value="printf expired", expiry="2020-01-01T00:00:00Z"),
            rule("earlier", value="printf a"),
        )
    )
    # This mirrors the existing combined-row canonical sort, without assuming
    # projection order, contiguous retained IDs or SQLite row identities.
    sorted_rows = sorted(reversed(result.rows), key=lambda item: item.sort_key)
    active = []
    for index, item in enumerate(sorted_rows, start=41):
        bound = item.bind_snapshot_row_id(index)
        if bound.row.expires_at_ms is None or bound.row.expires_at_ms > 1789689600000:
            active.append(bound)
    assert len(active) == 3
    expected = {"later": "printf z", "earlier": "printf a"}
    for bound in active:
        value = cast(Any, bound.expression_mapping())
        if bound.identity.rule_id == "generic":
            assert value is None
        else:
            assert value["decision_id"] == bound.row.decision_id
            assert value["expression"]["conditions"][0]["value"] == expected[bound.identity.rule_id]
    assert len({bound.row.decision_id for bound in active}) == 3
    assert {row.identity.rule_id for row in result.rows} == {"later", "generic", "expired", "earlier"}


def test_target_filter_never_uses_local_installation_as_alias():
    result = materialize(projection(rule("target"), rule("other", target=OTHER), rule("local", target=LOCAL)))
    assert [row.identity.rule_id for row in result.rows] == ["target"]
    assert len(result.projection.rule_dispositions) == 3
    with pytest.raises(ValueError, match="target_identity_mismatch"):
        materialize(result.projection, target=LOCAL)


@pytest.mark.parametrize("kwargs", [{"operator": "regex"}, {"operator": "glob"}, {"case": False}])
def test_unsupported_off_target_expired_rule_refuses_before_filtering(kwargs):
    with pytest.raises(PolicyCompilationError, match="native_command_"):
        materialize(
            projection(rule("valid"), rule("unsupported", target=OTHER, expiry="2020-01-01T00:00:00Z", **kwargs))
        )


def test_source_and_returned_mappings_do_not_share_mutable_ast():
    item = materialize(projection(rule("expression"))).rows[0]
    value = cast(Any, item.source_mapping())
    value["_command_expression_json"] = json.dumps(expression("changed"))
    value["_policy_rule_identity"]["ruleId"] = "changed"
    bound = item.bind_snapshot_row_id(2)
    altered = cast(Any, bound.expression_mapping())
    altered["expression"]["conditions"][0]["value"] = "changed"
    assert cast(Any, bound.expression_mapping())["expression"] == expression()
    assert cast(Any, item.source_mapping())["_policy_rule_identity"]["ruleId"] == "expression"
    with pytest.raises(FrozenInstanceError):
        cast(Any, item).expression_payload = None


def test_expression_changes_canonical_sort_input_even_with_same_selectors():
    first = materialize(projection(rule("same", value="printf one"))).rows[0]
    second = materialize(projection(rule("same", value="printf two"))).rows[0]
    assert first.sort_key != second.sort_key
    assert first.source.payload_hash != second.source.payload_hash
    assert first.bind_snapshot_row_id(1).row == second.bind_snapshot_row_id(1).row
    assert first.bind_snapshot_row_id(1).expression_mapping() != second.bind_snapshot_row_id(1).expression_mapping()


@pytest.mark.parametrize("decision_id", [0, -1, True, 1.5, "1"])
def test_snapshot_id_is_positive_strict_integer(decision_id):
    item = materialize(projection(rule("expression"))).rows[0]
    with pytest.raises(NativePolicySnapshotError):
        item.bind_snapshot_row_id(decision_id)


def test_inconsistent_identity_and_target_flags_are_not_silently_repaired():
    projected = projection(rule("expression"))
    row = projected.rows[0]
    with pytest.raises(PolicyCompilationError, match="source_identity_mismatch"):
        materialize(replace(projected, rows=(replace(row, identity=replace(row.identity, policy_version="9")),)))
    with pytest.raises(PolicyCompilationError, match="target_disposition_mismatch"):
        materialize(replace(projected, rows=(replace(row, applicable_to_target=False),)))


@pytest.mark.parametrize("at", ["not-a-time", "2026-09-18T00:00:00", None])
def test_invalid_materialization_time_rejects_off_target_rows(at):
    with pytest.raises(NativePolicySnapshotError):
        materialize(projection(rule("other", target=OTHER)), at=at)


def test_inconsistent_frozen_association_cannot_be_replaced_independently():
    item = materialize(projection(rule("expression"))).rows[0]
    with pytest.raises(ValueError, match="row_association_invalid"):
        replace(item, expression_payload=json.dumps(expression("changed")))
    with pytest.raises(ValueError, match="row_association_invalid"):
        replace(item, identity=replace(item.identity, rule_id="sibling"))
    with pytest.raises(ValueError, match="row_association_invalid"):
        replace(item, source=replace(item.source, policy_version="9"))


def test_all_selector_fanout_rows_retain_the_same_complete_expression():
    raw = rule("fanout")
    raw_match = raw["match"]
    assert isinstance(raw_match, dict)
    match = cast(dict[str, object], raw_match)
    match["harnesses"] = ["codex", "claude-code"]
    match["artifacts"] = ["tool-action:shell:a", "tool-action:shell:b"]
    result = materialize(projection(raw))
    assert len(result.rows) == 4
    assert result.projection.rule_dispositions[0].row_count == 4
    bound = [item.bind_snapshot_row_id(index) for index, item in enumerate(result.rows, start=1)]
    assert {(item.row.harness, item.row.artifact_id) for item in bound} == {
        (harness, artifact)
        for harness in ("codex", "claude-code")
        for artifact in ("tool-action:shell:a", "tool-action:shell:b")
    }
    assert all(
        item.row.workspace == "/synthetic/project" and item.row.exact_command_sha256 == "c" * 64 for item in bound
    )
    assert all(cast(Any, item.expression_mapping())["expression"] == expression() for item in bound)
