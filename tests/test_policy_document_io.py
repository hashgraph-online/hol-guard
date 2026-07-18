from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.policy_document import (
    GuardPolicyDocument,
    policy_document_digest,
)
from codex_plugin_scanner.guard.policy_document_io import (
    PolicyCompilationError,
    PolicyFileTrustError,
    build_policy_document_from_rows,
    compile_policy_document,
    diff_policy_documents,
    load_trusted_policy_document,
    read_trusted_policy_text,
    write_private_policy_text,
)
from codex_plugin_scanner.guard.policy_document_yaml import (
    MAX_POLICY_BYTES,
    format_policy_document_yaml,
)


def _policy_document(*, effect: str = "allow", match: dict[str, object] | None = None) -> GuardPolicyDocument:
    return GuardPolicyDocument.from_mapping(
        {
            "apiVersion": "guard.hashgraphonline.com/v1alpha1",
            "kind": "GuardPolicy",
            "metadata": {"id": "test-policy", "name": "Test policy", "revision": 1},
            "spec": {
                "defaults": {"mode": "prompt"},
                "rules": [
                    {
                        "id": "rule-1",
                        "enabled": True,
                        "effect": effect,
                        "match": match or {"artifacts": ["skill:hol/deploy"]},
                        "lifetime": {"mode": "permanent", "expiresAt": None},
                        "provenance": {
                            "source": "import",
                            "createdAt": "2026-07-16T10:00:00Z",
                            "createdBy": "owner@example.com",
                        },
                    }
                ],
            },
        }
    )


def _private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def test_local_rows_round_trip_through_canonical_document() -> None:
    document = build_policy_document_from_rows(
        [
            {
                "decision_id": 7,
                "harness": "codex",
                "scope": "artifact",
                "artifact_id": "skill:hol/deploy",
                "artifact_hash": "sha256:abc",
                "workspace": "/workspace",
                "publisher": "hashgraph-online",
                "action": "allow",
                "reason": "Approved deployment skill",
                "owner": "owner@example.com",
                "source": "review-decision",
                "expires_at": None,
                "updated_at": "2026-07-16T10:00:00+00:00",
            }
        ],
        include_provenance=True,
    )

    compiled = compile_policy_document(document)

    mapping = document.to_mapping()
    spec = mapping["spec"]
    assert isinstance(spec, dict)
    rules = spec["rules"]
    assert isinstance(rules, list)
    first_rule = rules[0]
    assert isinstance(first_rule, dict)
    assert first_rule["id"] == "local-7"
    assert len(compiled) == 1
    assert compiled[0].rule_id == "local-7"
    assert compiled[0].decision.harness == "codex"
    assert compiled[0].decision.scope == "artifact"
    assert compiled[0].decision.artifact_id == "skill:hol/deploy"
    assert compiled[0].decision.artifact_hash == "sha256:abc"
    assert compiled[0].decision.workspace == "/workspace"
    assert compiled[0].decision.publisher == "hashgraph-online"
    assert compiled[0].decision.action == "allow"


def test_export_redacts_sensitive_provenance_by_default() -> None:
    document = build_policy_document_from_rows(
        [
            {
                "decision_id": 7,
                "harness": "codex",
                "scope": "global",
                "action": "allow",
                "reason": "Contains local context",
                "owner": "owner@example.com",
                "source": "review-decision",
                "updated_at": "2026-07-16T10:00:00Z",
            }
        ]
    )

    formatted = format_policy_document_yaml(document)

    assert "owner@example.com" not in formatted
    assert "Contains local context" not in formatted
    assert "review-decision" not in formatted
    assert "export-redacted" in formatted


def test_export_requires_privileged_intent_for_workspace_selectors() -> None:
    with pytest.raises(PolicyCompilationError, match="sensitive_local_policy_requires_provenance"):
        build_policy_document_from_rows(
            [
                {
                    "decision_id": 8,
                    "harness": "codex",
                    "scope": "workspace",
                    "workspace": "/workspace/repository",
                    "action": "allow",
                }
            ]
        )


def test_export_rejects_unsupported_local_actions() -> None:
    with pytest.raises(PolicyCompilationError, match="unsupported_local_policy_action"):
        build_policy_document_from_rows(
            [
                {
                    "decision_id": 9,
                    "harness": "codex",
                    "scope": "global",
                    "action": "prompt",
                }
            ]
        )


def test_export_rejects_invalid_local_expiry() -> None:
    with pytest.raises(PolicyCompilationError, match="invalid_local_policy_expiry"):
        build_policy_document_from_rows(
            [
                {
                    "decision_id": 9,
                    "harness": "codex",
                    "scope": "global",
                    "action": "allow",
                    "expires_at": "not-a-timestamp",
                }
            ]
        )


def test_export_rejects_invalid_local_timestamp() -> None:
    with pytest.raises(PolicyCompilationError, match="invalid_local_policy_timestamp"):
        build_policy_document_from_rows(
            [
                {
                    "decision_id": 10,
                    "harness": "codex",
                    "scope": "global",
                    "action": "allow",
                    "source": "review-decision",
                    "updated_at": "not-a-timestamp",
                }
            ],
            include_provenance=True,
        )


def test_export_identifies_yaml_import_provenance() -> None:
    document = build_policy_document_from_rows(
        [
            {
                "decision_id": 11,
                "harness": "codex",
                "scope": "global",
                "action": "allow",
                "source": "policy-yaml-import",
                "updated_at": "2026-07-16T10:00:00Z",
            }
        ],
        include_provenance=True,
    )

    rule = document.rules[0]
    assert rule.provenance is not None
    assert rule.provenance.source == "import"


def test_export_order_is_stable_when_primary_fields_tie() -> None:
    rows = [
        {
            "harness": "codex",
            "scope": "artifact",
            "artifact_id": "skill:hol/deploy",
            "publisher": "publisher-b",
            "action": "block",
        },
        {
            "harness": "codex",
            "scope": "artifact",
            "artifact_id": "skill:hol/deploy",
            "publisher": "publisher-a",
            "action": "allow",
        },
    ]

    forward = build_policy_document_from_rows(rows)
    reverse = build_policy_document_from_rows(reversed(rows))

    assert policy_document_digest(forward) == policy_document_digest(reverse)


def test_compile_rejects_effect_not_supported_by_local_store() -> None:
    document = _policy_document(effect="review")

    with pytest.raises(PolicyCompilationError, match="unsupported_policy_effect"):
        compile_policy_document(document)


def test_compile_rejects_match_not_supported_by_local_store() -> None:
    document = _policy_document(match={"commands": ["deploy"]})

    with pytest.raises(PolicyCompilationError, match="unsupported_policy_match"):
        compile_policy_document(document)

@pytest.mark.parametrize(
    ("tool", "family"),
    (("mcp", "mcp"), ("shell", "tool-action"), ("tool-action", "tool-action")),
)
def test_compile_maps_portable_tool_selectors_to_local_families(tool: str, family: str) -> None:
    compiled = compile_policy_document(_policy_document(match={"tools": [tool]}))

    assert len(compiled) == 1
    assert compiled[0].decision.scope == "harness"
    assert compiled[0].decision.artifact_id == f"family:{family}"


def test_compile_preserves_harness_for_tool_family_selector() -> None:
    compiled = compile_policy_document(
        _policy_document(match={"tools": ["mcp"], "harnesses": ["codex"]})
    )

    assert len(compiled) == 1
    assert compiled[0].decision.harness == "codex"
    assert compiled[0].decision.scope == "harness"
    assert compiled[0].decision.artifact_id == "family:mcp"


def test_compile_rejects_unknown_tool_family() -> None:
    document = _policy_document(match={"tools": ["unknown-tool"]})

    with pytest.raises(PolicyCompilationError, match="unsupported_policy_match"):
        compile_policy_document(document)


def test_compile_rejects_artifact_and_tool_selector_combination() -> None:
    document = _policy_document(
        match={"artifacts": ["skill:hol/deploy"], "tools": ["mcp"]}
    )

    with pytest.raises(PolicyCompilationError, match="unsupported_policy_match"):
        compile_policy_document(document)


def test_compile_rejects_empty_selector_lists() -> None:
    document = _policy_document(match={"artifacts": []})

    with pytest.raises(PolicyCompilationError, match="invalid_policy_match_selector"):
        compile_policy_document(document)


def test_compile_rejects_invalid_until_expiry() -> None:
    mapping = _policy_document().to_mapping()
    spec = mapping["spec"]
    assert isinstance(spec, dict)
    rules = spec["rules"]
    assert isinstance(rules, list)
    rule = rules[0]
    assert isinstance(rule, dict)
    rule["lifetime"] = {"mode": "until", "expiresAt": "not-a-timestamp"}
    document = GuardPolicyDocument.from_mapping(mapping)

    with pytest.raises(PolicyCompilationError, match="invalid_policy_expiry"):
        compile_policy_document(document)


def test_compile_rejects_selector_expansion_over_limit() -> None:
    document = _policy_document(
        match={
            "artifacts": [f"artifact-{index}" for index in range(101)],
            "workspaces": [f"workspace-{index}" for index in range(101)],
        }
    )

    with pytest.raises(PolicyCompilationError, match="policy_compilation_limit"):
        compile_policy_document(document)


def test_trusted_file_round_trip_and_atomic_private_output(tmp_path: Path) -> None:
    directory = _private_directory(tmp_path / "private")
    source = directory / "source.yaml"
    source.write_text(format_policy_document_yaml(_policy_document()), encoding="utf-8")
    source.chmod(0o600)
    destination = directory / "output.yaml"

    document = load_trusted_policy_document(source)
    write_private_policy_text(destination, format_policy_document_yaml(document))

    assert policy_document_digest(load_trusted_policy_document(destination)) == policy_document_digest(document)
    assert destination.stat().st_mode & 0o777 == 0o600


def test_trusted_read_rejects_symlink(tmp_path: Path) -> None:
    directory = _private_directory(tmp_path / "private")
    target = directory / "target.yaml"
    target.write_text(format_policy_document_yaml(_policy_document()), encoding="utf-8")
    target.chmod(0o600)
    link = directory / "link.yaml"
    link.symlink_to(target)

    with pytest.raises(PolicyFileTrustError, match="policy_file_not_regular"):
        read_trusted_policy_text(link)


def test_trusted_read_rejects_symlinked_ancestor(tmp_path: Path) -> None:
    trusted = _private_directory(tmp_path / "trusted")
    directory = _private_directory(trusted / "private")
    source = directory / "policy.yaml"
    source.write_text(format_policy_document_yaml(_policy_document()), encoding="utf-8")
    source.chmod(0o600)
    alias = tmp_path / "alias"
    alias.symlink_to(trusted, target_is_directory=True)

    with pytest.raises(PolicyFileTrustError, match="policy_parent_unavailable"):
        read_trusted_policy_text(alias / "private" / source.name)


def test_trusted_read_rejects_hardlink(tmp_path: Path) -> None:
    directory = _private_directory(tmp_path / "private")
    target = directory / "target.yaml"
    target.write_text(format_policy_document_yaml(_policy_document()), encoding="utf-8")
    target.chmod(0o600)
    link = directory / "hardlink.yaml"
    os.link(target, link)

    with pytest.raises(PolicyFileTrustError, match="policy_file_link_count"):
        read_trusted_policy_text(link)


def test_trusted_read_rejects_group_writable_file(tmp_path: Path) -> None:
    directory = _private_directory(tmp_path / "private")
    source = directory / "policy.yaml"
    source.write_text(format_policy_document_yaml(_policy_document()), encoding="utf-8")
    source.chmod(0o620)

    with pytest.raises(PolicyFileTrustError, match="policy_file_insecure_mode"):
        read_trusted_policy_text(source)


def test_trusted_read_rejects_world_writable_parent(tmp_path: Path) -> None:
    directory = _private_directory(tmp_path / "private")
    source = directory / "policy.yaml"
    source.write_text(format_policy_document_yaml(_policy_document()), encoding="utf-8")
    source.chmod(0o600)
    directory.chmod(0o777)

    with pytest.raises(PolicyFileTrustError, match="policy_parent_insecure_mode"):
        read_trusted_policy_text(source)


def test_trusted_read_rejects_oversized_file(tmp_path: Path) -> None:
    directory = _private_directory(tmp_path / "private")
    source = directory / "policy.yaml"
    source.write_bytes(b"x" * (MAX_POLICY_BYTES + 1))
    source.chmod(0o600)

    with pytest.raises(PolicyFileTrustError, match="policy_file_too_large"):
        read_trusted_policy_text(source)


def test_private_output_rejects_oversized_content(tmp_path: Path) -> None:
    directory = _private_directory(tmp_path / "private")
    destination = directory / "policy.yaml"

    with pytest.raises(PolicyFileTrustError, match="policy_output_too_large"):
        write_private_policy_text(destination, "x" * (MAX_POLICY_BYTES + 1))

    assert not destination.exists()


def test_private_output_rejects_existing_symlink(tmp_path: Path) -> None:
    directory = _private_directory(tmp_path / "private")
    target = directory / "target.yaml"
    target.write_text("target", encoding="utf-8")
    target.chmod(0o600)
    destination = directory / "policy.yaml"
    destination.symlink_to(target)

    with pytest.raises(PolicyFileTrustError, match="policy_file_not_regular"):
        write_private_policy_text(destination, "replacement")

    assert target.read_text(encoding="utf-8") == "target"


def test_private_output_rejects_existing_hardlink(tmp_path: Path) -> None:
    directory = _private_directory(tmp_path / "private")
    target = directory / "target.yaml"
    target.write_text("target", encoding="utf-8")
    target.chmod(0o600)
    destination = directory / "policy.yaml"
    os.link(target, destination)

    with pytest.raises(PolicyFileTrustError, match="policy_file_link_count"):
        write_private_policy_text(destination, "replacement")

    assert target.read_text(encoding="utf-8") == "target"


def test_private_output_retries_short_writes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    directory = _private_directory(tmp_path / "private")
    destination = directory / "policy.yaml"
    original_write = os.write

    def short_write(descriptor: int, payload: bytes | memoryview) -> int:
        return original_write(descriptor, payload[:1])

    monkeypatch.setattr(os, "write", short_write)

    write_private_policy_text(destination, "complete")

    assert destination.read_text(encoding="utf-8") == "complete"


def test_atomic_output_preserves_existing_file_when_replace_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = _private_directory(tmp_path / "private")
    destination = directory / "policy.yaml"
    destination.write_text("before", encoding="utf-8")
    destination.chmod(0o600)

    def fail_replace(_source: str, _destination: str, **_kwargs: int) -> None:
        raise OSError("replace failed")

    monkeypatch.setattr(os, "replace", fail_replace)

    with pytest.raises(PolicyFileTrustError, match="policy_output_write_failed"):
        write_private_policy_text(destination, "after")

    assert destination.read_text(encoding="utf-8") == "before"
    assert not list(directory.glob(".*.tmp"))


def test_document_diff_is_deterministic() -> None:
    baseline = _policy_document(effect="allow")
    candidate = _policy_document(effect="block")

    first = diff_policy_documents(baseline, candidate)
    second = diff_policy_documents(baseline, candidate)

    assert first.changed is True
    assert first == second
    assert "-    effect: allow" in first.text
    assert "+    effect: block" in first.text
    assert first.additions == ()
    assert first.modifications == ("rule-1",)
    assert first.removals == ()
    assert first.impacted_scopes == ("artifacts",)
    assert first.impacted_harnesses == ()
    assert first.impacted_artifact_families == ("skill",)
    assert first.conflict_warnings == ()
    assert first.effective_action_changes == ("rule-1:allow->block",)
    assert first.broadened_rules == ()
    assert first.narrowed_rules == ()
    assert first.broad_relaxing_changes == ()


def test_document_diff_flags_broad_relaxing_changes() -> None:
    baseline = _policy_document(effect="block")
    mapping = baseline.to_mapping()
    spec = mapping["spec"]
    assert isinstance(spec, dict)
    rules = spec["rules"]
    assert isinstance(rules, list)
    rule = rules[0]
    assert isinstance(rule, dict)
    rule["effect"] = "allow"
    rule["match"] = {}
    candidate = GuardPolicyDocument.from_mapping(mapping)

    difference = diff_policy_documents(baseline, candidate)

    assert difference.broadened_rules == ("rule-1",)
    assert difference.narrowed_rules == ()
    assert difference.effective_action_changes == ("rule-1:block->allow",)
    assert difference.broad_relaxing_changes == ("rule-1",)


def test_document_diff_flags_relaxed_defaults() -> None:
    baseline_mapping = _policy_document(effect="block").to_mapping()
    baseline_spec = baseline_mapping["spec"]
    assert isinstance(baseline_spec, dict)
    baseline_defaults = baseline_spec["defaults"]
    assert isinstance(baseline_defaults, dict)
    baseline_defaults["defaultAction"] = "block"
    baseline_defaults["unknownPublisherAction"] = "review"
    baseline = GuardPolicyDocument.from_mapping(baseline_mapping)
    candidate_mapping = baseline.to_mapping()
    candidate_spec = candidate_mapping["spec"]
    assert isinstance(candidate_spec, dict)
    candidate_defaults = candidate_spec["defaults"]
    assert isinstance(candidate_defaults, dict)
    candidate_defaults["defaultAction"] = "allow"
    candidate_defaults["unknownPublisherAction"] = "allow"
    candidate = GuardPolicyDocument.from_mapping(candidate_mapping)

    difference = diff_policy_documents(baseline, candidate)

    assert difference.effective_action_changes == (
        "defaults.defaultAction:block->allow",
        "defaults.unknownPublisherAction:review->allow",
    )
    assert difference.broad_relaxing_changes == (
        "defaults.defaultAction",
        "defaults.unknownPublisherAction",
    )


def test_document_diff_flags_shorter_restrictive_lifetime() -> None:
    baseline = _policy_document(effect="block")
    candidate_mapping = baseline.to_mapping()
    candidate_spec = candidate_mapping["spec"]
    assert isinstance(candidate_spec, dict)
    candidate_rules = candidate_spec["rules"]
    assert isinstance(candidate_rules, list)
    candidate_rule = candidate_rules[0]
    assert isinstance(candidate_rule, dict)
    candidate_rule["lifetime"] = {
        "mode": "until",
        "expiresAt": "2026-07-17T10:00:00Z",
    }
    candidate = GuardPolicyDocument.from_mapping(candidate_mapping)

    difference = diff_policy_documents(baseline, candidate)

    assert difference.broad_relaxing_changes == ("rule-1",)


def test_document_diff_compares_mixed_precision_lifetimes_chronologically() -> None:
    baseline_mapping = _policy_document(effect="block").to_mapping()
    baseline_spec = baseline_mapping["spec"]
    assert isinstance(baseline_spec, dict)
    baseline_rules = baseline_spec["rules"]
    assert isinstance(baseline_rules, list)
    baseline_rule = baseline_rules[0]
    assert isinstance(baseline_rule, dict)
    baseline_rule["lifetime"] = {
        "mode": "until",
        "expiresAt": "2026-07-17T10:00:00.500Z",
    }
    baseline = GuardPolicyDocument.from_mapping(baseline_mapping)
    candidate_mapping = baseline.to_mapping()
    candidate_spec = candidate_mapping["spec"]
    assert isinstance(candidate_spec, dict)
    candidate_rules = candidate_spec["rules"]
    assert isinstance(candidate_rules, list)
    candidate_rule = candidate_rules[0]
    assert isinstance(candidate_rule, dict)
    candidate_rule["lifetime"] = {
        "mode": "until",
        "expiresAt": "2026-07-17T10:00:00Z",
    }
    candidate = GuardPolicyDocument.from_mapping(candidate_mapping)

    difference = diff_policy_documents(baseline, candidate)

    assert difference.broad_relaxing_changes == ("rule-1",)


def test_document_diff_flags_constrained_relaxing_addition() -> None:
    baseline = _policy_document(effect="block")
    candidate_mapping = baseline.to_mapping()
    candidate_spec = candidate_mapping["spec"]
    assert isinstance(candidate_spec, dict)
    candidate_rules = candidate_spec["rules"]
    assert isinstance(candidate_rules, list)
    candidate_rules.append(
        {
            "id": "rule-2",
            "enabled": True,
            "effect": "allow",
            "match": {"artifacts": ["skill:hol/deploy"]},
            "lifetime": {"mode": "permanent", "expiresAt": None},
            "provenance": {
                "source": "import",
                "createdAt": "2026-07-16T10:00:00Z",
                "createdBy": "owner@example.com",
            },
        }
    )
    candidate = GuardPolicyDocument.from_mapping(candidate_mapping)

    difference = diff_policy_documents(baseline, candidate)

    assert difference.broad_relaxing_changes == ("rule-2",)
    assert difference.conflict_warnings == ("overlapping_effects:rule-1:rule-2",)


def test_document_diff_reports_overlapping_effect_conflicts() -> None:
    baseline = _policy_document(effect="allow")
    mapping = baseline.to_mapping()
    spec = mapping["spec"]
    assert isinstance(spec, dict)
    rules = spec["rules"]
    assert isinstance(rules, list)
    rules.append(
        {
            "id": "rule-2",
            "enabled": True,
            "effect": "block",
            "match": {"artifacts": ["skill:hol/deploy"]},
            "lifetime": {"mode": "permanent", "expiresAt": None},
            "provenance": {
                "source": "import",
                "createdAt": "2026-07-16T10:00:00Z",
                "createdBy": "owner@example.com",
            },
        }
    )
    candidate = GuardPolicyDocument.from_mapping(mapping)

    difference = diff_policy_documents(baseline, candidate)

    assert difference.additions == ("rule-2",)
    assert difference.impacted_scopes == ("artifacts",)
    assert difference.impacted_artifact_families == ("skill",)
    assert difference.conflict_warnings == ("overlapping_effects:rule-1:rule-2",)
