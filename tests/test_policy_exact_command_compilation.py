"""Exact command selectors survive verified compilation without widening scope."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.exact_command import exact_command_sha256
from codex_plugin_scanner.guard.policy_document import GuardPolicyDocument, policy_document_digest
from codex_plugin_scanner.guard.policy_document_compile import build_policy_document_from_rows, compile_policy_document
from codex_plugin_scanner.guard.policy_document_diff import diff_policy_documents
from codex_plugin_scanner.guard.policy_document_import_identity import validate_import_identities
from codex_plugin_scanner.guard.policy_document_types import PolicyCompilationError
from codex_plugin_scanner.guard.policy_document_yaml import PolicyDocumentError, parse_policy_document_yaml
from codex_plugin_scanner.guard.review_contracts import (
    validate_decision_memory_bundle_target,
    validated_decision_memory_bundle,
)
from codex_plugin_scanner.guard.review_memory_authority import decision_from_memory_rule
from codex_plugin_scanner.guard.review_oauth_binding import GuardReviewContractError, guard_review_oauth_metadata
from codex_plugin_scanner.guard.runtime.canonical_policy_decisions import build_canonical_policy_bundle_decisions
from tests.test_guard_review_policy_memory_command import _bundle, _resign_bundle, _store


def _selector(command: str = " printf 'synthetic  value'\n") -> dict[str, object]:
    return {"contractVersion": "guard.exact-command.v1", "sha256": exact_command_sha256(command)}


def _mapping() -> dict[str, object]:
    return {
        "apiVersion": "guard.hashgraphonline.com/v1alpha1",
        "kind": "GuardPolicy",
        "metadata": {"id": "synthetic-policy", "name": "Synthetic policy", "revision": 1},
        "spec": {
            "defaults": {"mode": "prompt"},
            "rules": [
                {
                    "id": "synthetic-rule",
                    "enabled": True,
                    "effect": "allow",
                    "match": {
                        "artifacts": ["codex:project:Shell"],
                        "harnesses": ["codex"],
                        "exactCommand": _selector(),
                    },
                    "lifetime": {"mode": "until", "expiresAt": "2099-01-01T00:00:00Z"},
                    "provenance": {"source": "import", "createdAt": "2026-09-01T00:00:00Z"},
                }
            ],
        },
    }


def _rule(mapping):
    return mapping["spec"]["rules"][0]


@pytest.mark.parametrize("workspace", [None, "/synthetic-workspace"])
def test_canonical_selector_is_preserved_through_real_bundle_compilation(workspace: str | None) -> None:
    mapping = _mapping()
    if workspace is not None:
        _rule(mapping)["match"]["workspaces"] = [workspace]
    document = parse_policy_document_yaml(json.dumps(mapping))
    assert document.to_mapping() == mapping
    decision = build_canonical_policy_bundle_decisions(
        {"payload": mapping},
        device_id="synthetic-device",
        device_name="Synthetic",
    )[0]
    assert decision.exact_command_sha256 == _selector()["sha256"]
    assert decision.artifact_id == "codex:project:Shell"
    assert decision.harness == "codex"
    assert decision.workspace == workspace
    assert decision.scope == ("workspace" if workspace else "artifact")
    assert decision.source == "policy-bundle-canonical"


@pytest.mark.parametrize("command", ["echo x", " echo x", "echo x ", "echo\tx", "echo\nx", "Echo x", "printf 'a  b'"])
def test_exact_digest_changes_are_canonical_identity(command: str) -> None:
    mapping = _mapping()
    _rule(mapping)["match"]["exactCommand"] = _selector(command)
    document = parse_policy_document_yaml(json.dumps(mapping))
    assert compile_policy_document(document)[0].decision.exact_command_sha256 == _selector(command)["sha256"]
    assert policy_document_digest(document) != policy_document_digest(GuardPolicyDocument.from_mapping(_mapping()))


@pytest.mark.parametrize(
    "selector",
    [
        None,
        {},
        [],
        "a" * 64,
        {"contractVersion": "guard.exact-command.v2", "sha256": "a" * 64},
        {"contractVersion": "guard.exact-command.v1", "sha256": "A" * 64},
        {"contractVersion": "guard.exact-command.v1", "sha256": "a" * 63},
        {"contractVersion": "guard.exact-command.v1", "sha256": "a" * 64 + "\n"},
        {"contractVersion": "guard.exact-command.v1", "sha256": "a" * 64, "ignored": True},
    ],
)
def test_invalid_exact_selector_is_never_silently_dropped(selector: object) -> None:
    mapping = _mapping()
    _rule(mapping)["match"]["exactCommand"] = selector
    with pytest.raises(PolicyDocumentError):
        parse_policy_document_yaml(json.dumps(mapping))
    with pytest.raises(ValueError, match="invalid_exact_command_selector"):
        GuardPolicyDocument.from_mapping(mapping)


@pytest.mark.parametrize("artifact", [None, "*", "family:tool-action", " padded ", "bad\nartifact"])
def test_exact_selector_requires_original_artifact(artifact: str | None) -> None:
    mapping = _mapping()
    match = _rule(mapping)["match"]
    if artifact is None:
        match.pop("artifacts")
    else:
        match["artifacts"] = [artifact]
    with pytest.raises(PolicyCompilationError, match="invalid_exact_command_policy"):
        compile_policy_document(GuardPolicyDocument.from_mapping(mapping))


@pytest.mark.parametrize("scope", ["global", "publisher", "harness"])
def test_exact_selector_cannot_be_projected_to_broader_scope(scope: str) -> None:
    mapping = _mapping()
    _rule(mapping)["x-hol-local"] = {"scope": scope}
    with pytest.raises(PolicyCompilationError):
        compile_policy_document(GuardPolicyDocument.from_mapping(mapping))


def _export_row(harness: str, selector: dict[str, object]) -> dict[str, object]:
    return {
        "policy_rule_id": "synthetic-rule",
        "harness": harness,
        "scope": "artifact",
        "artifact_id": "synthetic-artifact",
        "exact_command_sha256": selector["sha256"],
        "action": "allow",
    }


def test_export_coalesces_only_identical_exact_predicates() -> None:
    document = build_policy_document_from_rows([_export_row("codex", _selector()), _export_row("cursor", _selector())])
    rows = compile_policy_document(document)
    assert len(rows) == 2
    assert {row.decision.exact_command_sha256 for row in rows} == {_selector()["sha256"]}
    assert document.rules[0].match.to_mapping()["exactCommand"] == _selector()
    with pytest.raises(PolicyCompilationError, match="policy_rule_export_conflict"):
        build_policy_document_from_rows([_export_row("codex", _selector()), _export_row("cursor", _selector("echo x"))])


def test_merge_identity_cannot_reuse_a_rule_id_with_a_different_exact_predicate() -> None:
    document = GuardPolicyDocument.from_mapping(_mapping())
    compiled = compile_policy_document(document)[0]
    current = {
        "policy_rule_id": compiled.rule_id,
        "policy_document_id": document.metadata.id,
        "harness": "codex",
        "scope": "artifact",
        "artifact_id": compiled.decision.artifact_id,
        "artifact_hash": None,
        "workspace": None,
        "publisher": None,
        "source": "policy-yaml-import",
        "exact_command_sha256": compiled.decision.exact_command_sha256,
    }
    rows = [(compiled, compiled.decision.artifact_id, None, None, None)]
    validate_import_identities(rows, [current], document=document, mode="merge")
    current["exact_command_sha256"] = _selector("echo changed")["sha256"]
    with pytest.raises(PolicyCompilationError, match="policy_rule_identity_conflict"):
        validate_import_identities(rows, [current], document=document, mode="merge")


def test_removing_exact_predicate_is_a_broader_allow_and_distinct_digests_do_not_overlap() -> None:
    mapping = _mapping()
    previous = GuardPolicyDocument.from_mapping(mapping)
    broader = copy.deepcopy(mapping)
    _rule(broader)["match"].pop("exactCommand")
    diff = diff_policy_documents(previous, GuardPolicyDocument.from_mapping(broader))
    assert diff.broadened_rules == ("synthetic-rule",)
    other = copy.deepcopy(_rule(mapping))
    other.update(id="different", effect="block")
    other["match"]["exactCommand"] = _selector("echo different")
    mapping["spec"]["rules"].append(other)
    assert diff_policy_documents(previous, GuardPolicyDocument.from_mapping(mapping)).conflict_warnings == ()


def test_real_signed_memory_retains_digest_and_every_existing_selector(tmp_path: Path) -> None:
    store = _store(tmp_path)
    bundle = _bundle(store)
    rule = bundle["memoryRules"][0]
    rule.pop("projectIdentity")
    rule["exactCommand"] = _selector()
    verified = validated_decision_memory_bundle(_resign_bundle(bundle), store=store)
    oauth = guard_review_oauth_metadata(store, require_device_dpop_binding=True)
    validate_decision_memory_bundle_target(bundle=verified, oauth=oauth)
    decision = decision_from_memory_rule(bundle=verified, rule=rule, oauth=oauth)
    assert decision.exact_command_sha256 == _selector()["sha256"]
    assert decision.artifact_id == rule["artifactId"]
    assert decision.artifact_hash == rule["artifactHash"]
    assert decision.harness == rule["harnessId"]
    tampered = copy.deepcopy(verified)
    tampered["memoryRules"][0]["exactCommand"] = _selector("echo changed")
    with pytest.raises(GuardReviewContractError, match="hash_mismatch"):
        validated_decision_memory_bundle(tampered, store=store)


@pytest.mark.parametrize(
    "change",
    [
        {"exactCommand": None},
        {"scope": "project"},
        {"scope": "machine"},
        {"scope": "team", "action": "block"},
        {"artifactId": "family:tool-action"},
        {"artifactId": " padded "},
    ],
)
def test_even_genuinely_signed_unrepresentable_memory_exact_rules_reject(tmp_path: Path, change) -> None:
    store = _store(tmp_path)
    bundle = _bundle(store)
    rule = bundle["memoryRules"][0]
    rule["exactCommand"] = _selector()
    rule.update(change)
    verified = validated_decision_memory_bundle(_resign_bundle(bundle), store=store)
    oauth = guard_review_oauth_metadata(store, require_device_dpop_binding=True)
    with pytest.raises(GuardReviewContractError, match="invalid_decision_memory_exact_command"):
        validate_decision_memory_bundle_target(bundle=verified, oauth=oauth)
    with pytest.raises(GuardReviewContractError):
        decision_from_memory_rule(bundle=verified, rule=rule, oauth=oauth)
