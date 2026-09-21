from __future__ import annotations

import hashlib
import json
from copy import deepcopy

import pytest

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.effect_contract import ProofRoute
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot
from codex_plugin_scanner.guard.runtime.native_command_extension_evidence import (
    NativeCommandExtensionEvidenceError,
    observations_from_native_evidence,
)


def _payload(command_text: str) -> tuple[dict[str, object], object, ExtensionControlRuntimeSnapshot]:
    command = parse_shell_command(command_text)
    snapshot = ExtensionControlRuntimeSnapshot(
        AuthorityHealth.PROTECTED,
        7,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        "d" * 64,
        (),
        3,
    )
    observation = {
        "extension_id": "command.api-gateway",
        "extension_version": "1.0.0",
        "rule_id": "command.api-gateway.delete",
        "rule_version": "1.0.0",
        "match_class": "unsafe",
        "match_classes": ["unsafe"],
        "matcher_evidence": [
            {
                "segment_index": 0,
                "executable": "aws",
                "detail": "Matched bounded structured command constraints.",
            }
        ],
        "safe_variants": [],
        "uncertainty_reasons": [],
        "effective_segment_indexes": [0],
    }
    evidence: dict[str, object] = {
        "schema": "guard.native-command-observations.v1",
        "binding": {
            "schema": "guard.native-command-receipt-binding.v1",
            "program_digest": BUILT_IN_COMMAND_EXTENSION_REGISTRY.program_digest,
            "catalog_digest": BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            "trust_digest": "c" * 64,
            "control_revision": snapshot.revision,
            "managed_control_revision": snapshot.managed_revision,
            "control_effective_digest": snapshot.effective_digest,
            "observations_digest": "0" * 64,
            "observation_count": 1,
            "uncertainty_count": 0,
        },
        "observations": [observation],
        "permission_observations": [],
        "evaluation_error": None,
    }
    _rehash(evidence)
    return (
        {"command_model": {"normalized_text": command.normalized_text}, "command_extensions": evidence},
        command,
        snapshot,
    )


def _rehash(evidence: dict[str, object]) -> None:
    canonical = json.dumps(
        {key: evidence[key] for key in ("observations", "permission_observations", "evaluation_error")},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    evidence["binding"]["observations_digest"] = hashlib.sha256(
        b"hol-guard.native-command-observations.v1\0" + canonical
    ).hexdigest()


def test_native_evidence_projects_only_when_command_controls_and_owners_match() -> None:
    payload, command, snapshot = _payload("aws apigateway delete-rest-api --rest-api-id abc")
    observations = observations_from_native_evidence(
        payload,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        command=command,
        control_snapshot=snapshot,
    )
    assert [item.rule.rule_id for item in observations] == ["command.api-gateway.delete"]

    payload["command_model"]["normalized_text"] = "aws s3 ls"
    with pytest.raises(NativeCommandExtensionEvidenceError, match="command_mismatch"):
        observations_from_native_evidence(
            payload,
            BUILT_IN_COMMAND_EXTENSION_REGISTRY,
            command=command,
            control_snapshot=snapshot,
        )


def test_native_evidence_rejects_stale_controls_and_rule_versions() -> None:
    payload, command, snapshot = _payload("aws apigateway delete-rest-api --rest-api-id abc")
    stale = ExtensionControlRuntimeSnapshot(
        snapshot.health,
        snapshot.revision + 1,
        snapshot.catalog_digest,
        snapshot.effective_digest,
        snapshot.layers,
        snapshot.managed_revision,
    )
    with pytest.raises(NativeCommandExtensionEvidenceError, match="binding_mismatch"):
        observations_from_native_evidence(
            payload,
            BUILT_IN_COMMAND_EXTENSION_REGISTRY,
            command=command,
            control_snapshot=stale,
        )

    evidence = payload["command_extensions"]
    evidence["observations"][0]["rule_version"] = "9.9.9"
    _rehash(evidence)
    with pytest.raises(NativeCommandExtensionEvidenceError, match="unknown_identity"):
        observations_from_native_evidence(
            payload,
            BUILT_IN_COMMAND_EXTENSION_REGISTRY,
            command=command,
            control_snapshot=snapshot,
        )


def _failed_payload():
    payload, command, snapshot = _payload("env FOO=bar curl https://example.test")
    evidence = payload["command_extensions"]
    evidence["observations"] = []
    evidence["evaluation_error"] = "native_command_evaluation_failed"
    evidence["binding"]["observation_count"] = 0
    evidence["binding"]["uncertainty_count"] = 1
    _rehash(evidence)
    payload.update(
        decision="deny",
        policy_action="block",
        minimum_action="block",
        explicitly_benign=False,
    )
    return payload, command, snapshot


def test_native_evaluation_rejection_projects_a_block_without_rewriting_evidence() -> None:
    payload, command, snapshot = _failed_payload()
    original = deepcopy(payload)
    evaluation = evaluate_command(
        command.normalized_text,
        canonical_command=command,
        extension_control_snapshot=snapshot,
        native_extension_evidence=payload,
    )
    assert evaluation.minimum_action == "block"
    assert evaluation.decision_plane.action == "block"
    assert evaluation.matches == ()
    assert evaluation.extension_observations == ()
    assert evaluation.controlling_action_class is None
    assert ProofRoute.VERIFIED not in evaluation.decision_plane.proof_routes
    assert payload == original


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("decision", "allow"),
        ("decision", None),
        ("policy_action", "allow"),
        ("policy_action", "review"),
        ("policy_action", None),
        ("minimum_action", "allow"),
        ("minimum_action", "review"),
        ("minimum_action", None),
        ("explicitly_benign", True),
        ("explicitly_benign", None),
    ],
)
def test_native_evaluation_rejection_requires_an_unambiguous_hard_block(field: str, value: object) -> None:
    payload, command, snapshot = _failed_payload()
    if value is None:
        payload.pop(field)
    else:
        payload[field] = value
    original = deepcopy(payload)
    with pytest.raises(NativeCommandExtensionEvidenceError, match="evidence_invalid"):
        observations_from_native_evidence(
            payload,
            BUILT_IN_COMMAND_EXTENSION_REGISTRY,
            command=command,
            control_snapshot=snapshot,
        )
    assert payload == original


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("catalog_digest", "e" * 64),
        ("program_digest", "e" * 64),
        ("control_revision", 8),
        ("managed_control_revision", 4),
        ("control_effective_digest", "e" * 64),
    ],
)
def test_native_evaluation_rejection_still_requires_exact_binding(field: str, value: object) -> None:
    payload, command, snapshot = _failed_payload()
    payload["command_extensions"]["binding"][field] = value
    with pytest.raises(NativeCommandExtensionEvidenceError, match="binding_mismatch"):
        observations_from_native_evidence(
            payload,
            BUILT_IN_COMMAND_EXTENSION_REGISTRY,
            command=command,
            control_snapshot=snapshot,
        )


@pytest.mark.parametrize("malformation", ["unknown_error", "observations", "permissions", "digest"])
def test_native_evaluation_rejection_cannot_carry_malformed_or_mixed_evidence(malformation: str) -> None:
    payload, command, snapshot = _failed_payload()
    evidence = payload["command_extensions"]
    if malformation == "unknown_error":
        evidence["evaluation_error"] = "unknown_failure"
    elif malformation in {"observations", "permissions"}:
        field = "observations" if malformation == "observations" else "permission_observations"
        evidence[field] = [{}]
        evidence["binding"]["observation_count"] = 1
    _rehash(evidence)
    if malformation == "digest":
        evidence["binding"]["observations_digest"] = "e" * 64
    with pytest.raises(NativeCommandExtensionEvidenceError, match="evidence_invalid"):
        observations_from_native_evidence(
            payload,
            BUILT_IN_COMMAND_EXTENSION_REGISTRY,
            command=command,
            control_snapshot=snapshot,
        )


def test_real_native_evaluation_rejection_keeps_its_error_and_block() -> None:
    from codex_plugin_scanner.guard.runtime.secret_file_requests import (
        build_tool_action_request_artifact,
        extract_sensitive_tool_action_request,
    )
    from tests.native_command_test_support import project_native_review_fixture, real_native_review_fixture

    fixture = real_native_review_fixture("env FOO=bar curl https://example.test")
    original = json.dumps(fixture.payload, sort_keys=True, separators=(",", ":"))
    assert fixture.payload["command_extensions"]["evaluation_error"] == "native_command_evaluation_failed"
    assert fixture.payload["decision"] == "deny"
    reviewed = project_native_review_fixture(fixture)
    assert reviewed.payload is fixture.payload
    assert reviewed.evaluation.minimum_action == "block"
    assert reviewed.evaluation.decision_plane.action == "block"
    assert reviewed.evaluation.matches == ()
    assert reviewed.evaluation.extension_observations == ()
    assert ProofRoute.VERIFIED not in reviewed.evaluation.decision_plane.proof_routes
    request = extract_sensitive_tool_action_request(
        "Bash",
        {"command": fixture.command},
        canonical_command=reviewed.evaluation.command,
        native_evaluation=reviewed.evaluation,
    )
    assert request is not None
    assert request.action_class == "unmodeled shell command"
    assert request.guard_default_action == "block"
    artifact = build_tool_action_request_artifact(
        "codex",
        request,
        config_path="native-error-test",
        source_scope="project",
        native_extension_evidence=fixture.payload,
        extension_control_snapshot=fixture.snapshot,
        native_evaluation=reviewed.evaluation,
    )
    assert artifact.metadata["command_action_floor"] == "block"
    assert artifact.metadata["command_rule_matches"] == []
    assert json.dumps(fixture.payload, sort_keys=True, separators=(",", ":")) == original
