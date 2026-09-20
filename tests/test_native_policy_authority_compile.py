"""Scoped compilation preserves authority and refuses unsupported consumers."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_policy_authority_compile import (
    compile_native_managed_authority,
    compile_native_policy_authority,
    compile_native_policy_row,
)
from codex_plugin_scanner.guard.native_policy_authority_contract import (
    NATIVE_MANAGED_AUTHORITY_FEATURE,
    NATIVE_SCOPED_AUTHORITY_FEATURE,
    NativeManagedControl,
    NativeManagedPolicyAuthority,
    NativePolicyAuthorityCapabilities,
    NativePolicyAuthorityDraft,
)
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    ControlLayerKind,
    ControlState,
    ControlTargetKind,
)
from codex_plugin_scanner.guard.store_base import _scoped_runtime_row_requires_exact_match
from tests.test_canonical_policy_row_authority import _ARTIFACT, _NOW, _activated_store
from tests.test_guard_extension_control_resolver import _catalog_subjects, _control, _layer

_V4 = NativePolicyAuthorityCapabilities(4, frozenset({NATIVE_SCOPED_AUTHORITY_FEATURE}))


def test_shared_native_fixture_matches_actual_compiler_and_digest() -> None:
    fixture_path = (
        Path(__file__).parents[1] / "rust" / "crates" / "guard-policy-snapshot" / "src"
        / "scoped_authority_fixture.json"
    )
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    raw = fixture["authority"]["managed"]
    managed = NativeManagedPolicyAuthority(
        raw["revision"], raw["managed_revision"], raw["catalog_digest"], raw["global_lockdown"],
        tuple(NativeManagedControl(item["target_kind"], item["target_id"], item["state"]) for item in raw["controls"]),
    )
    capabilities = NativePolicyAuthorityCapabilities(
        4, frozenset({NATIVE_SCOPED_AUTHORITY_FEATURE, NATIVE_MANAGED_AUTHORITY_FEATURE}), managed.catalog_digest
    )
    draft = compile_native_policy_authority(fixture["source_rows"], managed=managed)
    assert draft.content_digest == fixture["content_digest"]
    assert draft.for_snapshot(capabilities) == fixture["authority"]


def _row(**changes: object) -> dict[str, object]:
    return {
        "decision_id": 1,
        "harness": "codex",
        "scope": "workspace",
        "artifact_id": "synthetic-artifact",
        "artifact_hash": "sha256:" + "a" * 64,
        "workspace": "synthetic-workspace",
        "publisher": None,
        "action": "block",
        "source": "policy-bundle-canonical",
        "updated_at": "2026-09-17T00:00:00.000123+00:00",
        "expires_at": "2026-09-18T00:00:00.000123+00:00",
        "reason": "synthetic-private-description",
        "owner": "synthetic-private-author",
        **changes,
    }


def test_verified_signed_row_can_be_compiled_but_v3_cannot_consume_it(tmp_path: Path) -> None:
    store = _activated_store(tmp_path)
    lookup = store.resolve_policy_decision_lookup("codex", _ARTIFACT, now=_NOW, consume_one_shot=False)
    row = lookup["decision"]
    assert isinstance(row, dict)
    draft = compile_native_policy_authority((row,))
    compiled = draft.for_snapshot(_V4)["rows"]
    assert isinstance(compiled, list) and isinstance(compiled[0], dict)
    assert compiled[0]["artifact_id"] == _ARTIFACT
    assert compiled[0]["action"] == "allow"
    assert compiled[0]["source_kind"] == "signed-bundle"
    with pytest.raises(NativePolicySnapshotError, match="capability_unsupported"):
        draft.for_snapshot(NativePolicyAuthorityCapabilities(3, _V4.features))


def test_compiler_preserves_intersecting_selectors_and_omits_display_metadata() -> None:
    draft = compile_native_policy_authority((_row(),))
    payload = draft.for_snapshot(_V4)
    compiled = payload["rows"][0]
    assert {key: compiled[key] for key in ("harness", "artifact_id", "artifact_hash", "workspace")} == {
        key: _row()[key] for key in ("harness", "artifact_id", "artifact_hash", "workspace")
    }
    assert compiled["updated_at_us"] == 1_789_603_200_000_123
    assert compiled["expires_at_ms"] == 1_789_689_600_000
    encoded = json.dumps(payload)
    assert "synthetic-private" not in encoded
    assert "synthetic-workspace" not in repr(draft)


def test_compiler_binds_exact_command_without_dropping_original_selectors() -> None:
    digest = "a" * 64
    original = _row(exact_command_sha256=digest)
    draft = compile_native_policy_authority((original,))
    compiled = draft.for_snapshot(_V4)["rows"][0]
    for key in ("harness", "workspace", "artifact_id", "artifact_hash", "exact_command_sha256"):
        assert compiled[key] == original[key]
    assert draft.content_digest != compile_native_policy_authority((_row(),)).content_digest
    different = compile_native_policy_authority((_row(exact_command_sha256="b" * 64),))
    assert draft.content_digest != different.content_digest


@pytest.mark.parametrize("changes", [
    {"exact_command_sha256": ""}, {"exact_command_sha256": "a" * 63},
    {"exact_command_sha256": "A" * 64}, {"exact_command_sha256": True},
    {"exact_command_sha256": "a" * 64, "artifact_id": None},
    {"exact_command_sha256": "a" * 64, "scope": "harness", "workspace": None, "artifact_id": "family:tool-action"},
])
def test_exact_command_selector_cannot_be_malformed_or_lose_original_artifact(changes) -> None:
    with pytest.raises(NativePolicySnapshotError):
        compile_native_policy_row(_row(**changes))


def test_row_order_cannot_change_payload_digest_or_recency() -> None:
    cloud = _row()
    local = _row(decision_id=2, action="allow", source="local", updated_at="2026-09-17T00:00:00.000124Z")
    forward = compile_native_policy_authority((cloud, local))
    reverse = compile_native_policy_authority((local, cloud))
    assert forward.content_digest == reverse.content_digest
    rows = forward.for_snapshot(_V4)["rows"]
    assert rows[1]["updated_at_us"] > rows[0]["updated_at_us"]
    assert rows[1]["source_kind"] == "local"


def test_encoded_payload_mutation_cannot_change_immutable_draft() -> None:
    draft = compile_native_policy_authority((_row(),))
    digest = draft.content_digest
    exported = draft.for_snapshot(_V4)
    exported["rows"][0]["action"] = "allow"
    assert draft.content_digest == digest
    assert draft.for_snapshot(_V4)["rows"][0]["action"] == "block"


@pytest.mark.parametrize(
    "family", ["file-read", "mcp-tool", "package-request", "prompt", "tool-action", "mcp", "prompt-file"]
)
@pytest.mark.parametrize("scope", ["harness", "global"])
@pytest.mark.parametrize("source", ["local", "policy-bundle-canonical", "cloud-signed-memory"])
def test_exact_context_requirement_matches_existing_runtime_guard(family: str, scope: str, source: str) -> None:
    row = _row(scope=scope, artifact_id=f"family:{family}", workspace=None, source=source)
    compiled = compile_native_policy_row(row)
    # Absence of request identity exposes whether the existing runtime row
    # requires exact context. This compares behavior across all supported
    # families and source kinds without reconstructing its family predicate.
    existing_rejects = _scoped_runtime_row_requires_exact_match(
        scope=scope,
        stored_artifact_id=row["artifact_id"],
        stored_artifact_hash=row["artifact_hash"],
        source=source,
        requested_artifact_id=None,
    )
    assert compiled.requires_exact_context is existing_rejects
    assert compiled.to_mapping()["requires_exact_context"] is existing_rejects


@pytest.mark.parametrize(
    "changes",
    [
        {"decision_id": True}, {"action": "ignore"}, {"action": "unknown"},
        {"artifact_id": ""}, {"artifact_hash": "x" * 4097}, {"workspace": None},
        {"publisher": "must-not-be-dropped"}, {"updated_at": "2026-09-17T00:00:00"},
        {"expires_at": "invalid"}, {"source": "cloud-sync"},
        {"approval_id": "one-shot"}, {"source": "approval-gate"},
    ],
)
def test_invalid_or_unrepresentable_inputs_are_rejected_without_dropping_fields(changes: dict[str, object]) -> None:
    with pytest.raises(NativePolicySnapshotError):
        compile_native_policy_row(_row(**changes))


def test_duplicate_rows_and_overflow_fail_before_encoding() -> None:
    with pytest.raises(NativePolicySnapshotError, match="row_duplicate"):
        compile_native_policy_authority((_row(), _row()))
    with pytest.raises(NativePolicySnapshotError, match="row_limit"):
        compile_native_policy_authority(_row(decision_id=index + 1) for index in range(257))


def test_managed_projection_preserves_disable_dominance_and_requires_exact_catalog() -> None:
    extension_id, permission_id = _catalog_subjects()
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    local = _layer(
        ControlLayerKind.LOCAL_ADMIN,
        _control(ControlTargetKind.PERMISSION, permission_id, ControlState.ENABLED),
    )
    cloud = _layer(
        ControlLayerKind.SIGNED_CLOUD,
        _control(ControlTargetKind.EXTENSION, extension_id, ControlState.DISABLED),
        _control(ControlTargetKind.PERMISSION, permission_id, ControlState.DISABLED),
        lockdown=True,
    )
    view = ExtensionControlAuthorityView(AuthorityHealth.PROTECTED, 4, registry.catalog_digest, (local, cloud), 8)
    managed = compile_native_managed_authority(view, registry)
    draft = NativePolicyAuthorityDraft((), managed)
    capabilities = NativePolicyAuthorityCapabilities(
        4, frozenset({NATIVE_SCOPED_AUTHORITY_FEATURE, NATIVE_MANAGED_AUTHORITY_FEATURE}), registry.catalog_digest
    )
    payload = draft.for_snapshot(capabilities)["managed"]
    assert payload["global_lockdown"] is True
    assert all(control["state"] == "disabled" for control in payload["controls"])
    with pytest.raises(NativePolicySnapshotError, match="catalog_mismatch"):
        draft.for_snapshot(replace(capabilities, catalog_digest="a" * 64))
    with pytest.raises(NativePolicySnapshotError, match="capability_unsupported"):
        draft.for_snapshot(_V4)
    with pytest.raises(NativePolicySnapshotError, match="managed_unavailable"):
        compile_native_managed_authority(replace(view, health=AuthorityHealth.TAMPERED), registry)


@pytest.mark.parametrize("snapshot_version", [True, None, "4", 0])
def test_native_capability_version_is_exact(snapshot_version: object) -> None:
    with pytest.raises(NativePolicySnapshotError):
        NativePolicyAuthorityCapabilities.from_mapping(
            {"policy_snapshot_version": snapshot_version, "features": [NATIVE_SCOPED_AUTHORITY_FEATURE]}
        )
