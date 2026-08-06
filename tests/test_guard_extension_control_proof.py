from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_gate import ApprovalGateError, ApprovalGateInput, update_settings
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.extension_control_proof import (
    ExtensionControlMutation,
    ExtensionControlProofError,
    consume_extension_control_proof,
    issue_extension_control_proof,
)

_PASSWORD = "correct horse battery staple"
_NOW = "2026-07-20T12:00:00+00:00"


def _configure(guard_home: Path) -> None:
    update_settings(
        guard_home,
        {
            "enabled": True,
            "new_password": _PASSWORD,
            "confirm_password": _PASSWORD,
            "cooldown_seconds": 0,
        },
        now=_NOW,
    )


def _mutation(
    *, actor_id: str = "local-admin", layers: tuple[ExtensionControlLayer, ...] = ()
) -> ExtensionControlMutation:
    return ExtensionControlMutation(
        previous_revision=0,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        layers=layers,
        actor_id=actor_id,
        idempotency_key="mutation-1",
        nonce="nonce-1",
    )


def test_extension_control_proof_requires_configured_gate(tmp_path: Path) -> None:
    with pytest.raises(ApprovalGateError, match="Configure the approval gate") as error:
        issue_extension_control_proof(
            tmp_path,
            _mutation(),
            approval_gate_input=ApprovalGateInput(password=_PASSWORD),
            session_nonce="session-1",
            now=_NOW,
        )

    assert error.value.code == "approval_gate_configuration_required"


def test_extension_control_proof_is_exact_and_one_use(tmp_path: Path) -> None:
    _configure(tmp_path)
    mutation = _mutation()
    proof = issue_extension_control_proof(
        tmp_path,
        mutation,
        approval_gate_input=ApprovalGateInput(password=_PASSWORD),
        session_nonce="session-1",
        now=_NOW,
    )

    consume_extension_control_proof(tmp_path, proof, mutation, now=_NOW)

    with pytest.raises(ApprovalGateError, match="Approval proof is required"):
        consume_extension_control_proof(tmp_path, proof, mutation, now=_NOW)


def test_mismatched_mutation_does_not_consume_proof(tmp_path: Path) -> None:
    _configure(tmp_path)
    mutation = _mutation()
    proof = issue_extension_control_proof(
        tmp_path,
        mutation,
        approval_gate_input=ApprovalGateInput(password=_PASSWORD),
        session_nonce="session-1",
        now=_NOW,
    )

    with pytest.raises(ExtensionControlProofError, match="does not match"):
        consume_extension_control_proof(tmp_path, proof, _mutation(actor_id="different-actor"), now=_NOW)

    consume_extension_control_proof(tmp_path, proof, mutation, now=_NOW)


def test_preview_digest_is_independent_of_layer_and_control_order() -> None:
    digest = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    controls = (
        ExtensionControl(ControlTarget(ControlTargetKind.EXTENSION, "command.alpha"), ControlState.DISABLED),
        ExtensionControl(
            ControlTarget(ControlTargetKind.PERMISSION, "command.alpha.permission.write"),
            ControlState.ENABLED,
        ),
    )
    local = ExtensionControlLayer(CONTROL_SCHEMA_VERSION, ControlLayerKind.LOCAL_ADMIN, digest, False, controls)
    cloud = ExtensionControlLayer(CONTROL_SCHEMA_VERSION, ControlLayerKind.SIGNED_CLOUD, digest, True, ())
    first = _mutation(layers=(local, cloud))
    reordered_local = ExtensionControlLayer(
        CONTROL_SCHEMA_VERSION,
        ControlLayerKind.LOCAL_ADMIN,
        digest,
        False,
        tuple(reversed(controls)),
    )
    second = _mutation(layers=(cloud, reordered_local))

    assert first.canonical_digest == second.canonical_digest
