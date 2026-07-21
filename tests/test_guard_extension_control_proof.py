from __future__ import annotations

import subprocess
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
    ExtensionControlEnrollment,
    ExtensionControlMutation,
    ExtensionControlProofError,
    _require_local_terminal_confirmation,
    _terminal_session_is_local,
    consume_extension_control_enrollment_proof,
    consume_extension_control_proof,
    issue_extension_control_enrollment_proof,
    issue_extension_control_proof,
)

_PASSWORD = "correct horse battery staple"
_NOW = "2026-07-20T12:00:00+00:00"


@pytest.fixture(autouse=True)
def _allow_local_terminal_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._require_local_terminal_confirmation",
        lambda _enrollment: None,
    )


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


def _enrollment(*, actor_id: str = "local-admin", nonce: str = "enrollment-nonce") -> ExtensionControlEnrollment:
    return ExtensionControlEnrollment(
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        actor_id=actor_id,
        nonce=nonce,
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


def test_enrollment_proof_is_exact_one_use_and_redacted(tmp_path: Path) -> None:
    _configure(tmp_path)
    enrollment = _enrollment()
    proof = issue_extension_control_enrollment_proof(
        tmp_path,
        enrollment,
        approval_gate_input=ApprovalGateInput(password=_PASSWORD),
        session_nonce="enrollment-session",
        now=_NOW,
    )

    rendered = repr(proof)
    assert rendered == "ExtensionControlEnrollmentProof(<redacted>)"
    for private_value in (
        _PASSWORD,
        proof.proof_id,
        proof.grant.grant_id,
        proof.actor_id,
        proof.nonce,
        proof.session_nonce,
    ):
        assert private_value not in rendered

    with pytest.raises(ExtensionControlProofError, match="does not match"):
        consume_extension_control_enrollment_proof(
            tmp_path,
            proof,
            _enrollment(actor_id="different-actor"),
            now=_NOW,
        )

    consume_extension_control_enrollment_proof(tmp_path, proof, enrollment, now=_NOW)
    with pytest.raises(ApprovalGateError, match="Approval proof is required"):
        consume_extension_control_enrollment_proof(tmp_path, proof, enrollment, now=_NOW)


def test_enrollment_proof_rejects_remote_terminal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _configure(tmp_path)
    monkeypatch.setenv("SSH_CONNECTION", "client server")

    with pytest.raises(ExtensionControlProofError, match="requires a local terminal"):
        _require_local_terminal_confirmation(_enrollment())


@pytest.mark.parametrize(
    ("who_output", "expected"),
    (
        ("local-admin ttys020 Jul 21 09:07\n", True),
        ("local-admin ttys020 Jul 21 09:07 (203.0.113.8)\n", False),
        ("local-admin ttys021 Jul 21 09:07\n", False),
    ),
)
def test_terminal_locality_requires_hostless_matching_login_record(
    monkeypatch: pytest.MonkeyPatch,
    who_output: str,
    expected: bool,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._current_login_name",
        lambda: "local-admin",
    )
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(("/usr/bin/who",), 0, who_output, ""),
    )

    assert _terminal_session_is_local("/dev/ttys020") is expected


def test_extension_control_proof_rejects_stale_grant(tmp_path: Path) -> None:
    _configure(tmp_path)
    mutation = _mutation()
    proof = issue_extension_control_proof(
        tmp_path,
        mutation,
        approval_gate_input=ApprovalGateInput(password=_PASSWORD),
        session_nonce="session-1",
        now=_NOW,
    )

    with pytest.raises(ApprovalGateError) as error:
        consume_extension_control_proof(
            tmp_path,
            proof,
            mutation,
            now="2026-07-20T12:06:00+00:00",
        )
    assert error.value.code == "approval_gate_grant_expired"


def test_extension_control_proof_repr_redacts_all_bindings(tmp_path: Path) -> None:
    _configure(tmp_path)
    proof = issue_extension_control_proof(
        tmp_path,
        _mutation(),
        approval_gate_input=ApprovalGateInput(password=_PASSWORD),
        session_nonce="session-1",
        now=_NOW,
    )

    assert repr(proof) == "ExtensionControlProof(<redacted>)"


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
