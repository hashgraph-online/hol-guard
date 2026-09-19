"""Enroll the protected control authority assumed by review-flow fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_gate import ApprovalGateInput, require_high_risk, update_settings
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.runtime.extension_control_proof import (
    ExtensionControlEnrollment,
    issue_extension_control_enrollment_proof,
)
from codex_plugin_scanner.guard.store import GuardStore

_FIXTURE_PASSWORD = "synthetic review fixture password"


def enroll_review_authority(guard_home: Path) -> None:
    """Use real enrollment and persistence, supplying only terminal interaction."""
    store = GuardStore(guard_home)
    previous = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    if previous.health is AuthorityHealth.PROTECTED:
        return
    assert previous.health is AuthorityHealth.UNENROLLED
    update_settings(
        guard_home,
        {
            "enabled": True,
            "new_password": _FIXTURE_PASSWORD,
            "confirm_password": _FIXTURE_PASSWORD,
            "cooldown_seconds": 0,
        },
    )
    enrollment = ExtensionControlEnrollment(
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        actor_id="review-fixture",
        nonce="review-fixture-enrollment",
    )
    with pytest.MonkeyPatch.context() as confirmation:
        confirmation.setattr(
            "codex_plugin_scanner.guard.runtime.extension_control_proof._require_local_terminal_confirmation",
            lambda _enrollment: None,
        )
        proof = issue_extension_control_enrollment_proof(
            guard_home,
            enrollment,
            approval_gate_input=ApprovalGateInput(password=_FIXTURE_PASSWORD),
            session_nonce="review-fixture-session",
        )
    enrolled = store.enroll_extension_control_authority(
        catalog_digest=enrollment.catalog_digest,
        actor_id=enrollment.actor_id,
        nonce=enrollment.nonce,
        proof=proof,
    )
    assert enrolled.health is AuthorityHealth.PROTECTED
    # Enrollment requires a password proof, while these existing review tests
    # exercise the default approval settings. Restore those settings through
    # their authenticated API without removing the enrolled authority.
    settings_grant = require_high_risk(
        guard_home,
        purpose="settings_write",
        approval_gate_input=ApprovalGateInput(password=_FIXTURE_PASSWORD),
    )
    settings = update_settings(guard_home, {"enabled": False}, approval_gate_grant=settings_grant)
    assert settings.enabled is False
    # A hook or daemon opens its own store; a fabricated in-memory view would
    # not establish the setup needed by the real review path.
    observed = GuardStore(guard_home).read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    assert observed.health is AuthorityHealth.PROTECTED
