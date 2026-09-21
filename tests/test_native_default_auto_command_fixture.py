"""Generated-key fixture enrollment and privacy-safe denial diagnostics."""

from __future__ import annotations

from pathlib import Path

import pytest

from ci.native_runtime import probe_native_default_auto as probe
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_base import EncryptedFileSecretStore


def test_fresh_fixture_provisions_real_authenticated_empty_authority(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    catalog = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    assert store.read_extension_control_authority(catalog_digest=catalog).health is AuthorityHealth.UNENROLLED
    receipt = probe._prepare_empty_command_authority(store)
    assert receipt == {
        "provisioning": "isolated_ci_generated_key_empty_authority",
        "enrollment_flow": "not_exercised",
        "verified_health": "protected",
    }
    # A second independent store must authenticate the persisted generated key
    # and anchor; the fixture's returned view is not an admission oracle.
    reopened = GuardStore(tmp_path)
    reopened._extension_control_authority_secret_store = EncryptedFileSecretStore(tmp_path)
    verified = reopened.read_extension_control_authority(catalog_digest=catalog)
    assert verified.health is AuthorityHealth.PROTECTED
    assert verified.layers == ()
    key = reopened._authority_key(required=True)
    assert isinstance(key, bytes) and len(key) == 32


def test_fixture_rejects_existing_authority_instead_of_resetting_it(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    probe._prepare_empty_command_authority(store)
    first_key = store._authority_key(required=True)
    with pytest.raises(RuntimeError, match="freshly unenrolled"):
        probe._prepare_empty_command_authority(store)
    assert store._authority_key(required=True) == first_key


def test_fixture_verifies_persisted_authority_after_bootstrap(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path)
    monkeypatch.setattr(store, "_bootstrap_extension_control_authority", lambda *args, **kwargs: object())
    with pytest.raises(RuntimeError, match="verified empty protected"):
        probe._prepare_empty_command_authority(store)


def test_denial_diagnostic_retains_only_fixed_public_codes() -> None:
    assert probe._delivery_diagnostic(
        {
            "decision": "deny",
            "policy_action": "block",
            "reason_code": "native_command_control_authority_block",
            "hookSpecificOutput": {"permissionDecision": "deny", "permissionDecisionReason": "PRIVATE SOURCE"},
            "source": "PRIVATE SOURCE",
        }
    ) == {
        "decision": "deny",
        "policy_action": "block",
        "reason_code": "native_command_control_authority_block",
        "permission_decision": "deny",
    }
    assert probe._delivery_diagnostic(
        {
            "decision": "PRIVATE SOURCE",
            "policy_action": [],
            "reason_code": "PRIVATE SOURCE",
            "hookSpecificOutput": {"permissionDecision": "PRIVATE SOURCE"},
        }
    ) == {"decision": "other", "policy_action": "other", "reason_code": "other", "permission_decision": "other"}
