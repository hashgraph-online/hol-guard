"""Generated-key session setup is verified before any daemon starts."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_base import EncryptedFileSecretStore
from scripts.native_slo_command_fixture import prepare_empty_command_authority, verify_empty_command_authority


def test_generated_authority_survives_independent_store_read(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    receipt = prepare_empty_command_authority(store)
    assert receipt["verified_health"] == "protected"
    assert receipt["enrollment_flow"] == "not_exercised"
    reopened = GuardStore(tmp_path)
    reopened._extension_control_authority_secret_store = EncryptedFileSecretStore(tmp_path)
    assert verify_empty_command_authority(reopened) == receipt
    with pytest.raises(RuntimeError, match="freshly unenrolled"):
        prepare_empty_command_authority(reopened)


def test_unenrolled_fixture_is_never_treated_as_protected(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="verified empty protected"):
        verify_empty_command_authority(GuardStore(tmp_path))


def test_session_verifies_authority_before_constructing_daemon(tmp_path: Path, monkeypatch) -> None:
    from scripts import native_slo_session

    seen = []

    class Publisher:
        def register_workspace(self, workspace):
            seen.append("registered")

    def daemon(store, **kwargs):
        assert verify_empty_command_authority(store)["verified_health"] == "protected"
        seen.append("protected_before_daemon")
        return SimpleNamespace(
            _server=SimpleNamespace(hook_worker=SimpleNamespace(policy_snapshot_publisher=Publisher()))
        )

    monkeypatch.setattr(native_slo_session, "GuardDaemonServer", daemon)
    session = native_slo_session.AdapterSession(tmp_path / "runtime")
    try:
        assert seen == ["protected_before_daemon", "registered"]
        assert session.command_authority_fixture["verified_health"] == "protected"
    finally:
        session.temporary.cleanup()
