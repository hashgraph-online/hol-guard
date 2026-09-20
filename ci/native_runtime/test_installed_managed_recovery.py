"""Actual local HTTP/SQLite recovery; installed native enforcement is separate."""

from __future__ import annotations

from pathlib import Path

import pytest

from ci.native_runtime.installed_managed_recovery import repair_local_authority
from codex_plugin_scanner.guard.approval_gate import ApprovalGateGrant
from codex_plugin_scanner.guard.daemon import extension_control_api
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlLayerKind
from tests.native_managed_source_support import managed_store
from tests.test_guard_extension_control_authority import _PASSWORD


def test_actual_authenticated_http_recovery_consumes_approval_and_preserves_signed_floor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = managed_store(tmp_path, monkeypatch, lockdown=True, scoped=False)
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    before = store.read_extension_control_authority_for_registry(registry)
    signed = tuple(layer for layer in before.layers if layer.kind is ControlLayerKind.SIGNED_CLOUD)
    assert before.health is AuthorityHealth.PROTECTED and signed
    consumed: list[tuple[str, str, str]] = []
    consume = extension_control_api.consume_extension_control_grant

    def observe_consumption(
        guard_home: Path,
        approval_gate_grant: ApprovalGateGrant,
        *,
        action: str,
        subject: str,
        session_nonce: str,
        now: str | None = None,
    ) -> None:
        consume(
            guard_home,
            approval_gate_grant,
            action=action,
            subject=subject,
            session_nonce=session_nonce,
            now=now,
        )
        consumed.append((action, subject, session_nonce))

    monkeypatch.setattr(extension_control_api, "consume_extension_control_grant", observe_consumption)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        revision = repair_local_authority(daemon, store, _PASSWORD)
        current = store.read_extension_control_authority_for_registry(registry)
        assert current.health is AuthorityHealth.PROTECTED
        assert current.revision == revision
        assert current.managed_revision == before.managed_revision
        assert tuple(layer for layer in current.layers if layer.kind is ControlLayerKind.SIGNED_CLOUD) == signed
        assert len(consumed) == 1
        assert consumed[0][0] == "recover-authority"
        assert consumed[0][1].startswith("recover-authority:tampered:")
        assert len(consumed[0][2]) == 32
    finally:
        daemon.stop()
