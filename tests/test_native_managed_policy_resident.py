"""Actual managed policy publication and resident consumption with staged negotiation.

The signed source, authenticated local state, catalog, snapshot ACK and action are real.
Only the staged feature names are supplied by the fixture. This does not certify
production advertisement, installed artifacts or unrelated managed request shapes.
"""

from __future__ import annotations

import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_hook_edge
from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.native_policy_authority_contract import NATIVE_MANAGED_AUTHORITY_FEATURE
from codex_plugin_scanner.guard.native_policy_authority_read import read_native_policy_authority_inputs
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from scripts.native_slo_session import stop_native_resident
from tests.native_managed_source_support import PERMISSION, managed_store
from tests.native_scoped_resident_fixtures import explicitly_negotiated_test_status


def test_managed_resident_fixture_has_genuine_signed_and_local_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = managed_store(tmp_path, monkeypatch, lockdown=True)
    inputs = read_native_policy_authority_inputs(store, now=time.time())
    managed = inputs.authority.managed
    assert managed is not None and managed.global_lockdown
    assert managed.revision == 1 and managed.managed_revision == 1
    assert managed.catalog_digest == BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    assert [(control.target_id, control.state) for control in managed.controls] == [(PERMISSION, "disabled")]
    assert any(source["kind"] == "managed-controls" for source in inputs.sources)
    assert inputs.authority.rows and inputs.expires_at_ms is not None


@pytest.mark.slow
@pytest.mark.parametrize("mode", ["enforce", "observe"])
def test_signed_managed_lockdown_is_consumed_by_actual_resident(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    for variable in ("HOL_GUARD_TEST_MODE", "HOL_GUARD_PYTHON_ORACLE", "HOL_GUARD_NATIVE_DIAGNOSTIC"):
        monkeypatch.delenv(variable, raising=False)
    actual = explicitly_negotiated_test_status()
    assert actual.identity is not None and actual.capabilities is not None
    assert actual.capabilities.extension_catalog_digest == BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    status = replace(
        actual,
        capabilities=replace(
            actual.capabilities,
            features=tuple(sorted(set(actual.capabilities.features) | {NATIVE_MANAGED_AUTHORITY_FEATURE})),
        ),
    )
    monkeypatch.setattr(native_hook_edge, "native_runtime_status", lambda: status)
    store = managed_store(tmp_path, monkeypatch, lockdown=True)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (store.guard_home / "config.toml").write_text(
        f'mode = "{mode}"\ndefault_action = "warn"\nunknown_publisher_action = "warn"\n[harnesses]\ncodex = "warn"\n',
        encoding="utf-8",
    )
    # The generic artifact has no publisher; keep that ordinary floor explicit.
    assert load_guard_config(store.guard_home).unknown_publisher_action == "warn"
    publisher = NativePolicySnapshotPublisher(store=store, status_provider=lambda: status)

    def evaluate(payload: dict[str, object] | None = None) -> dict[str, Any] | None:
        return native_hook_edge.review_raw_hook_native(
            payload=payload or {"tool_name": "Bash", "tool_input": {"command": "printf Synthetic"}},
            harness="codex",
            event="PreToolUse",
            guard_home=store.guard_home,
            home_dir=tmp_path,
            cwd=workspace,
            source_ref_external_allowed=False,
            observe_mode=mode == "observe",
            deadline=time.monotonic() + 5,
            policy_snapshot=publisher.current_snapshot_binding(),
        )

    try:
        publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
        first_binding = publisher.current_snapshot_binding()
        assert first_binding is not None and first_binding["mode"] == mode
        blocked = evaluate()  # First request after the real signed publication and ACK.
        assert blocked is not None
        assert blocked["authority"] == "rust" and blocked["schema"] == "guard-hook-edge-result.v3"
        assert blocked["result"]["decision"] == "deny" and blocked["result"]["policy_action"] == "block"
        assert blocked["policy_binding"]["selected_decision_id"] is None
        assert publisher.result_binding_is_current(blocked["policy_binding"])
        assert blocked["receipt"]["rule_digest"] == actual.capabilities.rule_digest
        # Lockdown stays terminal in Observe; no policy-only action was projected.
        assert blocked["observed_policy_action"] is None
        assert blocked["receipt"]["observed_policy_action"] is None
        assert blocked["receipt"]["observe_mode"] is (mode == "observe")
        # The admitted managed subset cannot silently drop observations for an unrelated tool.
        assert evaluate({"tool_name": "mcp__synthetic__inspect", "tool_input": {}}) is None

        keyring = store.get_sync_payload("policy_bundle_keyring")
        assert isinstance(keyring, dict)
        keys = keyring["keys"]
        assert isinstance(keys, list) and isinstance(keys[0], dict)
        keys[0]["state"] = "revoked"
        now = datetime.now(timezone.utc).isoformat()
        store.set_sync_payload("policy_bundle_keyring", keyring, now)
        publisher.request_publish()
        assert not publisher.result_binding_is_current(blocked["policy_binding"])
        publisher._publish_once()
        assert not publisher.is_ready(), "revoked signing authority must not publish a reduced policy"

        # The existing explicit authority-clear operation retains the independent local layer.
        store.clear_policy_bundle_authority(now, policy_bundle_last_error={"reason": "synthetic-clear"})
        publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
        final_binding = publisher.current_snapshot_binding()
        assert final_binding is not None and final_binding["policy_digest"] != first_binding["policy_digest"]
        allowed = evaluate()
        assert allowed is not None
        assert allowed["result"]["decision"] == "allow" and allowed["result"]["policy_action"] == "warn"
        assert allowed["policy_binding"]["selected_decision_id"] is None
        assert publisher.result_binding_is_current(allowed["policy_binding"])
        inputs = read_native_policy_authority_inputs(store, now=time.time())
        managed = inputs.authority.managed
        assert managed is not None and not managed.global_lockdown
        assert managed.revision == 1 and managed.managed_revision == 2
        assert [(control.target_id, control.state) for control in managed.controls] == [(PERMISSION, "enabled")]
    finally:
        publisher.close()
        assert stop_native_resident(actual.identity.path, store.guard_home, write_diagnostic=False).contained
