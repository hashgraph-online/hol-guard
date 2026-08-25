from __future__ import annotations

import json
import urllib.request
from pathlib import Path

from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon.manager import load_guard_daemon_auth_token
from codex_plugin_scanner.guard.managed_controls_policy_bundle import MANAGED_CONTROLS_ACTIVE_STATE_KEY
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.store import GuardStore
from tests.managed_controls_activation_support import activate_managed_bundle, managed_bundle


def test_rule_target_only_activation_omits_absent_authority_mode(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    bundle = managed_bundle()
    payload = bundle["payload"]
    assert isinstance(payload, dict)
    payload.pop("x-hol-extension-controls")
    assert activate_managed_bundle(store, bundle) is True
    active = store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY)
    assert isinstance(active, dict)
    assert "authorityMode" not in active
    status = store.managed_controls_public_status(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)
    assert status is not None
    assert "authority_mode" not in status


def test_policy_api_serializes_authenticated_managed_authority_label(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    decision = PolicyDecision(
        harness="codex",
        scope="artifact",
        action="block",
        artifact_id="command.git.permission.force-push",
        reason="Managed force-push restriction",
        owner="force-push-review",
        source="policy-bundle",
    )
    assert activate_managed_bundle(store, managed_bundle(), decisions=(decision,)) is True
    status = store.managed_controls_public_status(
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    )
    assert status is not None
    assert status["control_set_id"] == "managed-git-safety"
    assert status["control_set_name"] == "Managed Git safety"
    assert status["issued_at"] == "2026-08-21T12:00:00.000Z"
    assert status["expires_at"] == "2026-09-21T12:00:00.000Z"
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        auth_token = load_guard_daemon_auth_token(store.guard_home)
        assert auth_token is not None
        request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/policy?harness=codex",
            headers={"X-Guard-Token": auth_token},
        )
        with urllib.request.urlopen(request, timeout=2) as response:
            item = json.loads(response.read())["items"][0]
        assert item["source"] == "policy-bundle"
        assert item["authority_mode"] == "managed-restrictive"
        assert item["cloud_workspace_label"] == "workspace-managed-controls"
    finally:
        daemon.stop()
