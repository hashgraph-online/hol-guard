"""Unavailable execution cannot acquire consent through old or forged clients."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_approval_scope_contract import _post, _request, _store_request, _v2_selection


@pytest.mark.parametrize("client", ["legacy", "current", "stale"])
@pytest.mark.parametrize("remember", [False, True])
def test_unavailable_native_approval_is_rejected_without_writing_consent(
    tmp_path: Path, client: str, remember: bool,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    row = _store_request(store, _request(
        "unavailable-script", artifact_id="omp:native-pretool:bash",
        artifact_type="tool_call", artifact_hash="unbound-request", policy_action="review",
    ))
    payload: dict[str, object] = {"scope": "artifact", "persist_policy": remember}
    if client != "legacy":
        payload.update(_v2_selection(row, "artifact"))
    if client == "stale":
        payload["scope_contract_digest"] = "0" * 64
    # A client cannot manufacture execution capability in its resolution.
    payload["execution_approval"] = {"can_run_once": True, "can_persist_exact_version": True}
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        status, response = _post(daemon, "/v1/requests/unavailable-script/approve", payload)
    finally:
        daemon.stop()
    assert status == (409 if client == "stale" else 422), response
    assert response["allowed_scopes_by_action"]["allow"] == []
    assert response["execution_approval"]["can_run_once"] is False
    assert response["execution_approval"]["can_persist_exact_version"] is False
    assert store.get_approval_request("unavailable-script")["status"] == "pending"
    assert store.list_policy_decisions() == []
    assert store.list_events(event_name="approval.resolved") == []
