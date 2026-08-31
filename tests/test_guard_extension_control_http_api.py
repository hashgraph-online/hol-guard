from __future__ import annotations

import http.client
import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon.client import GuardDaemonRequestError, GuardSurfaceDaemonClient
from codex_plugin_scanner.guard.daemon.manager import load_guard_daemon_auth_token
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_extension_control_api import _dashboard_token, _mutation_payload


def test_http_repair_converges_when_store_recovered_after_daemon_cached_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    stale = ExtensionControlAuthorityView(
        AuthorityHealth.RECOVERY_REQUIRED,
        4,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        (),
    )
    protected = ExtensionControlAuthorityView(
        AuthorityHealth.PROTECTED,
        4,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        (),
    )
    monkeypatch.setattr(store, "read_extension_control_authority_for_registry", lambda _registry: stale)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    monkeypatch.setattr(store, "read_extension_control_authority_for_registry", lambda _registry: protected)
    daemon.start()
    try:
        auth_token = load_guard_daemon_auth_token(store.guard_home)
        assert auth_token is not None
        client = GuardSurfaceDaemonClient(f"http://127.0.0.1:{daemon.port}", auth_token)

        repaired = client.recover_extension_control_authority({"session_nonce": "nonce"})

        assert repaired["health"] == AuthorityHealth.PROTECTED.value
        assert client.effective_extension_controls()["health"] == AuthorityHealth.PROTECTED.value
    finally:
        daemon.stop()


def test_http_routes_authenticate_before_reading_sensitive_post_body(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    connection = http.client.HTTPConnection("127.0.0.1", daemon.port, timeout=2)
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/extension-controls/catalog",
            method="GET",
        )
        with pytest.raises(urllib.error.HTTPError) as unauthorized:
            urllib.request.urlopen(request, timeout=2)
        assert unauthorized.value.code == 401

        auth_token = load_guard_daemon_auth_token(store.guard_home)
        assert auth_token is not None
        authenticated = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/extension-controls/catalog",
            method="GET",
            headers={"X-Guard-Dashboard-Session": _dashboard_token(auth_token)},
        )
        with urllib.request.urlopen(authenticated, timeout=2) as response:
            assert response.status == 200
            assert json.loads(response.read())["catalog_digest"] == (BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest)

        connection.putrequest("POST", "/v1/extension-controls/apply")
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", "1000000")
        connection.endheaders()
        response = connection.getresponse()
        assert response.status == 401
        response.read()
        connection.close()
        connection = http.client.HTTPConnection("127.0.0.1", daemon.port, timeout=2)
        connection.putrequest("POST", "/v1/extension-controls/apply")
        connection.putheader("X-Guard-Token", auth_token)
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", "1000001")
        connection.endheaders()
        response = connection.getresponse()
        client = GuardSurfaceDaemonClient(f"http://127.0.0.1:{daemon.port}", auth_token)
        refreshed = client.refresh_extension_controls()
        assert refreshed["health"] == "unenrolled"
        with pytest.raises(GuardDaemonRequestError) as not_recoverable:
            client.recover_extension_control_authority({"session_nonce": "nonce"})
        assert not_recoverable.value.status == 409
        assert not_recoverable.value.code == "authority_not_recoverable"
        with pytest.raises(GuardDaemonRequestError) as not_degraded:
            client.acknowledge_degraded_extension_controls({})
        assert not_degraded.value.status == 409
        assert not_degraded.value.code == "authority_not_degraded"
        with pytest.raises(GuardDaemonRequestError) as unavailable:
            client.preview_extension_controls(_mutation_payload(revision=0))
        assert unavailable.value.status == 423
        assert unavailable.value.code == "authority_unavailable"
        assert unavailable.value.recovery_action == "enroll_or_repair_authority"
        assert response.status == 413
    finally:
        connection.close()
        daemon.stop()
