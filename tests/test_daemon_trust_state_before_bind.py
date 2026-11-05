"""An integrity change before the daemon listens must not fail policy publication."""

from __future__ import annotations

from types import SimpleNamespace

from codex_plugin_scanner.guard.daemon import server as daemon_module


def test_trust_state_reported_before_the_socket_is_bound_is_deferred(tmp_path, monkeypatch):
    written: list[int] = []
    monkeypatch.setattr(daemon_module, "write_guard_daemon_state", lambda _home, port, *_a, **_k: written.append(port))
    http = object.__new__(daemon_module._GuardDaemonHTTPServer)
    http.store = SimpleNamespace(guard_home=tmp_path, get_cached_policy_integrity_state=lambda: {"state": "degraded"})
    http.auth_token = "unit-token"
    http.runtime_session_id = "unit-session"
    http.runtime_started_at = "2026-11-05T00:00:00Z"

    # The store's listener fires from the policy publisher while the hook
    # worker starts. Raising here left the publisher's last error as
    # `attributeerror` and the workspace policy never became ready.
    http.publish_trust_state({"state": "degraded"})
    assert written == []

    # The superclass assigns the requested address before it binds, so a
    # requested port 0 is present but is not the port the daemon listens on.
    http.server_address = ("127.0.0.1", 0)
    http.publish_trust_state()
    assert written == []

    http.server_address = ("127.0.0.1", 48123)
    http._socket_bound = True
    http.publish_trust_state()
    assert written == [48123]
