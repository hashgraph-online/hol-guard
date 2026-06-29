"""Tests for _cloud_local_identity_payload and _cloud_local_identity_source_payload.

These functions populate the localIdentity and localIdentitySource fields
sent during runtime session sync. The values must come from real system calls
(socket.gethostname, socket probe), not user-entered fixtures.
"""

from __future__ import annotations

import socket
from unittest.mock import patch

from codex_plugin_scanner.guard.runtime.runner import (
    _cloud_local_identity_payload,
    _cloud_local_identity_source_payload,
)


class TestCloudLocalIdentityPayload:
    """HAO006: _cloud_local_identity_payload populates real host/IP from system calls."""

    def test_payload_includes_last_synced_at(self) -> None:
        payload = _cloud_local_identity_payload(observed_at="2026-06-29T00:00:00.000Z")
        assert payload["lastSyncedAt"] == "2026-06-29T00:00:00.000Z"

    def test_payload_includes_hostname_when_available(self) -> None:
        with patch("codex_plugin_scanner.guard.runtime.runner.socket.gethostname", return_value="worker-1"):
            payload = _cloud_local_identity_payload(observed_at="2026-06-29T00:00:00.000Z")
        assert payload["hostname"] == "worker-1"

    def test_payload_omits_hostname_when_unavailable(self) -> None:
        with patch("codex_plugin_scanner.guard.runtime.runner.socket.gethostname", side_effect=OSError):
            payload = _cloud_local_identity_payload(observed_at="2026-06-29T00:00:00.000Z")
        assert "hostname" not in payload

    def test_payload_includes_ip_address_when_available(self) -> None:
        class FakeSock:
            def getsockname(self): return ("10.0.0.5", 80)
            def connect(self, addr): pass
            def close(self): pass
            def __enter__(self): return self
            def __exit__(self, *args): pass
        fake_sock = FakeSock()
        with (
            patch("codex_plugin_scanner.guard.runtime.runner.socket.socket", return_value=fake_sock),
            patch("codex_plugin_scanner.guard.runtime.runner.socket.gethostname", return_value="worker-1"),
        ):
            payload = _cloud_local_identity_payload(observed_at="2026-06-29T00:00:00.000Z")
        assert payload["ipAddress"] == "10.0.0.5"
        assert payload["privateIpAddress"] == "10.0.0.5"

    def test_payload_omits_ip_when_all_probes_fail(self) -> None:
        with (
            patch("codex_plugin_scanner.guard.runtime.runner.socket.socket", side_effect=OSError),
            patch("codex_plugin_scanner.guard.runtime.runner.socket.gethostname", side_effect=OSError),
            patch("codex_plugin_scanner.guard.runtime.runner.socket.getaddrinfo", side_effect=OSError),
        ):
            payload = _cloud_local_identity_payload(observed_at="2026-06-29T00:00:00.000Z")
        assert "ipAddress" not in payload
        assert "privateIpAddress" not in payload
        assert "hostname" not in payload
        assert payload == {"lastSyncedAt": "2026-06-29T00:00:00.000Z"}

    def test_hostname_truncated_to_255_chars(self) -> None:
        long_name = "a" * 300
        with patch("codex_plugin_scanner.guard.runtime.runner.socket.gethostname", return_value=long_name):
            payload = _cloud_local_identity_payload(observed_at="2026-06-29T00:00:00.000Z")
        assert len(payload["hostname"]) == 255  # type: ignore[arg-type]


class TestCloudLocalIdentitySourcePayload:
    """HAO006: source payload marks all fields as 'local-guard'."""

    def test_source_always_includes_daemon_fields(self) -> None:
        source = _cloud_local_identity_source_payload({})
        assert source["daemonId"] == "local-guard"
        assert source["daemonVersion"] == "local-guard"
        assert source["daemonStatus"] == "local-guard"
        assert source["relayState"] == "local-guard"

    def test_source_includes_hostname_when_present(self) -> None:
        source = _cloud_local_identity_source_payload({"hostname": "worker-1"})
        assert source["hostname"] == "local-guard"

    def test_source_omits_hostname_when_absent(self) -> None:
        source = _cloud_local_identity_source_payload({})
        assert "hostname" not in source

    def test_source_includes_ip_when_present(self) -> None:
        source = _cloud_local_identity_source_payload({"ipAddress": "10.0.0.5", "privateIpAddress": "10.0.0.5"})
        assert source["ipAddress"] == "local-guard"
        assert source["privateIpAddress"] == "local-guard"
