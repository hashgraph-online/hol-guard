"""Transport contracts for the connection-reset found by real Gauntlet sessions."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.adapters.pi_extension_previous_source_body import build_previous_source_body
from codex_plugin_scanner.guard.adapters.pi_extension_source_body import build_extension_source_body


@pytest.mark.parametrize("harness,display_name", [("pi", "Pi"), ("omp", "Oh My Pi")])
def test_current_daemon_review_declares_one_request_per_connection(harness, display_name):
    """Avoid stale pooled sockets without changing authentication, payload or deadlines."""
    source = build_extension_source_body(harness=harness, display_name=display_name)
    start = source.index("    const response = await fetch(`http://127.0.0.1:")
    request = source[start : source.index("    });", start)]
    assert f"/v1/hooks/{harness}?" in request
    assert "'Connection': 'close'," in request
    assert "'X-Guard-Token': connection.authToken," in request
    assert "'Content-Type': 'application/json'," in request
    assert "body: daemonPayload," in request
    assert "signal: controller?.signal," in request
    assert request.count("'Connection':") == 1
    assert "headers: { 'X-Guard-Token': connection.authToken, 'Connection': 'close' }," in source


@pytest.mark.parametrize("harness", ["pi", "omp"])
def test_frozen_previous_extension_is_not_rewritten_by_transport_fix(harness):
    """Keep migration matching independent of the current transport implementation."""
    previous = build_previous_source_body(harness=harness, display_name=harness)
    assert "'Connection': 'close'" not in previous
