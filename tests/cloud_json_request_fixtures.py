"""Carry native Guard Cloud JSON requests over urllib unless a test asks for the native command."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _cloud_json_request_over_urllib(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Send native Guard Cloud requests through the urllib a test fakes.

    Mark a test ``native_cloud_json_request`` to send them with the native command.
    """

    if request.node.get_closest_marker("native_cloud_json_request") is not None:
        return
    from codex_plugin_scanner.guard.runtime import cloud_bundle_sync
    from tests.support.cloud_json_request_transport import cloud_json_request_over_urllib

    monkeypatch.setattr(cloud_bundle_sync, "cloud_json_request", cloud_json_request_over_urllib)
