"""Carry native Guard Cloud requests over urllib unless a test asks for the native command."""

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


@pytest.fixture(autouse=True)
def _cloud_oauth_refresh_over_urllib(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Send Guard OAuth refresh exchanges through the urllib a test fakes.

    Mark a test ``native_oauth_refresh`` to send them with the native command.
    """

    if request.node.get_closest_marker("native_oauth_refresh") is not None:
        return
    from codex_plugin_scanner.guard.runtime import cloud_bundle_sync
    from tests.support.oauth_refresh_transport import cloud_oauth_refresh_over_urllib

    monkeypatch.setattr(cloud_bundle_sync, "cloud_oauth_refresh", cloud_oauth_refresh_over_urllib)
