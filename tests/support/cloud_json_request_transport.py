"""Carry native Guard Cloud requests over urllib in unit tests.

The native ``cloud-event-sync`` command sends the command queue, Cloud Review
and enrollment requests itself, so a test that fakes
``_guard_sync_request`` or ``_urlopen_json_with_timeout_retry`` in
``tests.support.cloud_sync_transport`` would otherwise never see them. This
double sends each request through those functions, which the tests fake.

The native request is tested in
``rust/crates/guard-runtime/src/cloud_json_request_tests.rs``; mark a test
``native_cloud_json_request`` to run the real command.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

import pytest


def cloud_json_request_via(transport: Any) -> Callable[..., dict[str, object]]:
    """Return a native-request double that sends through ``transport``'s request functions."""

    def send(
        auth_context: Mapping[str, object],
        *,
        url: str,
        body: bytes | None,
        timeout_seconds: float,
        retry_timeout_seconds: float,
    ) -> dict[str, object]:
        request = transport._guard_sync_request(
            auth_context,
            request_url=url,
            method="GET" if body is None else "POST",
            data=body,
            extra_headers=None,
        )
        return transport._urlopen_json_with_timeout_retry(
            request=request,
            timeout_seconds=timeout_seconds,
            retry_timeout_seconds=retry_timeout_seconds,
        )

    return send


def use_runner_transport(monkeypatch: pytest.MonkeyPatch, runner: Any) -> None:
    """Send native Guard Cloud requests through a fake transport a test passes in."""

    from codex_plugin_scanner.guard.runtime import cloud_bundle_sync

    monkeypatch.setattr(cloud_bundle_sync, "cloud_json_request", cloud_json_request_via(runner))


def cloud_json_request_over_urllib(
    auth_context: Mapping[str, object],
    *,
    url: str,
    body: bytes | None,
    timeout_seconds: float,
    retry_timeout_seconds: float,
) -> dict[str, object]:
    """Send one request the way the Python runner did before the native command."""

    from tests.support import cloud_sync_transport

    return cloud_json_request_via(cloud_sync_transport)(
        auth_context,
        url=url,
        body=body,
        timeout_seconds=timeout_seconds,
        retry_timeout_seconds=retry_timeout_seconds,
    )
