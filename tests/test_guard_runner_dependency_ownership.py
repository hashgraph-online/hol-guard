"""The established runner namespace remains the live owner of runtime seams."""

from __future__ import annotations

import io
import urllib.error
import urllib.request
from email.message import Message
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.runtime.runner import (
    GuardSyncEndpointUntrustedError,
    GuardSyncNotConfiguredError,
    _get_default_detector_registry,
    _resolve_guard_sync_auth_context,
    _urlopen_json_with_timeout_retry,
)
from codex_plugin_scanner.guard.store import GuardStore


def test_imported_detector_getter_tracks_replaced_factory_and_shared_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def first_factory() -> tuple[()]:
        calls.append("first")
        return ()

    def second_factory() -> tuple[()]:
        calls.append("second")
        return ()

    monkeypatch.setattr(runner, "_DEFAULT_DETECTOR_REGISTRY", None)
    monkeypatch.setattr(runner, "register_default_detectors", first_factory)
    first = _get_default_detector_registry()
    assert _get_default_detector_registry() is first
    monkeypatch.setattr(runner, "register_default_detectors", second_factory)
    second = _get_default_detector_registry()
    assert second is not first
    assert (second_factory, second) == runner._DEFAULT_DETECTOR_REGISTRY
    assert _get_default_detector_registry() is second
    assert calls == ["first", "second"]


def test_imported_auth_resolver_reads_current_override_and_preserves_endpoint_refusal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    override: dict[str, object] = {"sync_url": "https://hol.org/api/guard/sync", "access_token": "fixture-token"}
    monkeypatch.setattr(runner, "_test_sync_auth_context_override", override)
    resolved = _resolve_guard_sync_auth_context(store)
    assert resolved == override
    assert resolved is not override
    monkeypatch.setattr(
        runner, "_test_sync_auth_context_override", {**override, "sync_url": "http://untrusted.invalid"}
    )
    with pytest.raises(GuardSyncEndpointUntrustedError) as caught:
        _resolve_guard_sync_auth_context(store)
    assert isinstance(caught.value, GuardSyncNotConfiguredError)
    assert runner.GuardSyncEndpointUntrustedError is GuardSyncEndpointUntrustedError


@pytest.mark.parametrize("retry_limit", [0, 1])
def test_http_retry_reads_live_transport_and_limit_after_first_failure(
    monkeypatch: pytest.MonkeyPatch, retry_limit: int
) -> None:
    request = urllib.request.Request("https://hol.org/api/guard/sync")
    calls: list[tuple[str, int]] = []
    sleeps: list[float] = []
    failure = urllib.error.HTTPError(request.full_url, 503, "fixture unavailable", Message(), io.BytesIO(b"{}"))

    def replacement_transport(_request: urllib.request.Request, *, timeout: int) -> io.BytesIO:
        assert _request is request
        calls.append(("replacement", timeout))
        return io.BytesIO(b'{"source":"replacement"}')

    def first_transport(_request: urllib.request.Request, *, timeout: int) -> io.BytesIO:
        assert _request is request
        calls.append(("first", timeout))
        monkeypatch.setattr(runner, "managed_urlopen", replacement_transport)
        monkeypatch.setattr(runner, "_SYNC_RETRYABLE_GATEWAY_MAX_ATTEMPTS", retry_limit)
        raise failure

    monkeypatch.setattr(runner, "managed_urlopen", first_transport)
    monkeypatch.setattr(runner, "_request_for_gateway_retry", lambda current: current)
    monkeypatch.setattr(runner.time, "sleep", sleeps.append)
    if retry_limit == 0:
        with pytest.raises(urllib.error.HTTPError) as caught:
            _urlopen_json_with_timeout_retry(request=request, timeout_seconds=3, retry_timeout_seconds=7)
        assert caught.value is failure
        assert calls == [("first", 3)]
        assert sleeps == []
    else:
        result = _urlopen_json_with_timeout_retry(request=request, timeout_seconds=3, retry_timeout_seconds=7)
        assert result == {"source": "replacement"}
        assert calls == [("first", 3), ("replacement", 3)]
        assert len(sleeps) == 1
