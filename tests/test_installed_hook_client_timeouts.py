"""Installed fallback transport diagnoses timeouts without dispatch retries."""

import urllib.error
from pathlib import Path
from types import SimpleNamespace

import pytest

from ci.native_runtime import installed_hook_client as client


@pytest.mark.parametrize("kind", ("wrapped-timeout", "direct-timeout", "other-error"))
def test_installed_fallback_preserves_errors_and_never_retries(monkeypatch: pytest.MonkeyPatch, kind: str) -> None:
    timeout = TimeoutError("fixture-private-value")
    original = (
        timeout
        if kind == "direct-timeout"
        else urllib.error.URLError(timeout if kind == "wrapped-timeout" else OSError("fixture-private-value"))
    )
    calls = 0

    def fail_once(*_args: object, **_kwargs: object) -> None:
        nonlocal calls
        calls += 1
        raise original

    monkeypatch.setattr(client.urllib.request, "urlopen", fail_once)
    daemon = SimpleNamespace(port=5245, _server=SimpleNamespace(auth_token="fixture-token"))
    expected = urllib.error.URLError if kind == "other-error" else TimeoutError
    with pytest.raises(expected) as caught:
        client.installed_hook_request(
            daemon, Path("fixture-home"), Path("fixture-workspace"), "cursor", "PreToolUse", {}
        )
    assert calls == 1
    if kind == "wrapped-timeout":
        assert caught.value.__cause__ is original
        assert str(caught.value) == "installed hook transport timed out"
    else:
        assert caught.value is original
