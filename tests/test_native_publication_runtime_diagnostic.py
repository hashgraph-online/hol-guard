"""Runtime selection timing observes exactly the existing status call."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_runtime
from scripts import native_publication_diagnostic as diagnostic


@pytest.mark.parametrize("injected", [False, True])
def test_runtime_observation_preserves_result_and_provider_restoration(
    monkeypatch: pytest.MonkeyPatch, injected: bool
) -> None:
    result = object()
    calls: list[int] = []

    def status() -> object:
        calls.append(1)
        return result

    original = status if injected else None
    publisher = SimpleNamespace(_client_request=None, _status_provider=original)
    monkeypatch.setattr(native_runtime, "native_runtime_status", status)
    ticks = iter([10.0, 10.032])
    monkeypatch.setattr(diagnostic, "_phase_clock", lambda: next(ticks))
    with diagnostic.observe_publication(publisher) as observation:
        assert calls == []
        assert publisher._status_provider() is result
        assert calls == [1]
        description = observation.readiness.describe()
        assert "preparation_runtime=returned; preparation_runtime_calls=1/1" in description
        assert "preparation_runtime_elapsed_ms=32; preparation_runtime_max_ms=32" in description
        assert "private" not in description
    assert publisher._status_provider is original and calls == [1]


def test_runtime_observation_preserves_failure_and_resolves_current_default(monkeypatch: pytest.MonkeyPatch) -> None:
    failure = RuntimeError("private-runtime-diagnostic-canary")
    publisher = SimpleNamespace(_client_request=None, _status_provider=None)
    calls: list[int] = []

    def fail() -> object:
        calls.append(1)
        raise failure

    with diagnostic.observe_publication(publisher) as observation:
        monkeypatch.setattr(native_runtime, "native_runtime_status", fail)
        with pytest.raises(RuntimeError) as caught:
            publisher._status_provider()
        assert caught.value is failure
        description = observation.readiness.describe()
        assert "preparation_runtime=raised; preparation_runtime_calls=1/1" in description
        assert "private" not in description and "canary" not in description
    assert publisher._status_provider is None and calls == [1]
