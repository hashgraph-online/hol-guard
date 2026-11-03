"""The dashboard's plugin update routes answer from the native runtime and never cache."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon import plugin_updates_http
from codex_plugin_scanner.guard.plugin_telemetry.report import PluginTelemetryError

_NO_STORE = {"Cache-Control": "no-store, max-age=0"}


def _handler(answers: list[tuple[int, object, object]]) -> SimpleNamespace:
    handler = SimpleNamespace(server=SimpleNamespace(store=SimpleNamespace(guard_home="/tmp/guard-home")))
    handler._write_json = lambda payload, *, status=200, extra_headers=None: answers.append(
        (status, payload, extra_headers)
    )
    return handler


def test_read_returns_the_native_comparison(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[Path] = []
    result = {"updates": [{"slug": "acme/deploy-kit", "latestVersion": "0.4.0"}], "dismissed": 1}
    monkeypatch.setattr(plugin_updates_http, "check_updates", lambda home: (asked.append(home), result)[1])
    answers: list[tuple[int, object, object]] = []

    plugin_updates_http.handle_plugin_updates_read(_handler(answers))

    assert asked == [Path("/tmp/guard-home")]
    assert answers == [(200, result, _NO_STORE)]


def test_read_reports_an_unavailable_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(_home: Path) -> dict[str, object]:
        raise PluginTelemetryError("This command needs a newer Guard native runtime.")

    monkeypatch.setattr(plugin_updates_http, "check_updates", fail)
    answers: list[tuple[int, object, object]] = []

    plugin_updates_http.handle_plugin_updates_read(_handler(answers))

    assert answers == [
        (
            503,
            {
                "error": "plugin_updates_unavailable",
                "message": "This command needs a newer Guard native runtime.",
            },
            _NO_STORE,
        )
    ]


def test_dismiss_passes_the_slug_and_version(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[tuple[Path, str, str]] = []
    monkeypatch.setattr(
        plugin_updates_http,
        "dismiss_update",
        lambda home, slug, version: (asked.append((home, slug, version)), {"dismissed": True})[1],
    )
    answers: list[tuple[int, object, object]] = []

    plugin_updates_http.handle_plugin_updates_dismiss(
        _handler(answers), {"slug": " acme/deploy-kit ", "version": "0.4.0"}
    )

    assert asked == [(Path("/tmp/guard-home"), "acme/deploy-kit", "0.4.0")]
    assert answers == [(200, {"dismissed": True}, _NO_STORE)]


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"slug": "acme/deploy-kit"},
        {"slug": "", "version": "0.4.0"},
        {"slug": "acme/deploy-kit", "version": 4},
        {"slug": "a" * 257, "version": "0.4.0"},
        {"slug": "é" * 129, "version": "0.4.0"},
        {"slug": "acme/deploy-kit", "version": "-1.0"},
        {"slug": "acme/deploy-kit", "version": "1.0 beta"},
        {"slug": "acme/deploy-kit", "version": "1" * 65},
    ],
)
def test_dismiss_rejects_a_malformed_request(monkeypatch: pytest.MonkeyPatch, payload: dict[str, object]) -> None:
    called: list[object] = []
    monkeypatch.setattr(plugin_updates_http, "dismiss_update", lambda *args: called.append(args))
    answers: list[tuple[int, object, object]] = []

    plugin_updates_http.handle_plugin_updates_dismiss(_handler(answers), payload)

    assert called == []
    assert answers == [
        (
            400,
            {"error": "invalid_plugin_update", "message": "Name the listing slug and the version to dismiss."},
            _NO_STORE,
        )
    ]
