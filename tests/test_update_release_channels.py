"""Release-channel selection regressions for Guard updates."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.cli import update_commands


def test_alpha_channel_selects_newer_stable_release(monkeypatch: pytest.MonkeyPatch) -> None:
    reserved_calls: list[str | None] = []
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "3.0.20")
    monkeypatch.setattr(
        update_commands,
        "_newest_reserved_alpha_version",
        lambda *, latest_pypi: reserved_calls.append(latest_pypi) or "3.0.1a3",
    )
    monkeypatch.setattr(
        update_commands,
        "_last_pypi_payload",
        {
            "releases": {
                "3.0.1a2": [{"yanked": False}],
                "3.0.20": [{"yanked": False}],
            }
        },
    )

    assert update_commands._latest_alpha_version_from_pypi("3.0.11") == "3.0.20"
    payload = update_commands._version_check_payload("3.0.11", include_alpha=True)

    assert payload["release_channel"] == "alpha"
    assert payload["status"] == "stale"
    assert payload["latest_version"] == "3.0.20"
    assert payload["update_available"] is True
    assert payload["reserved_alpha_version"] == "3.0.1a3"
    assert reserved_calls == ["3.0.1a2"]


def test_stable_python_fallback_excludes_prereleases(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "3.0.20")
    monkeypatch.setattr(update_commands, "_runtime_python_version", lambda: "3.12.0")
    monkeypatch.setattr(
        update_commands,
        "_last_pypi_payload",
        {
            "releases": {
                "3.0.18": [{"yanked": False, "requires_python": ">=3.10"}],
                "3.0.19rc1": [{"yanked": False, "requires_python": ">=3.10"}],
                "3.0.20": [{"yanked": False, "requires_python": ">=3.13"}],
            }
        },
    )

    payload = update_commands._version_check_payload("3.0.11")

    assert payload["status"] == "stale"
    assert payload["latest_version"] == "3.0.18"
    assert payload["pypi_latest_version"] == "3.0.20"
    assert payload["pypi_latest_python_incompatible"] is True
