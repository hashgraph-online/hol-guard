"""Stable minor discovery through Desktop status and signed update paths."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.cli import update_commands, update_desktop_apply, update_desktop_core


def test_stable_core_update_discovers_new_minor_without_crossing_major() -> None:
    assert (
        update_desktop_core.select_desktop_core_latest(
            "3.24.2", ["3.24.2", "3.25.0", "3.26.0a1", "4.0.0"], include_alpha=False
        )
        == "3.25.0"
    )
    assert (
        update_desktop_core.select_desktop_core_latest("3.24.2", ["3.24.2", "3.25.0a1", "4.0.0"], include_alpha=False)
        == "3.24.2"
    )


@pytest.fixture
def stable_desktop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")
    monkeypatch.setattr(update_desktop_core, "is_frozen_runtime", lambda: True)
    monkeypatch.setattr(update_commands, "_is_frozen_runtime", lambda: True)
    monkeypatch.setattr(update_commands, "_is_desktop_managed_runtime", lambda: True)
    monkeypatch.setattr(update_commands, "_current_version", lambda: "3.24.2")
    monkeypatch.setattr(update_commands, "load_guard_config", lambda _home: SimpleNamespace(update_channel="stable"))
    monkeypatch.setattr(update_desktop_apply, "desktop_core_updates_supported", lambda: True)
    monkeypatch.setattr(
        update_commands,
        "_last_pypi_payload",
        {"releases": {v: [{"yanked": False}] for v in ("3.24.2", "3.25.0", "3.26.0a1", "4.0.0")}},
    )
    monkeypatch.setattr(
        update_commands,
        "_version_check_payload",
        lambda current_version, **_kwargs: {
            "source": "pypi",
            "status": "stale",
            "current_version": current_version,
            "latest_version": "4.0.0",
            "update_available": True,
        },
    )


def test_desktop_status_advertises_stable_minor(stable_desktop: None, tmp_path: Path) -> None:
    _ = stable_desktop
    payload = update_commands.build_guard_update_status_payload(guard_home=tmp_path)
    assert payload["current_version"] == "3.24.2"
    assert payload["latest_version"] == "3.25.0"
    assert payload["release_channel"] == "stable"
    assert payload["update_available"] is True


def test_desktop_update_fetches_and_installs_stable_minor(
    stable_desktop: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _ = stable_desktop
    monkeypatch.setattr(update_desktop_core, "platform_target", lambda: "aarch64-apple-darwin")
    monkeypatch.setattr(update_desktop_core, "desktop_core_root", lambda: tmp_path / "core")
    monkeypatch.setattr(update_desktop_core, "_macos_codesign_ok", lambda _path: True)
    monkeypatch.setattr(update_desktop_core, "_macos_signing_team", lambda _path: "TEAMID")
    binary = b"signed-stable-core"
    manifest = {
        "schema": update_desktop_core.UPDATE_SCHEMA,
        "channel": "stable",
        "version": "3.25.0",
        "sourceCommit": "b" * 40,
        "sourceTag": "v3.25.0",
        "target": "aarch64-apple-darwin",
        "artifact": "hol-guard-core-3.25.0-aarch64-apple-darwin",
        "sha256": update_desktop_core._sha256_hex(binary),
        "size": len(binary),
        "bootstrapSchema": update_desktop_core.BOOTSTRAP_SCHEMA,
        "minimumDesktopVersion": "0.1.0",
        "publishedAt": "2026-10-05T00:00:00Z",
    }
    urls: list[str] = []

    def fetch_bytes(url: str, limit: int) -> bytes:
        _ = limit
        urls.append(url)
        if ".onedir." in url:
            raise update_desktop_core.DesktopCoreUpdateError("desktop_core_asset_missing")
        return json.dumps(manifest).encode() if url.endswith(".json") else binary

    monkeypatch.setattr(
        update_desktop_apply,
        "apply_desktop_core_update",
        lambda **kwargs: update_desktop_core.apply_desktop_core_update(**kwargs, fetch_bytes=fetch_bytes),
    )
    payload, exit_code = update_commands.run_guard_update(
        dry_run=False, include_alpha=False, guard_home=tmp_path / "guard"
    )
    assert exit_code == 0
    assert payload["status"] == "updated"
    assert payload["resulting_version"] == "3.25.0"
    assert payload["changed"] is True
    prefix = "/releases/download/v3.25.0/hol-guard-core-3.25.0-aarch64-apple-darwin"
    assert urls[0].endswith(prefix + ".json")
    assert urls[-1].endswith(prefix)
