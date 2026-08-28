"""Stable signed Core updates for Desktop-managed installs."""

from __future__ import annotations

import importlib.metadata
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from codex_plugin_scanner.guard.cli import update_commands, update_desktop_core
from codex_plugin_scanner.guard.cli.update_commands import build_guard_update_status_payload


def _stable_manifest(*, sha256: str, size: int) -> dict[str, object]:
    return {
        "schema": update_desktop_core.UPDATE_SCHEMA,
        "channel": "stable",
        "version": "3.0.7",
        "sourceCommit": "b" * 40,
        "sourceTag": "v3.0.7",
        "target": "aarch64-apple-darwin",
        "artifact": "hol-guard-core-3.0.7-aarch64-apple-darwin",
        "sha256": sha256,
        "size": size,
        "bootstrapSchema": update_desktop_core.BOOTSTRAP_SCHEMA,
        "minimumDesktopVersion": "0.1.0",
        "publishedAt": "2026-08-27T00:00:00Z",
    }


def test_apply_installs_stable_sidecar_from_stable_tag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_desktop_core, "platform_target", lambda: "aarch64-apple-darwin")
    monkeypatch.setattr(update_desktop_core, "desktop_core_root", lambda: tmp_path / "core")
    monkeypatch.setattr(update_desktop_core, "_macos_codesign_ok", lambda _path: True)
    monkeypatch.setattr(update_desktop_core, "_macos_signing_team", lambda _path: "TEAMID")
    binary = b"signed-stable-core"
    manifest = _stable_manifest(sha256=update_desktop_core._sha256_hex(binary), size=len(binary))
    urls: list[str] = []

    def fetch_bytes(url: str, limit: int) -> bytes:
        _ = limit
        urls.append(url)
        return json.dumps(manifest).encode("utf-8") if url.endswith(".json") else binary

    result = update_desktop_core.apply_desktop_core_update(
        current_version="3.0.0a239",
        target_version="3.0.7",
        include_alpha=False,
        fetch_bytes=fetch_bytes,
    )

    assert result.changed is True
    assert result.version == "3.0.7"
    prefix = "/releases/download/v3.0.7/hol-guard-core-3.0.7-aarch64-apple-darwin"
    assert urls[0].endswith(f"{prefix}.json")
    assert urls[1].endswith(prefix)


@pytest.mark.parametrize("target_version", ["3.0.1a1", "3.0.1b1", "3.0.1rc1"])
def test_stable_channel_rejects_prerelease_targets(
    target_version: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(update_desktop_core, "platform_target", lambda: "aarch64-apple-darwin")
    with pytest.raises(update_desktop_core.DesktopCoreUpdateError) as error:
        update_desktop_core.apply_desktop_core_update(
            current_version="3.0.0",
            target_version=target_version,
            include_alpha=False,
            fetch_bytes=lambda _url, _limit: b"{}",
        )
    assert error.value.reason_code == "desktop_core_channel_unsupported"


def test_pypi_versions_separate_stable_and_alpha() -> None:
    payload = {
        "releases": {
            "3.0.7": [{"yanked": False}],
            "3.0.8a1": [{"yanked": False}],
            "3.0.8b1": [{"yanked": False}],
            "3.0.8rc1": [{"yanked": False}],
            "3.0.6": [{"yanked": True}],
        }
    }
    assert update_desktop_core.pypi_desktop_core_versions(payload, include_alpha=False) == ["3.0.7"]
    assert update_desktop_core.pypi_desktop_core_versions(payload, include_alpha=True) == ["3.0.8a1"]


def test_status_migrates_embedded_alpha_core_to_stable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_desktop_core, "is_frozen_runtime", lambda: True)
    monkeypatch.setattr(update_commands, "_is_frozen_runtime", lambda: True)
    monkeypatch.setattr(update_commands, "load_guard_config", lambda _home: SimpleNamespace(update_channel="stable"))
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")
    monkeypatch.setattr(update_commands.package_version, "__version__", "3.0.0a138")
    monkeypatch.setattr(
        update_commands.importlib.metadata,
        "version",
        MagicMock(side_effect=importlib.metadata.PackageNotFoundError),
    )
    version_check = MagicMock(
        return_value={
            "source": "pypi",
            "status": "stale",
            "current_version": "3.0.0a138",
            "latest_version": "3.0.7",
            "update_available": True,
        }
    )
    monkeypatch.setattr(update_commands, "_version_check_payload", version_check)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_desktop_apply.desktop_core_updates_supported",
        lambda: True,
    )

    payload = build_guard_update_status_payload()

    assert payload["current_version"] == "3.0.0a138"
    assert payload["latest_version"] == "3.0.7"
    assert payload["release_channel"] == "stable"
    assert payload["auto_updatable"] is True
    assert payload["update_available"] is True
    assert payload["blocked_reason"] is None
    assert version_check.call_args.kwargs["include_alpha"] is False


def test_status_supports_current_stable_core(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_desktop_core, "is_frozen_runtime", lambda: True)
    monkeypatch.setattr(update_commands, "_is_frozen_runtime", lambda: True)
    monkeypatch.setattr(update_commands, "_current_version", lambda: "3.0.7")
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_desktop_apply.desktop_core_updates_supported",
        lambda: True,
    )
    monkeypatch.setattr(
        update_commands,
        "_version_check_payload",
        lambda current_version, **_kwargs: {
            "source": "pypi",
            "status": "current",
            "current_version": current_version,
            "latest_version": current_version,
            "update_available": False,
        },
    )

    payload = build_guard_update_status_payload(guard_home=tmp_path)

    assert payload["auto_updatable"] is True
    assert payload["update_available"] is False
    assert payload["blocked_reason"] is None
    assert payload["release_channel"] == "stable"
