"""Signed Core feed updates for frozen Desktop installs."""

from __future__ import annotations

import importlib.metadata
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import MagicMock

import pytest

from codex_plugin_scanner.guard.cli import update_commands, update_desktop_core
from codex_plugin_scanner.guard.cli.update_commands import build_guard_update_status_payload
from codex_plugin_scanner.guard.daemon import manager as daemon_manager
from codex_plugin_scanner.guard.daemon.dashboard_update import (
    build_dashboard_update_runner_command,
    build_dashboard_update_runner_popen_kwargs,
)


def _alpha_manifest(*, sha256: str, size: int, minimum: str = "0.1.0") -> dict[str, object]:
    return {
        "schema": update_desktop_core.UPDATE_SCHEMA,
        "channel": "alpha",
        "version": "3.0.0a200",
        "sourceCommit": "a" * 40,
        "sourceTag": "alpha/v3.0.0a200",
        "target": "aarch64-apple-darwin",
        "artifact": "hol-guard-core-3.0.0a200-aarch64-apple-darwin",
        "sha256": sha256,
        "size": size,
        "bootstrapSchema": update_desktop_core.BOOTSTRAP_SCHEMA,
        "minimumDesktopVersion": minimum,
        "publishedAt": "2026-08-22T00:00:00Z",
    }


def test_executable_is_desktop_core_for_app_bundle_and_managed_sidecar(tmp_path: Path) -> None:
    bundled = tmp_path / "HOL Guard.app" / "Contents" / "MacOS" / "hol-guard"
    bundled.parent.mkdir(parents=True)
    bundled.write_text("core", encoding="utf-8")
    managed = tmp_path / "org.hol.guard.desktop" / "core" / "versions" / "3.0.0a200" / "hol-guard"
    managed.parent.mkdir(parents=True)
    managed.write_text("core", encoding="utf-8")
    sibling_dir = tmp_path / "runtime"
    sibling_dir.mkdir()
    sibling_core = sibling_dir / "hol-guard"
    sibling_desktop = sibling_dir / "hol-guard-desktop"
    sibling_core.write_text("core", encoding="utf-8")
    sibling_desktop.write_text("desktop", encoding="utf-8")

    assert update_desktop_core.executable_is_desktop_core(bundled) is True
    assert update_desktop_core.executable_is_desktop_core(managed) is True
    assert update_desktop_core.executable_is_desktop_core(sibling_core) is True
    assert update_desktop_core.executable_is_desktop_core(tmp_path / "venv" / "bin" / "python") is False


def test_platform_target_only_supports_macos_arm64(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_desktop_core.sys, "platform", "linux")
    monkeypatch.setattr(update_desktop_core.platform, "machine", lambda: "x86_64")
    assert update_desktop_core.platform_target() is None
    monkeypatch.setattr(update_desktop_core.sys, "platform", "win32")
    monkeypatch.setattr(update_desktop_core.platform, "machine", lambda: "amd64")
    assert update_desktop_core.platform_target() is None
    monkeypatch.setattr(update_desktop_core.sys, "platform", "darwin")
    monkeypatch.setattr(update_desktop_core.platform, "machine", lambda: "x86_64")
    assert update_desktop_core.platform_target() is None
    monkeypatch.setattr(update_desktop_core.platform, "machine", lambda: "arm64")
    assert update_desktop_core.platform_target() == "aarch64-apple-darwin"


def test_apply_desktop_core_update_installs_verified_sidecar(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(update_desktop_core, "platform_target", lambda: "aarch64-apple-darwin")
    monkeypatch.setattr(update_desktop_core, "desktop_core_root", lambda: tmp_path / "core")
    monkeypatch.setattr(update_desktop_core, "_macos_codesign_ok", lambda _path: True)
    monkeypatch.setattr(update_desktop_core, "_macos_signing_team", lambda _path: "TEAMID")
    binary = b"signed-core-bytes"
    manifest = _alpha_manifest(sha256=update_desktop_core._sha256_hex(binary), size=len(binary))

    def fetch_bytes(url: str, limit: int) -> bytes:
        _ = limit
        if url.endswith(".json"):
            return json.dumps(manifest).encode("utf-8")
        return binary

    result = update_desktop_core.apply_desktop_core_update(
        current_version="3.0.0a138",
        target_version="3.0.0a200",
        include_alpha=True,
        fetch_bytes=fetch_bytes,
    )

    assert result.changed is True
    assert result.version == "3.0.0a200"
    assert result.executable.is_file()
    pointer = json.loads((tmp_path / "core" / "current.json").read_text(encoding="utf-8"))
    assert pointer["schema"] == update_desktop_core.INSTALL_SCHEMA
    assert pointer["version"] == "3.0.0a200"
    assert pointer["sha256"] == update_desktop_core._sha256_hex(binary)


def test_apply_desktop_core_update_rejects_integrity_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(update_desktop_core, "platform_target", lambda: "aarch64-apple-darwin")
    manifest = _alpha_manifest(sha256="b" * 64, size=4)

    def fetch_bytes(url: str, limit: int) -> bytes:
        _ = limit
        if url.endswith(".json"):
            return json.dumps(manifest).encode("utf-8")
        return b"nope"

    with pytest.raises(update_desktop_core.DesktopCoreUpdateError) as error:
        update_desktop_core.apply_desktop_core_update(
            current_version="3.0.0a138",
            target_version="3.0.0a200",
            include_alpha=True,
            fetch_bytes=fetch_bytes,
        )
    assert error.value.reason_code == "desktop_core_integrity_mismatch"


def test_apply_rejects_missing_minimum_desktop_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(update_desktop_core, "platform_target", lambda: "aarch64-apple-darwin")
    manifest = _alpha_manifest(sha256="a" * 64, size=4)
    del manifest["minimumDesktopVersion"]

    def fetch_bytes(url: str, limit: int) -> bytes:
        _ = limit
        if url.endswith(".json"):
            return json.dumps(manifest).encode("utf-8")
        return b"core"

    with pytest.raises(update_desktop_core.DesktopCoreUpdateError) as error:
        update_desktop_core.apply_desktop_core_update(
            current_version="3.0.0a138",
            target_version="3.0.0a200",
            include_alpha=True,
            fetch_bytes=fetch_bytes,
        )
    assert error.value.reason_code == "desktop_core_manifest_invalid"


def test_apply_rejects_older_desktop_when_version_is_known(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(update_desktop_core, "platform_target", lambda: "aarch64-apple-darwin")
    monkeypatch.setenv("HOL_GUARD_DESKTOP_VERSION", "0.0.1")
    manifest = _alpha_manifest(sha256="a" * 64, size=4)

    def fetch_bytes(url: str, limit: int) -> bytes:
        _ = limit
        if url.endswith(".json"):
            return json.dumps(manifest).encode("utf-8")
        return b"core"

    with pytest.raises(update_desktop_core.DesktopCoreUpdateError) as error:
        update_desktop_core.apply_desktop_core_update(
            current_version="3.0.0a138",
            target_version="3.0.0a200",
            include_alpha=True,
            fetch_bytes=fetch_bytes,
        )
    assert error.value.reason_code == "desktop_core_desktop_too_old"


def test_install_rejects_symlink_version_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(update_desktop_core, "platform_target", lambda: "aarch64-apple-darwin")
    monkeypatch.setattr(update_desktop_core, "_macos_codesign_ok", lambda _path: True)
    monkeypatch.setattr(update_desktop_core, "_macos_signing_team", lambda _path: "TEAMID")
    core_root = tmp_path / "core"
    destination = tmp_path / "elsewhere"
    destination.mkdir()
    version_dir = core_root / "versions" / "3.0.0a200"
    version_dir.parent.mkdir(parents=True)
    version_dir.symlink_to(destination)
    monkeypatch.setattr(update_desktop_core, "desktop_core_root", lambda: core_root)
    binary = b"signed-core-bytes"
    manifest = _alpha_manifest(sha256=update_desktop_core._sha256_hex(binary), size=len(binary))

    def fetch_bytes(url: str, limit: int) -> bytes:
        _ = limit
        if url.endswith(".json"):
            return json.dumps(manifest).encode("utf-8")
        return binary

    with pytest.raises(update_desktop_core.DesktopCoreUpdateError) as error:
        update_desktop_core.apply_desktop_core_update(
            current_version="3.0.0a138",
            target_version="3.0.0a200",
            include_alpha=True,
            fetch_bytes=fetch_bytes,
        )
    assert error.value.reason_code == "desktop_core_path_untrusted"


def test_download_bytes_rejects_untrusted_source() -> None:
    with pytest.raises(update_desktop_core.DesktopCoreUpdateError) as error:
        update_desktop_core._download_bytes(
            "https://example.com/hol-guard-core",
            16,
            network_policy=None,
        )
    assert error.value.reason_code == "desktop_core_source_untrusted"


def test_frozen_runtime_without_desktop_marker_keeps_installer_detection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(update_desktop_core, "is_frozen_runtime", lambda: True)
    monkeypatch.delenv("HOL_GUARD_DESKTOP", raising=False)
    monkeypatch.setattr(update_desktop_core, "executable_is_desktop_core", lambda _path: False)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pip")

    payload = update_commands.build_guard_install_surface_payload()

    assert payload["installer"] == "pip"
    assert cast(dict[str, object], payload["binary_diagnostics"])["path_status"] != "bundled"


def test_frozen_desktop_path_without_env_uses_desktop_installer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(update_desktop_core, "is_frozen_runtime", lambda: True)
    monkeypatch.delenv("HOL_GUARD_DESKTOP", raising=False)
    monkeypatch.setattr(update_desktop_core, "executable_is_desktop_core", lambda _path: True)

    payload = update_commands.build_guard_install_surface_payload()

    assert payload["installer"] == "desktop"
    assert cast(dict[str, object], payload["binary_diagnostics"])["path_status"] == "bundled"


def test_frozen_desktop_status_stays_blocked_on_unsupported_platform(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(update_desktop_core, "is_frozen_runtime", lambda: True)
    monkeypatch.setattr(update_commands, "_is_frozen_runtime", lambda: True)
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")
    monkeypatch.setattr(update_commands.package_version, "__version__", "3.0.0a138")
    monkeypatch.setattr(
        update_commands.importlib.metadata,
        "version",
        MagicMock(side_effect=importlib.metadata.PackageNotFoundError),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_desktop_apply.desktop_core_updates_supported",
        lambda: False,
    )
    monkeypatch.setattr(
        update_commands,
        "_version_check_payload",
        lambda current_version, **_kwargs: {
            "source": "pypi",
            "status": "stale",
            "current_version": current_version,
            "latest_version": "3.0.0a200",
            "update_available": True,
        },
    )

    payload = build_guard_update_status_payload()

    assert payload["installer"] == "desktop"
    assert payload["auto_updatable"] is False
    assert payload["update_available"] is False
    assert "HOL Guard Desktop releases" in str(payload["blocked_reason"])


def test_desktop_cli_update_applies_signed_core_feed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from codex_plugin_scanner.guard.cli.update_desktop_core import DesktopCoreApplyResult

    new_core = tmp_path / "hol-guard"
    new_core.write_text("core", encoding="utf-8")
    monkeypatch.setattr(update_commands, "_is_desktop_managed_runtime", lambda: True)
    monkeypatch.setattr(update_commands, "_current_version", lambda: "3.0.0a138")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_desktop_apply.desktop_core_updates_supported",
        lambda: True,
    )
    monkeypatch.setattr(
        update_commands,
        "_version_check_payload",
        lambda current_version, **_kwargs: {
            "source": "pypi",
            "status": "stale",
            "current_version": current_version,
            "latest_version": "3.0.0a200",
            "update_available": True,
        },
    )
    apply = MagicMock(return_value=DesktopCoreApplyResult(executable=new_core, version="3.0.0a200", changed=True))
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_desktop_apply.apply_desktop_core_update",
        apply,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_desktop_apply.refresh_desktop_core_daemon",
        lambda context, *, executable: ({"status": "restarted", "url": "http://127.0.0.1:1"}, None),
    )
    monkeypatch.setattr(
        update_commands,
        "build_trusted_update_context",
        MagicMock(side_effect=AssertionError("desktop updates must not use pip")),
    )

    payload, exit_code = update_commands.run_guard_update(
        dry_run=False,
        include_alpha=True,
        guard_home=tmp_path / "guard-home",
    )

    assert exit_code == 0
    assert payload["installer"] == "desktop"
    assert payload["status"] == "updated"
    assert payload["resulting_version"] == "3.0.0a200"
    apply.assert_called_once()


def test_desktop_cli_update_fails_when_latest_version_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(update_commands, "_is_desktop_managed_runtime", lambda: True)
    monkeypatch.setattr(update_commands, "_current_version", lambda: "3.0.0a138")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_desktop_apply.desktop_core_updates_supported",
        lambda: True,
    )
    monkeypatch.setattr(
        update_commands,
        "_version_check_payload",
        lambda current_version, **_kwargs: {
            "source": "pypi",
            "status": "unavailable",
            "current_version": current_version,
            "latest_version": None,
            "update_available": None,
        },
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_desktop_apply.apply_desktop_core_update",
        MagicMock(side_effect=AssertionError("must not apply without a target version")),
    )

    payload, exit_code = update_commands.run_guard_update(
        dry_run=False,
        include_alpha=True,
        guard_home=tmp_path / "guard-home",
    )

    assert exit_code == 1
    assert payload["status"] == "failed"
    assert payload["reason_code"] == "desktop_core_version_unavailable"


def test_frozen_runner_command_uses_desktop_dashboard_update(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    command = build_dashboard_update_runner_command(
        guard_home.resolve(),
        daemon_pid=99,
        daemon_port=1234,
        update_token="a" * 64,
        include_alpha=True,
    )
    assert command[1:3] == ["desktop", "dashboard-update"]
    assert "--guard-home" in command
    assert "--alpha" in command
    assert "-c" not in command
    assert "-I" not in command


def test_desktop_dashboard_update_parser_accepts_runner_args(tmp_path: Path) -> None:
    from codex_plugin_scanner.cli import _build_parser

    guard_home = tmp_path / "guard-home"
    parser = _build_parser("hol-guard", program_mode="guard")
    args = parser.parse_args(
        [
            "desktop",
            "dashboard-update",
            "--guard-home",
            str(guard_home),
            "--daemon-pid",
            "99",
            "--daemon-port",
            "1234",
            "--update-token",
            "a" * 64,
            "--alpha",
        ]
    )
    assert args.guard_command == "desktop"
    assert args.desktop_command == "dashboard-update"
    assert str(args.guard_home) == str(guard_home)
    assert args.daemon_pid == 99
    assert args.daemon_port == 1234
    assert args.alpha is True


def test_wait_for_updated_core_binds_spawned_pid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}

    def fake_live(
        _guard_home: Path,
        *,
        require_current_runtime: bool = True,
        expected_pid: int | None = None,
    ) -> str:
        seen["require_current_runtime"] = require_current_runtime
        seen["expected_pid"] = expected_pid
        return "http://127.0.0.1:5410"

    monkeypatch.setattr(daemon_manager, "_live_guard_daemon_url", fake_live)
    url = daemon_manager._wait_for_guard_daemon_url(
        tmp_path,
        timeout=1.0,
        require_current_runtime=False,
        expected_pid=4242,
    )
    assert url == "http://127.0.0.1:5410"
    assert seen["require_current_runtime"] is False
    assert seen["expected_pid"] == 4242


def test_select_desktop_core_latest_stays_on_current_series() -> None:
    selected = update_desktop_core.select_desktop_core_latest(
        "3.0.0a239",
        ["3.1.0a13", "3.1.0a5", "3.0.0a239", "3.0.0a238", "2.2.122"],
    )
    assert selected == "3.0.0a239"
    assert (
        update_desktop_core.select_desktop_core_latest(
            "4.0.0a2",
            ["4.0.0a2", "4.0.0a1", "3.0.0a239"],
        )
        == "4.0.0a2"
    )


def test_select_desktop_core_latest_picks_newer_same_series() -> None:
    selected = update_desktop_core.select_desktop_core_latest(
        "3.0.0a230",
        ["3.1.0a13", "3.0.0a239", "3.0.0a231"],
    )
    assert selected == "3.0.0a239"


def test_desktop_status_does_not_advertise_newer_train(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(update_desktop_core, "is_frozen_runtime", lambda: True)
    monkeypatch.setattr(update_commands, "_is_frozen_runtime", lambda: True)
    monkeypatch.setattr(update_commands, "load_guard_config", lambda _home: SimpleNamespace(update_channel="alpha"))
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")
    monkeypatch.setattr(update_commands.package_version, "__version__", "3.0.0a239")
    monkeypatch.setattr(
        update_commands.importlib.metadata,
        "version",
        MagicMock(side_effect=importlib.metadata.PackageNotFoundError),
    )
    monkeypatch.setattr(
        update_commands,
        "_status_installed_distribution",
        MagicMock(side_effect=AssertionError("frozen Desktop must not probe package metadata")),
    )
    monkeypatch.setattr(
        update_commands,
        "_version_check_payload",
        lambda current_version, **_kwargs: {
            "source": "pypi",
            "status": "stale",
            "current_version": current_version,
            "latest_version": "3.1.0a13",
            "update_available": True,
        },
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_desktop_apply.pypi_desktop_core_versions",
        lambda _payload, *, include_alpha: (
            ["3.1.0a13", "3.1.0a5", "3.0.0a239", "3.0.0a238"] if include_alpha else ["3.0.7"]
        ),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_desktop_apply.desktop_core_updates_supported",
        lambda: True,
    )

    payload = build_guard_update_status_payload()

    assert payload["installer"] == "desktop"
    assert payload["current_version"] == "3.0.0a239"
    assert payload["latest_version"] == "3.0.0a239"
    assert payload["update_available"] is False
    assert payload["auto_updatable"] is True
    assert payload["version_check"]["latest_version"] == "3.0.0a239"
    assert payload["version_check"]["update_available"] is False


def test_desktop_cli_update_does_not_apply_newer_train(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(update_commands, "_is_desktop_managed_runtime", lambda: True)
    monkeypatch.setattr(update_commands, "_current_version", lambda: "3.0.0a239")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_desktop_apply.desktop_core_updates_supported",
        lambda: True,
    )
    monkeypatch.setattr(
        update_commands,
        "_version_check_payload",
        lambda current_version, **_kwargs: {
            "source": "pypi",
            "status": "stale",
            "current_version": current_version,
            "latest_version": "3.1.0a13",
            "update_available": True,
        },
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_desktop_apply.pypi_desktop_core_versions",
        lambda _payload, *, include_alpha: ["3.1.0a13", "3.0.0a239"] if include_alpha else ["3.0.7"],
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_desktop_apply.apply_desktop_core_update",
        MagicMock(side_effect=AssertionError("must not apply a newer 3.Y train")),
    )

    payload, exit_code = update_commands.run_guard_update(
        dry_run=False,
        include_alpha=True,
        guard_home=tmp_path / "guard-home",
    )

    assert exit_code == 0
    assert payload["status"] == "current"
    assert payload["resulting_version"] == "3.0.0a239"
    assert payload["changed"] is False
    assert payload["version_check"]["latest_version"] == "3.0.0a239"


def test_refine_keeps_current_when_older_same_series_is_listed() -> None:
    from codex_plugin_scanner.guard.cli.update_desktop_apply import refine_desktop_version_check

    refined = refine_desktop_version_check(
        "3.0.0a239",
        {
            "source": "pypi",
            "status": "stale",
            "current_version": "3.0.0a239",
            "latest_version": "3.1.0a13",
            "update_available": True,
        },
        candidates=["3.1.0a13", "3.0.0a238"],
        include_alpha=True,
    )
    assert refined["latest_version"] == "3.0.0a239"
    assert refined["update_available"] is False
    assert refined["status"] == "current"


def test_refine_preserves_unavailable_and_managed_sources() -> None:
    from codex_plugin_scanner.guard.cli.update_desktop_apply import refine_desktop_version_check

    unavailable = {
        "source": "pypi",
        "status": "unavailable",
        "current_version": "3.0.0a239",
        "latest_version": None,
        "update_available": None,
    }
    managed = {
        "source": "managed_index",
        "status": "stale",
        "current_version": "3.0.0a239",
        "latest_version": "3.0.0a240",
        "update_available": True,
    }
    assert (
        refine_desktop_version_check(
            "3.0.0a239",
            unavailable,
            candidates=["3.0.0a239"],
            include_alpha=True,
        )
        == unavailable
    )
    assert (
        refine_desktop_version_check(
            "3.0.0a239",
            managed,
            candidates=["3.1.0a13"],
            include_alpha=True,
        )
        == managed
    )


def test_desktop_apply_download_failure_explains_missing_core() -> None:
    from codex_plugin_scanner.guard.cli.update_desktop_apply import desktop_core_apply_failure_message

    message = desktop_core_apply_failure_message("desktop_core_download_failed")
    assert "not available for Desktop" in message
    assert "stays in place" in message


def test_dashboard_runner_and_daemon_env_preserve_desktop_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.daemon import dashboard_update as dashboard_update_module

    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")
    monkeypatch.setenv("HOL_GUARD_DESKTOP_VERSION", "0.2.0")
    popen_kwargs = build_dashboard_update_runner_popen_kwargs(tmp_path / "guard-home")
    runner_env = popen_kwargs["env"]
    popen_kwargs["log_handle"].close()
    assert runner_env["HOL_GUARD_DESKTOP_VERSION"] == "0.2.0"
    assert "HOL_GUARD_DESKTOP_VERSION" in dashboard_update_module._DASHBOARD_UPDATE_RUNNER_ENV_KEYS
    assert "HOL_GUARD_DESKTOP_VERSION" in daemon_manager._GUARD_DAEMON_ENV_KEYS
