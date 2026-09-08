from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import pi_extension_runtime_ownership, pi_extension_source


def _source(tmp_path: Path) -> str:
    return pi_extension_source.managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path / "home",
        settings_path=tmp_path / "settings.json",
        harness="omp",
        display_name="Oh My Pi",
    )


def test_pi_extension_keeps_fallbacks_inside_outer_hook_deadline(tmp_path: Path) -> None:
    source = _source(tmp_path)
    for constant in (
        "const GUARD_TIMEOUT_MS = 4250;",
        "const GUARD_DEADLINE_RESERVE_MS = 250;",
        "const GUARD_DAEMON_TIMEOUT_MS = 3100;",
        "const GUARD_DAEMON_RECOVERY_TIMEOUT_MS = 250;",
        "const GUARD_DAEMON_RETRY_TIMEOUT_MS = 150;",
        "const GUARD_CLI_TIMEOUT_MS = 300;",
    ):
        assert constant in source
    assert "const deadlineAt = Date.now() + GUARD_TIMEOUT_MS - GUARD_DEADLINE_RESERVE_MS" in source
    assert "Math.max(deadlineAt - Date.now(), 1)" in source
    assert "spawnSync" not in source


@pytest.mark.skipif(pi_extension_runtime_ownership.os.name == "nt", reason="POSIX runtime ownership contract")
def test_managed_extension_uses_official_user_install_not_appimage_mount(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    official_cli = home / ".local" / "bin" / "hol-guard"
    official_cli.parent.mkdir(parents=True)
    official_cli.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    official_cli.chmod(0o755)
    transient = "/tmp/.mount_HOL-Guard123/usr/lib/hol-guard-core/hol-guard"
    monkeypatch.setattr(pi_extension_source, "__file__", f"{transient}/pi_extension_source.py")
    monkeypatch.setattr(pi_extension_runtime_ownership.shutil, "which", lambda _command: transient)

    source = _source(tmp_path)

    assert f"const GUARD_CLI_WRAPPER_COMMAND = {json.dumps(str(official_cli))};" in source
    assert f"const GUARD_DAEMON_RECOVERY_COMMAND = {json.dumps(str(official_cli))};" in source
    assert "const GUARD_CLI_WRAPPER_ACCEPTS_JSON_ARGS = false;" in source
    assert "const GUARD_DAEMON_RECOVERY_ACCEPTS_FAILURE_KIND = true;" in source
    assert 'const GUARD_DAEMON_RECOVERY_ARGS = ["daemon", "recover"' in source
    assert ".mount_HOL-Guard123" not in source


@pytest.mark.skipif(pi_extension_runtime_ownership.os.name == "nt", reason="POSIX runtime ownership contract")
def test_managed_extension_prefers_persistent_desktop_runtime_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    desktop_owner = tmp_path / "desktop-core" / "hol-guard"
    desktop_owner.parent.mkdir(parents=True)
    desktop_owner.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    desktop_owner.chmod(0o755)
    monkeypatch.setenv("HOL_GUARD_DESKTOP_RUNTIME_OWNER", str(desktop_owner))

    source = _source(tmp_path)

    assert f"const GUARD_CLI_WRAPPER_COMMAND = {json.dumps(str(desktop_owner))};" in source
    assert f"const GUARD_DAEMON_RECOVERY_COMMAND = {json.dumps(str(desktop_owner))};" in source


@pytest.mark.skipif(pi_extension_runtime_ownership.os.name == "nt", reason="POSIX runtime ownership contract")
def test_managed_extension_maps_versioned_desktop_wrapper_to_stable_launcher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    core_root = tmp_path / "core"
    desktop_owner = core_root / "bundled" / "3.0.63" / "bin" / "hol-guard"
    desktop_owner.parent.mkdir(parents=True)
    desktop_owner.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    desktop_owner.chmod(0o755)
    stable_owner = core_root / "current-hol-guard"
    stable_owner.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    stable_owner.chmod(0o755)
    monkeypatch.setenv("HOL_GUARD_DESKTOP_RUNTIME_OWNER", str(desktop_owner))

    source = _source(tmp_path)

    assert f"const GUARD_CLI_WRAPPER_COMMAND = {json.dumps(str(stable_owner))};" in source
    assert f"const GUARD_DAEMON_RECOVERY_COMMAND = {json.dumps(str(stable_owner))};" in source
    assert str(desktop_owner) not in source


@pytest.mark.skipif(pi_extension_runtime_ownership.os.name == "nt", reason="POSIX runtime ownership contract")
def test_managed_extension_uses_stable_launcher_while_versioned_owner_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    core_root = tmp_path / "core"
    desktop_owner = core_root / "bundled" / "3.0.63" / "bin" / "hol-guard"
    stable_owner = core_root / "current-hol-guard"
    stable_owner.parent.mkdir(parents=True)
    stable_owner.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    stable_owner.chmod(0o755)
    monkeypatch.setenv("HOL_GUARD_DESKTOP_RUNTIME_OWNER", str(desktop_owner))

    source = _source(tmp_path)

    assert f"const GUARD_CLI_WRAPPER_COMMAND = {json.dumps(str(stable_owner))};" in source


@pytest.mark.skipif(pi_extension_runtime_ownership.os.name == "nt", reason="POSIX runtime ownership contract")
def test_managed_extension_rejects_versioned_owner_without_stable_launcher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    official_cli = home / ".local" / "bin" / "hol-guard"
    official_cli.parent.mkdir(parents=True)
    official_cli.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    official_cli.chmod(0o755)
    desktop_owner = tmp_path / "core" / "bundled" / "3.0.63" / "bin" / "hol-guard"
    desktop_owner.parent.mkdir(parents=True)
    desktop_owner.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    desktop_owner.chmod(0o755)
    monkeypatch.setenv("HOL_GUARD_DESKTOP_RUNTIME_OWNER", str(desktop_owner))

    source = _source(tmp_path)

    assert f"const GUARD_CLI_WRAPPER_COMMAND = {json.dumps(str(official_cli))};" in source
    assert str(desktop_owner) not in source


@pytest.mark.skipif(pi_extension_runtime_ownership.os.name == "nt", reason="POSIX runtime ownership contract")
def test_managed_extension_rejects_transient_path_when_official_cli_is_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        pi_extension_runtime_ownership.shutil,
        "which",
        lambda _command: "/tmp/.mount_HOL-Guard123/usr/lib/hol-guard-core/hol-guard",
    )

    source = _source(tmp_path)

    assert 'const GUARD_CLI_WRAPPER_COMMAND = "hol-guard";' in source
    assert 'const GUARD_DAEMON_RECOVERY_COMMAND = "hol-guard";' in source
    assert ".mount_HOL-Guard123" not in source
