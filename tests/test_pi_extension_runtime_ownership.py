from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import extension_runtime
from codex_plugin_scanner.guard.hook_execution_environment import _DEFAULT_EQUIVALENT_PAGER
from tests.pi_extension_support import managed_extension_source


def _source(tmp_path: Path) -> str:
    return managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path / "home",
        settings_path=tmp_path / "settings.json",
        harness="omp",
        display_name="Oh My Pi",
    )


def test_pi_extension_keeps_fallbacks_inside_outer_hook_deadline(tmp_path: Path) -> None:
    source = _source(tmp_path)
    assert "guard_execution_environment" in source
    assert "home: typeof process.env.HOME" in source
    assert "['1', 'true', 'yes', 'on']" in source
    pager_rule = '/^(?:cat|less(?: -[ABCEFGIJKLMNQRSUVWXacdefgimnqrsuw~]+)*|sh -c "head -n 10000 [|] cat")?$/'
    assert f"{pager_rule}.test(process.env.GIT_PAGER)" in source
    assert f"{pager_rule}.test(process.env.PAGER)" in source
    assert pager_rule == f"/^{_DEFAULT_EQUIVALENT_PAGER.pattern}$/"
    assert "let payloadToSend = {" in source
    for constant in (
        "const GUARD_TIMEOUT_MS = 4250;",
        "const GUARD_DEADLINE_RESERVE_MS = 250;",
        "const GUARD_DAEMON_TIMEOUT_MS = 3100;",
        "const GUARD_DAEMON_RECOVERY_TIMEOUT_MS = 250;",
        "const GUARD_DAEMON_RETRY_TIMEOUT_MS = 150;",
        "const GUARD_CLI_TIMEOUT_MS = 300;",
    ):
        assert constant in source
    assert (
        "const deadlineAt = options?.deadlineAt ?? Date.now() + GUARD_TIMEOUT_MS - GUARD_DEADLINE_RESERVE_MS" in source
    )
    assert "Math.max(deadlineAt - Date.now(), 1)" in source
    assert "spawnSync" not in source


@pytest.mark.skipif(os.name == "nt", reason="POSIX runtime ownership contract")
def test_managed_extension_uses_official_user_install_not_appimage_mount(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    official_cli = home / ".local" / "bin" / "hol-guard"
    official_cli.parent.mkdir(parents=True)
    official_cli.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    official_cli.chmod(0o755)
    transient = "/tmp/.mount_HOL-Guard123/usr/lib/hol-guard-core/hol-guard"
    monkeypatch.setattr(extension_runtime, "installing_runtime_cli_candidates", lambda: [transient])

    source = _source(tmp_path)

    assert f"const GUARD_CLI_WRAPPER_COMMAND = {json.dumps(str(official_cli))};" in source
    assert f"const GUARD_DAEMON_RECOVERY_COMMAND = {json.dumps(str(official_cli))};" in source
    assert "const GUARD_CLI_WRAPPER_ACCEPTS_JSON_ARGS = false;" in source
    assert "const GUARD_DAEMON_RECOVERY_ACCEPTS_FAILURE_KIND = true;" in source
    assert 'const GUARD_DAEMON_RECOVERY_ARGS = ["daemon", "recover"' in source
    assert ".mount_HOL-Guard123" not in source


@pytest.mark.skipif(os.name == "nt", reason="POSIX runtime ownership contract")
def test_managed_extension_prefers_durable_desktop_shim_over_path_pipx(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    official_cli = home / ".local" / "bin" / "hol-guard"
    official_cli.parent.mkdir(parents=True)
    official_cli.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    official_cli.chmod(0o755)
    desktop_shim = home / ".local" / "share" / "org.hol.guard.desktop" / "core" / "current-hol-guard"
    desktop_shim.parent.mkdir(parents=True)
    desktop_shim.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    desktop_shim.chmod(0o755)
    monkeypatch.delenv("HOL_GUARD_DESKTOP_RUNTIME_OWNER", raising=False)
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setattr(extension_runtime, "installing_runtime_cli_candidates", lambda: [str(official_cli)])

    source = _source(tmp_path)

    assert f"const GUARD_CLI_WRAPPER_COMMAND = {json.dumps(str(desktop_shim))};" in source
    assert f"const GUARD_DAEMON_RECOVERY_COMMAND = {json.dumps(str(desktop_shim))};" in source
    assert str(official_cli) not in source


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS Desktop support directory")
def test_managed_extension_prefers_macos_desktop_support_shim_over_path_pipx(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    official_cli = home / ".local" / "bin" / "hol-guard"
    official_cli.parent.mkdir(parents=True)
    official_cli.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    official_cli.chmod(0o755)
    desktop_shim = home / "Library" / "Application Support" / "org.hol.guard.desktop" / "core" / "current-hol-guard"
    desktop_shim.parent.mkdir(parents=True)
    desktop_shim.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    desktop_shim.chmod(0o755)
    monkeypatch.delenv("HOL_GUARD_DESKTOP_RUNTIME_OWNER", raising=False)
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setattr(extension_runtime, "installing_runtime_cli_candidates", lambda: [str(official_cli)])

    source = _source(tmp_path)

    assert f"const GUARD_CLI_WRAPPER_COMMAND = {json.dumps(str(desktop_shim))};" in source
    assert f"const GUARD_DAEMON_RECOVERY_COMMAND = {json.dumps(str(desktop_shim))};" in source
    assert str(official_cli) not in source


@pytest.mark.skipif(os.name == "nt", reason="POSIX runtime ownership contract")
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


@pytest.mark.skipif(os.name == "nt", reason="POSIX runtime ownership contract")
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


@pytest.mark.skipif(os.name == "nt", reason="POSIX runtime ownership contract")
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


@pytest.mark.skipif(os.name == "nt", reason="POSIX runtime ownership contract")
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


@pytest.mark.skipif(os.name == "nt", reason="POSIX runtime ownership contract")
def test_managed_extension_rejects_transient_path_when_official_cli_is_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        extension_runtime,
        "installing_runtime_cli_candidates",
        lambda: ["/tmp/.mount_HOL-Guard123/usr/lib/hol-guard-core/hol-guard"],
    )

    source = _source(tmp_path)

    assert 'const GUARD_CLI_WRAPPER_COMMAND = "hol-guard";' in source
    assert 'const GUARD_DAEMON_RECOVERY_COMMAND = "hol-guard";' in source
    assert ".mount_HOL-Guard123" not in source


def _executable(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


@pytest.mark.skipif(os.name == "nt", reason="POSIX runtime ownership contract")
def test_managed_extension_runs_the_installing_runtime_cli_not_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime_scripts = tmp_path / "venv" / "bin"
    runtime_cli = _executable(runtime_scripts / "hol-guard")
    path_cli = _executable(tmp_path / "other-install" / "bin" / "hol-guard")
    monkeypatch.delenv("HOL_GUARD_DESKTOP_RUNTIME_OWNER", raising=False)
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setenv("PATH", str(path_cli.parent))
    monkeypatch.setattr(extension_runtime.sys, "frozen", False, raising=False)
    monkeypatch.setattr(extension_runtime.site, "ENABLE_USER_SITE", False)
    monkeypatch.setattr(extension_runtime.sysconfig, "get_path", lambda name, *_args: str(runtime_scripts))

    source = _source(tmp_path)

    assert f"const GUARD_CLI_WRAPPER_COMMAND = {json.dumps(str(runtime_cli))};" in source
    assert f"const GUARD_DAEMON_RECOVERY_COMMAND = {json.dumps(str(runtime_cli))};" in source
    assert str(path_cli) not in source


@pytest.mark.skipif(os.name == "nt", reason="POSIX runtime ownership contract")
def test_managed_extension_falls_back_to_the_bare_name_without_a_runtime_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path_cli = _executable(tmp_path / "other-install" / "bin" / "hol-guard")
    monkeypatch.delenv("HOL_GUARD_DESKTOP_RUNTIME_OWNER", raising=False)
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setenv("PATH", str(path_cli.parent))
    monkeypatch.setattr(extension_runtime.sys, "frozen", False, raising=False)
    monkeypatch.setattr(extension_runtime.site, "ENABLE_USER_SITE", False)
    monkeypatch.setattr(extension_runtime.sysconfig, "get_path", lambda name, *_args: str(tmp_path / "empty"))

    source = _source(tmp_path)

    assert 'const GUARD_CLI_WRAPPER_COMMAND = "hol-guard";' in source
    assert str(path_cli) not in source


def test_frozen_runtime_owns_the_extension_through_its_own_executable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(extension_runtime.sys, "frozen", True, raising=False)
    monkeypatch.setattr(extension_runtime.sys, "executable", "/opt/guard/hol-guard")

    assert extension_runtime.installing_runtime_cli_candidates() == ["/opt/guard/hol-guard"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX script names")
def test_user_install_prefers_its_own_scripts_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    user_site = Path(extension_runtime.__file__).resolve().parent
    monkeypatch.setattr(extension_runtime.sys, "frozen", False, raising=False)
    monkeypatch.setattr(extension_runtime.site, "ENABLE_USER_SITE", True)
    monkeypatch.setattr(extension_runtime.site, "getusersitepackages", lambda: str(user_site))
    monkeypatch.setattr(
        extension_runtime.sysconfig,
        "get_path",
        lambda name, scheme=None: str(tmp_path / ("user-bin" if scheme else "global-bin")),
    )

    assert extension_runtime.installing_runtime_cli_candidates() == [
        str(tmp_path / "user-bin" / "hol-guard"),
        str(tmp_path / "global-bin" / "hol-guard"),
    ]


def test_windows_sink_uses_the_profile_temp_and_stays_off_without_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard import windows_paths

    monkeypatch.setattr(windows_paths, "trusted_windows_local_temp", lambda: tmp_path / "Temp")
    facts = extension_runtime._windows_facts("nt")
    assert facts is not None
    assert facts["request_root"] == str(tmp_path / "Temp")
    sink = facts["sink_command"]
    assert isinstance(sink, list)
    assert sink[1:3] == ["-I", "-c"]
    assert sink[-1] == "guard"

    def unavailable() -> Path:
        raise OSError("no profile")

    monkeypatch.setattr(windows_paths, "trusted_windows_local_temp", unavailable)
    facts = extension_runtime._windows_facts("nt")
    assert facts is not None
    assert (facts["sink_command"], facts["request_root"]) == ([], "")
    if os.name != "nt":
        assert extension_runtime._windows_facts() is None
        source = _source(tmp_path)
        assert "const GUARD_CONTAINED_SINK_COMMAND: string[] = [];\n" in source
        assert 'const GUARD_CONTAINED_REQUEST_ROOT = "";\n' in source
