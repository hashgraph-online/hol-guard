from __future__ import annotations

import json
import shlex
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import codex_hook_runtime_trust, frozen_codex_runtime
from codex_plugin_scanner.guard import daemon as daemon_api
from codex_plugin_scanner.guard.adapters import codex as codex_adapter
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter
from codex_plugin_scanner.guard.daemon import manager as daemon_manager
from codex_plugin_scanner.guard.frozen_runtime_commands import (
    frozen_daemon_recovery_command,
    frozen_daemon_recovery_worker_command,
)


@pytest.fixture
def frozen_codex_contract() -> Iterator[None]:
    original_local = codex_adapter._local_hook_command_parts_for_home_mode
    original_daemon = codex_adapter._daemon_start_command
    original_hook = codex_adapter._hook_command_parts_for_home_mode
    original_paths = codex_adapter._hook_packaged_file_paths
    original_validator = codex_hook_runtime_trust.validate_codex_hook_launch
    had_marker = hasattr(codex_adapter, "_HOL_GUARD_FROZEN_CODEX_RUNTIME")
    marker_value = getattr(codex_adapter, "_HOL_GUARD_FROZEN_CODEX_RUNTIME", None)
    try:
        assert frozen_codex_runtime.install_frozen_codex_runtime(force=True) is True
        yield
    finally:
        codex_adapter._local_hook_command_parts_for_home_mode = original_local
        codex_adapter._daemon_start_command = original_daemon
        codex_adapter._hook_command_parts_for_home_mode = original_hook
        codex_adapter._hook_packaged_file_paths = original_paths
        codex_hook_runtime_trust.validate_codex_hook_launch = original_validator
        if had_marker:
            codex_adapter._HOL_GUARD_FROZEN_CODEX_RUNTIME = marker_value
        elif hasattr(codex_adapter, "_HOL_GUARD_FROZEN_CODEX_RUNTIME"):
            delattr(codex_adapter, "_HOL_GUARD_FROZEN_CODEX_RUNTIME")


def _context(tmp_path: Path) -> HarnessContext:
    home_dir = tmp_path / "home"
    workspace = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    home_dir.mkdir()
    workspace.mkdir()
    guard_home.mkdir(mode=0o700)
    return HarnessContext(
        home_dir=home_dir,
        workspace_dir=workspace,
        guard_home=guard_home,
        home_override_explicit=True,
        workspace_override_explicit=True,
    )


def test_source_runtime_does_not_install_frozen_contract() -> None:
    if frozen_codex_runtime.is_frozen_guard_runtime():
        pytest.skip("source-runtime assertion is not meaningful from a frozen test executable")
    assert frozen_codex_runtime.install_frozen_codex_runtime() is False


def test_frozen_recovery_command_schedules_one_detached_worker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "home"
    guard_home.mkdir()
    home_dir.mkdir()
    scheduled: list[tuple[Path, Path, str, Path]] = []

    def schedule(
        requested_guard_home: Path,
        *,
        home_dir: Path,
        failure_kind: str,
        executable: Path,
    ) -> None:
        scheduled.append((requested_guard_home, home_dir, failure_kind, executable))

    monkeypatch.setattr(daemon_api, "schedule_guard_daemon_recovery", schedule)
    monkeypatch.setenv("HOL_GUARD_HOOK_FAILURE_KIND", "transport-failure")
    command = frozen_daemon_recovery_command(
        guard_home,
        home_dir,
        executable=sys.executable,
    )

    assert frozen_codex_runtime.run_frozen_internal_command(command) == 0
    assert scheduled == [
        (
            guard_home,
            home_dir,
            "transport-failure",
            Path(sys.executable).expanduser().resolve(strict=True),
        )
    ]


def test_frozen_recovery_worker_releases_its_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "home"
    guard_home.mkdir()
    home_dir.mkdir()
    recovered: list[tuple[Path, Path, str]] = []
    cleared: list[tuple[Path, str]] = []
    monkeypatch.setattr(
        daemon_manager,
        "recover_guard_daemon_after_hook_failure",
        lambda requested_guard_home, *, home_dir, failure_kind, **_kwargs: recovered.append(
            (requested_guard_home, home_dir, failure_kind)
        ),
    )
    monkeypatch.setattr(
        daemon_manager,
        "clear_guard_daemon_recovery_reservation",
        lambda requested_guard_home, *, token: cleared.append((requested_guard_home, token)) or True,
    )
    command = frozen_daemon_recovery_worker_command(
        guard_home,
        home_dir,
        "overload",
        "recovery-token",
        executable=sys.executable,
    )

    assert frozen_codex_runtime.run_frozen_internal_command(command) == 0
    assert recovered == [(guard_home, home_dir, "overload")]
    assert cleared == [(guard_home, "recovery-token")]


def test_frozen_codex_contract_binds_commands_and_roles_to_one_executable(
    tmp_path: Path,
    frozen_codex_contract: None,
) -> None:
    context = _context(tmp_path)

    bridge_argv = codex_adapter._hook_command_parts(context)
    bridge_config = json.loads(bridge_argv[2])
    fallback_argv = bridge_config["fallback_command"]
    daemon_argv = bridge_config["start_command"]
    package_paths = codex_adapter._hook_packaged_file_paths()
    invocation = str(Path(sys.executable).expanduser().absolute())
    executable_target = Path(sys.executable).expanduser().resolve(strict=True)

    assert bridge_argv[:2] == (invocation, "--_hol-guard-codex-bridge")
    assert fallback_argv[:4] == [invocation, "hook", "--harness", "codex"]
    assert "guard" not in fallback_argv[:2]
    assert daemon_argv[:2] == [invocation, "--_hol-guard-codex-daemon-recover"]
    assert {path for _role, path in package_paths} == {executable_target}
    assert {role for role, _path in package_paths} == {
        "bridge",
        "bridge_resume",
        "bridge_runtime",
        "daemon_entrypoint",
        "daemon_manager",
        "fallback_entrypoint",
        "launch_runtime",
        "runtime_trust",
        "windows_job",
    }


def test_frozen_codex_install_and_runtime_trust_validate_without_source_files(
    tmp_path: Path,
    frozen_codex_contract: None,
) -> None:
    context = _context(tmp_path)
    codex_config = context.home_dir / ".codex" / "config.toml"
    codex_config.parent.mkdir(parents=True)
    codex_config.write_text("[features]\ncodex_hooks = true\n", encoding="utf-8")

    CodexHarnessAdapter().install(context)
    state = codex_adapter.codex_native_hook_state(context)

    assert state["managed_hook_installed"] is True
    assert state["protection_active"] is True
    assert state["integrity_status"] == "valid"

    config_payload = codex_adapter._read_toml(codex_config)
    hooks = config_payload["hooks"]
    pre_tool_group = hooks["PreToolUse"][-1]
    handler = pre_tool_group["hooks"][0]
    bridge_argv = shlex.split(handler["command"])
    bridge_config_json = bridge_argv[2]
    bridge_config = json.loads(bridge_config_json)

    trusted = codex_hook_runtime_trust.validate_codex_hook_launch(
        manifest_path=bridge_config["manifest_path"],
        state_path=bridge_config["state_path"],
        fallback_command=bridge_config["fallback_command"],
        start_command=bridge_config["start_command"],
        config_json=bridge_config_json,
    )

    assert trusted.cwd == Path(bridge_config["manifest_path"]).parent.resolve(strict=True)


def test_frozen_runtime_trust_rejects_bridge_command_tampering(
    tmp_path: Path,
    frozen_codex_contract: None,
) -> None:
    context = _context(tmp_path)
    codex_config = context.home_dir / ".codex" / "config.toml"
    codex_config.parent.mkdir(parents=True)
    codex_config.write_text("[features]\ncodex_hooks = true\n", encoding="utf-8")
    CodexHarnessAdapter().install(context)

    config_payload = codex_adapter._read_toml(codex_config)
    handler = config_payload["hooks"]["PreToolUse"][-1]["hooks"][0]
    bridge_argv = shlex.split(handler["command"])
    bridge_config_json = bridge_argv[2]
    bridge_config = json.loads(bridge_config_json)
    tampered_fallback = list(bridge_config["fallback_command"])
    tampered_fallback.append("--policy-action=allow")

    with pytest.raises(ValueError, match=r"fallback contract|bridge config"):
        codex_hook_runtime_trust.validate_codex_hook_launch(
            manifest_path=bridge_config["manifest_path"],
            state_path=bridge_config["state_path"],
            fallback_command=tampered_fallback,
            start_command=bridge_config["start_command"],
            config_json=bridge_config_json,
        )
