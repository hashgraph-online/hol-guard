from __future__ import annotations

import hashlib
import io
import json
import shlex
import sys
import time
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from types import ModuleType

import pytest

from codex_plugin_scanner.cli import _build_parser
from codex_plugin_scanner.guard import codex_hook_runtime_trust, frozen_codex_runtime
from codex_plugin_scanner.guard import daemon as daemon_api
from codex_plugin_scanner.guard.adapters import codex as codex_adapter
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter
from codex_plugin_scanner.guard.daemon import manager as daemon_manager
from codex_plugin_scanner.guard.daemon.live_identity import DaemonArtifactBinding
from codex_plugin_scanner.guard.frozen_runtime_commands import (
    frozen_daemon_recovery_command,
    frozen_daemon_recovery_worker_command,
    frozen_daemon_serve_command,
    frozen_windows_extension_control_commands,
)


@pytest.fixture
def frozen_codex_contract(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    original_interpreter = codex_adapter._guard_python_executable
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
        # Tests can patch functions installed by this fixture. Undo those
        # patches before restoring the source contract, otherwise pytest's
        # later monkeypatch teardown reinstates a temporary frozen function.
        monkeypatch.undo()
        codex_adapter._guard_python_executable = original_interpreter
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


def test_frozen_windows_extension_control_commands_quote_the_running_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "Guard's Runtime" / "hol-guard.exe"
    executable.parent.mkdir()
    executable.write_bytes(b"frozen-runtime")
    guard_home = tmp_path / "custom Guard's Home"
    monkeypatch.setattr("codex_plugin_scanner.guard.frozen_runtime_commands.sys.platform", "win32")
    monkeypatch.setattr("codex_plugin_scanner.guard.frozen_runtime_commands.sys.frozen", True, raising=False)
    monkeypatch.setattr("codex_plugin_scanner.guard.frozen_runtime_commands.sys.executable", str(executable))

    commands = frozen_windows_extension_control_commands(guard_home)

    assert commands == {
        "shell": "powershell",
        "enroll": (
            f"& '{str(executable).replace(chr(39), chr(39) * 2)}' command --guard-home "
            f"'{str(guard_home).replace(chr(39), chr(39) * 2)}' controls enroll"
        ),
        "recover_authority": (
            f"& '{str(executable).replace(chr(39), chr(39) * 2)}' command --guard-home "
            f"'{str(guard_home).replace(chr(39), chr(39) * 2)}' controls recover-authority"
        ),
    }

    parser = _build_parser("hol-guard", program_mode="hol-guard")
    parsed = parser.parse_args(["command", "--guard-home", str(guard_home), "controls", "enroll"])
    assert parsed.guard_home == str(guard_home)


def test_frozen_windows_extension_control_commands_stay_absent_for_source_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("codex_plugin_scanner.guard.frozen_runtime_commands.sys.platform", "darwin")
    monkeypatch.setattr("codex_plugin_scanner.guard.frozen_runtime_commands.sys.frozen", False, raising=False)

    assert frozen_windows_extension_control_commands(Path("/guard-home")) is None


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


@pytest.mark.parametrize("gate_input", [b"", b"0"])
def test_frozen_daemon_serve_gate_fails_closed_before_cli_import(
    tmp_path: Path,
    gate_input: bytes,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "home"
    guard_home.mkdir()
    home_dir.mkdir()
    command = frozen_daemon_serve_command(guard_home, home_dir, 4781, executable=sys.executable)
    monkeypatch.setattr(frozen_codex_runtime.sys, "stdin", io.BytesIO(gate_input))

    with pytest.raises(SystemExit) as exit_info:
        frozen_codex_runtime.run_frozen_internal_command(command)

    assert exit_info.value.code == 70


def test_frozen_daemon_serve_gate_rejects_different_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "home"
    guard_home.mkdir()
    home_dir.mkdir()
    executable = tmp_path / "other-hol-guard"
    executable.write_bytes(b"signed-peer")
    command = frozen_daemon_serve_command(guard_home, home_dir, 4781, executable=str(executable))
    monkeypatch.setattr(frozen_codex_runtime.sys, "stdin", io.BytesIO(b"1"))

    with pytest.raises(ValueError, match="current executable"):
        frozen_codex_runtime.run_frozen_internal_command(command)


def test_frozen_daemon_serve_gate_releases_only_signed_private_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "home"
    guard_home.mkdir()
    home_dir.mkdir()
    command = frozen_daemon_serve_command(guard_home, home_dir, 4781, executable=sys.executable)
    observed: list[list[str]] = []
    cli_module = ModuleType("codex_plugin_scanner.cli")
    cli_module.main = lambda argv: observed.append(argv) or 0  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "codex_plugin_scanner.cli", cli_module)
    monkeypatch.setattr(frozen_codex_runtime.sys, "stdin", io.BytesIO(b"1"))

    assert frozen_codex_runtime.run_frozen_internal_command(command) == 0
    assert observed == [
        [
            "daemon",
            "--serve",
            "--guard-home",
            str(guard_home.resolve()),
            "--home",
            str(home_dir.resolve()),
            "--port",
            "4781",
        ]
    ]


def test_frozen_daemon_serve_gate_rejects_noncanonical_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    home_dir = tmp_path / "home"
    guard_home.mkdir()
    home_dir.mkdir()
    command = frozen_daemon_serve_command(guard_home, home_dir, 4781, executable=sys.executable)
    payload = json.loads(command[2])
    payload["port"] = True
    monkeypatch.setattr(frozen_codex_runtime.sys, "stdin", io.BytesIO(b"1"))

    with pytest.raises(ValueError, match="port is invalid"):
        frozen_codex_runtime.run_frozen_internal_command((command[0], command[1], json.dumps(payload)))


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
    invocation = str(Path(sys.executable).expanduser().resolve(strict=True))
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
        "hook_probe",
        "native_receipt",
        "daemon_entrypoint",
        "daemon_manager",
        "fallback_entrypoint",
        "launch_runtime",
        "runtime_trust",
        "windows_job",
    }


@pytest.mark.parametrize("desktop_launcher", [False, True], ids=["direct", "desktop_shell_launcher"])
def test_frozen_codex_install_and_runtime_trust_validate_without_source_files(
    tmp_path: Path,
    frozen_codex_contract: None,
    monkeypatch: pytest.MonkeyPatch,
    desktop_launcher: bool,
) -> None:
    if desktop_launcher:
        core_root = tmp_path / "desktop-core"
        executable = core_root / "versions" / "fixture" / "hol-guard"
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"isolated frozen main fixture")
        executable.chmod(0o700)
        launcher = core_root / "current-hol-guard"
        launcher.write_text('#!/bin/sh\nexec "' + str(executable) + '" "$@"\n', encoding="utf-8")
        launcher.chmod(0o700)
        monkeypatch.setattr(sys, "executable", str(executable))
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(sys, "platform", "darwin")
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

    assert bridge_argv[0] == str(Path(sys.executable).resolve(strict=True))
    assert bridge_config["fallback_command"][0] == bridge_argv[0]
    assert bridge_config["start_command"][0] == bridge_argv[0]

    trusted = codex_hook_runtime_trust.validate_codex_hook_launch(
        manifest_path=bridge_config["manifest_path"],
        state_path=bridge_config["state_path"],
        fallback_command=bridge_config["fallback_command"],
        start_command=bridge_config["start_command"],
        config_json=bridge_config_json,
    )

    assert trusted.cwd == Path(bridge_config["manifest_path"]).parent.resolve(strict=True)


@pytest.mark.parametrize("legacy_roles", [False, True], ids=["current_roles", "legacy_nine_roles"])
def test_retained_frozen_hook_can_be_validated_against_exact_transition_artifact(
    tmp_path,
    frozen_codex_contract,
    monkeypatch,
    legacy_roles,
):
    from codex_plugin_scanner import __version__

    context = _context(tmp_path)
    previous = tmp_path / "previous-core"
    previous.write_bytes(b"isolated previous frozen artifact fixture")
    previous.chmod(0o700)
    candidate = tmp_path / "candidate-core"
    candidate.write_bytes(b"isolated candidate frozen artifact fixture")
    candidate.chmod(0o700)
    monkeypatch.setattr(sys, "executable", str(previous))
    with monkeypatch.context() as role_patch:
        if legacy_roles:
            roles = codex_adapter._hook_packaged_file_paths
            role_patch.setattr(
                codex_adapter,
                "_hook_packaged_file_paths",
                lambda: tuple((role, path) for role, path in roles() if role not in {"hook_probe", "native_receipt"}),
            )
        CodexHarnessAdapter().install(context)
    argv = codex_adapter._hook_command_parts(context)
    bridge = json.loads(argv[2])
    kwargs = dict(
        manifest_path=bridge["manifest_path"],
        state_path=bridge["state_path"],
        fallback_command=bridge["fallback_command"],
        start_command=bridge["start_command"],
        config_json=argv[2],
    )
    config = context.home_dir / ".codex" / "config.toml"
    before = config.read_bytes()
    manifest_path = Path(bridge["manifest_path"])
    before_manifest = manifest_path.read_bytes()
    monkeypatch.setattr(sys, "executable", str(candidate))
    with pytest.raises(ValueError, match="executable identity"):
        codex_hook_runtime_trust.validate_codex_hook_launch(**kwargs)
    binding = DaemonArtifactBinding(previous, hashlib.sha256(previous.read_bytes()).hexdigest(), __version__)
    trusted = frozen_codex_runtime._validate_frozen_codex_hook_launch(**kwargs, expected_artifact=binding)
    assert isinstance(trusted, codex_hook_runtime_trust.TrustedCodexHookLaunch)
    assert config.read_bytes() == before and manifest_path.read_bytes() == before_manifest
    assert sys.executable == str(candidate)  # No process-wide identity override.
    for invalid in (
        replace(binding, executable=candidate),
        replace(binding, executable_sha256="a" * 64),
        replace(binding, package_version="0.0.0"),
    ):
        with pytest.raises(ValueError, match="transition artifact identity"):
            frozen_codex_runtime._validate_frozen_codex_hook_launch(**kwargs, expected_artifact=invalid)
    with pytest.raises(ValueError, match="fallback"):
        frozen_codex_runtime._validate_frozen_codex_hook_launch(
            **{**kwargs, "fallback_command": [*bridge["fallback_command"], "foreign"]},
            expected_artifact=binding,
        )
    from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError, hook_validation_deadline

    with (
        pytest.raises(CodexHookIntegrityError, match="operation deadline"),
        hook_validation_deadline(time.monotonic() - 1),
    ):
        frozen_codex_runtime._validate_frozen_codex_hook_launch(**kwargs, expected_artifact=binding)
    previous.write_bytes(b"changed frozen artifact")
    with pytest.raises(CodexHookIntegrityError):
        frozen_codex_runtime._validate_frozen_codex_hook_launch(**kwargs, expected_artifact=binding)


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
