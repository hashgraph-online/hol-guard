"""The Python side of the native bounded hook bridge: install argv, detection and handoff."""

from __future__ import annotations

import json
import os
import shlex
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import bounded_cli_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters import (
    bounded_cli_hook_daemon,
    cline_hooks,
    copilot,
    devin_config,
    hermes_runtime_hooks,
)
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.bounded_cli_hook_native import (
    NATIVE_BOUNDED_HOOK_COMMAND,
    NATIVE_BOUNDED_HOOK_FEATURE,
    bounded_python_argv,
    take_native_handoff_environment,
)
from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult

_ELAPSED_ENV = "HOL_GUARD_BOUNDED_NATIVE_ELAPSED_MS"
_DAEMON_TRIED_ENV = "HOL_GUARD_BOUNDED_NATIVE_DAEMON_TRIED"
_NATIVE_HARNESSES = ("copilot", "kimi", "devin", "zcode", "openclaw", "hermes", "cline")
_POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="asserts POSIX hook command syntax")


def _offer_native(monkeypatch: pytest.MonkeyPatch, runtime: Path, features: tuple[str, ...]) -> None:
    from codex_plugin_scanner.guard import native_runtime
    from codex_plugin_scanner.guard.native_runtime import (
        NativeRuntimeCapabilities,
        NativeRuntimeIdentity,
        NativeRuntimeStatus,
    )

    status = NativeRuntimeStatus(
        mode="auto",
        available=True,
        compatible=True,
        reason="ok",
        identity=NativeRuntimeIdentity(path=runtime, size=1, mtime_ns=1, sha256="0" * 64),
        capabilities=NativeRuntimeCapabilities(
            protocol_version=1,
            runtime_version="0",
            rule_digest="0" * 64,
            build_sha="0" * 40,
            target="test",
            features=features,
        ),
    )
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda *, deadline_monotonic=None: status)


def _command(tmp_path: Path, harness: str) -> tuple[str, ...]:
    return bridge.bounded_cli_hook_command(
        python_executable=sys.executable,
        package_root=Path(__file__).resolve().parents[1] / "src",
        guard_home=tmp_path / "g",
        cli_args=["guard", "hook", "--harness", harness],
        harness=harness,
        timeout_seconds=20,
    )


@pytest.mark.native_bounded_hook_bridge
@pytest.mark.parametrize("harness", _NATIVE_HARNESSES)
def test_hook_uses_the_native_bridge_when_the_runtime_offers_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, harness: str
) -> None:
    runtime = tmp_path / "hol-guard-runtime"
    _offer_native(monkeypatch, runtime, (NATIVE_BOUNDED_HOOK_FEATURE,))

    argv = _command(tmp_path, harness)

    assert argv[:2] == (str(runtime), NATIVE_BOUNDED_HOOK_COMMAND)
    assert argv[2:5] == (sys.executable, "-I", "-c")
    assert "bounded_cli_hook_bridge" in argv[5]
    config = json.loads(argv[6])
    assert config["harness"] == harness
    # The native bridge restarts an unreachable daemon with this, never Python.
    start = config["start_command"]
    assert start[:3] == [sys.executable, "-I", "-c"]
    assert "schedule_guard_daemon_recovery" in start[3]
    assert bounded_python_argv(list(argv)) == list(argv[2:])


@pytest.mark.native_bounded_hook_bridge
def test_other_harnesses_keep_the_python_bridge(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _offer_native(monkeypatch, tmp_path / "hol-guard-runtime", (NATIVE_BOUNDED_HOOK_FEATURE,))

    argv = _command(tmp_path, "claude")

    assert argv[:2] == (sys.executable, "-I")


@pytest.mark.native_bounded_hook_bridge
def test_hook_keeps_the_python_bridge_without_the_native_feature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _offer_native(monkeypatch, tmp_path / "hol-guard-runtime", ("codex-hook-bridge-v1",))

    argv = _command(tmp_path, "copilot")

    assert argv[:2] == (sys.executable, "-I")


@pytest.mark.native_bounded_hook_bridge
def test_python_bridge_pin_keeps_the_python_argv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOL_GUARD_BOUNDED_HOOK_BRIDGE", "python")
    _offer_native(monkeypatch, tmp_path / "hol-guard-runtime", (NATIVE_BOUNDED_HOOK_FEATURE,))

    argv = _command(tmp_path, "copilot")

    assert argv[:2] == (sys.executable, "-I")


@pytest.mark.parametrize(
    "argv",
    [
        [sys.executable, "-I", "-c", "code", "{}"],
        ["", NATIVE_BOUNDED_HOOK_COMMAND, sys.executable, "-I"],
        ["/runtime", "codex-hook-bridge", sys.executable, "-I"],
        ["/runtime", NATIVE_BOUNDED_HOOK_COMMAND],
    ],
)
def test_only_a_native_prefix_is_stripped(argv: list[object]) -> None:
    assert bounded_python_argv(argv) == argv


@pytest.mark.native_bounded_hook_bridge
@_POSIX_ONLY
def test_native_copilot_devin_and_hermes_commands_stay_managed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _offer_native(monkeypatch, tmp_path / "hol guard runtime", (NATIVE_BOUNDED_HOOK_FEATURE,))
    context = HarnessContext(home_dir=tmp_path / "h", workspace_dir=None, guard_home=tmp_path / "g")

    copilot_command = shlex.join(copilot._hook_command_parts(context, include_workspace=False))
    devin_command = shlex.join(_command(tmp_path, "devin"))

    assert NATIVE_BOUNDED_HOOK_COMMAND in copilot_command
    assert copilot._is_managed_hook_command(copilot_command)
    assert devin_config.is_guard_managed_hook_command(devin_command)
    hermes_command = hermes_runtime_hooks.hermes_hook_command_string(_command(tmp_path, "hermes"))
    assert hermes_runtime_hooks._legacy_guard_pretool_command(hermes_command)


@pytest.mark.native_bounded_hook_bridge
@_POSIX_ONLY
def test_cline_worker_runs_the_native_bridge_once_per_payload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = tmp_path / "hol-guard-runtime"
    _offer_native(monkeypatch, runtime, (NATIVE_BOUNDED_HOOK_FEATURE,))
    context = HarnessContext(home_dir=tmp_path / "h", workspace_dir=None, guard_home=tmp_path / "g")

    argv = cline_hooks._bounded_hook_argv(context, sys.executable)
    source = cline_hooks._hook_source(context, event_name="PreToolUse", guard_cli=list(argv))

    assert argv[:2] == (str(runtime), NATIVE_BOUNDED_HOOK_COMMAND)
    config = json.loads(argv[-1])
    assert config["harness"] == "cline"
    assert config["cli_args"][:2] == ["guard", "hook"]
    assert config["timeout_seconds"] < cline_hooks._TIMEOUT
    assert f"GUARD={list(argv)!r}" in source
    assert "[*GUARD" not in source


def test_handoff_environment_is_read_once_and_only_shortens(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_ELAPSED_ENV, "1500")
    monkeypatch.setenv(_DAEMON_TRIED_ENV, "1")

    elapsed, daemon_tried = take_native_handoff_environment()

    assert daemon_tried is True
    assert elapsed(20.0) == 1.5
    assert elapsed(1.0) == 1.0
    assert elapsed(-1.0) == 0.0
    elapsed, daemon_tried = take_native_handoff_environment()
    assert daemon_tried is False
    assert elapsed(20.0) == 0.0


@pytest.mark.parametrize("raw", ["-5", "1.5", "", " 7", "\u0661"])
def test_malformed_elapsed_time_is_ignored(monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    monkeypatch.setenv(_ELAPSED_ENV, raw)

    elapsed, _daemon_tried = take_native_handoff_environment()

    assert elapsed(20.0) == 0.0


def _config(tmp_path: Path) -> dict[str, object]:
    return {
        "python_executable": sys.executable,
        "package_root": str(tmp_path),
        "guard_home": str(tmp_path / "g"),
        "cli_args": ["guard", "hook", "--harness", "copilot"],
        "harness": "copilot",
        "timeout_seconds": 20,
        "frozen_launcher": False,
    }


def test_daemon_tried_hook_goes_straight_to_the_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def no_daemon(**_kwargs: object) -> None:
        raise AssertionError("the daemon was asked twice")

    def isolated(*_args: object, **_kwargs: object) -> BoundedHookProcessResult:
        return BoundedHookProcessResult(
            returncode=0, stdout='{"decision":"allow"}\n', output_limit_exceeded=False, timed_out=False
        )

    monkeypatch.setattr(bounded_cli_hook_daemon, "try_daemon_hook", no_daemon)
    monkeypatch.setattr(bridge, "run_isolated_hook_process", isolated)

    assert bridge.run_bounded_cli_hook(_config(tmp_path), input_text="{}", skip_daemon=True) == 0


def test_main_passes_the_native_handoff_to_the_hook(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def run(config: object, *, input_text: str, deadline_monotonic: float, skip_daemon: bool) -> int:
        seen["skip_daemon"] = skip_daemon
        seen["deadline"] = deadline_monotonic
        return 0

    monkeypatch.setenv(_ELAPSED_ENV, "999999999")
    monkeypatch.setenv(_DAEMON_TRIED_ENV, "1")
    monkeypatch.setattr(bridge, "_read_bounded_stdin", lambda _deadline: ("{}", ""))
    monkeypatch.setattr(bridge, "run_bounded_cli_hook", run)
    before = bridge.time.monotonic()

    assert bridge.main_from_argv([json.dumps(_config(tmp_path))]) == 0

    assert seen["skip_daemon"] is True
    # The whole budget was already spent natively, so the deadline is now.
    assert isinstance(seen["deadline"], float)
    assert seen["deadline"] <= before + 1.0
    assert _ELAPSED_ENV not in os.environ
    assert _DAEMON_TRIED_ENV not in os.environ
