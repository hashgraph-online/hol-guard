"""The Python side of the native bounded hook bridge: install argv and detection."""

from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import bounded_cli_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters import (
    cline_runtime,
    copilot,
    hermes_runtime_hooks,
)
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.bounded_cli_hook_native import (
    NATIVE_BOUNDED_HOOK_COMMAND,
    NATIVE_BOUNDED_HOOK_FEATURE,
    NATIVE_MUSE_HOOK_FEATURE,
    bounded_python_argv,
)
from tests.cline_worker_config import worker_config

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
    # The Devin install recognizes its own native command by this verb and harness field.
    assert NATIVE_BOUNDED_HOOK_COMMAND in devin_command
    assert '"harness":"devin"' in devin_command
    # The Hermes install recognizes its own native command by the inline bridge bootstrap.
    hermes_tokens = shlex.split(hermes_runtime_hooks.hermes_hook_command_string(_command(tmp_path, "hermes")))
    assert "bounded_cli_hook_bridge" in hermes_tokens[hermes_tokens.index("-c") + 1]


@pytest.mark.native_bounded_hook_bridge
@_POSIX_ONLY
def test_cline_worker_runs_the_native_bridge_once_per_payload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = tmp_path / "hol-guard-runtime"
    _offer_native(monkeypatch, runtime, (NATIVE_BOUNDED_HOOK_FEATURE,))
    context = HarnessContext(home_dir=tmp_path / "h", workspace_dir=None, guard_home=tmp_path / "g")

    argv = tuple(cline_runtime._facts(context, "plugin")["hook_argv"])  # pyright: ignore[reportPrivateUsage]
    worker = json.loads(worker_config(context, event_name="PreToolUse", guard_cli=list(argv)))

    assert argv[:2] == (str(runtime), NATIVE_BOUNDED_HOOK_COMMAND)
    config = json.loads(argv[-1])
    assert config["harness"] == "cline"
    assert config["cli_args"][:2] == ["guard", "hook"]
    # The native worker gives the bridge 9 seconds; the bridge answers inside it.
    assert config["timeout_seconds"] < 9
    assert worker["guard"] == list(argv)


@pytest.mark.native_bounded_hook_bridge
def test_muse_uses_the_native_bridge_only_with_its_own_feature(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = tmp_path / "hol-guard-runtime"
    _offer_native(monkeypatch, runtime, (NATIVE_BOUNDED_HOOK_FEATURE,))
    assert _command(tmp_path, "muse")[:2] == (sys.executable, "-I")

    _offer_native(monkeypatch, runtime, (NATIVE_MUSE_HOOK_FEATURE,))
    argv = _command(tmp_path, "muse")

    assert argv[:2] == (str(runtime), NATIVE_BOUNDED_HOOK_COMMAND)
    assert json.loads(argv[-1])["harness"] == "muse"
