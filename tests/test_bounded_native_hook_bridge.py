"""The Python side of the native bounded hook bridge: install argv, detection and recovery."""

from __future__ import annotations

import io
import json
import shlex
import sys
from collections.abc import Callable, Sequence
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import bounded_cli_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters import (
    bounded_cli_hook_daemon,
    bounded_cli_hook_recovery,
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
    daemon_start_command,
)
from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult

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
    worker = json.loads(cline_hooks._worker_config(context, event_name="PreToolUse", guard_cli=list(argv)))

    assert argv[:2] == (str(runtime), NATIVE_BOUNDED_HOOK_COMMAND)
    config = json.loads(argv[-1])
    assert config["harness"] == "cline"
    assert config["cli_args"][:2] == ["guard", "hook"]
    assert config["timeout_seconds"] < cline_hooks._TIMEOUT
    assert worker["guard"] == list(argv)


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


def _started(commands: list[tuple[str, ...]]) -> Callable[..., BoundedHookProcessResult]:
    def start(command: Sequence[str], **_kwargs: object) -> BoundedHookProcessResult:
        commands.append(tuple(command))
        return BoundedHookProcessResult(returncode=0, stdout="", output_limit_exceeded=False, timed_out=False)

    return start


def _identities(monkeypatch: pytest.MonkeyPatch, *values: tuple[str, str] | None) -> list[tuple[str, str] | None]:
    """Name the daemon each `daemon_identity` read finds; the last one repeats."""
    reads: list[tuple[str, str] | None] = []

    def identity(_guard_home: Path) -> tuple[str, str] | None:
        value = values[min(len(reads), len(values) - 1)]
        reads.append(value)
        return value

    monkeypatch.setattr(bounded_cli_hook_recovery, "daemon_identity", identity)
    return reads


def test_a_daemon_miss_starts_the_daemon_and_asks_it_once_more(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = _config(tmp_path)
    answers: list[tuple[str, str, int] | None] = [None, ('{"permissionDecision":"allow"}\n', "", 0)]
    started: list[tuple[str, ...]] = []
    monkeypatch.setattr(bounded_cli_hook_daemon, "try_daemon_hook", lambda **_kwargs: answers.pop(0))
    monkeypatch.setattr(bounded_cli_hook_recovery, "run_isolated_hook_process", _started(started))
    _identities(monkeypatch, None, ("new", "token"))
    output = io.StringIO()
    with redirect_stdout(output):
        returncode = bridge.run_bounded_cli_hook(config, input_text="{}")

    assert answers == []
    assert started == [
        tuple(daemon_start_command(sys.executable, tmp_path, tmp_path / "g", ["guard", "hook", "--harness", "copilot"]))
    ]
    assert (json.loads(output.getvalue())["permissionDecision"], returncode) == ("allow", 0)


def test_a_daemon_that_stays_down_fails_the_hook_closed_without_evaluating(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    asked: list[object] = []
    started: list[tuple[str, ...]] = []
    monkeypatch.setattr(bounded_cli_hook_daemon, "try_daemon_hook", lambda **kwargs: asked.append(kwargs))
    monkeypatch.setattr(bounded_cli_hook_recovery, "run_isolated_hook_process", _started(started))
    _identities(monkeypatch, None, ("new", "token"))
    output = io.StringIO()
    with redirect_stdout(output):
        returncode = bridge.run_bounded_cli_hook(_config(tmp_path), input_text="{}")

    # The only process the bridge runs is the daemon start; no Guard CLI evaluates the hook.
    assert len(asked) == 2
    assert len(started) == 1
    assert "daemon" in " ".join(started[0])
    assert (json.loads(output.getvalue())["permissionDecision"], returncode) == ("deny", 0)


def test_recovery_waits_for_the_started_daemon_to_come_up(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    answers: list[tuple[str, str, int] | None] = [None, ('{"permissionDecision":"allow"}\n', "", 0)]
    monkeypatch.setattr(bounded_cli_hook_daemon, "try_daemon_hook", lambda **_kwargs: answers.pop(0))
    monkeypatch.setattr(bounded_cli_hook_recovery, "run_isolated_hook_process", _started([]))
    # No daemon state at the miss, none for two polls after the start, then the new daemon.
    reads = _identities(monkeypatch, None, None, None, ("new", "token"))
    output = io.StringIO()
    with redirect_stdout(output):
        returncode = bridge.run_bounded_cli_hook(_config(tmp_path), input_text="{}")

    assert answers == []
    assert len(reads) == 4
    assert (json.loads(output.getvalue())["permissionDecision"], returncode) == ("allow", 0)


@pytest.mark.parametrize(
    ("state", "named"),
    [
        ("{}", False),
        ("not json", False),
        ('{"host": "203.0.113.5", "port": 4100}', False),
        ('{"host": "127.0.0.1", "port": true}', False),
        ('{"host": "127.0.0.1", "port": 4100}', True),
    ],
)
def test_only_a_published_daemon_state_names_a_daemon(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: str, named: bool
) -> None:
    # The start path clears the state to `{}` before a daemon comes up; the
    # recovery poll must keep waiting rather than take it for a new daemon.
    monkeypatch.setattr(bounded_cli_hook_recovery, "read_private_regular_text", lambda *_a, **_k: state)
    monkeypatch.setattr(bounded_cli_hook_recovery, "load_guard_daemon_auth_token", lambda _home: "token")

    identity = bounded_cli_hook_recovery.daemon_identity(tmp_path)

    assert identity == ((state, "token") if named else None)


def test_the_daemon_that_missed_the_hook_is_never_asked_again(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[object] = []
    monkeypatch.setattr(bounded_cli_hook_daemon, "try_daemon_hook", lambda **kwargs: asked.append(kwargs))
    monkeypatch.setattr(bounded_cli_hook_recovery, "run_isolated_hook_process", _started([]))
    # The slow daemon that already saw the hook stays the only one the state names.
    _identities(monkeypatch, ("slow", "token"))
    config = {**_config(tmp_path), "timeout_seconds": 3}
    output = io.StringIO()
    with redirect_stdout(output):
        returncode = bridge.run_bounded_cli_hook(config, input_text="{}")

    assert len(asked) == 1
    assert (json.loads(output.getvalue())["permissionDecision"], returncode) == ("deny", 0)
