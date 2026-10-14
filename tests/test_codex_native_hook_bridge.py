"""The Python side of the native Codex hook bridge: install argv, trust hashes and handoff."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import codex as codex_adapter
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.codex_hook_bridge_runtime import (
    NATIVE_ELAPSED_ENV,
    NATIVE_HANDOFF_SCHEMA,
    native_elapsed_seconds,
    read_native_handoff,
)
from codex_plugin_scanner.guard.codex_hook_compatibility import (
    NATIVE_CODEX_HOOK_COMMAND,
    NATIVE_CODEX_HOOK_FEATURE,
    bridge_argv_sha256,
    python_bridge_argv,
)
from codex_plugin_scanner.guard.codex_hook_registration import (
    _is_live_guard_codex_hook_command,
    missing_guard_hook_program,
)


def _native_status(features: tuple[str, ...], path: Path) -> object:
    from codex_plugin_scanner.guard.native_runtime import (
        NativeRuntimeCapabilities,
        NativeRuntimeIdentity,
        NativeRuntimeStatus,
    )

    return NativeRuntimeStatus(
        mode="auto",
        available=True,
        compatible=True,
        reason="ok",
        identity=NativeRuntimeIdentity(path=path, size=1, mtime_ns=1, sha256="0" * 64),
        capabilities=NativeRuntimeCapabilities(
            protocol_version=1,
            runtime_version="0",
            rule_digest="0" * 64,
            build_sha="0" * 40,
            target="test",
            features=features,
        ),
    )


def _hook_argv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, features: tuple[str, ...]) -> tuple[str, ...]:
    from dataclasses import fields

    from codex_plugin_scanner.guard import native_runtime
    from codex_plugin_scanner.guard.config import GuardConfig

    runtime = tmp_path / "hol-guard-runtime"
    timeout = next(field.default for field in fields(GuardConfig) if field.name == "approval_wait_timeout_seconds")
    monkeypatch.setattr(
        native_runtime,
        "native_runtime_status",
        lambda *, deadline_monotonic=None: _native_status(features, runtime),
    )
    # The timeout read goes through the native config loader. This test checks
    # the hook argv, so it supplies the shipped default instead of a runtime.
    monkeypatch.setattr(
        codex_adapter,
        "load_guard_config",
        lambda *_args, **_kwargs: type("_Config", (), {"approval_wait_timeout_seconds": timeout})(),
    )
    context = HarnessContext(home_dir=tmp_path / "h", workspace_dir=None, guard_home=tmp_path / "g")
    return codex_adapter._hook_command_parts_for_home_mode(
        context,
        home_is_current=False,
        python_executable=sys.executable,
    )


@pytest.mark.native_codex_hook_bridge
def test_hook_uses_the_native_bridge_when_the_runtime_offers_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    argv = _hook_argv(tmp_path, monkeypatch, (NATIVE_CODEX_HOOK_FEATURE,))

    assert argv[:2] == (str(tmp_path / "hol-guard-runtime"), NATIVE_CODEX_HOOK_COMMAND)
    assert argv[2:4] == (sys.executable, "-I")
    assert Path(argv[4]).name == "codex_daemon_hook_bridge.py"
    assert python_bridge_argv(list(argv)) == list(argv[2:])
    # The trust hash names the Python bridge either way.
    assert bridge_argv_sha256(list(argv)) == bridge_argv_sha256(list(argv[2:]))


@pytest.mark.native_codex_hook_bridge
def test_python_bridge_pin_keeps_the_python_argv_when_native_is_offered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOL_GUARD_CODEX_HOOK_BRIDGE", "python")
    argv = _hook_argv(tmp_path, monkeypatch, (NATIVE_CODEX_HOOK_FEATURE,))

    assert argv[:2] == (sys.executable, "-I")
    assert python_bridge_argv(list(argv)) == list(argv)


def test_python_bridge_pin_skips_native_selection_in_a_fresh_process() -> None:
    """A subprocess installer must see the same Python bridge pin as the parent."""

    child = r"""
import sys
from codex_plugin_scanner.guard import native_runtime
from codex_plugin_scanner.guard.adapters.codex import _native_bridge_executable

def boom(*, deadline_monotonic=None):
    raise RuntimeError("native status consulted")

native_runtime.native_runtime_status = boom
try:
    result = _native_bridge_executable()
except RuntimeError as error:
    if str(error) != "native status consulted":
        raise
    sys.exit(2)
sys.exit(0 if result is None else 3)
"""
    src = Path(__file__).resolve().parents[1] / "src"
    base = os.environ.copy()
    base["PYTHONPATH"] = str(src)
    pinned = {**base, "HOL_GUARD_CODEX_HOOK_BRIDGE": "python"}
    pinned_child = subprocess.run(
        [sys.executable, "-c", child],
        check=False,
        capture_output=True,
        text=True,
        env=pinned,
        timeout=30,
    )
    assert pinned_child.returncode == 0, pinned_child.stderr
    unpinned = base.copy()
    unpinned.pop("HOL_GUARD_CODEX_HOOK_BRIDGE", None)
    unpinned_child = subprocess.run(
        [sys.executable, "-c", child],
        check=False,
        capture_output=True,
        text=True,
        env=unpinned,
        timeout=30,
    )
    assert unpinned_child.returncode == 2, unpinned_child.stderr


@pytest.mark.native_codex_hook_bridge
def test_hook_keeps_the_python_bridge_without_the_native_feature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    argv = _hook_argv(tmp_path, monkeypatch, ("resident-protocol-v2",))

    assert argv[:2] == (sys.executable, "-I")
    assert python_bridge_argv(list(argv)) == list(argv)


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["/opt/runtime", NATIVE_CODEX_HOOK_COMMAND],
        ["", NATIVE_CODEX_HOOK_COMMAND, "python3", "bridge.py"],
        [None, NATIVE_CODEX_HOOK_COMMAND, "python3", "bridge.py"],
        ["/opt/runtime", "claude-hook-bridge", "python3", "bridge.py"],
        ["python3", "-I", "bridge.py", "{}"],
    ],
)
def test_only_a_native_prefix_is_stripped(argv: list[object]) -> None:
    assert python_bridge_argv(argv) == argv


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX hook command syntax")
def test_native_hook_command_is_a_live_guard_hook(tmp_path: Path) -> None:
    bridge_path = tmp_path / "codex_daemon_hook_bridge.py"
    bridge_path.write_text("", encoding="utf-8")
    runtime = tmp_path / "hol-guard-runtime"
    command = f"{runtime} {NATIVE_CODEX_HOOK_COMMAND} {sys.executable} -I {bridge_path} cfg"

    assert _is_live_guard_codex_hook_command(command, windows=False)
    assert missing_guard_hook_program(command, windows=False) == str(runtime)
    runtime.write_text("", encoding="utf-8")
    assert missing_guard_hook_program(command, windows=False) is None
    bridge_path.unlink()
    assert missing_guard_hook_program(command, windows=False) == str(bridge_path)
    assert not _is_live_guard_codex_hook_command(f"{runtime} {NATIVE_CODEX_HOOK_COMMAND}", windows=False)


def test_native_elapsed_time_only_shortens_the_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(NATIVE_ELAPSED_ENV, "1500")
    assert native_elapsed_seconds(10.0) == 1.5
    # The bridge reads the value once; its children never inherit it.
    assert native_elapsed_seconds(10.0) == 0.0
    monkeypatch.setenv(NATIVE_ELAPSED_ENV, "90000")
    assert native_elapsed_seconds(10.0) == 10.0
    for raw in ("-5", "1.5", "", chr(0x0661)):
        monkeypatch.setenv(NATIVE_ELAPSED_ENV, raw)
        assert native_elapsed_seconds(10.0) == 0.0


def _stdin(monkeypatch: pytest.MonkeyPatch, envelope: object) -> None:
    raw = json.dumps(envelope).encode("utf-8")
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(raw)))


def _envelope(**overrides: object) -> dict[str, object]:
    envelope: dict[str, object] = {
        "schema": NATIVE_HANDOFF_SCHEMA,
        "hook_input": json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash"}),
        "event_name": "PreToolUse",
        "daemon_response": json.dumps({"decision": "allow"}),
        "elapsed_ms": 250,
    }
    envelope.update(overrides)
    return envelope


def test_native_handoff_is_read_when_well_formed(monkeypatch: pytest.MonkeyPatch) -> None:
    _stdin(monkeypatch, _envelope())

    handoff = read_native_handoff(bridge.runtime_hook_event_name)

    assert handoff is not None
    assert handoff.event_name == "PreToolUse"
    assert handoff.response == {"decision": "allow"}
    assert handoff.elapsed_seconds == 0.25


@pytest.mark.parametrize(
    "overrides",
    [
        {"schema": "hol-guard.codex-native-handoff.v0"},
        {"event_name": "PostToolUse"},
        {"elapsed_ms": -1},
        {"elapsed_ms": True},
        {"daemon_response": "[]"},
        {"hook_input": "not json"},
        {"extra": 1},
    ],
)
def test_malformed_native_handoff_fails_closed(monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object]) -> None:
    _stdin(monkeypatch, _envelope(**overrides))
    assert read_native_handoff(bridge.runtime_hook_event_name) is None

    _stdin(monkeypatch, _envelope(**overrides))
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    assert bridge.native_handoff_main(state_path="/missing", query="", hook_timeouts={}) == 0
    decision = json.loads(out.getvalue())["hookSpecificOutput"]
    assert decision["permissionDecision"] == "deny"
