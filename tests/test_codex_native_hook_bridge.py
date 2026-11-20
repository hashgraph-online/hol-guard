"""The Python side of the native Codex hook bridge: install argv and owner recognition."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import codex_harness_client as codex_adapter
from codex_plugin_scanner.guard.codex_hook_registration import (
    is_live_guard_codex_hook_command,
    missing_guard_hook_program,
)
from codex_plugin_scanner.guard.harness_context import HarnessContext

NATIVE_CODEX_HOOK_COMMAND = "codex-hook-bridge"
NATIVE_CODEX_HOOK_FEATURE = "codex-hook-bridge-v1"


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


def _hook_argv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, features: tuple[str, ...] | None) -> tuple[str, ...]:
    """The hook argv; ``features=None`` asks the real native runtime, which derives it."""
    from dataclasses import fields

    from codex_plugin_scanner.guard import native_runtime
    from codex_plugin_scanner.guard.config import GuardConfig

    timeout = next(field.default for field in fields(GuardConfig) if field.name == "approval_wait_timeout_seconds")
    if features is not None:
        runtime = tmp_path / "hol-guard-runtime"
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
    )


def test_hook_runs_the_native_bridge_with_only_its_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import native_runtime

    status = native_runtime.native_runtime_status()
    if (
        not status.available
        or status.identity is None
        or NATIVE_CODEX_HOOK_FEATURE not in (status.capabilities.features if status.capabilities else ())
    ):
        pytest.skip("the hook argv is derived by the native runtime")
    argv = _hook_argv(tmp_path, monkeypatch, None)

    assert argv[:2] == (str(status.identity.path), NATIVE_CODEX_HOOK_COMMAND)
    assert len(argv) == 3


def test_hook_without_the_native_feature_asks_for_repair(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(RuntimeError, match="hol-guard repair"):
        _hook_argv(tmp_path, monkeypatch, ("resident-protocol-v2",))


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX hook command syntax")
def test_native_hook_command_is_a_live_guard_hook(tmp_path: Path) -> None:
    bridge_path = tmp_path / "codex_daemon_hook_bridge.py"
    bridge_path.write_text("", encoding="utf-8")
    runtime = tmp_path / "hol-guard-runtime"
    command = f"{runtime} {NATIVE_CODEX_HOOK_COMMAND} {sys.executable} -I {bridge_path} cfg"

    assert is_live_guard_codex_hook_command(command, windows=False)
    assert missing_guard_hook_program(command, windows=False) == str(runtime)
    runtime.write_text("", encoding="utf-8")
    assert missing_guard_hook_program(command, windows=False) is None
    bridge_path.unlink()
    assert missing_guard_hook_program(command, windows=False) == str(bridge_path)
    assert not is_live_guard_codex_hook_command(f"{runtime} {NATIVE_CODEX_HOOK_COMMAND}", windows=False)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX hook command syntax")
def test_native_only_hook_command_is_a_live_guard_hook(tmp_path: Path) -> None:
    runtime = tmp_path / "hol-guard-runtime"
    command = f"{runtime} {NATIVE_CODEX_HOOK_COMMAND} cfg"

    assert is_live_guard_codex_hook_command(command, windows=False)
    assert missing_guard_hook_program(command, windows=False) == str(runtime)
    runtime.write_text("", encoding="utf-8")
    assert missing_guard_hook_program(command, windows=False) is None
