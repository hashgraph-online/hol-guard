"""Cursor hooks run the generated client behind the native runtime."""

from __future__ import annotations

import hashlib
import re
import shlex
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cursor_hook_config import (
    _is_structured_managed_cursor_hook_command,
    _live_cursor_hook_script_path,
    _managed_hook_command,
)
from codex_plugin_scanner.guard.adapters.cursor_hook_native import (
    NATIVE_CURSOR_HOOK_COMMAND,
    NATIVE_CURSOR_HOOK_FEATURE,
)
from codex_plugin_scanner.guard.adapters.cursor_hooks import _HOOK_SCRIPT_TEMPLATE, cursor_hook_script_source

_POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="the native Cursor bridge is POSIX-only")
_PYTHON = Path("/usr/bin/python3")
_NATIVE_SCRIPT = Path(__file__).resolve().parents[1] / "rust/crates/guard-runtime/src/cursor_hook_bridge_script.rs"
_CONSTANTS = (
    "GUARD_HOME",
    "GUARD_CLI",
    "GUARD_RECOVERY_COMMAND",
    "GUARD_HOOK_ARGV",
    "GUARD_INHERIT_ENV_KEYS",
    "GUARD_HOOK_TIMEOUT_SECONDS",
)


def _offer_native(monkeypatch: pytest.MonkeyPatch, runtime: Path) -> None:
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
            features=(NATIVE_CURSOR_HOOK_FEATURE,),
        ),
    )
    monkeypatch.delenv("HOL_GUARD_CURSOR_HOOK_BRIDGE", raising=False)
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda *, deadline_monotonic=None: status)


def _script(tmp_path: Path) -> Path:
    script = tmp_path / "guard" / "managed" / "cursor" / "hol-guard-cursor-hook.py"
    script.parent.mkdir(parents=True)
    script.write_text("", encoding="utf-8")
    return script


@_POSIX_ONLY
def test_cursor_hook_runs_the_client_behind_the_native_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = tmp_path / "hol-guard-runtime"
    _offer_native(monkeypatch, runtime)
    script = _script(tmp_path)

    command = _managed_hook_command(python_executable=_PYTHON, script_path=script, event_name="preToolUse")

    assert shlex.split(command) == [
        str(runtime),
        NATIVE_CURSOR_HOOK_COMMAND,
        str(_PYTHON),
        "-I",
        str(script.resolve()),
        "--cursor-hook-event",
        "preToolUse",
    ]
    assert _live_cursor_hook_script_path(command) == script.resolve()
    assert _is_structured_managed_cursor_hook_command(command) is True


@_POSIX_ONLY
def test_pinning_the_python_client_keeps_its_argv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _offer_native(monkeypatch, tmp_path / "hol-guard-runtime")
    monkeypatch.setenv("HOL_GUARD_CURSOR_HOOK_BRIDGE", "python")
    script = _script(tmp_path)

    command = _managed_hook_command(python_executable=_PYTHON, script_path=script, event_name="beforeReadFile")

    assert shlex.split(command)[:2] == [str(_PYTHON), "-I"]


def test_frozen_cursor_hook_keeps_its_launcher(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _offer_native(monkeypatch, tmp_path / "hol-guard-runtime")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.cursor_hook_config.isolated_cursor_hook_python", lambda: None
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.cursor_hook_config._frozen_cursor_hook_launcher", lambda: "/bin/hol-guard"
    )

    command = _managed_hook_command(python_executable=None, script_path=_script(tmp_path), event_name="preToolUse")

    assert shlex.split(command)[:2] == ["/bin/hol-guard", "__guard-cursor-hook"]


def _native_digest() -> str:
    match = re.search(r'CURSOR_SCRIPT_SHA256: &str =\s*"([0-9a-f]{64})"', _NATIVE_SCRIPT.read_text(encoding="utf-8"))
    assert match is not None
    return match.group(1)


def test_native_bridge_was_ported_from_the_current_client() -> None:
    # A template change must be ported to cursor_hook_bridge.rs before the
    # digest is updated; until then the native bridge would answer for a
    # client it does not match.
    digest = hashlib.sha256(_HOOK_SCRIPT_TEMPLATE.encode("utf-8")).hexdigest()

    assert digest == _native_digest()


def test_rendered_client_reads_back_as_the_template(tmp_path: Path) -> None:
    home = tmp_path / "home dir é"
    context = HarnessContext(home_dir=home, guard_home=home / ".hol-guard", workspace_dir=None)
    source = cursor_hook_script_source(context, guard_cli=["/bin/hol-guard"], recovery_command=["/bin/hol-guard"])

    lines = []
    for line in source.split("\n"):
        name = next((name for name in _CONSTANTS if line.startswith(f"{name} = ")), None)
        lines.append(line if name is None else f"{name} = __{name}__")

    assert "\n".join(lines) == _HOOK_SCRIPT_TEMPLATE


def _client(tmp_path: Path, timeout: str = "8") -> dict[str, object]:
    context = HarnessContext(home_dir=tmp_path, guard_home=tmp_path / "guard", workspace_dir=None)
    context.guard_home.mkdir()
    source = cursor_hook_script_source(context, guard_cli=[sys.executable], recovery_command=[sys.executable])
    source = source.replace("GUARD_HOOK_TIMEOUT_SECONDS = 42\n", f"GUARD_HOOK_TIMEOUT_SECONDS = {timeout}\n")
    namespace: dict[str, object] = {"__name__": "cursor_native_fixture"}
    exec(compile(source, "generated-cursor-hook", "exec"), namespace)
    return namespace


def test_client_takes_the_native_handoff_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOL_GUARD_BOUNDED_NATIVE_ELAPSED_MS", "1500")

    namespace = _client(tmp_path)

    budget = float(namespace["_HOOK_DEADLINE_MONOTONIC"]) - float(namespace["_HOOK_STARTED_MONOTONIC"])
    assert budget == pytest.approx(6.5)
    assert "HOL_GUARD_BOUNDED_NATIVE_ELAPSED_MS" not in namespace["os"].environ


@pytest.mark.parametrize("raw", ["-5", "1.5", "", " 7", "\u0661", "99999999"])
def test_client_never_gains_time_from_the_handoff(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    monkeypatch.setenv("HOL_GUARD_BOUNDED_NATIVE_ELAPSED_MS", raw)

    namespace = _client(tmp_path)

    budget = float(namespace["_HOOK_DEADLINE_MONOTONIC"]) - float(namespace["_HOOK_STARTED_MONOTONIC"])
    assert 0 <= budget <= 8
