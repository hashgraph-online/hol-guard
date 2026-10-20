"""Grok hooks run the generated stdlib client behind the native bounded bridge."""

from __future__ import annotations

import hashlib
import io
import json
import re
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext, _shell_command
from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import _render_bounded_hook_script
from codex_plugin_scanner.guard.adapters.bounded_cli_hook_native import (
    NATIVE_BOUNDED_HOOK_COMMAND,
    NATIVE_BOUNDED_HOOK_FEATURE,
)
from codex_plugin_scanner.guard.adapters.bounded_cli_hook_script_template import BOUNDED_HOOK_SCRIPT_TEMPLATE
from codex_plugin_scanner.guard.adapters.grok import GrokHarnessAdapter
from codex_plugin_scanner.guard.cli.grok_hook_validation import is_grok_hook_command
from codex_plugin_scanner.guard.cli.update_grok_repair import _isolated_bounded_hook_is_current
from tests.test_bounded_cli_hook_script_template import _load_script, _serve, _write_daemon_files

_POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="asserts POSIX paths and hook command syntax")
_PYTHON = "/usr/bin/python3"
_NATIVE_SCRIPT = (
    Path(__file__).resolve().parents[1] / "rust/crates/guard-runtime/src/bounded_hook_bridge_grok_script.rs"
)
_PLACEHOLDERS = {
    "GUARD_HOME = ": "GUARD_HOME = __GUARD_HOME__",
    "HARNESS = ": "HARNESS = __HARNESS__",
    "TIMEOUT_SECONDS = ": "TIMEOUT_SECONDS = __TIMEOUT_SECONDS__",
}


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
            features=(NATIVE_BOUNDED_HOOK_FEATURE,),
        ),
    )
    monkeypatch.delenv("HOL_GUARD_BOUNDED_HOOK_BRIDGE", raising=False)
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda *, deadline_monotonic=None: status)


def _isolated_python(monkeypatch: pytest.MonkeyPatch) -> None:
    for module in ("bounded_cli_hook_bridge", "cursor_hook_config"):
        monkeypatch.setattr(
            f"codex_plugin_scanner.guard.adapters.{module}.isolated_cursor_hook_python",
            lambda: _PYTHON,
        )


def _context(tmp_path: Path) -> HarnessContext:
    return HarnessContext(tmp_path / "home", tmp_path / "workspace", tmp_path / "guard")


@_POSIX_ONLY
def test_grok_hook_runs_the_client_behind_the_native_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = tmp_path / "hol-guard-runtime"
    _offer_native(monkeypatch, runtime)
    _isolated_python(monkeypatch)
    context = _context(tmp_path)

    command = GrokHarnessAdapter._hook_command_parts(context)

    assert command[:4] == (str(runtime), NATIVE_BOUNDED_HOOK_COMMAND, _PYTHON, "-I")
    assert command[4].endswith("managed/bounded-hooks/grok.py")
    assert json.loads(command[5])["harness"] == "grok"
    assert is_grok_hook_command(_shell_command(command), context) is True
    assert _isolated_bounded_hook_is_current(_shell_command(command), context=context) is True


@_POSIX_ONLY
def test_grok_hook_from_another_runtime_is_not_managed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _offer_native(monkeypatch, tmp_path / "hol-guard-runtime")
    _isolated_python(monkeypatch)
    context = _context(tmp_path)
    command = list(GrokHarnessAdapter._hook_command_parts(context))
    command[0] = str(tmp_path / "other-runtime")

    assert is_grok_hook_command(_shell_command(tuple(command)), context) is False


@_POSIX_ONLY
def test_native_grok_hook_needs_the_native_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _offer_native(monkeypatch, tmp_path / "hol-guard-runtime")
    _isolated_python(monkeypatch)
    context = _context(tmp_path)
    command = _shell_command(GrokHarnessAdapter._hook_command_parts(context))

    # Pinning the Python bridge retires the native launcher, so the hook is repaired.
    monkeypatch.setenv("HOL_GUARD_BOUNDED_HOOK_BRIDGE", "python")

    assert is_grok_hook_command(command, context) is False


def test_frozen_grok_hook_keeps_the_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _offer_native(monkeypatch, tmp_path / "hol-guard-runtime")
    _isolated_python(monkeypatch)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.delenv("HOL_GUARD_DESKTOP", raising=False)

    command = GrokHarnessAdapter._hook_command_parts(_context(tmp_path))

    assert command[:2] == (_PYTHON, "-I")


def test_client_takes_the_native_handoff_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOL_GUARD_BOUNDED_NATIVE_ELAPSED_MS", "1500")
    monkeypatch.setenv("HOL_GUARD_BOUNDED_NATIVE_DAEMON_TRIED", "1")

    module = _load_script(tmp_path, harness="grok", timeout_seconds=8)

    assert module._NATIVE_DAEMON_TRIED is True
    budget = module._HOOK_DEADLINE_MONOTONIC - module._HOOK_STARTED_MONOTONIC
    assert budget == pytest.approx(6.5)
    assert "HOL_GUARD_BOUNDED_NATIVE_ELAPSED_MS" not in module.os.environ
    assert "HOL_GUARD_BOUNDED_NATIVE_DAEMON_TRIED" not in module.os.environ


@pytest.mark.parametrize("raw", ["-5", "1.5", "", " 7", "\u0661"])
def test_client_ignores_a_malformed_elapsed_time(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    monkeypatch.setenv("HOL_GUARD_BOUNDED_NATIVE_ELAPSED_MS", raw)

    module = _load_script(tmp_path, harness="grok", timeout_seconds=8)

    assert module._HOOK_DEADLINE_MONOTONIC == module._HOOK_STARTED_MONOTONIC + 8


def test_client_never_asks_the_daemon_twice(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOL_GUARD_BOUNDED_NATIVE_DAEMON_TRIED", "1")
    module = _load_script(tmp_path, harness="grok")
    host, port, server = _serve({("POST", "/v1/hooks/grok"): {"policy_action": "allow"}})
    stdin = io.BytesIO(b'{"hook_event_name":"PreToolUse","tool_name":"Write"}')
    monkeypatch.setattr(module.sys, "stdin", stdin)
    monkeypatch.setattr(stdin, "buffer", stdin, raising=False)
    stdout = io.StringIO()
    monkeypatch.setattr(module.sys, "stdout", stdout)
    monkeypatch.setattr(module.sys, "argv", [module.__file__])
    try:
        _write_daemon_files(module, host=host, port=port)
        assert module.main() == 0
    finally:
        server.shutdown()
        server.server_close()

    assert json.loads(stdout.getvalue()) == {"decision": "deny", "reason": module._FAILURE_REASON}


def _native_digest() -> str:
    match = re.search(r'GROK_SCRIPT_SHA256: &str =\s*"([0-9a-f]{64})"', _NATIVE_SCRIPT.read_text(encoding="utf-8"))
    assert match is not None
    return match.group(1)


def test_native_bridge_was_ported_from_the_current_client() -> None:
    # A template change must be ported to bounded_hook_bridge_grok.rs before
    # the digest is updated: the native bridge answers for every client it
    # can read, with no Python to hand a newer template to.
    digest = hashlib.sha256(BOUNDED_HOOK_SCRIPT_TEMPLATE.encode("utf-8")).hexdigest()

    assert digest == _native_digest()


@pytest.mark.parametrize("timeout_seconds", [8, 2.5])
def test_rendered_client_reads_back_as_the_template(tmp_path: Path, timeout_seconds: float) -> None:
    source = _render_bounded_hook_script(guard_home=tmp_path, harness="grok", timeout_seconds=timeout_seconds)

    lines = []
    for line in source.split("\n"):
        prefix = next((prefix for prefix in _PLACEHOLDERS if line.startswith(prefix)), None)
        lines.append(line if prefix is None else _PLACEHOLDERS[prefix])

    assert "\n".join(lines) == BOUNDED_HOOK_SCRIPT_TEMPLATE
