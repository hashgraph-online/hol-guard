"""The installer's native Claude SessionStart lane and the Python command it falls back to."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_runtime
from codex_plugin_scanner.guard.adapters import claude_code
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.native_runtime_values import (
    NativeRuntimeCapabilities,
    NativeRuntimeIdentity,
    NativeRuntimeStatus,
)

_REPO = Path(__file__).resolve().parents[1]
_RUST_SOURCE = _REPO / "rust" / "crates" / "guard-runtime" / "src" / "claude_session_start.rs"
_RUST_ARGV = _REPO / "rust" / "crates" / "guard-runtime" / "src" / "adapters" / "harness_adapter" / "claude_argv.rs"
_CURSOR_ENV = ("CURSOR_VERSION", "CURSOR_PROJECT_DIR", "CURSOR_TRACE_ID", "CURSOR_SESSION_ID", "CURSOR_TRANSCRIPT_PATH")
_BOTH_FEATURES = (claude_code.NATIVE_CLAUDE_HOOK_FEATURE, claude_code.NATIVE_CLAUDE_SESSION_START_FEATURE)
_MODE = "session-start"
_SESSION_MARKER = claude_code.CLAUDE_GUARD_SESSION_START_HOOK_MARKER
_ADAPTER = claude_code.ClaudeCodeHarnessAdapter

posix_only = pytest.mark.skipif(os.name == "nt", reason="these lane fixtures are POSIX only")


def _status(features: tuple[str, ...], path: Path) -> NativeRuntimeStatus:
    return NativeRuntimeStatus(
        mode="auto",
        available=True,
        compatible=True,
        reason="ok",
        identity=NativeRuntimeIdentity(path=path, size=1, mtime_ns=1, sha256="0" * 64),
        capabilities=NativeRuntimeCapabilities(
            protocol_version=1,
            runtime_version="9.9.9",
            rule_digest="0" * 64,
            build_sha="a" * 40,
            target="test",
            features=features,
        ),
    )


def _own_home_context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> HarnessContext:
    home = tmp_path / "home 雪 'quote'"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    for key in _CURSOR_ENV:
        monkeypatch.delenv(key, raising=False)
    workspace = tmp_path / 'work "quoted"'
    workspace.mkdir()
    return HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=home / ".hol-guard")


def _python_argv(context: HarnessContext) -> tuple[str, ...]:
    return claude_code._argv("python_session_start", context)  # pyright: ignore[reportPrivateUsage]


def _handler(argv: tuple[str, ...] | list[str]) -> dict[str, object]:
    return {"type": "command", "command": argv[0], "args": list(argv[1:]), "timeout": 10}


def _use_runtime(monkeypatch: pytest.MonkeyPatch, runtime: Path, features: tuple[str, ...]) -> None:
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda **_kwargs: _status(features, runtime))
    monkeypatch.setattr(claude_code, "load_guard_daemon_url", lambda _guard_home: "http://127.0.0.1:43123")


@posix_only
def test_installer_writes_the_native_lane_when_the_runtime_offers_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _own_home_context(tmp_path, monkeypatch)
    runtime = tmp_path / "hol-guard-runtime"
    _use_runtime(monkeypatch, runtime, _BOTH_FEATURES)

    argv = _ADAPTER._session_start_command_parts(context)

    assert argv[:4] == (
        str(runtime),
        "claude-hook-bridge",
        _MODE,
        _SESSION_MARKER,
    )
    lane = json.loads(argv[4])
    python_argv = _python_argv(context)
    assert lane["fallback_command"] == list(python_argv)
    assert python_argv[1] == "-c"
    assert lane["home"] == str(Path.home())
    assert lane["home_dir"] == str(context.home_dir)
    assert lane["runtime_build"] == "9.9.9+" + "a" * 40


@posix_only
def test_lane_describes_exactly_the_daemon_hook_the_refresh_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _own_home_context(tmp_path, monkeypatch)
    _use_runtime(monkeypatch, tmp_path / "hol-guard-runtime", _BOTH_FEATURES)
    url = "http://127.0.0.1:43123"

    lane = json.loads(_ADAPTER._session_start_command_parts(context)[4])
    daemon_argv = _ADAPTER._daemon_hook_command_parts(context)

    assert tuple(lane["daemon_hook_command"]) == daemon_argv[:3]
    bridge_config = json.loads(daemon_argv[3])
    assert bridge_config.pop("fallback_daemon_url") == url
    assert bridge_config == lane["bridge_config"]


@posix_only
@pytest.mark.parametrize(
    "features",
    [
        pytest.param(None, id="native-runtime-missing"),
        pytest.param((claude_code.NATIVE_CLAUDE_HOOK_FEATURE,), id="session-start-feature-missing"),
    ],
)
def test_installer_keeps_the_python_command_without_the_native_lane(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    features: tuple[str, ...] | None,
) -> None:
    context = _own_home_context(tmp_path, monkeypatch)
    if features is None:
        monkeypatch.setattr(claude_code, "native_hook_bridge_executable", lambda _feature, **_kwargs: None)
    else:
        _use_runtime(monkeypatch, tmp_path / "hol-guard-runtime", features)

    argv = _ADAPTER._session_start_command_parts(context)

    assert argv == _python_argv(context)
    assert argv[1] == "-c"


@posix_only
def test_installer_keeps_the_python_command_for_another_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context = _own_home_context(tmp_path, monkeypatch)
    other = HarnessContext(home_dir=tmp_path / "other", workspace_dir=None, guard_home=context.guard_home)
    (tmp_path / "other").mkdir()
    _use_runtime(monkeypatch, tmp_path / "hol-guard-runtime", _BOTH_FEATURES)

    assert _ADAPTER._session_start_command_parts(other)[1] == "-c"


def test_rust_lane_constants_match_the_installer() -> None:
    source = _RUST_SOURCE.read_text(encoding="utf-8")

    def rust_const(name: str, text: str = source) -> str:
        match = re.search(rf'const {name}: &str = "([^"]*)";', text)
        assert match is not None, name
        return match.group(1)

    assert rust_const("SESSION_START_MODE") == _MODE
    assert rust_const("SESSION_START_MODE", _RUST_ARGV.read_text(encoding="utf-8")) == _MODE
    assert rust_const("SESSION_START_MARKER") == _SESSION_MARKER
    assert rust_const("SESSION_START_FEATURE") == claude_code.NATIVE_CLAUDE_SESSION_START_FEATURE
    for key in _CURSOR_ENV:
        assert f'"{key}"' in source


@posix_only
def test_compiled_lane_hands_a_stale_session_to_the_python_command(native_hook_force: Path, tmp_path: Path) -> None:
    fallback = [sys.executable, "-c", "import sys; print('fallback', sys.argv[1:], sys.stdin.read())", "a b", "雪"]
    lane = {
        "fallback_command": fallback,
        "home": str(tmp_path),
        "home_dir": str(tmp_path),
        "runtime_build": "0.0.0+stale",
        "daemon_hook_command": [
            str(native_hook_force),
            "claude-hook-bridge",
            claude_code.CLAUDE_GUARD_DAEMON_HOOK_MARKER,
        ],
        "bridge_config": {"state_path": str(tmp_path / "daemon-state.json"), "fallback_command": ["x"], "query": ""},
    }
    argv = (
        str(native_hook_force),
        "claude-hook-bridge",
        _MODE,
        _SESSION_MARKER,
        json.dumps(lane),
    )

    completed = subprocess.run(
        argv, input='{"hook_event_name":"SessionStart"}', capture_output=True, text=True, timeout=30
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "fallback ['a b', '雪'] {\"hook_event_name\":\"SessionStart\"}\n"


@posix_only
def test_python_refresh_moves_an_upgraded_install_back_onto_the_native_lane(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _own_home_context(tmp_path, monkeypatch)
    runtime = tmp_path / "hol-guard-runtime"
    _use_runtime(monkeypatch, runtime, _BOTH_FEATURES)
    stale = list(_ADAPTER._session_start_command_parts(context))
    lane = json.loads(stale[4])
    lane["runtime_build"] = "0.0.0+" + "b" * 40
    stale[4] = json.dumps(lane)
    user_hook = {"type": "command", "command": "echo mine"}
    settings_path = context.home_dir / ".claude" / "settings.json"
    settings_path.parent.mkdir()
    settings_path.write_text(
        json.dumps(
            {
                "hooks": {
                    "SessionStart": [
                        {"matcher": "startup", "hooks": [user_hook]},
                        {"hooks": [_handler(stale)]},
                    ]
                }
            }
        ),
        encoding="utf-8",
    )

    _ADAPTER.refresh_installed_hook_urls(
        home_dir=context.home_dir, workspace_dir=context.workspace_dir, guard_home=context.guard_home
    )

    entries = json.loads(settings_path.read_text(encoding="utf-8"))["hooks"]["SessionStart"]
    handlers = [handler for entry in entries for handler in entry["hooks"]]
    assert user_hook in handlers
    argvs = [(handler["command"], *handler["args"]) for handler in handlers if handler != user_hook]
    lanes = [argv for argv in argvs if argv[2:3] == (_MODE,)]
    expected = _ADAPTER._session_start_command_parts(context)
    assert lanes == [expected] * 4
    assert json.loads(lanes[0][4])["runtime_build"] == "9.9.9+" + "a" * 40
