"""The installer's native Claude SessionStart lane and its Python parity."""

from __future__ import annotations

import copy
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_runtime
from codex_plugin_scanner.guard.adapters import claude_hook_argv
from codex_plugin_scanner.guard.adapters import claude_hook_config as config
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.native_runtime_values import (
    NativeRuntimeCapabilities,
    NativeRuntimeIdentity,
    NativeRuntimeStatus,
)

_REPO = Path(__file__).resolve().parents[1]
_FIXTURE = _REPO / "tests" / "fixtures" / "claude_session_start" / "settings-current.v1.json"
_RUST_SOURCE = _REPO / "rust" / "crates" / "guard-runtime" / "src" / "claude_session_start.rs"
_CURSOR_ENV = ("CURSOR_VERSION", "CURSOR_PROJECT_DIR", "CURSOR_TRACE_ID", "CURSOR_SESSION_ID", "CURSOR_TRANSCRIPT_PATH")
_BOTH_FEATURES = (claude_hook_argv.NATIVE_CLAUDE_HOOK_FEATURE, claude_hook_argv.NATIVE_CLAUDE_SESSION_START_FEATURE)

posix_only = pytest.mark.skipif(os.name == "nt", reason="the native SessionStart lane is POSIX only")


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


def _use_runtime(monkeypatch: pytest.MonkeyPatch, runtime: Path, features: tuple[str, ...]) -> None:
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda **_kwargs: _status(features, runtime))


def _refresh(hooks: dict[str, object], argv: tuple[str, ...]) -> None:
    config.sync_runtime_hook_groups(hooks, argv)
    config.remove_unsupported_guard_hook_groups(hooks)


def test_shared_fixture_is_what_the_python_refresh_writes_and_keeps() -> None:
    fixture = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    argv = (
        *fixture["daemon_hook_command"],
        claude_hook_argv.bridge_config_text(fixture["bridge_config"], fixture["daemon_url"]),
    )
    from_seed = copy.deepcopy(fixture["seed_hooks"])
    _refresh(from_seed, argv)
    assert from_seed == fixture["settings"]["hooks"]
    # The Rust lane calls these settings current, so the refresh must leave them byte for byte.
    again = copy.deepcopy(fixture["settings"])
    _refresh(again["hooks"], argv)
    assert json.dumps(again, indent=2) == json.dumps(fixture["settings"], indent=2)


@posix_only
def test_installer_writes_the_native_lane_when_the_runtime_offers_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _own_home_context(tmp_path, monkeypatch)
    runtime = tmp_path / "hol-guard-runtime"
    _use_runtime(monkeypatch, runtime, _BOTH_FEATURES)

    argv = claude_hook_argv.session_start_command_parts(context)

    assert argv[:4] == (
        str(runtime),
        "claude-hook-bridge",
        "session-start",
        config.CLAUDE_GUARD_SESSION_START_HOOK_MARKER,
    )
    lane = json.loads(argv[4])
    python_argv = claude_hook_argv._python_session_start_command_parts(context)
    assert lane["fallback_command"] == list(python_argv)
    assert python_argv[1] == "-c"
    assert lane["home"] == str(Path.home())
    assert lane["home_dir"] == str(context.home_dir)
    assert lane["runtime_build"] == "9.9.9+" + "a" * 40
    handler = config.guard_command_handler(argv, timeout=10)
    assert config.prune_guard_hook_entries([{"matcher": "startup", "hooks": [handler]}]) == []


@posix_only
def test_lane_describes_exactly_the_daemon_hook_the_refresh_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _own_home_context(tmp_path, monkeypatch)
    _use_runtime(monkeypatch, tmp_path / "hol-guard-runtime", _BOTH_FEATURES)
    url = "http://127.0.0.1:43123"

    lane = json.loads(claude_hook_argv.session_start_command_parts(context)[4])
    daemon_argv = claude_hook_argv.daemon_hook_command_parts(context, fallback_daemon_url=url)

    assert tuple(lane["daemon_hook_command"]) == daemon_argv[:3]
    assert claude_hook_argv.bridge_config_text(lane["bridge_config"], url) == daemon_argv[3]
    assert set(lane["bridge_config"]) <= {
        *config.CLAUDE_BRIDGE_CONFIG_REQUIRED_KEYS,
        *config.CLAUDE_BRIDGE_CONFIG_OPTIONAL_KEYS,
    }


@posix_only
@pytest.mark.parametrize(
    "features",
    [
        pytest.param(None, id="native-runtime-missing"),
        pytest.param((claude_hook_argv.NATIVE_CLAUDE_HOOK_FEATURE,), id="session-start-feature-missing"),
    ],
)
def test_installer_keeps_the_python_command_without_the_native_lane(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    features: tuple[str, ...] | None,
) -> None:
    context = _own_home_context(tmp_path, monkeypatch)
    if features is None:
        monkeypatch.setattr(claude_hook_argv, "native_hook_bridge_executable", lambda _feature: None)
        monkeypatch.setattr(claude_hook_argv, "_native_bridge_executable", lambda: None)
    else:
        _use_runtime(monkeypatch, tmp_path / "hol-guard-runtime", features)

    argv = claude_hook_argv.session_start_command_parts(context)

    assert argv == claude_hook_argv._python_session_start_command_parts(context)
    assert argv[1] == "-c"


@posix_only
def test_installer_keeps_the_python_command_for_another_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context = _own_home_context(tmp_path, monkeypatch)
    other = HarnessContext(home_dir=tmp_path / "other", workspace_dir=None, guard_home=context.guard_home)
    (tmp_path / "other").mkdir()
    _use_runtime(monkeypatch, tmp_path / "hol-guard-runtime", _BOTH_FEATURES)

    assert claude_hook_argv.session_start_command_parts(other)[1] == "-c"


def test_rust_lane_constants_match_the_installer() -> None:
    source = _RUST_SOURCE.read_text(encoding="utf-8")

    def rust_const(name: str) -> str:
        match = re.search(rf'const {name}: &str = "([^"]*)";', source)
        assert match is not None, name
        return match.group(1)

    assert rust_const("SESSION_START_MODE") == claude_hook_argv.NATIVE_CLAUDE_SESSION_START_MODE
    assert rust_const("SESSION_START_MARKER") == config.CLAUDE_GUARD_SESSION_START_HOOK_MARKER
    assert rust_const("SESSION_START_FEATURE") == claude_hook_argv.NATIVE_CLAUDE_SESSION_START_FEATURE
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
        "daemon_hook_command": [str(native_hook_force), "claude-hook-bridge", config.CLAUDE_GUARD_DAEMON_HOOK_MARKER],
        "bridge_config": {"state_path": str(tmp_path / "daemon-state.json"), "fallback_command": ["x"], "query": ""},
    }
    argv = (
        str(native_hook_force),
        "claude-hook-bridge",
        claude_hook_argv.NATIVE_CLAUDE_SESSION_START_MODE,
        config.CLAUDE_GUARD_SESSION_START_HOOK_MARKER,
        json.dumps(lane),
    )

    completed = subprocess.run(
        argv, input='{"hook_event_name":"SessionStart"}', capture_output=True, text=True, timeout=30
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "fallback ['a b', '雪'] {\"hook_event_name\":\"SessionStart\"}\n"
