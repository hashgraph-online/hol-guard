"""The hand-off from ``daemon --serve`` to the native daemon process."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import native_serve


def test_native_serve_is_the_default_unless_opted_out(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    called: list[object] = []
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.native_hook_bridge.native_hook_bridge_executable",
        lambda *args, **kwargs: called.append(args) or tmp_path / "runtime",
    )
    monkeypatch.setenv(native_serve.NATIVE_SERVE_ENV, "0")
    assert native_serve.native_serve_executable(tmp_path) is None
    assert called == []

    monkeypatch.delenv(native_serve.NATIVE_SERVE_ENV, raising=False)
    expected = tmp_path / "runtime" if os.name == "posix" else None
    assert native_serve.native_serve_executable(tmp_path) == expected


def test_launch_configuration_names_the_daemon_and_its_state(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    nonce = "ab" * 32
    monkeypatch.setenv("HOL_GUARD_DAEMON_LAUNCH_NONCE", nonce)

    config = native_serve.launch_configuration(tmp_path, 5474, user_home=tmp_path / "home")

    assert config["schema"] == native_serve.LAUNCH_SCHEMA
    assert config["guard_home"] == os.path.abspath(tmp_path)
    assert config["port"] == 5474
    assert config["store_path"] == os.path.join(os.path.abspath(tmp_path), "guard.db")
    assert config["source"] == "default"
    assert config["launch_nonce"] == nonce
    assert config["user_home"] == str(tmp_path / "home")
    assert isinstance(config["cli_command"], list) and config["cli_command"]
    state = config["state"]
    assert isinstance(state, dict)
    assert state["compatibility_version"] == 2
    assert {"package_version", "executable", "source_root", "runtime_fingerprint"} <= set(state)


def test_launch_configuration_drops_a_malformed_nonce(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOL_GUARD_DAEMON_LAUNCH_NONCE", "short")

    assert "launch_nonce" not in native_serve.launch_configuration(tmp_path, 0)


@pytest.mark.skipif(os.name != "posix", reason="the native daemon serves POSIX hosts")
def test_exec_hands_the_launch_line_to_the_runtime_on_stdin(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    runtime = tmp_path / "hol-guard-runtime"
    monkeypatch.setattr(native_serve, "native_serve_executable", lambda guard_home: runtime)
    saved_stdin = os.dup(0)
    seen: dict[str, object] = {}

    def fake_execv(path: str, argv: list[str]) -> None:
        seen["path"] = path
        seen["argv"] = argv
        seen["line"] = os.read(0, 1 << 16)

    monkeypatch.setattr(native_serve.os, "execv", fake_execv)
    try:
        native_serve.exec_native_daemon(tmp_path, 5474)
    finally:
        os.dup2(saved_stdin, 0)
        os.close(saved_stdin)

    assert seen["path"] == str(runtime)
    assert seen["argv"] == [
        str(runtime),
        "daemon-serve",
        "--guard-home",
        os.path.abspath(tmp_path),
        "--port",
        "5474",
    ]
    line = seen["line"]
    assert isinstance(line, bytes) and line.endswith(b"\n")
    assert json.loads(line)["port"] == 5474
