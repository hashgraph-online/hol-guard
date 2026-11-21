"""Adversarial daemon recovery coordination tests."""

# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false

from __future__ import annotations

import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_daemon_manage as daemon_manager_module


@pytest.fixture(autouse=True)
def _stub_locator_publish(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        daemon_manager_module,
        "publish_approval_center_locator",
        lambda _home, _url: None,
    )


def _old_generation() -> dict[str, object]:
    return {"started_at": (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()}


def _recent_generation() -> dict[str, object]:
    return {"started_at": datetime.now(timezone.utc).isoformat()}


def test_recovery_lock_serializes_separate_processes(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    with daemon_manager_module._guard_daemon_recovery_lock(guard_home):
        script = (
            "from pathlib import Path;"
            "from codex_plugin_scanner.guard.native_daemon_manage import _guard_daemon_recovery_lock;"
            f"home=Path({str(guard_home)!r});"
            "lock=_guard_daemon_recovery_lock(home);"
            "lock.__enter__();"
            "print('acquired', flush=True);"
            "lock.__exit__(None,None,None)"
        )
        process = subprocess.Popen(
            [sys.executable, "-c", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(0.2)
        assert process.poll() is None

    stdout, stderr = process.communicate(timeout=5)

    assert process.returncode == 0, stderr
    assert stdout.strip() == "acquired"


def test_managed_daemon_launch_disables_idle_shutdown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(daemon_manager_module, "_guard_home_is_ephemeral", lambda _home: False)

    child_env = daemon_manager_module._daemon_launcher_env(
        home_dir=tmp_path,
        guard_home=tmp_path / "guard-home",
    )

    assert child_env["GUARD_DAEMON_IDLE_TIMEOUT_SECONDS"] == "0"


@pytest.mark.parametrize(
    ("mode", "forwarded"),
    [("force", True), ("shadow", False), ("auto", False), ("off", False)],
)
def test_daemon_launch_forwards_only_a_pinned_native_runtime_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    forwarded: bool,
) -> None:
    runtime = tmp_path / "hol-guard-runtime"
    monkeypatch.setenv("HOL_GUARD_NATIVE", mode)
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(runtime))

    child_env = daemon_manager_module._daemon_launcher_env(home_dir=tmp_path)

    if forwarded:
        assert child_env["HOL_GUARD_NATIVE"] == mode
        assert child_env["HOL_GUARD_NATIVE_BINARY"] == str(runtime)
    else:
        assert "HOL_GUARD_NATIVE" not in child_env
        assert "HOL_GUARD_NATIVE_BINARY" not in child_env


def test_daemon_launch_drops_a_relative_native_runtime_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", "relative/hol-guard-runtime")

    child_env = daemon_manager_module._daemon_launcher_env(home_dir=tmp_path)

    assert "HOL_GUARD_NATIVE_BINARY" not in child_env


def test_daemon_launch_forwards_only_an_absolute_source_compiler_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Startup asks the compiler whether a release bundle is installed, so a
    # source checkout's daemon must see the compiler its caller named.
    compiler = tmp_path / "guard-command-source"
    monkeypatch.setenv("HOL_GUARD_NATIVE_SOURCE_COMPILER", str(compiler))
    monkeypatch.setenv("HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER", "relative/guard-command-source")

    child_env = daemon_manager_module._daemon_launcher_env(home_dir=tmp_path)

    assert child_env["HOL_GUARD_NATIVE_SOURCE_COMPILER"] == str(compiler)
    assert "HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER" not in child_env


def test_ephemeral_daemon_launch_retains_server_idle_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(daemon_manager_module, "_guard_home_is_ephemeral", lambda _home: True)

    child_env = daemon_manager_module._daemon_launcher_env(
        home_dir=tmp_path,
        guard_home=tmp_path / "guard-home",
    )

    assert "GUARD_DAEMON_IDLE_TIMEOUT_SECONDS" not in child_env
