"""Launch Codex through its local app-server for same-thread continuation."""

from __future__ import annotations

import os
import subprocess
import time
from collections.abc import Mapping
from pathlib import Path

_REMOTE_CONTROL_START_TIMEOUT_SECONDS = 10
_REMOTE_CONTROL_READY_TIMEOUT_SECONDS = 3.0
_REMOTE_INCOMPATIBLE_SUBCOMMANDS = frozenset(
    {
        "app-server",
        "apply",
        "cloud",
        "completion",
        "debug",
        "doctor",
        "exec",
        "exec-server",
        "features",
        "help",
        "login",
        "logout",
        "mcp",
        "mcp-server",
        "plugin",
        "remote-control",
        "review",
        "sandbox",
        "update",
    }
)


def codex_home_for_user(home_dir: Path) -> Path:
    return home_dir / ".codex"


def default_codex_control_socket(home_dir: Path) -> Path:
    return codex_home_for_user(home_dir) / "app-server-control" / "app-server-control.sock"


def guarded_codex_launch_command(
    *,
    executable: str,
    home_dir: Path,
    passthrough_args: list[str],
    environ: Mapping[str, str] | None = None,
) -> list[str]:
    """Return a remote TUI command when Codex app-server control is available."""

    plain_command = [executable, *passthrough_args]
    if not _supports_remote_tui(passthrough_args):
        return plain_command
    environment = dict(environ or os.environ)
    codex_home = codex_home_for_user(home_dir)
    try:
        codex_home.mkdir(parents=True, exist_ok=True)
    except OSError:
        return plain_command
    environment["HOME"] = str(home_dir)
    environment["CODEX_HOME"] = str(codex_home)
    try:
        result = subprocess.run(
            [executable, "remote-control", "start", "--json"],
            capture_output=True,
            text=True,
            timeout=_REMOTE_CONTROL_START_TIMEOUT_SECONDS,
            check=False,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired):
        result = None
    socket_path = default_codex_control_socket(home_dir)
    managed_daemon_ready = result is not None and result.returncode == 0 and _wait_for_socket(socket_path)
    if not managed_daemon_ready and not _start_direct_app_server(
        executable=executable,
        socket_path=socket_path,
        environment=environment,
    ):
        return plain_command
    return [executable, "--remote", f"unix://{socket_path}", *passthrough_args]


def codex_remote_launch_environment(home_dir: Path) -> dict[str, str]:
    return {"CODEX_HOME": str(codex_home_for_user(home_dir))}


def _supports_remote_tui(passthrough_args: list[str]) -> bool:
    if any(argument == "--remote" or argument.startswith("--remote=") for argument in passthrough_args):
        return False
    if any(argument in {"--help", "-h", "--version", "-V"} for argument in passthrough_args):
        return False
    return not passthrough_args or passthrough_args[0] not in _REMOTE_INCOMPATIBLE_SUBCOMMANDS


def _wait_for_socket(socket_path: Path) -> bool:
    deadline = time.monotonic() + _REMOTE_CONTROL_READY_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        try:
            if _socket_is_trusted(socket_path):
                return True
        except OSError:
            return False
        time.sleep(0.05)
    return False


def _socket_is_trusted(socket_path: Path) -> bool:
    getuid = getattr(os, "getuid", None)
    if not callable(getuid):
        return False
    try:
        stat_result = socket_path.stat()
        parent_stat = socket_path.parent.stat()
    except OSError:
        return False
    return (
        socket_path.is_socket()
        and stat_result.st_uid == getuid()
        and parent_stat.st_uid == getuid()
        and parent_stat.st_mode & 0o022 == 0
    )


def _start_direct_app_server(
    *,
    executable: str,
    socket_path: Path,
    environment: Mapping[str, str],
) -> bool:
    if os.name == "nt":
        return False
    if _wait_for_socket(socket_path):
        return True
    try:
        socket_path.parent.mkdir(parents=True, exist_ok=True)
        socket_path.parent.chmod(0o700)
        process = subprocess.Popen(
            [executable, "app-server", "--listen", f"unix://{socket_path}"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=dict(environment),
            start_new_session=True,
        )
        pid_path = socket_path.parent / "hol-guard-app-server.pid"
        pid_path.write_text(str(process.pid), encoding="utf-8")
        pid_path.chmod(0o600)
    except OSError:
        return False
    return _wait_for_socket(socket_path)
