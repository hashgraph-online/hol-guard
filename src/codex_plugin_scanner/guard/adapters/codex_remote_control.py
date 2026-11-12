"""Launch Codex through its local app-server for same-thread continuation.

The native runtime (``codex_remote_launch``) decides which argv a launch may
use, whether the control socket is trusted and live, and whether the
app-server Guard started before can be kept, or is stopped or gone. Python
starts processes and records the direct app-server's pid. A resident that
cannot answer leaves the ordinary launch.
"""

from __future__ import annotations

import functools
import os
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

_REMOTE_CONTROL_START_TIMEOUT_SECONDS = 10
_REMOTE_CONTROL_READY_TIMEOUT_SECONDS = 3.0
# Beyond the ready wait, the resident may spend a second reading the tracked
# command line and a second stopping it.
_RECLAIM_BUDGET_SECONDS = _REMOTE_CONTROL_READY_TIMEOUT_SECONDS + 4.0


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

    return guarded_codex_launch_command_from_prefix(
        executable_prefix=(executable,),
        home_dir=home_dir,
        passthrough_args=passthrough_args,
        environ=environ,
    )


def guarded_codex_launch_command_from_prefix(
    *,
    executable_prefix: Sequence[str],
    home_dir: Path,
    passthrough_args: list[str],
    environ: Mapping[str, str] | None = None,
) -> list[str]:
    """Prepare Codex using an already authorized canonical launch prefix.

    Script-backed Codex launchers may require a verified interpreter and
    launcher path. Keeping the complete prefix prevents remote-control or
    app-server setup from resolving an attacker-swapped PATH entry or symlink.
    """

    prefix = list(executable_prefix)
    if not prefix or any(not isinstance(part, str) or not part for part in prefix):
        raise ValueError("Codex launch preparation requires a canonical executable prefix.")
    plain_command = [*prefix, *passthrough_args]
    socket_path = default_codex_control_socket(home_dir)
    tails = _launch_tails(passthrough_args, socket_path)
    if len(tails) < 2:
        return plain_command
    environment = dict(os.environ if environ is None else environ)
    codex_home = codex_home_for_user(home_dir)
    try:
        codex_home.mkdir(parents=True, exist_ok=True)
    except OSError:
        return plain_command
    environment["HOME"] = str(home_dir)
    environment["CODEX_HOME"] = str(codex_home)
    try:
        result = subprocess.run(
            [*prefix, "remote-control", "start", "--json"],
            capture_output=True,
            text=True,
            timeout=_REMOTE_CONTROL_START_TIMEOUT_SECONDS,
            check=False,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired):
        result = None
    managed_daemon_ready = result is not None and result.returncode == 0 and _wait_for_socket(socket_path)
    if not managed_daemon_ready and not _start_direct_app_server(
        executable_prefix=prefix,
        socket_path=socket_path,
        environment=environment,
    ):
        return plain_command
    return [*prefix, *tails[0]]


def guarded_codex_launch_command_candidates(
    *,
    executable: str,
    home_dir: Path,
    passthrough_args: list[str],
) -> tuple[list[str], ...]:
    """Preview every argv the remote-control launch preparation may select.

    This function intentionally performs no remote-control or app-server
    setup; it only asks the resident for the plan. Compatible TUI launches may
    select the remote argv when setup succeeds or the ordinary argv when it
    does not; incompatible subcommands have only the ordinary form.
    """

    tails = _launch_tails(passthrough_args, default_codex_control_socket(home_dir))
    return tuple([executable, *tail] for tail in tails)


def codex_remote_launch_environment(home_dir: Path) -> dict[str, str]:
    return {"CODEX_HOME": str(codex_home_for_user(home_dir))}


def _ask(op: str, fields: Mapping[str, object], budget: float | None = None) -> dict[str, Any]:
    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        return native_runner_authority("codex_remote_launch", {**fields, "op": op}, timeout_seconds=budget)
    except NativeRunnerAuthorityError:
        return {}


def _launch_tails(passthrough_args: list[str], socket_path: Path) -> list[list[str]]:
    """The argv tails after the executable, remote TUI first; only the plain one on a bad answer."""

    return [list(tail) for tail in _planned_tails(tuple(passthrough_args), str(socket_path))]


@functools.lru_cache(maxsize=32)
def _planned_tails(passthrough_args: tuple[str, ...], socket: str) -> tuple[tuple[str, ...], ...]:
    """One answer per launch, so preparation selects only among the previewed argv."""

    tails = _ask("plan", {"args": list(passthrough_args), "socket": socket}).get("tails")
    if isinstance(tails, list) and tails and all(isinstance(tail, list) for tail in tails):
        return tuple(tuple(str(arg) for arg in tail) for tail in tails)
    return (passthrough_args,)


def _wait_for_socket(socket_path: Path) -> bool:
    seconds = _REMOTE_CONTROL_READY_TIMEOUT_SECONDS
    return _ask("wait", {"socket": str(socket_path), "seconds": seconds}, seconds + 2.0).get("ready") is True


def _start_direct_app_server(
    *,
    executable_prefix: Sequence[str],
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
    except OSError:
        return False
    seconds = _REMOTE_CONTROL_READY_TIMEOUT_SECONDS
    state = _ask("reclaim", {"socket": str(socket_path), "seconds": seconds}, _RECLAIM_BUDGET_SECONDS).get("state")
    if state == "ready":
        return True
    if state != "free":
        return False
    try:
        process = subprocess.Popen(
            [*executable_prefix, "app-server", "--listen", f"unix://{socket_path}"],
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
