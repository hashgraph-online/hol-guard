"""Launch Codex through its local app-server for same-thread continuation.

The native runtime (``codex_remote_launch``) decides which argv a launch may
use and runs the launch sequence: it names each process to start, checks the
control socket, keeps or stops the app-server Guard started before, and
records the pid of a new one. Python only starts the processes it names. A
resident that cannot answer leaves the ordinary launch.
"""

from __future__ import annotations

import functools
import os
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, TypeGuard

_REMOTE_CONTROL_READY_TIMEOUT_SECONDS = 3.0
# One step may wait for the socket three times and spend a second reading the
# tracked command line and a second stopping it.
_PREPARE_BUDGET_SECONDS = 3 * _REMOTE_CONTROL_READY_TIMEOUT_SECONDS + 4.0
_MAX_PREPARE_STEPS = 3


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
    if not _prepare_remote(prefix, home_dir, socket_path, environment):
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


def _prepare_remote(prefix: Sequence[str], home_dir: Path, socket_path: Path, environment: dict[str, str]) -> bool:
    """Run each process the resident's launch sequence names; True when the remote TUI can connect."""

    request: dict[str, object] = {
        "home_dir": str(home_dir),
        "socket": str(socket_path),
        "seconds": _REMOTE_CONTROL_READY_TIMEOUT_SECONDS,
        "stage": "start",
    }
    for _ in range(_MAX_PREPARE_STEPS):
        answer = _ask("prepare", request, _PREPARE_BUDGET_SECONDS)
        if "launch" in answer:
            return answer["launch"] == "remote"
        env = answer.get("env")
        if isinstance(env, dict):
            environment.update({str(key): str(value) for key, value in env.items()})
        stage, run, spawn = answer.get("stage"), answer.get("run"), answer.get("spawn")
        if _argv(run) and isinstance(answer.get("timeout"), int):
            try:
                exit_code = subprocess.run(
                    [*prefix, *run],
                    capture_output=True,
                    text=True,
                    timeout=answer["timeout"],
                    check=False,
                    env=environment,
                ).returncode
            except (OSError, subprocess.TimeoutExpired):
                exit_code = None
            request = {**request, "stage": stage, "exit": exit_code}
        elif _argv(spawn):
            try:
                process = subprocess.Popen(
                    [*prefix, *spawn],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=dict(environment),
                    start_new_session=True,
                )
            except OSError:
                return False
            request = {**request, "stage": stage, "pid": process.pid}
        else:
            return False
    return False


def _argv(value: object) -> TypeGuard[list[str]]:
    return isinstance(value, list) and bool(value) and all(isinstance(part, str) for part in value)
