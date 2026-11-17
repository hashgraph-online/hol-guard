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


def guarded_codex_launch_command(
    *,
    executable: str,
    home_dir: Path,
    passthrough_args: list[str],
    environ: Mapping[str, str] | None = None,
) -> list[str]:
    """Return a remote TUI command when Codex app-server control is available."""

    return guarded_codex_launch_command_from_prefixes(
        executable_prefixes=((executable,),),
        home_dir=home_dir,
        passthrough_args=passthrough_args,
        environ=environ,
    )


def guarded_codex_launch_command_from_prefixes(
    *,
    executable_prefixes: Sequence[Sequence[str]],
    home_dir: Path,
    passthrough_args: list[str],
    environ: Mapping[str, str] | None = None,
) -> list[str]:
    """Prepare Codex using the one already authorized canonical launch prefix the candidates share.

    Script-backed Codex launchers may require a verified interpreter and
    launcher path. Keeping the complete prefix prevents remote-control or
    app-server setup from resolving an attacker-swapped PATH entry or symlink.
    """

    plan = _launch_plan(executable_prefixes, home_dir, passthrough_args)
    if not _argv(plan.get("remote")) or not _argv(plan.get("prefix")):
        return _plain(plan, executable_prefixes, passthrough_args)
    environment = dict(os.environ if environ is None else environ)
    if _prepare_remote(plan, home_dir, environment):
        return list(plan["remote"])
    return _plain(plan, executable_prefixes, passthrough_args)


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

    plan = _launch_plan(((executable,),), home_dir, passthrough_args)
    candidates = plan.get("candidates")
    if isinstance(candidates, list) and candidates and all(_argv(candidate) for candidate in candidates):
        return tuple(list(candidate) for candidate in candidates)
    return ([executable, *passthrough_args],)


def _ask(op: str, fields: Mapping[str, object], budget: float | None = None) -> dict[str, Any]:
    from .native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        return native_runner_authority("codex_remote_launch", {**fields, "op": op}, timeout_seconds=budget)
    except NativeRunnerAuthorityError:
        return {}


def _launch_plan(prefixes: Sequence[Sequence[str]], home_dir: Path, passthrough_args: list[str]) -> Mapping[str, Any]:
    """The resident's launch plan: the one authorized prefix, the control socket, and the
    ordinary and remote commands. A refusal raises; a resident that cannot answer yields
    no plan, which leaves the ordinary launch."""

    return _planned(tuple(tuple(prefix) for prefix in prefixes), str(home_dir), tuple(passthrough_args))


@functools.lru_cache(maxsize=32)
def _planned(
    prefixes: tuple[tuple[str, ...], ...], home_dir: str, passthrough_args: tuple[str, ...]
) -> Mapping[str, Any]:
    """One answer per launch, so preparation selects only among the previewed argv."""

    plan = _ask(
        "launch",
        {"prefixes": [list(prefix) for prefix in prefixes], "home_dir": home_dir, "args": list(passthrough_args)},
    )
    if isinstance(plan.get("refusal"), str):
        raise ValueError(plan["refusal"])
    return plan


def _plain(plan: Mapping[str, Any], prefixes: Sequence[Sequence[str]], passthrough_args: list[str]) -> list[str]:
    """The ordinary command: the plan's, or the single prefix's when the resident gave none."""

    if _argv(plan.get("plain")):
        return list(plan["plain"])
    return [*next((prefix for prefix in prefixes if prefix), ()), *passthrough_args]


def _prepare_remote(plan: Mapping[str, Any], home_dir: Path, environment: dict[str, str]) -> bool:
    """Run each process the resident's launch sequence names; True when the remote TUI can connect."""

    prefix = list(plan["prefix"])
    request: dict[str, object] = {
        "home_dir": str(home_dir),
        "socket": str(plan["socket"]),
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
