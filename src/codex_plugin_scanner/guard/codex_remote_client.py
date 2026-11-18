"""Launch Codex through its local app-server for same-thread continuation.

The native runtime (``codex_remote_launch``) decides which argv a launch may
use and runs the whole launch sequence: it checks the control socket, starts
``remote-control`` or a direct app-server, keeps or stops the app-server Guard
started before, and records the pid of a new one. Python asks for the one argv
to run. A resident that cannot answer leaves the ordinary launch.
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, TypeGuard

# One launch may run ``remote-control`` for ten seconds and wait for the socket
# at each of three steps; the resident bounds the call at this budget.
_RUN_BUDGET_SECONDS = 55.0


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
    """Run the launch sequence in the runtime with the one already authorized canonical launch prefix.

    Script-backed Codex launchers may require a verified interpreter and
    launcher path. Keeping the complete prefix prevents remote-control or
    app-server setup from resolving an attacker-swapped PATH entry or symlink.
    """

    answer = _ask(
        "run",
        {
            "prefixes": [list(prefix) for prefix in executable_prefixes],
            "home_dir": str(home_dir),
            "args": list(passthrough_args),
            "environ": dict(os.environ if environ is None else environ),
        },
        _RUN_BUDGET_SECONDS,
    )
    if isinstance(answer.get("refusal"), str):
        raise ValueError(answer["refusal"])
    if _argv(answer.get("argv")):
        return list(answer["argv"])
    return [*next((prefix for prefix in executable_prefixes if prefix), ()), *passthrough_args]


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

    plan = _ask("launch", {"prefixes": [[executable]], "home_dir": str(home_dir), "args": list(passthrough_args)})
    if isinstance(plan.get("refusal"), str):
        raise ValueError(plan["refusal"])
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


def _argv(value: object) -> TypeGuard[list[str]]:
    return isinstance(value, list) and bool(value) and all(isinstance(part, str) for part in value)
