"""Peel the inert command prefixes and settings that native authority classified."""

from __future__ import annotations

import os
from collections.abc import Iterator, Mapping
from contextlib import contextmanager


def _read_command_prefix(command: list[str], *, drop_data: bool = False) -> tuple[list[str], dict[str, str], bool]:
    """Ask native authority where the command's own program stands.

    The native model reads `CI=1 command bun run build` as `bun run build`
    with an inert assignment. It owns the whole reading: which names stand
    transparently in front of a program, where each one's operands end, and
    which settings a prefix may carry. A second copy of any of that is what
    drift looks like — the copy here once held `env` as a bare spelling, so
    `/usr/bin/env CI=1 pytest -q` reached the planners with `/usr/bin/env` as
    its program and was refused, though native authority had already read it
    as the `pytest -q` it runs.

    With `drop_data`, a plain-data setting (`REPORT_DIR=/tmp/r`) is dropped
    too: callers ask for that only after the original drew a contained
    receipt, since native authority grants a read-only profile only when that
    profile's environment filter would drop the setting, and a workspace
    receipt still runs the original as issued.

    The last answer says whether a setting was dropped rather than carried, so
    a caller can tell a core that is the command as issued from one that is
    not without peeling the same command a second time.

    An unreadable answer peels nothing, so the command reaches the planners as
    it was written and they refuse what native authority has not read.
    """
    from ..native_restricted_pytest import restricted_native

    reply = restricted_native(
        "command_prefix_split",
        {"command": command, "drop_data": drop_data},
        (dict,),
    )
    index = reply.get("core_index")
    carried = reply.get("assignments")
    dropped = reply.get("dropped_data")
    if (
        type(index) is not int
        or not 0 <= index <= len(command)
        or type(carried) is not list
        or type(dropped) is not bool
    ):
        return command, {}, False
    assignments: dict[str, str] = {}
    for pair in carried:
        if type(pair) is not list or len(pair) != 2 or not all(type(word) is str for word in pair):
            return command, {}, False
        assignments[pair[0]] = pair[1]
    return command[index:], assignments, dropped


def _split_command_prefix(command: list[str], *, drop_data: bool = False) -> tuple[list[str], dict[str, str]]:
    """Where the command's own program stands, and the settings peeled off it."""
    core, assignments, _dropped = _read_command_prefix(command, drop_data=drop_data)
    return core, assignments


def _peel_for_receipt(command: list[str]) -> tuple[list[str], dict[str, str], bool]:
    """Peel with data settings dropped, and say whether one was dropped.

    A dropped setting means the core is not the command as issued, so the
    original must draw a contained receipt before the core runs.
    """
    return _read_command_prefix(command, drop_data=True)


@contextmanager
def _assignments_applied(assignments: Mapping[str, str]) -> Iterator[None]:
    """Export the assignments to the runner's source environment for one run.

    Each restricted profile still filters that environment, exactly as it
    filters a variable the agent's shell exported.
    """
    previous = {name: os.environ.get(name) for name in assignments}
    os.environ.update(assignments)
    try:
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def peel_run_prefixes(command: list[str]) -> tuple[list[str], int | None]:
    """Ask native authority for the program a contained run stands behind.

    `nice -n 10 timeout 20 pytest -q` runs `pytest -q` for twenty seconds. A
    system `timeout` bounds how long the work may take and not what it may
    do, and the launchers the parser reads set scheduling, buffering or the
    shell's own `exec`, so the program behind them is the program native
    authority judged. The whole reading — which names launch a program, which
    durations `timeout` accepts, and the inert prefix split between them —
    belongs to that authority, which answers it in one call, so the sink
    neither keeps a second copy of the grammar nor pays a round trip per
    prefix on the hook's path.

    The seconds are returned with the core so the run the clock was peeled
    from is still bounded. `None` means nothing bounds it.

    An unreadable answer peels nothing, so the command reaches the planners
    as it was written and they refuse what native authority has not read.
    """
    from ..native_restricted_pytest import restricted_native

    reply = restricted_native("run_prefix_peel", {"command": command}, (dict,))
    core = reply.get("core")
    seconds = reply.get("seconds")
    if (
        type(core) is not list
        or not all(type(word) is str for word in core)
        or (seconds is not None and type(seconds) is not int)
    ):
        return command, None
    return core, seconds
