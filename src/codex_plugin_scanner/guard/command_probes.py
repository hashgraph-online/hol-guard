"""Scope optional CLI diagnostics without skipping registration validation."""

from __future__ import annotations

import os
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

_COMMAND_PROBES_ENABLED: ContextVar[bool] = ContextVar("guard_diagnostic_command_probes", default=True)


@contextmanager
def without_command_probes() -> Iterator[None]:
    """Keep passive adapter checks while avoiding subprocess probes in global doctor."""

    token = _COMMAND_PROBES_ENABLED.set(False)
    try:
        yield
    finally:
        _COMMAND_PROBES_ENABLED.reset(token)


def command_probes_enabled() -> bool:
    """Whether this caller lets a harness CLI probe run."""

    return _COMMAND_PROBES_ENABLED.get()


#: The caller environment a harness CLI probe runs with.
_PROBE_ENV_KEYS = (
    "PATH",
    "PATHEXT",
    "HOME",
    "USERPROFILE",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
    "TMPDIR",
    "APPDATA",
    "LOCALAPPDATA",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "LANG",
    "LC_ALL",
)


def _run_command_probe(
    command: list[str],
    timeout_seconds: int = 5,
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Run a harness CLI's ``--help`` or ``--version`` through the native ``command_probe`` kind.

    The working directory and the probe environment are facts of the calling
    Python process, so they travel with the request until the resident request
    envelope stamps them.
    """

    from .native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    if not command_probes_enabled():
        # The runtime answers the record that says nothing ran.
        return native_runner_authority("command_probe", {"command": [str(part) for part in command], "probes": False})
    request = {
        "command": [str(part) for part in command],
        "cwd": str((cwd or Path.cwd()).absolute()),
        "env": {key: os.environ[key] for key in _PROBE_ENV_KEYS if key in os.environ} if env is None else dict(env),
        "timeout_seconds": timeout_seconds,
    }
    try:
        return native_runner_authority("command_probe", request, timeout_seconds=timeout_seconds + 10.0)
    except NativeRunnerAuthorityError:
        # A diagnostic probe never fails the doctor; it reports that nothing ran.
        return {"command": command, "ok": False, "return_code": None, "stdout": "", "stderr": "probe unavailable"}


__all__ = ["_run_command_probe", "command_probes_enabled", "without_command_probes"]
