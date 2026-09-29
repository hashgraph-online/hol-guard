"""Scope optional CLI diagnostics without skipping registration validation."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

_COMMAND_PROBES_ENABLED: ContextVar[bool] = ContextVar("guard_diagnostic_command_probes", default=True)


@contextmanager
def without_command_probes() -> Iterator[None]:
    """Keep passive adapter checks while avoiding subprocess probes in global doctor."""

    token = _COMMAND_PROBES_ENABLED.set(False)
    try:
        yield
    finally:
        _COMMAND_PROBES_ENABLED.reset(token)


def skipped_command_probe(command: list[str]) -> dict[str, object] | None:
    if _COMMAND_PROBES_ENABLED.get():
        return None
    return {
        "command": command,
        "ok": None,
        "return_code": None,
        "stdout": "",
        "stderr": "",
        "skipped": True,
        "skip_reason": "global_doctor_passive_checks",
    }
