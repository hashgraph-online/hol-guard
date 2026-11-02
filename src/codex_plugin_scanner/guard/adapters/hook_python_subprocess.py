"""Bounded subprocess runner for Guard probes.

Probes run through the same bounded runner Guard uses to launch its native
runtime: no input, their own process group (a job object on Windows), a hard
deadline and one byte budget that stdout and stderr share. It needs no native
runtime, so a Python-only install can still attest its hook interpreter and
run the evaluator's host checks.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from ..codex_hook_launch_runtime import run_isolated_hook_process

_PROBE_TIMEOUT_SECONDS: Final = 15
_PROBE_OUTPUT_LIMIT_BYTES: Final = 64 * 1024


@dataclass(frozen=True, slots=True)
class ProbeResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    output_overflow: bool
    capture_incomplete: bool = False


def run_probe(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: float | None = None,
    output_limit_bytes: int | None = None,
) -> ProbeResult:
    """Run a probe with no stdin and strictly bounded output and duration.

    stdout and stderr share one output budget of at most 64 KiB.
    """

    timeout = float(_PROBE_TIMEOUT_SECONDS) if timeout_seconds is None else timeout_seconds
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or not 0 < timeout <= 3600
    ):
        raise ValueError("invalid probe timeout")
    output_limit = _PROBE_OUTPUT_LIMIT_BYTES if output_limit_bytes is None else output_limit_bytes
    if (
        isinstance(output_limit, bool)
        or not isinstance(output_limit, int)
        or not 0 < output_limit <= _PROBE_OUTPUT_LIMIT_BYTES
    ):
        raise ValueError("invalid probe output limit")
    result = run_isolated_hook_process(
        command,
        input_text="",
        cwd=cwd,
        environment=env,
        timeout_seconds=float(timeout),
        output_limit=output_limit,
    )
    capture_incomplete = result.containment_failed
    if result.returncode is None and not (result.timed_out or result.output_limit_exceeded or capture_incomplete):
        raise OSError("probe could not start")
    return ProbeResult(
        returncode=-1 if result.returncode is None else result.returncode,
        stdout=result.stdout.encode("utf-8"),
        stderr=result.stderr.encode("utf-8"),
        timed_out=result.timed_out,
        output_overflow=result.output_limit_exceeded,
        capture_incomplete=capture_incomplete,
    )


__all__ = ["ProbeResult", "run_probe"]
