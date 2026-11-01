"""Bounded subprocess runner for Guard probes.

The native runtime (`bounded-probe --stdin`) runs the probe with no stdin, in
its own process group (a job object on Windows), with a hard deadline and one
byte budget that stdout and stderr share. This module validates the budget and
frames the request. Without a runtime the probe does not run.
"""

from __future__ import annotations

import base64
import binascii
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from ..mdm.runtime_request import runtime_answer

_FEATURE: Final = "native-bounded-probe-v1"
_COMMAND: Final = "bounded-probe"
_SCHEMA: Final = "bounded-probe.v1"
_PROBE_TIMEOUT_SECONDS: Final = 15
_PROBE_OUTPUT_LIMIT_BYTES: Final = 128 * 1024
# Time for the runtime to reap the probe after its own deadline.
_RUNTIME_GRACE_SECONDS: Final = 5.0
_ANSWER_LIMIT_BYTES: Final = 512 * 1024
_EXECUTION_FAILED: Final = "guard_hook_python_probe_execution_failed"


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

    stdout and stderr share one output budget of at most 128 KiB.
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
    request = {
        "schema": _SCHEMA,
        "argv": list(command),
        "cwd": str(cwd),
        "env": dict(env),
        "timeout_seconds": float(timeout),
        "output_limit_bytes": output_limit,
    }
    answer = runtime_answer(
        _FEATURE,
        _COMMAND,
        request,
        output_limit=_ANSWER_LIMIT_BYTES,
        timeout_seconds=timeout + _RUNTIME_GRACE_SECONDS,
    )
    if answer is None or "error" in answer:
        raise RuntimeError(_EXECUTION_FAILED)
    return _result(answer)


def _result(answer: dict[str, object]) -> ProbeResult:
    returncode = answer.get("returncode")
    flags = [answer.get(name) for name in ("timed_out", "output_overflow", "capture_incomplete")]
    if (
        isinstance(returncode, bool)
        or not isinstance(returncode, int)
        or not all(isinstance(flag, bool) for flag in flags)
    ):
        raise RuntimeError(_EXECUTION_FAILED)
    streams: list[bytes] = []
    for name in ("stdout", "stderr"):
        value = answer.get(name)
        if not isinstance(value, str):
            raise RuntimeError(_EXECUTION_FAILED)
        try:
            streams.append(base64.b64decode(value, validate=True))
        except (binascii.Error, ValueError):
            raise RuntimeError(_EXECUTION_FAILED) from None
    return ProbeResult(
        returncode=returncode,
        stdout=streams[0],
        stderr=streams[1],
        timed_out=flags[0] is True,
        output_overflow=flags[1] is True,
        capture_incomplete=flags[2] is True,
    )


__all__ = ["ProbeResult", "run_probe"]
