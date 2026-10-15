"""Ask the resident's direct lane about an Oh My Pi hook before the worker.

The Oh My Pi extension posts its hooks to the daemon, which has no Rust
bridge in front of it to ask the resident first. This sends the daemon's own
``/v1/hooks/pi`` and ``/v1/hooks/omp`` requests to the resident's
``hook_direct`` operation over the client the evidence drain uses, built as
the Rust bridges build theirs. An ``answer`` is the resident's harness
response, returned unchanged; a defer, an error, or a missing resident leaves
the request on the daemon path. Python never inspects the verdict.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from pathlib import Path
from typing import Any, cast

# `PI_DIRECT_HOOK=0` keeps every Oh My Pi hook on the daemon path, as the
# bridges' `HOL_GUARD_*_DIRECT_HOOK` switches do for theirs.
PI_DIRECT_SWITCH = "HOL_GUARD_PI_DIRECT_HOOK"
_PI_HARNESSES = frozenset({"pi", "omp"})
_DIRECT_RESULT_SCHEMA = "guard-hook-direct-result.v1"
# The bridges' `DIRECT_TIMEOUT` and `MINIMUM_DIRECT_TIMEOUT`.
_DIRECT_TIMEOUT_SECONDS = 1.0
_MINIMUM_DIRECT_TIMEOUT_SECONDS = 0.05


def pi_direct_enabled() -> bool:
    """`direct_enabled`: on unless the switch is exactly ``0``."""

    return os.environ.get(PI_DIRECT_SWITCH) != "0"


def pi_direct_request(
    *,
    harness: str,
    guard_home: Path,
    home_dir: str | None,
    workspace: str | None,
    payload: Mapping[str, object],
    budget_ms: int,
) -> bytes:
    """The ``hook_direct`` operation `request_body` sends for a bridge hook."""

    request: dict[str, object] = {
        "harness": harness,
        "guard_home": str(guard_home),
        "deadline_budget_ms": budget_ms,
        "payload": dict(payload),
    }
    if home_dir is not None:
        request["home_dir"] = home_dir
    if workspace is not None:
        request["workspace"] = workspace
    return json.dumps(
        {
            "operation": "hook_direct",
            # Without a budget the resident client falls back to 750 ms.
            "deadline_budget_ms": budget_ms,
            "request": request,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def answered_response(output: bytes | None) -> dict[str, object] | None:
    """`answered_response`: the harness response of an ``answer``, else ``None``."""

    if not output:
        return None
    try:
        result = json.loads(output)
    except ValueError:
        return None
    if (
        not isinstance(result, dict)
        or result.get("schema") != _DIRECT_RESULT_SCHEMA
        or result.get("outcome") != "answer"
    ):
        return None
    edge = result.get("edge")
    response = edge.get("harness_response") if isinstance(edge, dict) else None
    return cast("dict[str, object]", response) if isinstance(response, dict) else None


def pi_direct_answer(
    worker: Any,
    *,
    default_harness: str,
    params: Mapping[str, list[str]],
    payload: Mapping[str, object],
    home_dir: str | None,
    deadline: float,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, object] | None:
    """The resident's answer to an Oh My Pi hook, or ``None`` for the daemon path.

    ``worker`` is the daemon's hook worker, whose publisher holds the
    resident client, and ``home_dir`` the validated ``home`` query. The raw
    ``workspace`` query goes to the resident, which settles it as the daemon
    does. A ``runtime-harness`` query names another harness's review, so it
    keeps the daemon path.
    """

    from ..native_runtime import _isolated_environment

    runtime_harness = params.get("runtime-harness", [None])[-1]
    if (
        default_harness not in _PI_HARNESSES
        or (isinstance(runtime_harness, str) and runtime_harness.strip())
        or not pi_direct_enabled()
    ):
        return None
    workspace = params.get("workspace", [None])[-1]
    transport_factory = getattr(getattr(worker, "policy_snapshot_publisher", None), "direct_evidence_transport", None)
    if not callable(transport_factory):
        return None
    try:
        transport = cast("tuple[Path, Callable[..., bytes | None]] | None", transport_factory())
        if transport is None:
            return None
        executable, client = transport
        now = monotonic()
        direct_deadline = min(deadline, now + _DIRECT_TIMEOUT_SECONDS)
        remaining = direct_deadline - now
        if remaining < _MINIMUM_DIRECT_TIMEOUT_SECONDS:
            return None
        guard_home = Path(worker.guard_home)
        request = pi_direct_request(
            harness=default_harness,
            guard_home=guard_home,
            home_dir=home_dir,
            workspace=workspace if isinstance(workspace, str) else None,
            payload=payload,
            budget_ms=max(1, int(remaining * 1_000)),
        )
        output = client(
            executable=executable,
            guard_home=guard_home,
            environment=_isolated_environment(),
            payload=request,
            deadline_monotonic=direct_deadline,
        )
    except Exception:
        return None
    response = answered_response(output)
    if response is not None:
        with suppress(Exception):
            worker.metrics.record_route("native_resident")
    return response
