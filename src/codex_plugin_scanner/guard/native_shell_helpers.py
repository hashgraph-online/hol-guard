"""Strict resident transport for source-faithful shell helpers."""

from __future__ import annotations

import time
from typing import Any, cast


class NativeShellHelpersError(RuntimeError, ValueError):
    """The native shell owner could not supply a bound answer."""


def runtime_key() -> tuple[object, ...]:
    from .native_context import _native_runtime_status_memo as native_runtime_status

    status = native_runtime_status()
    if not status.available or not status.compatible or status.identity is None:
        raise NativeShellHelpersError("native_shell_helpers_unavailable")
    identity = status.identity
    return (identity.path, identity.size, identity.mtime_ns, identity.sha256)


def call(action: str, command: str, **fields: Any) -> Any:
    from . import native_execution
    from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
    from .native_context import _native_runtime_status_memo as native_runtime_status

    deadline = time.monotonic() + 10.0
    home = _resolve_digest_home(None)
    if not ensure_resident_prerequisite(home):
        raise NativeShellHelpersError("native_shell_helpers_unavailable")
    status = native_runtime_status()
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise NativeShellHelpersError("native_shell_helpers_deadline")
    request: dict[str, object] = {
        "schema": "guard-shell-helpers-request.v1",
        "request_id": native_execution._request_id("shell_helpers"),
        "action": action,
        "input": {"command": command, **fields},
        "timeout_ms": max(1, int(remaining * 1000)),
    }
    digest = _canonical_request_sha256(request)
    answer = native_execution._resident_request(
        operation="shell_helpers",
        request=request,
        guard_home=home,
        timeout_seconds=max(0.001, deadline - time.monotonic()),
        required_feature="shell-helpers-v1",
        status=status,
        response_schema="guard-shell-helpers-result.v1",
        max_request_bytes=6 * 1024 * 1024,
    )
    if (
        answer is None
        or set(answer) != {"schema", "request_id", "request_sha256", "status", "code", "result"}
        or answer["schema"] != "guard-shell-helpers-result.v1"
    ):
        raise NativeShellHelpersError("native_shell_helpers_unavailable")
    if answer["request_id"] != request["request_id"] or answer["request_sha256"] != digest:
        raise NativeShellHelpersError("native_shell_helpers_binding")
    if answer["status"] != "ok" or answer["code"] != "ok" or time.monotonic() >= deadline:
        raise NativeShellHelpersError("native_shell_helpers_rejected")
    result = answer["result"]
    if not _valid(action, result):
        raise NativeShellHelpersError("native_shell_helpers_malformed")
    return result


def _valid(action: str, value: Any) -> bool:
    if action in {"masked_bodies", "masked_complete"}:
        return type(value) is str
    if action in {"trusted_path", "top_level"}:
        return type(value) is bool
    if action in {"segments", "redirects", "pipe_segments"}:
        return type(value) is list and all(type(v) is str for v in value)
    shapes = {
        "pipes": {"left": str, "right": str},
        "heredocs": {
            "delimiter": str,
            "body": str,
            "operator_start": int,
            "declaration_end": int,
            "body_start": int,
            "body_end": int,
            "end": int,
            "quoted": bool,
            "strip_tabs": bool,
        },
        "substitutions": {"kind": str, "body": str, "start": int, "body_start": int, "body_end": int, "end": int},
        "normalization": {"raw_command": str, "normalized_command": str, "wrapper_chain": list},
    }
    if action == "trace":
        return type(value) is list and all(
            type(r) is list
            and len(r) == 6
            and type(r[0]) is int
            and type(r[1]) is int
            and (r[2] is None or (type(r[2]) is str and r[2] in {"'", '"'}))
            and type(r[3]) is int
            and type(r[4]) is bool
            and type(r[5]) is bool
            for r in value
        )
    shape = shapes.get("substitutions" if action == "expanded_substitutions" else action)
    rows = [value] if action == "normalization" else value
    return (
        shape is not None
        and type(rows) is list
        and all(
            type(r) is dict
            and set(r) == set(shape)
            and all(type(r[k]) is t for k, t in shape.items())
            and (action != "normalization" or all(type(s) is str for s in cast(list[Any], r["wrapper_chain"])))
            for r in rows
        )
    )
