"""Strict resident transport for source-faithful shell helpers."""

from __future__ import annotations

import json
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
    if "spans" in fields:
        encoded = json.dumps(fields.pop("spans"), separators=(",", ":"))
        fields["spans_chunks"] = [encoded[i : i + 131_072] for i in range(0, len(encoded), 131_072)]
    paged = action == "heredocs"
    offset = 0
    rows: list[Any] = []
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise NativeShellHelpersError("native_shell_helpers_deadline")
        request: dict[str, object] = {
            "schema": "guard-shell-helpers-request.v1",
            "request_id": native_execution._request_id("shell_helpers"),
            "action": "heredocs_page" if paged else action,
            "input": {
                "command_chunks": [command[i : i + 131_072] for i in range(0, len(command), 131_072)],
                **fields,
                **({"offset": offset} if paged else {}),
            },
            "timeout_ms": max(1, int(remaining * 1000)),
        }
        frame = {"operation": "shell_helpers", "request": request}
        try:
            json.dumps(frame, ensure_ascii=False, allow_nan=False).encode("utf-8")
            packet_bytes = len(json.dumps(frame, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))
        except (TypeError, ValueError, UnicodeError) as error:
            raise NativeShellHelpersError("shell_helpers_invalid") from error
        if packet_bytes > 6 * 1024 * 1024:
            raise NativeShellHelpersError("shell_helpers_request_bounds")
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
        if answer["status"] != "ok" or type(answer["code"]) is not str or time.monotonic() >= deadline:
            raise NativeShellHelpersError("native_shell_helpers_rejected")
        result = answer["result"]
        if answer["code"] != "ok":
            if result is None and answer["code"] in {
                "shell_helpers_bounds",
                "shell_helpers_invalid",
                "shell_helpers_invalid_state",
                "shell_helpers_invalid_spans",
                "shell_helpers_invalid_operation",
                "shell_helpers_response_bounds",
                "shell_helpers_deadline",
            }:
                raise NativeShellHelpersError(answer["code"])
            raise NativeShellHelpersError("native_shell_helpers_malformed")
        if not paged:
            if not _valid(action, result):
                raise NativeShellHelpersError("native_shell_helpers_malformed")
            return result
        if type(result) is not dict or set(result) != {"items", "next_offset"} or not _valid(action, result["items"]):
            raise NativeShellHelpersError("native_shell_helpers_malformed")
        rows.extend(result["items"])
        following = result["next_offset"]
        if following is None:
            return rows
        if type(following) is not int or following <= offset or not result["items"]:
            raise NativeShellHelpersError("native_shell_helpers_malformed")
        offset = following


def _valid(action: str, value: Any) -> bool:
    if action == "interpreter_payload":
        return value is None or (
            type(value) is dict
            and set(value) == {"script_text", "tokens_consumed"}
            and type(value["script_text"]) is str
            and type(value["tokens_consumed"]) is int
            and cast(int, value["tokens_consumed"]) >= 0
        )
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
            and r[0] >= 0
            and r[1] > r[0]
            and (r[2] is None or (type(r[2]) is str and r[2] in {"'", '"'}))
            and type(r[3]) is int
            and r[3] >= 0
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
            and all(type(r[k]) is t and (t is not int or cast(int, r[k]) >= 0) for k, t in shape.items())
            and (action != "normalization" or all(type(s) is str for s in cast(list[Any], r["wrapper_chain"])))
            for r in rows
        )
    )
