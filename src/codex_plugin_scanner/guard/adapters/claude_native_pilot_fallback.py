"""Exact existing bridge completion after a private Linux native pilot attempt.

This file is entered with Python -I by exec, with an anonymous-memory stdin.
It retains the installed interpreter invocation, process group and absolute
CLOCK_MONOTONIC deadline. Request material never enters argv or persistent files.
"""

from __future__ import annotations

import base64
import io
import json
import os
import sys
import time
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from codex_plugin_scanner.guard.adapters import claude_daemon_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters.claude_native_pilot_record import load_record


def _handoff_integer(handoff: dict[str, object], name: str) -> int:
    value = handoff.get(name)
    if type(value) is not int:
        raise ValueError("claude_pilot_handoff_integer_invalid")
    return value


def complete(record_path: Path, event: str, handoff: dict[str, object]) -> str:
    record = load_record(record_path, event)
    deadline_ns = handoff.get("deadline_monotonic_ns")
    if type(deadline_ns) is not int or not 0 < deadline_ns <= time.monotonic_ns() + 8_000_000_000:
        raise ValueError("claude_pilot_handoff_deadline_invalid")
    deadline = deadline_ns / 1_000_000_000
    encoded = str(handoff["body_base64"])
    raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
    if len(raw) > 4_000_005:
        raise ValueError("claude_pilot_handoff_input_limit")
    decoded = io.TextIOWrapper(
        io.BytesIO(raw),
        encoding=sys.stdin.encoding or "utf-8",
        errors=sys.stdin.errors or "surrogateescape",
        newline="\n",  # Linux sys.stdin preserves CRLF and standalone CR.
    ).read(bridge._MAX_HOOK_INPUT_BYTES + 1)
    data = decoded.strip() or "{}"
    kind = handoff.get("kind")
    config = record["bridge"]
    if kind == "before_send":
        # No native HTTP hook POST occurred. This is the existing bridge with
        # the original remaining deadline, not a fresh eight-second attempt.
        previous_in, previous_out = sys.stdin, sys.stdout
        result = io.StringIO()
        previous_budget = bridge._HOOK_DEADLINE_SECONDS
        try:
            sys.stdin, sys.stdout = io.StringIO(decoded), result
            bridge._HOOK_DEADLINE_SECONDS = max(0.0, deadline - time.monotonic())
            bridge.main(
                state_path=config["state_path"],
                fallback_daemon_url=config["fallback_daemon_url"],
                fallback_command=tuple(config["fallback_command"]),
                query=config["query"],
            )
        finally:
            sys.stdin, sys.stdout = previous_in, previous_out
            bridge._HOOK_DEADLINE_SECONDS = previous_budget
        return result.getvalue()
    if kind == "response":
        return bridge._valid_hook_json_or_degraded(
            str(handoff["response"]),
            reason="daemon returned malformed hook JSON",
            data=data,
        )
    if kind == "http":
        error: Exception = bridge._DaemonHTTPError(_handoff_integer(handoff, "status"), str(handoff["detail"]))
    elif kind == "identity":
        error = ValueError(str(handoff["detail"]))
    elif kind == "io":
        number = _handoff_integer(handoff, "errno")
        error = OSError(number, os.strerror(number))
    elif kind == "timeout":
        error = TimeoutError(str(handoff["detail"]))
    else:
        raise ValueError("claude_pilot_handoff_kind_invalid")
    reason = bridge._daemon_failure_reason(error)
    failure_kind = bridge._daemon_failure_kind(error)
    if failure_kind == "authenticated-control-plane-failure":
        return bridge._authenticated_control_plane_failure(reason, data)
    if bridge._daemon_failure_is_recoverable(error):
        return bridge._recover_retry_or_fallback(
            reason,
            data,
            state_path=config["state_path"],
            fallback_daemon_url=config["fallback_daemon_url"],
            fallback_command=tuple(config["fallback_command"]),
            recovery_command=tuple(record["recovery_command"]),
            query=config["query"],
            deadline=deadline,
            failure_kind=failure_kind,
        )
    return bridge._run_local_fallback(reason, data, tuple(config["fallback_command"]), deadline=deadline)


def main() -> int:
    if len(sys.argv) != 3:
        raise ValueError("claude_pilot_handoff_argv_invalid")
    raw = sys.stdin.buffer.read(8_000_001)
    if len(raw) > 8_000_000:
        raise ValueError("claude_pilot_handoff_limit")
    handoff = json.loads(raw)
    if not isinstance(handoff, dict):
        raise ValueError("claude_pilot_handoff_invalid")
    sys.stdout.write(complete(Path(sys.argv[1]), sys.argv[2], handoff))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
