#!/usr/bin/env python3
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from collections.abc import Callable
from typing import Any


def _ask() -> dict[str, str]:
    return {"decision": "ask"}


def _deny(reason: str) -> dict[str, str]:
    return {"decision": "deny", "reason": reason}


def evaluate_tool_call(
    payload: Any,
    *,
    which: Callable[[str], str | None] = shutil.which,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, str]:
    if not isinstance(payload, dict):
        return _deny("HOL_GUARD_INVALID_HOOK_INPUT")

    if payload.get("event") != "tool_call" or payload.get("tool_name") != "Bash":
        return _ask()

    tool_input = payload.get("input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str) or not command.strip():
        return _deny("HOL_GUARD_EMPTY_COMMAND")

    executable = which("hol-guard")
    if not executable:
        return _deny("HOL_GUARD_UNAVAILABLE")

    try:
        completed = run(
            [executable, "command", "test", command, "--json"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return _deny("HOL_GUARD_INSPECTION_FAILED")

    if completed.returncode != 0:
        return _deny("HOL_GUARD_INSPECTION_FAILED")

    try:
        verdict = json.loads(completed.stdout)
    except (json.JSONDecodeError, TypeError):
        return _deny("HOL_GUARD_INVALID_JSON")

    classification = verdict.get("classification") if isinstance(verdict, dict) else None
    explicitly_benign = isinstance(classification, dict) and classification.get("explicitly_benign") is True
    minimum_action = str(verdict.get("minimum_action", "")).lower() if isinstance(verdict, dict) else ""

    if explicitly_benign and minimum_action == "allow":
        return _ask()
    return _deny("HOL_GUARD_NOT_EXPLICITLY_BENIGN")


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, TypeError):
        result = _deny("HOL_GUARD_INVALID_HOOK_INPUT")
    else:
        result = evaluate_tool_call(payload)

    json.dump(result, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
