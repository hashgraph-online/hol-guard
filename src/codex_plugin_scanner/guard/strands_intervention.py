from __future__ import annotations

import json
import subprocess
from collections.abc import Mapping
from typing import Any

from strands.hooks import BeforeToolCallEvent  # pyright: ignore[reportMissingImports]
from strands.interventions import (  # pyright: ignore[reportMissingImports]
    Deny,
    InterventionHandler,
    OnError,
    Proceed,
)


class HolGuardIntervention(InterventionHandler):
    """Fail-closed HOL Guard intervention for command-bearing Strands tools.

    ``command_fields`` maps a Strands tool name to the input field containing the
    command text. Tools not present in the mapping are left unchanged.

    The intervention uses HOL Guard's side-effect-free ``command test`` surface.
    It proceeds only for an explicitly benign classification whose minimum action
    is ``allow``. Review/risky/unknown output, malformed output, CLI failures, and
    timeouts are denied before the protected tool executes.
    """

    def __init__(
        self,
        command_fields: Mapping[str, str],
        *,
        executable: str = "hol-guard",
        timeout_seconds: float = 10.0,
    ) -> None:
        super().__init__()
        self._command_fields = dict(command_fields)
        self._executable = executable
        self._timeout_seconds = timeout_seconds

    @property
    def name(self) -> str:
        return "hol-guard"

    @property
    def on_error(self) -> OnError:
        return "deny"

    def before_tool_call(self, event: BeforeToolCallEvent, **_kwargs: Any) -> Proceed | Deny:
        tool_use = event.tool_use
        tool_name = tool_use.get("name")
        command_field = self._command_fields.get(tool_name) if isinstance(tool_name, str) else None
        if command_field is None:
            return Proceed()

        tool_input = tool_use.get("input")
        if not isinstance(tool_input, dict):
            return Deny(reason="HOL Guard: command tool input was not structured as expected.")

        command = tool_input.get(command_field)
        if not isinstance(command, str) or not command.strip():
            return Deny(reason="HOL Guard: command text is missing or invalid.")

        try:
            completed = subprocess.run(
                [self._executable, "command", "test", command, "--json"],
                capture_output=True,
                text=True,
                timeout=self._timeout_seconds,
                check=False,
            )
            if completed.returncode != 0:
                return Deny(reason="HOL Guard: command inspection failed.")
            result = json.loads(completed.stdout)
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            return Deny(reason="HOL Guard: command inspection was unavailable or invalid.")

        classification = result.get("classification") if isinstance(result, dict) else None
        explicitly_benign = isinstance(classification, dict) and classification.get("explicitly_benign") is True
        minimum_action = result.get("minimum_action") if isinstance(result, dict) else None

        if explicitly_benign and minimum_action == "allow":
            return Proceed(reason="HOL Guard classified the command as explicitly benign.")

        return Deny(reason="HOL Guard: command requires review before execution.")
