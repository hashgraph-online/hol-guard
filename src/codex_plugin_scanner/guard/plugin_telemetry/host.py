"""Calls the native ``plugin-telemetry-host`` command.

The native runtime owns plugin install counts and update checks: the consent
state and device key, the weekly report, the downloads from HOL and the
comparison with what is installed. These CLIs only parse arguments and print
its answer.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

PLUGIN_TELEMETRY_HOST_COMMAND = "plugin-telemetry-host"
PLUGIN_TELEMETRY_HOST_FEATURE = "plugin-telemetry-host-v1"
PRIVACY_URL = "https://hol.org/privacy#guard-plugin-install-telemetry"
# Downloading the listing index can take a minute on a cold HOL server, and a
# send then posts the report.
_TIMEOUT_SECONDS = 120.0
_OUTPUT_LIMIT_BYTES = 1024 * 1024


class PluginTelemetryError(RuntimeError):
    """The request could not be completed; the message is safe to print."""


def host_request(command: str, guard_home: Path, **fields: object) -> dict[str, Any]:
    """The native host's ``result`` for ``command``, or its message as an error."""

    from ..codex_hook_launch_runtime import run_isolated_hook_process
    from ..native_runtime import native_runtime_status

    status = native_runtime_status()
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or PLUGIN_TELEMETRY_HOST_FEATURE not in status.capabilities.features
    ):
        raise PluginTelemetryError("This command needs a newer Guard native runtime. Run: hol-guard update")
    runtime = status.identity.path
    request = {"command": command, "guardHome": str(guard_home), **fields}
    completed = run_isolated_hook_process(
        (str(runtime), PLUGIN_TELEMETRY_HOST_COMMAND, "--stdin"),
        input_text=json.dumps(request, sort_keys=True, separators=(",", ":")),
        cwd=runtime.parent,
        environment=dict(os.environ),
        timeout_seconds=_TIMEOUT_SECONDS,
        output_limit=_OUTPUT_LIMIT_BYTES,
    )
    if (
        completed.returncode != 0
        or completed.timed_out
        or completed.output_limit_exceeded
        or completed.containment_failed
    ):
        raise PluginTelemetryError("The Guard native runtime did not answer.")
    try:
        response = json.loads(completed.stdout)
    except ValueError as error:
        raise PluginTelemetryError("The Guard native runtime did not answer.") from error
    if not isinstance(response, dict):
        raise PluginTelemetryError("The Guard native runtime did not answer.")
    if response.get("ok") is not True or not isinstance(response.get("result"), dict):
        message = response.get("error")
        raise PluginTelemetryError(message if isinstance(message, str) and message else "The request failed.")
    return response["result"]


def user_home() -> str:
    """The home the agent runtimes keep their plugins under."""

    return str(Path.home())
