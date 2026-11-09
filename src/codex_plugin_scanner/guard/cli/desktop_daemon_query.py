"""Answers the native daemon asks of Guard's CLI.

The daemon's native edge serves every HTTP route itself. Some answers depend
on how this Guard was installed (the package surface, the trusted update
environment, the harness adapters it ships), which only the installed CLI can
describe; the edge runs this hidden command for those and reads one JSON
envelope, ``{"status": <http status>, "body": <object>}``, from its output.
"""

from __future__ import annotations

import json
import platform
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from ...version import __version__

if TYPE_CHECKING:
    from ..adapters.base import HarnessContext
    from ..store import GuardStore

# ``manager.GUARD_DAEMON_COMPATIBILITY_VERSION``.
DAEMON_COMPATIBILITY_VERSION = 2
_HEADLESS_OPERATIONS = ("install", "repair", "remove", "status", "scan", "policy_sync")
_SAFE_FAILURE_REASONS = {
    "offline": "Local Guard daemon is unavailable.",
    "timeout": "Local Guard daemon did not answer before the browser timeout.",
    "unauthorized": "Dashboard session is missing or stale.",
    "unsupported": "Harness is not supported by this daemon.",
    "confirmation_required": "Remove actions need the harness confirmation phrase.",
}
_NATIVE_UNAVAILABLE: tuple[int, dict[str, object]] = (503, {"error": "native_handler_policy_unavailable"})

Answer = tuple[int, dict[str, object]]


def _update_status(guard_home: Path, payload: dict[str, object]) -> Answer:
    del payload
    from .update_commands import build_guard_update_status_payload

    return 200, build_guard_update_status_payload(guard_home=guard_home)


def _harness_items(guard_home: Path) -> tuple[HarnessContext, list[dict[str, object]]]:
    from ..adapters.base import HarnessContext
    from ..store import GuardStore
    from .install_commands import list_harness_setup_items

    context = HarnessContext(home_dir=Path.home().resolve(), workspace_dir=None, guard_home=guard_home)
    return context, list_harness_setup_items(context, GuardStore(guard_home))


def _harnesses(guard_home: Path, payload: dict[str, object]) -> Answer:
    del payload
    from ..harness_version_api import attach_version_compatibility

    context, items = _harness_items(guard_home)
    return 200, {"items": attach_version_compatibility(items, context)}


def _capabilities(guard_home: Path, payload: dict[str, object]) -> Answer:
    """The capability report less ``auth_state``, which the edge knows."""

    del payload
    from ..native_daemon_handler import NativeDaemonHandlerError, native_detection_app_statuses

    _, items = _harness_items(guard_home)
    listed = [item for item in items if isinstance(item.get("harness"), str)]
    try:
        app_statuses = native_detection_app_statuses([item.get("status") for item in listed], guard_home=guard_home)
    except NativeDaemonHandlerError:
        return _NATIVE_UNAVAILABLE
    supported = [
        {
            "display_name": item.get("display_name"),
            "harness": item["harness"],
            "status": app_status,
            "command_available": bool(item.get("command_available")),
            "headless_actions": list(_HEADLESS_OPERATIONS[:-1]),
            "safe_failure_reasons": dict(_SAFE_FAILURE_REASONS),
        }
        for item, app_status in zip(listed, app_statuses, strict=True)
    ]
    return 200, {
        "command_available": any(bool(item.get("command_available")) for item in items),
        "daemon": {
            "compatibility_version": DAEMON_COMPATIBILITY_VERSION,
            "package_version": __version__,
            "platform": platform.system().lower() or "unknown",
        },
        "headless_api": {"execution_mode": "guard_cloud_command_queue", "operations": list(_HEADLESS_OPERATIONS)},
        "package_firewall_api": {
            "execution_mode": "guard_cloud_command_queue",
            "operations": ["status", "connect", "install", "repair", "test", "audit", "sync", "remove"],
        },
        "safe_failure_reasons": dict(_SAFE_FAILURE_REASONS),
        "supported_harnesses": sorted(str(item["harness"]) for item in supported),
        "items": supported,
    }


def _store(guard_home: Path) -> GuardStore:
    from ..store import GuardStore

    return GuardStore(guard_home)


def _policy(guard_home: Path, payload: dict[str, object]) -> Answer:
    from ..daemon.managed_controls_api import managed_policy_rows

    harness = payload.get("harness")
    harness_filter = harness if isinstance(harness, str) else None
    store = _store(guard_home)
    return 200, {
        "items": managed_policy_rows(store, harness_filter),
        "cloud_exceptions": store.list_cloud_exceptions(harness=harness_filter),
    }


def _cloud_review(guard_home: Path, payload: dict[str, object]) -> Answer:
    del payload
    from ..daemon.cloud_review_settings import cloud_review_settings_status

    return 200, cloud_review_settings_status(_store(guard_home))


def _cloud_actions_status(guard_home: Path, payload: dict[str, object]) -> Answer:
    del payload
    from ..daemon.cloud_actions_status import CloudActionsStatusUnavailableError, cloud_actions_local_status

    try:
        return 200, cloud_actions_local_status(_store(guard_home))
    except CloudActionsStatusUnavailableError:
        return 503, {
            "error": "status_unavailable",
            "message": "Guard could not read the Cloud actions status on this computer.",
        }


_QUERIES: dict[str, Callable[[Path, dict[str, object]], Answer]] = {
    "capabilities": _capabilities,
    "cloud-actions-status": _cloud_actions_status,
    "cloud-review": _cloud_review,
    "policy": _policy,
    "harnesses": _harnesses,
    "update-status": _update_status,
}


# The edge refuses request bodies past 1 MiB; leave room for the JSON envelope.
_INPUT_LIMIT_BYTES = 2 * 1024 * 1024


def read_daemon_query_input(stream: TextIO) -> str | None:
    """The query input the edge wrote to stdin, or ``None`` past the limit."""

    text = stream.read(_INPUT_LIMIT_BYTES + 1)
    return None if len(text) > _INPUT_LIMIT_BYTES else text


def run_daemon_query(query: str, guard_home: Path, output_stream: TextIO, input_text: str | None = "") -> int:
    """Print the answer to ``query`` as one JSON envelope; 2 for a bad request."""

    answer = _QUERIES.get(query)
    payload: object = {}
    if input_text is None:
        payload = None
    elif input_text:
        try:
            payload = json.loads(input_text)
        except json.JSONDecodeError:
            payload = None
    if answer is None or not isinstance(payload, dict):
        output_stream.write(json.dumps({"error": "unknown_query"}) + "\n")
        return 2
    status, body = answer(guard_home, payload)
    output_stream.write(json.dumps({"status": status, "body": body}, separators=(",", ":"), default=str) + "\n")
    return 0


__all__ = ["DAEMON_COMPATIBILITY_VERSION", "run_daemon_query"]
