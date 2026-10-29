"""Connector setup reviews: a command held only because Guard does not know the CLI it launches.

A review whose only cause is non-recognition, of a command that launches a
local CLI this device has never allowed or blocked, is a setup decision rather
than a per-action one. Its inbox row is still written, under the connector's
``connector:<identity_hash>:<action>`` group, so the Inbox can show one setup
card over every call waiting on it. The agent is told the CLI is not set up on
this device. For a local CLI or script the row stays an ordinary review: the
agent waits for the user's Allow once or Always allow, as for any other review.

The resident looks the connector up inside the queue call, from the launch
``native_review_connector_lookup`` names, and answers what the notice needs
under ``connector_setup``.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from ..local_cli_hook import launch_env
from .hook_native_exact_action import launch_cwd, launch_path
from .hook_request_parsing import pre_tool_command

CONNECTOR_SETUP_REQUIRED = "connector_setup_required"
# Mirrors `connector_setup::NON_RECOGNITION_REASON_CODES`: any other review
# code carries a risk signal and keeps its per-action review.
NON_RECOGNITION_REASON_CODES = frozenset(
    {"native_command_review_required", "native_workspace_containment_executable_outside_roots"}
)


def native_review_connector_lookup(
    *,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    workspace: Path | None,
    home_dir: Path | None,
) -> dict[str, object] | None:
    """The launch the queue call looks the review's connector up from, or ``None`` for an ordinary review."""

    if native_result.get("reason_code") not in NON_RECOGNITION_REASON_CODES:
        return None
    command = pre_tool_command(payload)
    cwd = launch_cwd(payload, workspace)
    if command is None or cwd is None:
        return None
    return {
        "command": command,
        "cwd": str(cwd),
        "home_dir": None if home_dir is None else str(home_dir),
        "user_home": str(Path.home()),
        "env": launch_env(launch_path(payload)),
    }


def raise_connector_setup_notice(store: object, queued: object) -> None:
    """The desktop notice for a queued native connector row; an ordinary review raises none here."""

    if not isinstance(queued, dict):
        return
    setup = queued.get("connector_setup")
    name = setup.get("name") if isinstance(setup, dict) else None
    if not isinstance(name, str) or not name:
        return
    from ..approvals import notify_connector_setup

    notify_connector_setup(store, queued, connector_name=name)


__all__ = [
    "CONNECTOR_SETUP_REQUIRED",
    "NON_RECOGNITION_REASON_CODES",
    "native_review_connector_lookup",
    "raise_connector_setup_notice",
]
