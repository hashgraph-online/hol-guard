"""Connector setup reviews: a command held only because Guard does not know the CLI it launches.

A review whose only cause is non-recognition, of a command that launches a
local CLI this device has never allowed or blocked, is a setup decision rather
than a per-action one. Its inbox row is still written, under the connector's
``connector:<identity_hash>:<action>`` group, so the Inbox can show one setup
card over every call waiting on it. The agent is told the CLI is not set up on
this device, not asked to approve the action.
"""

from __future__ import annotations

import logging
import re
import sqlite3
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from ..blocked_request_mode import connector_setup_reason
from .hook_native_exact_action import launch_cwd
from .hook_request_parsing import pre_tool_command

if TYPE_CHECKING:
    from ..local_cli_hook import SetupConnector

_LOGGER = logging.getLogger(__name__)

CONNECTOR_SETUP_REQUIRED = "connector_setup_required"
# Mirrors `connector_setup::NON_RECOGNITION_REASON_CODES`: any other review
# code carries a risk signal and keeps its per-action review.
NON_RECOGNITION_REASON_CODES = frozenset({"native_command_review_required"})
_SAFE_NAME = re.compile(r"[A-Za-z0-9@][A-Za-z0-9._@+/-]{0,63}")


def native_review_setup_connector(
    store: object,
    *,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    workspace: Path | None,
    home_dir: Path | None,
) -> SetupConnector | None:
    """The connector this review waits on, or ``None`` for an ordinary per-action review."""

    if native_result.get("reason_code") not in NON_RECOGNITION_REASON_CODES:
        return None
    command = pre_tool_command(payload)
    cwd = launch_cwd(payload, workspace)
    if command is None or cwd is None:
        return None
    from ..local_cli_hook import local_cli_setup_connector

    try:
        return local_cli_setup_connector(
            store=store,  # pyright: ignore[reportArgumentType]
            command=command,
            cwd=cwd,
            home_dir=home_dir,
        )
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error) as error:
        # Without an answer the review stays an ordinary per-action one.
        _LOGGER.warning("Connector setup lookup failed (%s)", type(error).__name__)
        return None


def connector_display_name(connector: SetupConnector) -> str:
    """The CLI name for agent text, or a generic one when it is not a plain name."""

    name = connector.name.strip()
    return name if _SAFE_NAME.fullmatch(name) else "this local CLI"


def connector_agent_reason(connector: SetupConnector, *, ask: bool) -> str:
    return connector_setup_reason(connector_display_name(connector), connector.surface, ask=ask)


def raise_connector_setup_notice(store: object, queued: object, connector: SetupConnector | None) -> None:
    """The desktop notice for a queued native connector row; an ordinary review raises none here."""

    if connector is None or not isinstance(queued, dict):
        return
    from ..approvals import notify_connector_setup

    notify_connector_setup(store, queued, connector_name=connector_display_name(connector))


__all__ = [
    "CONNECTOR_SETUP_REQUIRED",
    "NON_RECOGNITION_REASON_CODES",
    "connector_agent_reason",
    "connector_display_name",
    "native_review_setup_connector",
    "raise_connector_setup_notice",
]
