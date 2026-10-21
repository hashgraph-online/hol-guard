"""Connector setup reviews: a command held only because Guard does not know the CLI it launches.

A review whose only cause is non-recognition, of a command that launches a
local CLI this device has never allowed or blocked, is a setup decision rather
than a per-action one. Its inbox row is still written, under the connector's
``connector:<identity_hash>:<action>`` group, so the Inbox can show one setup
card over every call waiting on it. The agent is told the CLI is not set up on
this device. For a local CLI or script the row stays an ordinary review: the
agent waits for the user's Allow once or Always allow, as for any other review.
"""

from __future__ import annotations

import logging
import re
import sqlite3
import time
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Final

from ..blocked_request_mode import LOCAL_CONNECTOR_SURFACES, connector_setup_reason
from .hook_native_exact_action import launch_cwd, launch_path
from .hook_request_parsing import pre_tool_command

if TYPE_CHECKING:
    from ..connector_setup_context import ConnectorSetupAdvice
    from ..local_cli_hook import SetupConnector

_LOGGER = logging.getLogger(__name__)

CONNECTOR_SETUP_REQUIRED = "connector_setup_required"
# Mirrors `connector_setup::NON_RECOGNITION_REASON_CODES`: any other review
# code carries a risk signal and keeps its per-action review.
NON_RECOGNITION_REASON_CODES = frozenset(
    {"native_command_review_required", "native_workspace_containment_executable_outside_roots"}
)
# The context write is optional, so it runs only while the hook has time to
# spare: it keeps a margin for the response and skips a nearly spent budget.
_CONTEXT_SAFETY_MARGIN_SECONDS: Final = 0.35
_MIN_CONTEXT_BUDGET_SECONDS: Final = 0.25
_SAFE_NAME = re.compile(r"[A-Za-z0-9@][A-Za-z0-9._@+/-]{0,63}")
# What first stopped the connector, by the review reason that queued it.
_FIRST_CAUSE_BY_REASON_CODE = {
    "native_workspace_containment_executable_outside_roots": "exec_outside_roots",
    "native_command_review_required": "unrecognised_tool",
}


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
            path=launch_path(payload),
        )
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error) as error:
        # Without an answer the review stays an ordinary per-action one.
        _LOGGER.warning("Connector setup lookup failed (%s)", type(error).__name__)
        return None


def record_native_review_connector_context(
    store: object,
    *,
    connector: SetupConnector,
    native_result: Mapping[str, object],
    stored: Mapping[str, object],
    harness: str,
    workspace: Path | None,
    deadline: float | None = None,
) -> ConnectorSetupAdvice | None:
    """Keep the queued review's context with the connector, and read back what is already allowed.

    Best effort: the review is already queued, so a failure here only leaves the
    connector without context. It is skipped when the hook's ``deadline`` (a
    monotonic time) leaves too little time. The resident scrubs and caps every
    field, and nothing here writes a grant or a capability.
    """

    from ..connector_setup_context import record_connector_setup_context

    reason_code = native_result.get("reason_code")
    cause = _FIRST_CAUSE_BY_REASON_CODE.get(reason_code) if isinstance(reason_code, str) else None
    command = stored.get("raw_command_text")
    budget = None if deadline is None else deadline - time.monotonic() - _CONTEXT_SAFETY_MARGIN_SECONDS
    if budget is not None and budget < _MIN_CONTEXT_BUDGET_SECONDS:
        return None
    try:
        return record_connector_setup_context(
            store,  # pyright: ignore[reportArgumentType]
            cli_id=connector.cli_id,
            identity_hash=connector.identity_hash,
            first_blocked_cause=cause,
            trigger_summary=_without_operands(stored.get("trigger_summary"), command),
            why_now=_without_operands(stored.get("why_now"), command),
            harness=harness,
            workspace_label=workspace.name if workspace is not None else None,
            budget_seconds=budget,
        )
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error) as error:
        _LOGGER.warning("Connector setup context not recorded (%s)", type(error).__name__)
        return None


def _without_operands(text: object, command: object) -> str | None:
    """Review wording that repeats no argument of the command, which is never kept."""

    if not isinstance(text, str) or not text.strip():
        return None
    operands = command.split()[1:] if isinstance(command, str) else []
    return None if any(operand in text for operand in operands) else text


def connector_display_name(connector: SetupConnector) -> str:
    """The CLI name for agent text, or a generic one when it is not a plain name."""

    name = connector.name.strip()
    return name if _SAFE_NAME.fullmatch(name) else "this local CLI"


def connector_agent_reason(connector: SetupConnector, *, ask: bool, approvable: bool = True) -> str:
    return connector_setup_reason(connector_display_name(connector), connector.surface, ask=ask, approvable=approvable)


def connector_is_local(connector: SetupConnector | None) -> bool:
    """Whether the setup review is for a local CLI or script, which is an ordinary approvable review."""

    return connector is not None and connector.surface in LOCAL_CONNECTOR_SURFACES


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
    "connector_is_local",
    "native_review_setup_connector",
    "raise_connector_setup_notice",
    "record_native_review_connector_context",
]
