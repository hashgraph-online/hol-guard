"""Backfill unlisted CLI suggestions from commands Guard already paused.

Detection normally happens at hook time. Commands paused before a release that
could identify them (for example ``npx wrangler``) would otherwise only appear
after the next run, so the Extensions refresh replays recent paused commands
through the same identity rules. Replay never executes anything, never grants
authority and never bumps the observed count of a CLI that is already listed.
Each replayed CLI keeps the time of its paused request, so it can age out.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from ..store_local_cli_retention import later_timestamp
from .custom_extension_suggestion import observation_path_class
from .local_cli_compound import identify_unlisted_cli_identities
from .time_support import parse_utc_timestamp

if TYPE_CHECKING:
    from ..store import GuardStore

_LOGGER = logging.getLogger(__name__)
MAX_OBSERVED_CLI_REQUESTS = 500
MAX_OBSERVED_CLI_COMMANDS = 100
_MAX_COMMAND_CHARS = 4096


def commands_from_requests(records: Sequence[Mapping[str, object]]) -> tuple[tuple[str, Path], ...]:
    """Return unique ``(command, workspace)`` pairs from paused shell requests."""

    seen: dict[tuple[str, str], None] = {}
    for record in records[:MAX_OBSERVED_CLI_REQUESTS]:
        command = record.get("raw_command_text")
        workspace = record.get("workspace")
        if not isinstance(command, str) or not isinstance(workspace, str):
            continue
        command = command.strip()
        if not command or len(command) > _MAX_COMMAND_CHARS or command.startswith("tool:"):
            continue
        seen.setdefault((command, workspace), None)
        if len(seen) >= MAX_OBSERVED_CLI_COMMANDS:
            break
    return tuple((command, Path(workspace)) for command, workspace in seen)


def discover_observed_local_clis(store: GuardStore, *, seen_at: str, home_dir: Path | None) -> int:
    """Record CLIs from paused commands that are not listed yet; return how many were added."""

    known = {item.get("cli_id") for item in store.list_local_cli_items()}
    records = store.list_approval_requests(status=None, limit=MAX_OBSERVED_CLI_REQUESTS)
    latest_seen = _latest_request_times(records)
    added = 0
    for command, workspace in commands_from_requests(records):
        if not workspace.is_dir():
            continue
        for identity in identify_unlisted_cli_identities(command, cwd=workspace, home_dir=home_dir):
            if identity.cli_id in known:
                continue
            # The store skips history older than retention or than a Forget.
            store.record_local_cli_observation(
                identity,
                seen_at=latest_seen.get((command, str(workspace)), seen_at),
                source_path=identity.path_class or observation_path_class(identity.source_path),
                surface="cli",
                only_if_missing=True,
                replayed_at=seen_at,
            )
            known.add(identity.cli_id)
            added += 1
    return added


def _latest_request_times(records: Sequence[Mapping[str, object]]) -> dict[tuple[str, str], str]:
    latest: dict[tuple[str, str], str] = {}
    for record in records[:MAX_OBSERVED_CLI_REQUESTS]:
        command, workspace = record.get("raw_command_text"), record.get("workspace")
        # A retried request refreshes last_seen_at, not created_at.
        stamp = record.get("last_seen_at") or record.get("created_at")
        if not all(isinstance(value, str) for value in (command, workspace, stamp)):
            continue
        if parse_utc_timestamp(stamp) is None:
            continue
        key = (str(command).strip(), str(Path(str(workspace))))
        latest[key] = later_timestamp(latest.get(key), str(stamp))
    return latest


def backfill_observed_local_clis(store: GuardStore, *, seen_at: str, home_dir: Path | None) -> None:
    """Best-effort backfill; a failure leaves the listing as it was."""

    try:
        discover_observed_local_clis(store, seen_at=seen_at, home_dir=home_dir)
    except (OSError, RuntimeError, TypeError, ValueError, KeyError, UnicodeError, sqlite3.Error):
        _LOGGER.warning("observed CLI backfill failed", exc_info=True)


__all__ = ["backfill_observed_local_clis", "commands_from_requests", "discover_observed_local_clis"]
