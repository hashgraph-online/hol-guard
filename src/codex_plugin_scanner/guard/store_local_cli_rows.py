"""Row normalization and suggestion scores for local CLI observations."""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Mapping
from typing import cast

from .runtime.custom_extension_suggestion import SuggestionTool, suggestion_tool, suggestion_verdicts

_LOGGER = logging.getLogger(__name__)
# Native batches allow 4096 tools and a 2 MiB request; source paths can be
# long, so stay well inside both.
_SUGGESTION_BATCH = 256


def _with_suggestions(items: list[dict[str, object]]) -> list[dict[str, object]]:
    """Rank items in bounded native batches; items the resident cannot rank stay hidden."""

    ranked: list[tuple[dict[str, object], SuggestionTool]] = []
    for item in items:
        item["suggestion_score"] = 0
        item["suggestable"] = False
        kind = item.get("kind")
        name = item.get("name")
        if not isinstance(kind, str) or not isinstance(name, str):
            continue
        raw_path = item.get("source_path")
        raw_count = item.get("observed_count")
        raw_help = item.get("help_status")
        raw_surface = item.get("surface")
        tool = suggestion_tool(
            name=name,
            kind="script" if kind == "script" else "executable",
            source_path=raw_path if isinstance(raw_path, str) else None,
            observed_count=raw_count if isinstance(raw_count, int) else 0,
            help_status=raw_help if isinstance(raw_help, str) else None,
            surface=raw_surface if isinstance(raw_surface, str) else "cli",
        )
        ranked.append((item, tool))
    for offset in range(0, len(ranked), _SUGGESTION_BATCH):
        batch = ranked[offset : offset + _SUGGESTION_BATCH]
        verdicts = suggestion_verdicts([tool for _item, tool in batch])
        if verdicts is None:
            _LOGGER.warning("native custom extension suggestion unavailable for %d tools", len(batch))
            continue
        for (item, _tool), verdict in zip(batch, verdicts, strict=True):
            item["suggestion_score"] = verdict["score"]
            item["suggestable"] = verdict["suggestable"]
    return items


def _observation_from_row(row: object) -> dict[str, object]:
    values = _row_values(row, 14)
    surface = values[10] if values[10] in {"cli", "mcp", "package-scripts"} else "cli"
    source_label = values[12]
    command = values[13]
    scope = (
        "host-namespace"
        if isinstance(command, str) and command.startswith("observed-mcp:")
        else ("configured-connection" if values[11] is not None and values[1] != values[11] else "legacy-device")
    )
    return {
        "cli_id": values[0],
        "identity_hash": values[1],
        "kind": values[2],
        "name": values[3],
        "interpreter_name": values[4],
        "example_label": values[5],
        "observed_count": values[6],
        "last_seen_at": values[7],
        "source_path": values[8],
        "help_status": values[9],
        "surface": surface,
        "server_identity_hash": values[11],
        "source_label": source_label if isinstance(source_label, str) and source_label else None,
        **({"permission_scope": scope} if surface == "mcp" else {}),
    }


def _grant_from_row(row: object) -> dict[str, object]:
    values = _row_values(row, 5)
    return {
        "cli_id": values[0],
        "identity_hash": values[1],
        "state": values[2],
        "revision": values[3],
        "updated_at": values[4],
    }


def _merge_item(observation: dict[str, object], grant: Mapping[str, object] | None) -> dict[str, object]:
    state = "unset"
    stale = False
    grant_revision = None
    if grant is not None:
        state = str(grant["state"])
        stale = str(grant["identity_hash"]) != str(observation["identity_hash"])
        grant_revision = grant["revision"]
    return {
        **observation,
        "state": state,
        "stale": stale,
        "grant_revision": grant_revision,
    }


def _row_values(row: object, count: int) -> tuple[object, ...]:
    if isinstance(row, sqlite3.Row):
        values = tuple(cast(object, row[index]) for index in range(count))
        if len(values) != count:
            raise ValueError("invalid local CLI row")
        return values
    if isinstance(row, tuple):
        values = cast(tuple[object, ...], row)
        if len(values) != count:
            raise ValueError("invalid local CLI row")
        return values
    raise ValueError("invalid local CLI row")


def _row_int(value: object) -> int:
    if type(value) is not int:
        raise ValueError("invalid local CLI row")
    return value


def _row_text(row: object, index: int) -> str:
    values = _row_values(row, 5)
    value = values[index]
    if not isinstance(value, str):
        raise ValueError("invalid local CLI row")
    return value


def local_cli_rules_exist(connection: sqlite3.Connection, *, blocks_only: bool) -> bool:
    """Whether a device grant or per-command state exists; only blocks if asked."""

    if blocks_only:
        query = (
            "select exists(select 1 from local_cli_grant where state = 'blocked')"
            " or exists(select 1 from local_cli_command_grant where state = 'block')"
        )
    else:
        query = "select exists(select 1 from local_cli_grant) or exists(select 1 from local_cli_command_grant)"
    row = connection.execute(query).fetchone()
    return bool(row and row[0])
