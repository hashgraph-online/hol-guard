"""Bind parent print events to the SDK's complete host lifecycle telemetry."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .evidence import public_events, read_events


def complete_host_events(
    raw_log: Path, host_log: Path, replacements: dict[str, str]
) -> tuple[list[dict[str, Any]], list[str]]:
    parent = public_events(read_events(raw_log), replacements)
    observed = public_events(read_events(host_log), replacements)

    # Parent stdout and SDK telemetry are independent views of the same calls.
    # Require each parent request/start/completion to survive unchanged.
    def index(events: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
        out = {}
        for event in events:
            if event["type"] == "model_turn":
                pairs = [(("model", call["id"]), call) for call in event["calls"]]
            elif event["type"] in {"tool_execution_start", "tool_execution_end"}:
                pairs = [((event["type"], event["toolCallId"]), event)]
            else:
                continue
            for key, value in pairs:
                if key in out:
                    raise ValueError("duplicate SDK lifecycle evidence")
                out[key] = value
        return out

    parent_index, observed_index = index(parent), index(observed)
    if any(observed_index.get(key) != value for key, value in parent_index.items()):
        raise ValueError("parent and SDK lifecycle evidence disagree")
    parent_ids = {key[1] for key in parent_index if key[0] == "tool_execution_start"}
    delegated = sorted(
        key[1] for key in observed_index if key[0] == "tool_execution_start" and key[1] not in parent_ids
    )
    # Only the primary stream proves the overall agent reached its terminal turn.
    return observed + [event for event in parent if event["type"] == "agent_end"], delegated
