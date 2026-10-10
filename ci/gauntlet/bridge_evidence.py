"""Bind SDK eval bridge hooks to their model-selected, executing eval parent."""

from typing import Any


def bridge_calls(events: list[dict[str, Any]], parents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    parent_ids = {call["id"] for call in parents if call["name"] == "eval"}
    active: set[str] = set()
    pending: dict[str, dict[str, Any]] = {}
    seen: set[str] = set()
    calls = []
    for row in events:
        kind = row.get("type")
        key = row.get("toolCallId")
        if kind == "tool_execution_start" and key in parent_ids:
            active.add(key)
        elif kind == "tool_execution_end" and key in parent_ids:
            if any(item["parent"] == key for item in pending.values()):
                raise ValueError("eval ended with an incomplete bridge call")
            active.remove(key)
        elif kind in {"eval_bridge_start", "eval_bridge_end"}:
            parent, event = row.get("parentToolCallId"), row.get("event")
            if active != {parent} or not isinstance(event, dict):
                raise ValueError("eval bridge lacks an executing model parent")
            key, name = event.get("toolCallId"), event.get("toolName")
            if not isinstance(key, str) or not isinstance(name, str) or not key.startswith(f"js-{name}-"):
                raise ValueError("invalid SDK bridge identity")
            if kind == "eval_bridge_start":
                if (
                    key in seen
                    or key in {call["id"] for call in parents}
                    or event.get("type") != "tool_call"
                    or not isinstance(event.get("input"), dict)
                ):
                    raise ValueError("duplicate or malformed SDK bridge start")
                seen.add(key)
                pending[key] = {"parent": parent, "event": event}
            else:
                start = pending.pop(key, None)
                if (
                    not start
                    or start["parent"] != parent
                    or start["event"]["toolName"] != name
                    or event.get("type") != "tool_result"
                ):
                    raise ValueError("SDK bridge completion differs from its start")
                if type(event.get("isError")) is not bool:
                    raise ValueError("SDK bridge lacks completion status")
                if event.get("input") != start["event"]["input"]:
                    raise ValueError("SDK bridge input changed during execution")
                calls.append(
                    {
                        "id": key,
                        "name": name,
                        "args": start["event"]["input"],
                        "is_error": event["isError"],
                        "result": {"content": event.get("content"), "details": event.get("details")},
                        "bridge_parent_id": parent,
                    }
                )
    if pending:
        raise ValueError("incomplete SDK bridge inventory")
    return calls
