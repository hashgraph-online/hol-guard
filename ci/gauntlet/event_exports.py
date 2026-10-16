"""Export actual tool events without system prompts or model reasoning."""

from typing import Any

from .input_evidence import redact_value

RESUMED = {"agent_start", "turn_start", "message_start", "tool_execution_start"}


def _terminal(event: dict[str, Any], later: list[dict[str, Any]], completed: bool) -> bool:
    """Whether an agent end finished the session.

    The SDK tags an end non-terminal while a background job the model started, such as a dev
    server, is still running, because that job's result could wake the agent again. Such an end
    still yielded the agent's turn. When the print process that wrote these events exited cleanly
    within its deadline and nothing resumed after the end, the session was disposed with the job,
    so it was the final settle.
    """
    if event.get("isTerminal") is True:
        return True
    return (
        completed
        and event.get("yielded") is True
        and event.get("awaitingAsyncWork") is True
        and not any(item.get("type") in RESUMED for item in later)
    )


def public_events(
    events: list[dict[str, Any]], replacements: dict[str, str], completed: bool = False
) -> list[dict[str, Any]]:
    """Public events of one print process; `completed` when it exited cleanly within its deadline."""
    selected = []
    for index, event in enumerate(events):
        kind = event["type"]
        if kind in {"tool_execution_start", "tool_execution_end"}:
            keys = ("type", "toolCallId", "toolName", "args", "result", "isError")
            selected.append({key: event[key] for key in keys if key in event})
        elif kind == "message_end" and event.get("message", {}).get("role") == "assistant":
            message = event["message"]
            selected.append(
                {
                    "type": "model_turn",
                    "provider": message.get("provider"),
                    "model": message.get("model"),
                    "stop_reason": message.get("stopReason"),
                    "calls": [
                        {"id": part.get("id"), "name": part.get("name"), "arguments": part.get("arguments")}
                        for part in message.get("content", [])
                        if part.get("type") == "toolCall"
                    ],
                }
            )
        elif kind == "agent_end":
            selected.append({"type": "agent_end", "terminal": _terminal(event, events[index + 1 :], completed)})
        elif kind in {"eval_bridge_start", "eval_bridge_end"}:
            raw = event.get("event")
            if not isinstance(raw, dict):
                raise ValueError("malformed SDK bridge event")
            keys = ("type", "toolCallId", "toolName", "input", "content", "details", "isError")
            selected.append(
                {
                    "type": kind,
                    "parentToolCallId": event.get("parentToolCallId"),
                    "parentToolCallIds": event.get("parentToolCallIds"),
                    "event": {key: raw[key] for key in keys if key in raw},
                }
            )
    return redact_value(selected, replacements)
