"""Export actual tool events without system prompts or model reasoning."""

from typing import Any

from .input_evidence import redact_value


def public_events(events: list[dict[str, Any]], replacements: dict[str, str]) -> list[dict[str, Any]]:
    selected = []
    for event in events:
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
            selected.append({"type": "agent_end", "terminal": event.get("isTerminal") is True})
        elif kind in {"eval_bridge_start", "eval_bridge_end"}:
            raw = event.get("event")
            if not isinstance(raw, dict):
                raise ValueError("malformed SDK bridge event")
            keys = ("type", "toolCallId", "toolName", "input", "content", "details", "isError")
            selected.append(
                {
                    "type": kind,
                    "parentToolCallId": event.get("parentToolCallId"),
                    "event": {key: raw[key] for key in keys if key in raw},
                }
            )
    return redact_value(selected, replacements)
