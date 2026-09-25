"""Parse bounded Codex CLI JSON traces into a privacy-safe structure.

A valid trace proves only Codex stream structure. Host identity, a Guard
receipt, and side-effect correlation are still required before an installed-
host evaluator can make an enforcement claim.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

MAX_TRACE_BYTES = 1_048_576
MAX_TRACE_EVENTS = 256
MAX_IDENTIFIER_CHARS = 256
MAX_STATUS_CHARS = 128
MAX_COMMAND_CHARS = 65_536

_SUCCESS_TURN_STATUSES = frozenset({"complete", "completed", "ok", "success", "succeeded"})
_ERROR_ITEM_TYPES = frozenset({"error", "turn_error"})
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*\Z")
_STARTED_COMMAND_STATUSES = frozenset({"in_progress", "pending"})
_COMPLETED_COMMAND_STATUSES = frozenset({"completed", "failed", "declined", "cancelled", "interrupted"})


class CodexEventTraceError(ValueError):
    """A Codex ``exec --json`` stream failed bounded structural validation."""


@dataclass(frozen=True, slots=True)
class CodexEventTraceSummary:
    """Structural result that deliberately excludes command text and output."""

    thread_id: str
    command_id: str
    command_status: str
    command_exit_code: int | None
    turn_status: str

    @property
    def status(self) -> str:
        """Return the completed command status."""

        return self.command_status

    @property
    def exit_code(self) -> int | None:
        """Return the completed command exit code."""

        return self.command_exit_code

    def to_dict(self) -> dict[str, object]:
        """Return the bounded summary without raw command material."""

        return {
            "thread_id": self.thread_id,
            "command_id": self.command_id,
            "command_status": self.command_status,
            "command_exit_code": self.command_exit_code,
            "turn_status": self.turn_status,
        }


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-standard JSON constant: {value}")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _decode_events(payload: str | bytes) -> list[dict[str, object]]:
    if isinstance(payload, bytes):
        if len(payload) > MAX_TRACE_BYTES:
            raise CodexEventTraceError("Codex event trace exceeds the byte limit")
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            raise CodexEventTraceError("Codex event trace is not valid UTF-8") from None
    elif isinstance(payload, str):
        try:
            encoded = payload.encode("utf-8")
        except UnicodeEncodeError:
            raise CodexEventTraceError("Codex event trace cannot be encoded as UTF-8") from None
        if len(encoded) > MAX_TRACE_BYTES:
            raise CodexEventTraceError("Codex event trace exceeds the byte limit")
        text = payload
    else:
        raise CodexEventTraceError("Codex event trace must be text or UTF-8 bytes")

    lines = [line.removesuffix("\r") for line in text.split("\n")]
    if lines and lines[-1] == "":
        lines.pop()
    if not lines:
        raise CodexEventTraceError("Codex event trace is empty")
    if len(lines) > MAX_TRACE_EVENTS:
        raise CodexEventTraceError("Codex event trace exceeds the event limit")

    events: list[dict[str, object]] = []
    for event_number, line in enumerate(lines, start=1):
        if not line.strip():
            raise CodexEventTraceError(f"Codex event {event_number} is empty")
        try:
            decoded = json.loads(
                line,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_json_constant,
            )
        except (json.JSONDecodeError, RecursionError, ValueError, TypeError):
            raise CodexEventTraceError(f"Codex event {event_number} is malformed JSON") from None
        if not isinstance(decoded, dict):
            raise CodexEventTraceError(f"Codex event {event_number} is not an object")
        events.append(cast(dict[str, object], decoded))
    return events


def _bounded_string(value: object, *, field: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise CodexEventTraceError(f"Codex event has an invalid {field}")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise CodexEventTraceError(f"Codex event has an invalid {field}")
    return value


def _bounded_command(value: object, *, field: str, origin: str = "Codex event") -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_COMMAND_CHARS:
        raise CodexEventTraceError(f"{origin} has an invalid {field}")
    if any(
        (ord(character) < 0x20 and character not in {"\n", "\r", "\t"}) or ord(character) == 0x7F for character in value
    ):
        raise CodexEventTraceError(f"{origin} has an invalid {field}")
    return value


def _bounded_identifier(value: object, *, field: str) -> str:
    identifier = _bounded_string(value, field=field, maximum=MAX_IDENTIFIER_CHARS)
    if _IDENTIFIER.fullmatch(identifier) is None:
        raise CodexEventTraceError(f"Codex event has an invalid {field}")
    return identifier


def _event_type(event: Mapping[str, object]) -> str:
    return _bounded_string(event.get("type"), field="event type", maximum=MAX_STATUS_CHARS)


def _mapping(value: object, *, field: str) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise CodexEventTraceError(f"Codex event has an invalid {field}")
    return dict(cast(Mapping[str, object], value))


def _command_id(item: Mapping[str, object]) -> str:
    return _bounded_identifier(item.get("id"), field="command ID")


def _command_text(item: Mapping[str, object], expected_command: str) -> None:
    command = _bounded_command(item.get("command"), field="command")
    if command != expected_command:
        raise CodexEventTraceError("Codex command does not match the expected command")


def _optional_thread_id(event: Mapping[str, object], thread_id: str | None) -> None:
    if "thread_id" not in event:
        return
    observed = _bounded_identifier(event["thread_id"], field="thread ID")
    if thread_id is None or observed != thread_id:
        raise CodexEventTraceError("Codex event thread ID does not match")


def _validate_optional_string(item: Mapping[str, object], field: str, maximum: int) -> None:
    if field in item:
        _bounded_string(item[field], field=field, maximum=maximum)


def _validate_optional_output(item: Mapping[str, object]) -> None:
    if "aggregated_output" in item and not isinstance(item["aggregated_output"], str):
        raise CodexEventTraceError("Codex command output has an invalid type")


def _validate_exit_code(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not -(2**63) <= value <= 2**63 - 1:
        raise CodexEventTraceError("Codex command has an invalid exit code")
    return value


def _validate_command_item(
    item: Mapping[str, object],
    *,
    expected_command: str,
    completion: bool,
) -> tuple[str, str | None, int | None]:
    command_id = _command_id(item)
    _command_text(item, expected_command)
    _validate_optional_output(item)
    _validate_optional_string(item, "status", MAX_STATUS_CHARS)
    if not completion:
        if "status" in item and item["status"] not in _STARTED_COMMAND_STATUSES:
            raise CodexEventTraceError("Codex command has an unsupported start status")
        return command_id, None, None

    status = _bounded_string(item.get("status"), field="command status", maximum=MAX_STATUS_CHARS)
    if status not in _COMPLETED_COMMAND_STATUSES:
        raise CodexEventTraceError("Codex command has an unsupported completion status")
    raw_exit = item.get("exit_code")
    exit_code = None if raw_exit is None and status == "declined" else _validate_exit_code(raw_exit)
    return command_id, status, exit_code


def parse_codex_event_trace(payload: str | bytes, expected_command: str) -> CodexEventTraceSummary:
    """Validate one bounded Codex ``exec --json`` NDJSON trace.

    The parser checks one thread, one turn, and exactly one expected command.
    Non-zero command exit codes are retained as observations; they are not
    interpreted as Guard decisions because a denied hook can produce one.
    """

    expected_command = _bounded_command(expected_command, field="expected command", origin="Caller")
    events = _decode_events(payload)
    thread_id: str | None = None
    turn_started = False
    turn_completed = False
    turn_status: str | None = None
    command_starts: dict[str, str] = {}
    command_results: dict[str, tuple[str, int | None]] = {}

    for event_number, raw_event in enumerate(events, start=1):
        event = _mapping(raw_event, field="event")
        event_type = _event_type(event)
        if event_type == "thread.started":
            if event_number != 1 or thread_id is not None:
                raise CodexEventTraceError("Codex thread started more than once or out of order")
            thread_id = _bounded_identifier(event.get("thread_id"), field="thread ID")
            continue

        _optional_thread_id(event, thread_id)
        if thread_id is None:
            raise CodexEventTraceError("Codex trace is missing thread.started")
        if turn_completed:
            raise CodexEventTraceError("Codex event appears after turn.completed")

        if event_type == "turn.started":
            if turn_started:
                raise CodexEventTraceError("Codex turn started more than once")
            turn_started = True
            continue

        if event_type in {"agent_message", "reasoning"}:
            if not turn_started:
                raise CodexEventTraceError("Codex item appears before turn.started")
            continue

        if event_type == "error":
            raise CodexEventTraceError("Codex trace contains an error event")

        if event_type in {"item.started", "item.completed"}:
            if not turn_started:
                raise CodexEventTraceError("Codex item appears before turn.started")
            item = _mapping(event.get("item"), field="item")
            _optional_thread_id(item, thread_id)
            item_type = _bounded_string(item.get("type"), field="item type", maximum=MAX_STATUS_CHARS)
            if item_type in _ERROR_ITEM_TYPES:
                raise CodexEventTraceError("Codex trace contains an error item")
            if item_type in {"agent_message", "reasoning"}:
                continue
            if item_type != "command_execution":
                raise CodexEventTraceError("Codex trace contains an unsupported item type")

            is_completion = event_type == "item.completed"
            command_id, status, exit_code = _validate_command_item(
                item,
                expected_command=expected_command,
                completion=is_completion,
            )
            if is_completion:
                if command_id not in command_starts:
                    raise CodexEventTraceError("Codex command completed without starting")
                if command_id in command_results:
                    raise CodexEventTraceError("Codex command completed more than once")
                if status is None:
                    raise CodexEventTraceError("Codex command completion has no status")
                command_results[command_id] = (status, exit_code)
            else:
                if command_id in command_starts:
                    raise CodexEventTraceError("Codex command started more than once")
                if command_starts:
                    raise CodexEventTraceError("Codex trace contains an extra command")
                command_starts[command_id] = expected_command
            continue

        if event_type == "turn.completed":
            if not turn_started:
                raise CodexEventTraceError("Codex turn completed without starting")
            if "status" in event:
                turn_status = _bounded_string(event["status"], field="turn status", maximum=MAX_STATUS_CHARS)
                if turn_status not in _SUCCESS_TURN_STATUSES:
                    raise CodexEventTraceError("Codex turn did not complete successfully")
            else:
                turn_status = "completed"
            if event.get("error") is not None:
                raise CodexEventTraceError("Codex turn contains an error")
            if event.get("exit_code") is not None and _validate_exit_code(event["exit_code"]) != 0:
                raise CodexEventTraceError("Codex turn has a non-zero exit code")
            if not command_starts:
                raise CodexEventTraceError("Codex trace is missing the expected command")
            if set(command_starts) != set(command_results):
                raise CodexEventTraceError("Codex command has no matching completion")
            turn_completed = True
            continue

        raise CodexEventTraceError(f"Codex event {event_number} has an unsupported type")

    if thread_id is None:
        raise CodexEventTraceError("Codex trace is missing thread.started")
    if not turn_started:
        raise CodexEventTraceError("Codex trace is missing turn.started")
    if not turn_completed:
        raise CodexEventTraceError("Codex trace is missing turn.completed")
    if len(command_starts) != 1 or len(command_results) != 1:
        raise CodexEventTraceError("Codex trace must contain exactly one command")

    command_id = next(iter(command_starts), None)
    if command_id is None:
        raise CodexEventTraceError("Codex trace is missing the expected command")
    command_status, command_exit_code = command_results[command_id]
    if turn_status is None:
        raise CodexEventTraceError("Codex turn completion has no status")
    return CodexEventTraceSummary(
        thread_id=thread_id,
        command_id=command_id,
        command_status=command_status,
        command_exit_code=command_exit_code,
        turn_status=turn_status,
    )


__all__ = [
    "MAX_TRACE_BYTES",
    "MAX_TRACE_EVENTS",
    "CodexEventTraceError",
    "CodexEventTraceSummary",
    "parse_codex_event_trace",
]
