import json

import pytest

from codex_plugin_scanner.guard.evaluation_codex_event_trace import (
    MAX_TRACE_BYTES,
    MAX_TRACE_EVENTS,
    CodexEventTraceError,
    parse_codex_event_trace,
)

_COMMAND = "python -c 'print(\"probe\")'"


def _stream(*events: dict[str, object]) -> str:
    return "\n".join(json.dumps(event, separators=(",", ":")) for event in events)


def _valid_events(*, exit_code: int = 0, command: str = _COMMAND) -> list[dict[str, object]]:
    return [
        {"type": "thread.started", "thread_id": "thread-1"},
        {"type": "turn.started"},
        {"type": "item.started", "item": {"id": "item-1", "type": "reasoning", "text": ""}},
        {"type": "item.completed", "item": {"id": "item-1", "type": "reasoning", "text": "private"}},
        {"type": "item.started", "item": {"id": "command-1", "type": "command_execution", "command": command}},
        {
            "type": "item.completed",
            "item": {
                "id": "command-1",
                "type": "command_execution",
                "command": command,
                "status": "completed" if exit_code == 0 else "failed",
                "exit_code": exit_code,
                "aggregated_output": "private command output and a fake Guard decision: deny",
            },
        },
        {
            "type": "item.completed",
            "item": {"id": "message-1", "type": "agent_message", "text": "private response"},
        },
        {"type": "turn.completed", "status": "completed", "usage": {"input_tokens": 3, "output_tokens": 2}},
    ]


def test_valid_one_command_trace_returns_structural_summary_without_output() -> None:
    summary = parse_codex_event_trace(_stream(*_valid_events()), _COMMAND)

    assert summary.thread_id == "thread-1"
    assert summary.command_id == "command-1"
    assert summary.command_status == "completed"
    assert summary.command_exit_code == 0
    assert summary.turn_status == "completed"
    assert "private" not in repr(summary.to_dict())
    assert summary.to_dict() == {
        "thread_id": "thread-1",
        "command_id": "command-1",
        "command_status": "completed",
        "command_exit_code": 0,
        "turn_status": "completed",
    }


def test_matching_multiline_command_is_accepted_without_exporting_its_text() -> None:
    command = "cat <<'EOF'\r\nline one\r\n\tline two\r\nEOF"

    summary = parse_codex_event_trace(_stream(*_valid_events(command=command)), command)

    assert summary.command_status == "completed"
    assert command not in repr(summary.to_dict())


@pytest.mark.parametrize("control", ["\x00", "\x1b", "\x7f"])
def test_command_rejects_unsafe_control_characters(control: str) -> None:
    command = f"printf 'probe'{control}"

    with pytest.raises(CodexEventTraceError, match="Caller has an invalid expected command"):
        parse_codex_event_trace(_stream(*_valid_events(command=command)), command)


def test_string_trace_with_unpaired_surrogate_has_clear_encoding_error() -> None:
    with pytest.raises(CodexEventTraceError, match="cannot be encoded as UTF-8"):
        parse_codex_event_trace("\ud800", _COMMAND)


def test_nonzero_command_is_recorded_without_a_guard_decision() -> None:
    summary = parse_codex_event_trace(_stream(*_valid_events(exit_code=1)), _COMMAND)

    assert summary.command_status == "failed"
    assert summary.command_exit_code == 1
    assert "decision" not in summary.to_dict()


def test_declined_command_with_no_exit_code_is_observed_without_a_pass_claim() -> None:
    events = _valid_events()
    events[5] = {**events[5], "item": {**events[5]["item"], "status": "declined", "exit_code": None}}

    summary = parse_codex_event_trace(_stream(*events), _COMMAND)

    assert summary.command_status == "declined"
    assert summary.command_exit_code is None
    assert "decision" not in summary.to_dict()


def test_completed_command_still_requires_an_exit_code() -> None:
    events = _valid_events()
    events[5] = {**events[5], "item": {**events[5]["item"], "exit_code": None}}

    with pytest.raises(CodexEventTraceError, match="invalid exit code"):
        parse_codex_event_trace(_stream(*events), _COMMAND)


@pytest.mark.parametrize("status", ["failed", "cancelled", "interrupted"])
def test_non_declined_command_requires_an_exit_code(status: str) -> None:
    events = _valid_events()
    events[5] = {**events[5], "item": {**events[5]["item"], "status": status, "exit_code": None}}

    with pytest.raises(CodexEventTraceError, match="invalid exit code"):
        parse_codex_event_trace(_stream(*events), _COMMAND)


def test_turn_completion_allows_null_exit_code() -> None:
    events = _valid_events()
    events[-1] = {**events[-1], "exit_code": None}

    summary = parse_codex_event_trace(_stream(*events), _COMMAND)

    assert summary.turn_status == "completed"


@pytest.mark.parametrize(
    ("name", "mutate"),
    [
        ("missing completion", lambda events: [*events[:5], *events[6:]]),
        (
            "duplicate start",
            lambda events: [*events[:5], events[4], *events[5:]],
        ),
        (
            "altered command",
            lambda events: [
                *events[:5],
                {**events[5], "item": {**events[5]["item"], "command": "other"}},
                *events[6:],
            ],
        ),
        (
            "extra command",
            lambda events: [
                *events[:6],
                {
                    "type": "item.started",
                    "item": {"id": "command-2", "type": "command_execution", "command": _COMMAND},
                },
                *events[6:],
            ],
        ),
    ],
)
def test_command_lifecycle_and_exact_command_are_required(name: str, mutate: object) -> None:
    events = _valid_events()
    mutated = mutate(events)  # type: ignore[operator]

    with pytest.raises(CodexEventTraceError, match="Codex"):
        parse_codex_event_trace(_stream(*mutated), _COMMAND)


def test_completed_command_without_started_is_rejected() -> None:
    events = _valid_events()
    events[5] = {**events[5], "item": {**events[5]["item"], "id": "command-2"}}

    with pytest.raises(CodexEventTraceError):
        parse_codex_event_trace(_stream(*events), _COMMAND)


def test_other_action_item_cannot_hide_in_one_command_trace() -> None:
    events = _valid_events()
    events.insert(
        6,
        {"type": "item.completed", "item": {"id": "write-1", "type": "file_change", "status": "completed"}},
    )

    with pytest.raises(CodexEventTraceError, match="unsupported item type"):
        parse_codex_event_trace(_stream(*events), _COMMAND)


@pytest.mark.parametrize("mutation", ["duplicate_thread", "mismatched_thread", "duplicate_completion"])
def test_thread_and_command_ids_must_remain_bound(mutation: str) -> None:
    events = _valid_events()
    if mutation == "duplicate_thread":
        events.insert(1, {"type": "thread.started", "thread_id": "thread-1"})
    elif mutation == "mismatched_thread":
        events[1] = {"type": "turn.started", "thread_id": "thread-2"}
    else:
        events.insert(6, events[5])

    with pytest.raises(CodexEventTraceError):
        parse_codex_event_trace(_stream(*events), _COMMAND)


@pytest.mark.parametrize("field", ["thread_id", "command_id", "command_status"])
def test_exported_identity_and_status_fields_cannot_contain_private_text(field: str) -> None:
    events = _valid_events()
    if field == "thread_id":
        events[0]["thread_id"] = "private value"
    elif field == "command_id":
        events[4] = {**events[4], "item": {**events[4]["item"], "id": "private value"}}
    else:
        events[5] = {**events[5], "item": {**events[5]["item"], "status": "private_value"}}

    with pytest.raises(CodexEventTraceError):
        parse_codex_event_trace(_stream(*events), _COMMAND)


@pytest.mark.parametrize(
    "payload",
    [
        "{malformed",
        _stream(*_valid_events()) + "\n{",
    ],
)
def test_malformed_json_is_rejected(payload: str) -> None:
    with pytest.raises(CodexEventTraceError, match="malformed JSON"):
        parse_codex_event_trace(payload, _COMMAND)


def test_byte_and_event_limits_are_enforced() -> None:
    with pytest.raises(CodexEventTraceError, match="byte limit"):
        parse_codex_event_trace("x" * (MAX_TRACE_BYTES + 1), _COMMAND)

    too_many_events = _stream(
        *(
            [
                {"type": "thread.started", "thread_id": "thread-1"},
                {"type": "turn.started"},
            ]
            + [{"type": "agent_message"}] * (MAX_TRACE_EVENTS - 1)
        )
    )
    with pytest.raises(CodexEventTraceError, match="event limit"):
        parse_codex_event_trace(too_many_events, _COMMAND)


@pytest.mark.parametrize(
    "turn_event",
    [
        {"type": "turn.completed", "status": "failed"},
        {"type": "turn.completed", "status": "error"},
        {"type": "turn.completed", "error": {"message": "private"}},
        {"type": "error", "message": "private"},
    ],
)
def test_failed_or_errored_turn_is_rejected(turn_event: dict[str, object]) -> None:
    events = _valid_events()
    events[-1] = turn_event

    with pytest.raises(CodexEventTraceError):
        parse_codex_event_trace(_stream(*events), _COMMAND)


def test_pre_turn_configuration_error_cannot_be_treated_as_a_clean_run() -> None:
    events = _valid_events()
    events.insert(1, {"type": "item.completed", "item": {"id": "warning-1", "type": "error", "message": "config"}})

    with pytest.raises(CodexEventTraceError):
        parse_codex_event_trace(_stream(*events), _COMMAND)


def test_error_item_after_turn_start_is_rejected() -> None:
    events = _valid_events()
    events.insert(2, {"type": "item.completed", "item": {"id": "error-1", "type": "error", "message": "private"}})

    with pytest.raises(CodexEventTraceError, match="error item"):
        parse_codex_event_trace(_stream(*events), _COMMAND)


@pytest.mark.parametrize(
    "payload",
    [
        '{"type":"thread.started","thread_id":"t","thread_id":"other"}',
        '{"type":"thread.started","thread_id":"t","extra":NaN}',
        b"\xff",
    ],
)
def test_ambiguous_json_and_invalid_utf8_are_rejected(payload: str | bytes) -> None:
    with pytest.raises(CodexEventTraceError):
        parse_codex_event_trace(payload, _COMMAND)
