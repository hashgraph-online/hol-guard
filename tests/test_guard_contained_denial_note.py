"""The note a failed workspace-contained run gets names what the sandbox blocked.

The native runtime owns the reading; its cases live beside it in
`contained_workspace_sink_denial_tests.rs`. These tests pin the request the
Python sandboxes send and what they keep from the answer.
"""

from __future__ import annotations

import base64
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_runner_authority as authority
from codex_plugin_scanner.guard.runtime import contained_denial_note as notes
from codex_plugin_scanner.guard.runtime.contained_denial_note import denial_answer, denial_note


@pytest.mark.parametrize(
    ("output", "names"),
    [
        (b"Error: EPERM: operation not permitted, mkdir '/opt/lanectl/cache'", "blocked a write outside the workspace"),
        (b"Error: spawn EACCES", "blocked starting a program"),
        (b"Error: connect EPERM 203.0.113.7:443", "blocked a network connection"),
        (b"OSError: out of pty devices", "blocked opening a pseudo-terminal"),
        (b"PermissionError: [Errno 13] Permission denied: 'data'", "denied an operation"),
    ],
)
def test_the_native_reading_names_the_cause(output: bytes, names: str) -> None:
    note = denial_note([output])
    assert note is not None
    assert names in note
    assert note.endswith("only commands Guard proves safe run directly, outside the sandbox.")


def test_output_without_a_denial_gets_no_note() -> None:
    assert denial_note([b"AssertionError: expected 2, got 3"]) is None
    assert denial_note([]) is None


def test_only_a_blocked_connection_to_this_machine_counts_as_loopback() -> None:
    assert denial_answer([b"", b"Error: connect EPERM 127.0.0.1:8080"])[1] is True
    assert denial_answer([b"Error: connect EPERM 203.0.113.7:443"])[1] is False
    assert denial_answer([b"listening on 127.0.0.1:8080"]) == (None, False)


def test_outputs_travel_as_base64_within_the_request_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[dict[str, Any]] = []

    def answer(kind: str, args: dict[str, Any], **_: object) -> dict[str, Any]:
        assert kind == "contained_denial_note"
        sent.append(args)
        return {"note": "noted", "loopback_denied": True}

    monkeypatch.setattr(authority, "native_runner_authority", answer)
    first = b"\xff" * (notes._MAX_OUTPUT_BYTES - 3)
    assert denial_answer([first, b"spawn EPERM", b"dropped"]) == ("noted", True)
    decoded = [base64.b64decode(output) for output in sent[0]["outputs"]]
    assert decoded == [first, b"spa"]


def test_a_native_outage_leaves_the_note_out(monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(*_: object, **__: object) -> dict[str, Any]:
        raise authority.NativeRunnerAuthorityError("native_runner_authority_unavailable")

    monkeypatch.setattr(authority, "native_runner_authority", unavailable)
    assert denial_answer([b"Error: connect EPERM 127.0.0.1:8080"]) == (None, False)


def test_a_malformed_answer_carries_no_note(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(authority, "native_runner_authority", lambda *_, **__: {"note": 7, "loopback_denied": "yes"})
    assert denial_answer([b"spawn EPERM"]) == (None, False)
