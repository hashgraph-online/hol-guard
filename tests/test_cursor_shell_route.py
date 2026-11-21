"""The Python worker relays Cursor's native route and its workspace binding."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import contained_sink_command, native_hook_render

_SHELL = {"hook_event_name": "PreToolUse", "tool_name": "Shell", "tool_input": {"command": "pytest -q"}}
_PROBE = {**_SHELL, "cursor_route_probe": True}
_ALLOW = {"policy_action": "allow"}
_BINDING = {"generation": 7, "policy_digest": "a" * 64, "runtime_identity": "b" * 64}


def _unexpected_binding() -> Mapping[str, object]:
    pytest.fail("the resident did not request a workspace binding")


def _respond(
    root: Path,
    payload: dict[str, object],
    *,
    binding: Callable[[], Mapping[str, object] | None] = _unexpected_binding,
    deadline: float | None = None,
) -> dict[str, object] | None:
    return native_hook_render.native_cursor_shell_route(
        payload,
        guard_home=root / "guard",
        home_dir=root,
        workspace=root / "work",
        binding=binding,
        deadline=deadline,
    )


@pytest.fixture
def resident(monkeypatch: pytest.MonkeyPatch):
    calls = []
    replies = []

    def render(kind, harness, params, *, guard_home, deadline):
        assert (kind, harness, params["op"]) == ("cursor_shell_route", "cursor", "answer")
        calls.append((dict(params), guard_home, deadline))
        reply = replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply

    monkeypatch.setattr(native_hook_render, "native_render_cli", render)
    monkeypatch.setattr(contained_sink_command, "contained_sink_command_prefix", lambda: ("guard",))
    return calls, replies


def test_the_sink_command_accepts_the_cursor_harness(tmp_path: Path) -> None:
    from codex_plugin_scanner.cli import _build_parser

    args = _build_parser("hol-guard", program_mode="hol-guard").parse_args(
        [
            "execute-contained-test",
            "--harness",
            "cursor",
            "--guard-home",
            str(tmp_path / "guard"),
            "--workspace",
            str(tmp_path),
            "--request-file",
            str(tmp_path / "request.json"),
            "--request-sha256",
            "0" * 64,
            "--home",
            str(tmp_path),
        ]
    )
    assert args.harness == "cursor"


@pytest.mark.parametrize("reply", [None, ("document", {"value": None, "needs": None})])
def test_an_unanswered_call_uses_ordinary_review_without_resolving_a_sink(tmp_path, resident, reply, monkeypatch):
    calls, replies = resident
    replies.append(reply)
    monkeypatch.setattr(
        contained_sink_command, "contained_sink_command_prefix", lambda: pytest.fail("the resident did not ask")
    )
    assert _respond(tmp_path, _SHELL) is None
    assert len(calls) == 1


def test_sink_admission_uses_the_native_answer_and_original_payload(tmp_path, resident):
    calls, replies = resident
    answer = {"policy_action": "allow", "reason_code": "native_contained_execution_sink"}
    replies.extend(
        [
            ("document", {"value": None, "needs": "sink_command"}),
            ("document", {"value": answer, "needs": None}),
        ]
    )
    payload = {**_SHELL, "cursor_source_hook_event": "beforeShellExecution"}
    deadline = time.monotonic() + 1.0
    assert _respond(tmp_path, payload, deadline=deadline) == answer
    request = {
        "op": "answer",
        "payload": payload,
        "workspace": str(tmp_path / "work"),
        "guard_home": str(tmp_path / "guard"),
        "home_dir": str(tmp_path),
        "native_sink": True,
    }
    assert calls == [
        (request, tmp_path / "guard", deadline),
        ({**request, "sink_command": ["guard"]}, tmp_path / "guard", deadline),
    ]


def test_probe_relays_only_the_requested_binding_under_the_same_deadline(tmp_path, resident):
    calls, replies = resident
    routed = {**_ALLOW, "reason_code": "native_contained_execution_routed"}
    replies.extend(
        [
            ("document", {"value": _ALLOW, "needs": "probe_binding"}),
            ("document", {"value": routed, "needs": None}),
        ]
    )
    deadline = time.monotonic() + 7.0
    postures = {"cursor": "protected"}
    snapshot = {**_BINDING, "policy": {}, "harness_postures": postures}
    assert _respond(tmp_path, _PROBE, binding=lambda: snapshot, deadline=deadline) == routed
    assert len(calls) == 2
    assert calls[0][2] == calls[1][2] == deadline
    assert "snapshot" not in calls[0][0]
    assert "sink_command" not in calls[0][0]
    assert calls[1][0]["snapshot"] == _BINDING
    assert calls[1][0]["sink_command"] == ["guard"]
    assert calls[1][0]["harness_postures"] == postures
    assert 0 < calls[1][0]["probe_budget_ms"] <= 7000


def test_probe_keeps_the_first_native_answer_when_binding_is_unavailable(tmp_path, resident):
    calls, replies = resident
    replies.append(("document", {"value": _ALLOW, "needs": "probe_binding"}))

    def binding():
        raise RuntimeError("binding unavailable")

    assert _respond(tmp_path, _PROBE, binding=binding) == _ALLOW
    assert len(calls) == 1


def test_probe_keeps_the_first_native_answer_when_second_call_fails(tmp_path, resident):
    calls, replies = resident
    replies.extend([("document", {"value": _ALLOW, "needs": "probe_binding"}), RuntimeError("resident stopped")])
    assert _respond(tmp_path, _PROBE, binding=lambda: _BINDING) == _ALLOW
    assert len(calls) == 2
