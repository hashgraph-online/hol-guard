"""Cursor's silent ``preToolUse`` probe: the daemon's shim over the resident's route ops.

Which route a call takes, what a reviewed probe is answered and whether a sink
command is admitted are the resident's, and are tested in
``hook_direct_cursor_route_ops_tests.rs`` and ``hook_direct_cursor_route_tests.rs``.
These tests prove the shim asks the resident and returns its answer.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import contained_sink_command, native_hook_render
from codex_plugin_scanner.guard.hook_review import cursor_shell_route as route

_SHELL = {"hook_event_name": "PreToolUse", "tool_name": "Shell", "tool_input": {"command": "pytest -q"}}
_PROBE = {**_SHELL, "cursor_route_probe": True}
_BEFORE_SHELL = {**_SHELL, "cursor_source_hook_event": "beforeShellExecution"}
_ROUTED = "native_contained_execution_routed"
_SINK = {"command": "guard execute-contained-test", "cwd": "/w"}
_SINK_PAYLOAD = {**_BEFORE_SHELL, "tool_input": {"command": "guard execute-contained-test --harness cursor"}}
_ALLOW = {"policy_action": "allow"}
_SNAPSHOT = {"mode": "enforce", "generation": 7}
_ROUTED_ANSWER = {"policy_action": "allow", "reason_code": _ROUTED, "hookSpecificOutput": {"updatedInput": _SINK}}

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="Cursor's contained route is macOS and Linux only")


class _Resident:
    """A stand-in for the resident's ``cursor_shell_route`` render."""

    def __init__(
        self, monkeypatch: pytest.MonkeyPatch, *, route: object = "review", answers: dict[str, object] | None = None
    ):
        self.route = route
        self.answers = answers or {}
        self.calls: list[tuple[str, str, dict[str, object], object]] = []
        monkeypatch.setattr(native_hook_render, "native_render_cli", self._render)
        monkeypatch.setattr(contained_sink_command, "contained_sink_command_prefix", lambda: ("guard", "-I"))

    def _render(
        self, kind: str, harness: str, params: dict[str, object], *, deadline: object = None, **_kwargs: object
    ) -> tuple[str, object]:
        self.calls.append((kind, harness, params, deadline))
        op = params.get("op")
        if op == "route":
            return ("document", {"value": self.route})
        if op == "probe_gate":
            return ("document", {"value": self.answers.get("probe_gate", True)})
        if op == "probe_response":
            return ("document", {"value": self.answers.get("probe_response")})
        return ("document", {"value": self.answers.get("sink")})

    def ops(self) -> list[object]:
        return [params.get("op") for _kind, _harness, params, _deadline in self.calls]


class _FailingWorker:
    def __init__(self) -> None:
        self.asked = False

    def _native_policy_snapshot(self, *_args: object, **_kwargs: object) -> object:
        self.asked = True
        raise RuntimeError("snapshot unavailable")


class _RoutingWorker:
    def __init__(self, edge: dict[str, object] | None = None):
        self.edge = edge
        self.containment_sink: list[object] = []

    def _native_policy_snapshot(self, *_args: object, **_kwargs: object) -> object:
        return _SNAPSHOT

    def _review_raw_hook_native(self, **kwargs: object) -> dict[str, object] | None:
        self.containment_sink.append(kwargs.get("containment_sink"))
        return self.edge


def _respond(
    payload: dict[str, object], workspace: Path | None, worker: object | None = None, deadline: float | None = None
) -> dict[str, object] | None:
    return route.cursor_shell_route_response(
        worker or _FailingWorker(),  # type: ignore[arg-type]
        payload=payload,
        home_dir=Path("/home/tester"),
        guard_home=Path("/home/tester/.hol-guard"),
        workspace=workspace,
        deadline=deadline,
    )


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


def test_the_route_is_the_residents_and_the_call_travels_whole(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    resident = _Resident(monkeypatch, route="review")
    assert _respond(_PROBE, tmp_path) is None
    kind, harness, params, _deadline = resident.calls[0]
    assert (kind, harness) == ("cursor_shell_route", "cursor")
    assert params == {"op": "route", "payload": _PROBE}


@pytest.mark.parametrize("answer", ["review", None, 3, "unknown"])
def test_a_call_the_resident_does_not_route_is_reviewed_as_usual(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: object
) -> None:
    resident = _Resident(monkeypatch, route=answer)
    assert _respond(_SINK_PAYLOAD, tmp_path) is None
    assert resident.ops() == ["route"]


def test_a_route_the_resident_cannot_answer_is_reviewed_as_usual(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unavailable(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("resident unavailable")

    monkeypatch.setattr(native_hook_render, "native_render_cli", unavailable)
    assert _respond(_PROBE, tmp_path) is None
    monkeypatch.setattr(native_hook_render, "native_render_cli", lambda *_a, **_k: None)
    assert _respond(_PROBE, tmp_path) is None


@posix_only
def test_a_failed_probe_is_a_plain_allow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _Resident(monkeypatch, route="probe")
    assert _respond(_PROBE, tmp_path) == _ALLOW
    assert _respond(_PROBE, None) == _ALLOW


@posix_only
def test_a_probe_the_edge_does_not_review_is_a_plain_allow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    resident = _Resident(monkeypatch, route="probe")
    assert _respond(_PROBE, tmp_path, _RoutingWorker(None)) == _ALLOW
    # beforeShellExecution still reviews the call; the resident is not asked for an answer.
    assert resident.ops() == ["route", "probe_gate"]


@posix_only
def test_a_reviewed_probe_is_answered_as_the_resident_reads_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    resident = _Resident(monkeypatch, route="probe", answers={"probe_response": _ROUTED_ANSWER})
    edge = {"containment_route": "sink", "containment_rewrite": "routed", "harness_response": _ROUTED_ANSWER}
    worker = _RoutingWorker(edge)
    assert _respond(_PROBE, tmp_path, worker) == _ROUTED_ANSWER
    # The edge is asked for the sink rewrite, and the resident reads its whole answer.
    assert worker.containment_sink == [True]
    assert resident.ops() == ["route", "probe_gate", "probe_response"]
    assert resident.calls[1][2] == {"op": "probe_gate", "snapshot": _SNAPSHOT, "has_workspace": True}
    assert resident.calls[2][2] == {"op": "probe_response", "edge": edge}


@posix_only
@pytest.mark.parametrize("gate", [False, None, "yes"])
def test_a_probe_the_resident_does_not_gate_in_is_not_reviewed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, gate: object
) -> None:
    resident = _Resident(monkeypatch, route="probe", answers={"probe_gate": gate})
    worker = _RoutingWorker({"containment_route": "sink"})
    assert _respond(_PROBE, tmp_path, worker) == _ALLOW
    assert worker.containment_sink == []
    assert resident.ops() == ["route", "probe_gate"]


@posix_only
def test_a_probe_answer_that_is_not_an_object_is_a_plain_allow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _Resident(monkeypatch, route="probe", answers={"probe_response": None})
    assert _respond(_PROBE, tmp_path, _RoutingWorker({"containment_route": "none"})) == _ALLOW


@posix_only
def test_before_shell_asks_the_resident_about_a_call_naming_the_sink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    resident = _Resident(monkeypatch, route="sink")
    # The resident admits only the exact sink command; anything else is reviewed.
    assert _respond(_SINK_PAYLOAD, tmp_path) is None
    admitted = {"policy_action": "allow", "reason_code": _ROUTED}
    resident.answers["sink"] = admitted
    assert _respond(_SINK_PAYLOAD, tmp_path) == admitted
    kind, harness, params, _deadline = resident.calls[-1]
    assert (kind, harness) == ("cursor_shell_route", "cursor")
    assert "op" not in params
    assert params["payload"] == _SINK_PAYLOAD
    assert params["workspace"] == str(tmp_path)
    assert "edge" not in params
    assert params["sink_command"] and all(isinstance(part, str) for part in params["sink_command"])  # type: ignore[union-attr]
    assert params["native_sink"] is True
    # Without a workspace the sink cannot be bound, so the call is reviewed.
    calls = len(resident.calls)
    assert _respond(_SINK_PAYLOAD, None) is None
    assert len(resident.calls) == calls + 1


@posix_only
def test_before_shell_bounds_every_resident_call_by_the_hook_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    resident = _Resident(monkeypatch, route="sink")
    _respond(_SINK_PAYLOAD, tmp_path, deadline=123.5)
    assert [call[3] for call in resident.calls] == [123.5, 123.5]


@posix_only
def test_a_sink_check_that_fails_is_reviewed_as_usual(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable() -> tuple[str, ...]:
        raise RuntimeError("Guard CLI unavailable")

    _Resident(monkeypatch, route="sink")
    monkeypatch.setattr(contained_sink_command, "contained_sink_command_prefix", unavailable)
    assert _respond(_SINK_PAYLOAD, tmp_path) is None
