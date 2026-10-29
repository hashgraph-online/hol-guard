"""Cursor's silent ``preToolUse`` probe: the daemon answer and the hook copy."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.adapters._modules.cursor.cursor_hook_script_template_route import (
    HOOK_SCRIPT_TEMPLATE_ROUTE,
)
from codex_plugin_scanner.guard.daemon import cursor_shell_route as route

_SHELL = {"hook_event_name": "PreToolUse", "tool_name": "Shell", "tool_input": {"command": "pytest -q"}}
_PROBE = {**_SHELL, "cursor_route_probe": True}
_BEFORE_SHELL = {**_SHELL, "cursor_source_hook_event": "beforeShellExecution"}
_ROUTED = "native_contained_execution_routed"
_SINK = {"command": "guard execute-contained-test", "cwd": "/w"}

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="Cursor's contained route is macOS and Linux only")


class _FailingWorker:
    def __init__(self) -> None:
        self.asked = False

    def _native_policy_snapshot(self, *_args: object, **_kwargs: object) -> object:
        self.asked = True
        raise RuntimeError("snapshot unavailable")


def _respond(
    payload: dict[str, object], workspace: Path | None, worker: _FailingWorker | None = None
) -> dict[str, object] | None:
    return route.cursor_shell_route_response(
        worker or _FailingWorker(),  # type: ignore[arg-type]
        payload=payload,
        home_dir=Path("/home/tester"),
        guard_home=Path("/home/tester/.hol-guard"),
        workspace=workspace,
        deadline=None,
    )


def test_only_cursors_own_shell_pretooluse_is_a_probe() -> None:
    assert route.is_cursor_shell_probe(_PROBE)
    # A Shell call another hook sends for Cursor keeps its ordinary review.
    assert not route.is_cursor_shell_probe(_SHELL)
    assert not route.is_cursor_shell_probe({**_SHELL, "cursor_route_probe": "true"})
    assert not route.is_cursor_shell_probe({**_PROBE, "cursor_source_hook_event": "beforeShellExecution"})
    assert not route.is_cursor_shell_probe(_BEFORE_SHELL)
    assert not route.is_cursor_shell_probe({**_PROBE, "tool_name": "Write"})
    assert not route.is_cursor_shell_probe({**_PROBE, "hook_event_name": "PostToolUse"})


@posix_only
def test_a_failed_probe_is_a_plain_allow(tmp_path: Path) -> None:
    assert _respond(_PROBE, tmp_path) == {"policy_action": "allow"}
    assert _respond(_PROBE, None) == {"policy_action": "allow"}


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


@posix_only
def test_non_probe_calls_are_reviewed_as_usual(tmp_path: Path) -> None:
    assert _respond({**_PROBE, "tool_name": "Write"}, tmp_path) is None
    assert _respond(_SHELL, tmp_path) is None
    assert _respond(_BEFORE_SHELL, tmp_path) is None
    assert _respond({**_PROBE, "guard_containment_receipt_only": True}, tmp_path) is None


@posix_only
def test_before_shell_asks_the_resident_about_a_call_naming_the_sink(tmp_path: Path, monkeypatch) -> None:
    from codex_plugin_scanner.guard import native_hook_render

    calls: list[tuple[str, str, dict[str, object]]] = []
    answer: dict[str, object] = {"value": None}

    def render(kind: str, harness: str, params: dict[str, object], **_kwargs: object) -> tuple[str, object]:
        calls.append((kind, harness, params))
        return ("document", dict(answer))

    monkeypatch.setattr(native_hook_render, "native_render_cli", render)
    payload = {**_BEFORE_SHELL, "tool_input": {"command": "guard execute-contained-test --harness cursor"}}
    # The resident admits only the exact sink command; anything else is reviewed.
    assert _respond(payload, tmp_path) is None
    admitted = {"policy_action": "allow", "reason_code": _ROUTED}
    answer["value"] = admitted
    assert _respond(payload, tmp_path) == admitted
    kind, harness, params = calls[-1]
    assert (kind, harness) == ("cursor_shell_route", "cursor")
    assert params["payload"] == payload
    assert params["workspace"] == str(tmp_path)
    assert "edge" not in params
    assert params["sink_command"] and all(isinstance(part, str) for part in params["sink_command"])  # type: ignore[union-attr]
    # Without a workspace the sink cannot be bound, so the call is reviewed.
    assert _respond(payload, None) is None
    assert len(calls) == 2


@posix_only
def test_before_shell_bounds_the_sink_check_by_the_hook_deadline(tmp_path: Path, monkeypatch) -> None:
    from codex_plugin_scanner.guard import native_hook_render

    deadlines: list[object] = []

    def render(*_args: object, deadline: object = None, **_kwargs: object) -> tuple[str, object]:
        deadlines.append(deadline)
        return ("document", {"value": None})

    monkeypatch.setattr(native_hook_render, "native_render_cli", render)
    payload = {**_BEFORE_SHELL, "tool_input": {"command": "guard execute-contained-test --harness cursor"}}
    route.cursor_shell_route_response(
        _FailingWorker(),  # type: ignore[arg-type]
        payload=payload,
        home_dir=Path("/home/tester"),
        guard_home=Path("/home/tester/.hol-guard"),
        workspace=tmp_path,
        deadline=123.5,
    )
    assert deadlines == [123.5]


@posix_only
def test_a_sink_check_that_fails_is_reviewed_as_usual(tmp_path: Path, monkeypatch) -> None:
    from codex_plugin_scanner.guard.adapters import zcode_contained_tests

    def unavailable() -> tuple[str, ...]:
        raise RuntimeError("Guard CLI unavailable")

    monkeypatch.setattr(zcode_contained_tests, "contained_sink_command_prefix", unavailable)
    payload = {**_BEFORE_SHELL, "tool_input": {"command": "guard execute-contained-test --harness cursor"}}
    assert _respond(payload, tmp_path) is None


def test_windows_is_never_routed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(route.sys, "platform", "win32")
    assert _respond(_PROBE, tmp_path) is None


def _hook_copy() -> dict[str, object]:
    namespace: dict[str, object] = {"json": json}
    exec(HOOK_SCRIPT_TEMPLATE_ROUTE, namespace)
    return namespace


def _routed_body(updated: object) -> str:
    return json.dumps(
        {"policy_action": "allow", "reason_code": _ROUTED, "hookSpecificOutput": {"updatedInput": updated}}
    )


def test_hook_copy_returns_the_sink_command_only_for_a_routed_answer() -> None:
    respond = _hook_copy()["_cursor_shell_route_response"]
    assert respond(_routed_body(_SINK) + "\n") == {"permission": "allow", "updated_input": _SINK}
    plain = {"permission": "allow"}
    for body in (
        "",
        "not json",
        "[]",
        json.dumps({"policy_action": "allow"}),
        json.dumps({"policy_action": "deny", "reason_code": _ROUTED}),
        _routed_body(None),
        _routed_body({"command": 1}),
        _routed_body(_SINK).replace('"/w"', "NaN"),
        _routed_body(_SINK).replace('"/w"', "1e400"),
        _routed_body(_SINK).replace('"/w"', '"\\ud800"'),
    ):
        assert respond(body) == plain, body


def test_hook_copy_probe_matches_the_daemon() -> None:
    # The hook detects its probe before it names it for the daemon.
    probe = _hook_copy()["_cursor_shell_route_probe"]
    for payload in (_SHELL, _BEFORE_SHELL, {**_SHELL, "tool_name": "Write"}):
        assert probe(payload) == route.is_cursor_shell_probe({**payload, "cursor_route_probe": True})


class _RoutingWorker:
    def __init__(
        self,
        route: str = "sink",
        *,
        features: tuple[str, ...] = (),
        answer: dict[str, object] | None = None,
        mark: str = "routed",
    ):
        self.route = route
        self.features = features
        self.answer = answer
        self.mark = mark
        self.containment_sink: list[object] = []

    def _native_policy_snapshot(self, *_args: object, **_kwargs: object) -> object:
        return object()

    def _native_runtime_status(self) -> SimpleNamespace:
        return SimpleNamespace(capabilities=SimpleNamespace(features=self.features))

    def _review_raw_hook_native(self, **kwargs: object) -> dict[str, object]:
        self.containment_sink.append(kwargs.get("containment_sink"))
        edge: dict[str, object] = {
            "harness": "cursor",
            "event_name": "PreToolUse",
            "containment_route": self.route,
            "result": {"decision": "deny"},
        }
        if self.answer is not None:
            edge["containment_rewrite"] = self.mark
            edge["harness_response"] = self.answer
        return edge


@posix_only
def test_a_probe_the_sink_takes_answers_with_the_rewritten_call(tmp_path: Path, monkeypatch) -> None:
    from codex_plugin_scanner.guard import native_hook_render, native_policy_snapshot_harness_postures

    routed = {"policy_action": "allow", "reason_code": _ROUTED, "hookSpecificOutput": {"updatedInput": _SINK}}
    asked: list[dict[str, object]] = []

    def render(kind: str, harness: str, params: dict[str, object], **_kwargs: object) -> tuple[str, object]:
        asked.append(params)
        return ("document", {"value": routed})

    monkeypatch.setattr(native_policy_snapshot_harness_postures, "recording_only_for_binding", lambda *_: False)
    monkeypatch.setattr(native_hook_render, "native_render_cli", render)
    assert _respond(_PROBE, tmp_path, _RoutingWorker()) == routed  # type: ignore[arg-type]
    # The resident reads the edge the daemon reviewed, never a re-review.
    assert [params["edge"] for params in asked] == [
        {
            "harness": "cursor",
            "event_name": "PreToolUse",
            "containment_route": "sink",
            "result": {"decision": "deny"},
        }
    ]
    assert asked[0]["payload"] == _PROBE


@posix_only
def test_a_probe_the_resident_cannot_answer_is_a_plain_allow(tmp_path: Path, monkeypatch) -> None:
    from codex_plugin_scanner.guard import native_hook_render, native_policy_snapshot_harness_postures

    monkeypatch.setattr(native_policy_snapshot_harness_postures, "recording_only_for_binding", lambda *_: False)
    monkeypatch.setattr(native_hook_render, "native_render_cli", lambda *_a, **_k: None)
    assert _respond(_PROBE, tmp_path, _RoutingWorker()) == {"policy_action": "allow"}  # type: ignore[arg-type]


@posix_only
@pytest.mark.parametrize("edge_route", ["none", "grant"])
def test_a_probe_the_edge_does_not_route_to_the_sink_skips_the_resident(
    tmp_path: Path, monkeypatch, edge_route: str
) -> None:
    from codex_plugin_scanner.guard import native_hook_render, native_policy_snapshot_harness_postures

    asked: list[str] = []
    monkeypatch.setattr(native_policy_snapshot_harness_postures, "recording_only_for_binding", lambda *_: False)
    monkeypatch.setattr(native_hook_render, "native_render_cli", lambda kind, *_a, **_k: asked.append(kind))
    worker = _RoutingWorker(edge_route)
    assert _respond(_PROBE, tmp_path, worker) == {"policy_action": "allow"}  # type: ignore[arg-type]
    assert asked == []


@posix_only
def test_a_probe_the_edge_answers_skips_the_resident(tmp_path: Path, monkeypatch) -> None:
    from codex_plugin_scanner.guard import native_hook_render, native_policy_snapshot_harness_postures

    routed = {"policy_action": "allow", "reason_code": _ROUTED, "hookSpecificOutput": {"updatedInput": _SINK}}
    asked: list[str] = []
    monkeypatch.setattr(native_policy_snapshot_harness_postures, "recording_only_for_binding", lambda *_: False)
    monkeypatch.setattr(native_hook_render, "native_render_cli", lambda kind, *_a, **_k: asked.append(kind))
    worker = _RoutingWorker(features=(route._EDGE_PROBE_FEATURE,), answer=routed)
    assert _respond(_PROBE, tmp_path, worker) == routed  # type: ignore[arg-type]
    # The edge is asked for the sink rewrite, and the resident never renders.
    assert worker.containment_sink == [True]
    assert asked == []


@posix_only
def test_an_older_resident_still_renders_the_probe(tmp_path: Path, monkeypatch) -> None:
    from codex_plugin_scanner.guard import native_hook_render, native_policy_snapshot_harness_postures

    routed = {"policy_action": "allow", "reason_code": _ROUTED, "hookSpecificOutput": {"updatedInput": _SINK}}
    asked: list[str] = []

    def render(kind: str, *_args: object, **_kwargs: object) -> tuple[str, object]:
        asked.append(kind)
        return ("document", {"value": routed})

    monkeypatch.setattr(native_policy_snapshot_harness_postures, "recording_only_for_binding", lambda *_: False)
    monkeypatch.setattr(native_hook_render, "native_render_cli", render)
    # Without the feature, an answer the edge carries anyway is not trusted.
    worker = _RoutingWorker(answer={"policy_action": "allow"})
    assert _respond(_PROBE, tmp_path, worker) == routed  # type: ignore[arg-type]
    assert worker.containment_sink == [False]
    assert asked == ["cursor_shell_route"]


@posix_only
@pytest.mark.parametrize(
    ("mark", "answer"),
    [
        # The generic rewrite keeps the receipt rather than the probe's allow.
        ("kept", {"policy_action": "block", "decision": "deny", "reason_code": "native_contained_execution_required"}),
        ("routed", {"policy_action": "allow"}),
    ],
)
def test_an_edge_answer_that_is_not_a_probe_answer_still_renders(
    tmp_path: Path, monkeypatch, mark: str, answer: dict[str, object]
) -> None:
    from codex_plugin_scanner.guard import native_hook_render, native_policy_snapshot_harness_postures

    routed = {"policy_action": "allow", "reason_code": _ROUTED, "hookSpecificOutput": {"updatedInput": _SINK}}
    asked: list[str] = []

    def render(kind: str, *_args: object, **_kwargs: object) -> tuple[str, object]:
        asked.append(kind)
        return ("document", {"value": routed})

    monkeypatch.setattr(native_policy_snapshot_harness_postures, "recording_only_for_binding", lambda *_: False)
    monkeypatch.setattr(native_hook_render, "native_render_cli", render)
    # A resident replaced after the feature was read answers with its own rewrite.
    worker = _RoutingWorker(features=(route._EDGE_PROBE_FEATURE,), answer=answer, mark=mark)
    assert _respond(_PROBE, tmp_path, worker) == routed  # type: ignore[arg-type]
    assert asked == ["cursor_shell_route"]


@posix_only
def test_a_probe_the_edge_keeps_is_its_plain_allow(tmp_path: Path, monkeypatch) -> None:
    from codex_plugin_scanner.guard import native_hook_render, native_policy_snapshot_harness_postures

    asked: list[str] = []
    monkeypatch.setattr(native_policy_snapshot_harness_postures, "recording_only_for_binding", lambda *_: False)
    monkeypatch.setattr(native_hook_render, "native_render_cli", lambda kind, *_a, **_k: asked.append(kind))
    worker = _RoutingWorker(features=(route._EDGE_PROBE_FEATURE,), answer={"policy_action": "allow"}, mark="kept")
    assert _respond(_PROBE, tmp_path, worker) == {"policy_action": "allow"}  # type: ignore[arg-type]
    assert asked == []
