"""Containment routing, asked of the resident through ``HookDecide``.

The resident decides whether a native PreToolUse answer is routed into the
contained sink, through the local CLI grant, or not at all, and whether the
sink takes a rendered receipt on this host. These pin the transport: the
facts it sends, the reply it accepts, and that anything else is a
``NativeHookDecisionError`` the hook answers with the host outage response.
The resident cases replay the retired Python tables on every host.
"""

from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_hook_containment_route as route_module
from codex_plugin_scanner.guard import native_resident_decision as shared
from codex_plugin_scanner.guard.native_hook_decision import NativeHookDecisionError

OUTSIDE = "native_workspace_containment_executable_outside_roots"
_SHELL_CALL = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "pytest -q"}}


def _receipt(reason: str, profile: str, **changes: object) -> dict[str, object]:
    return {
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": reason,
        "required_execution_profile": profile,
        **changes,
    }


_PYTEST = _receipt("native_pytest_readonly_containment_required", "pytest-readonly-v2")
_WORKSPACE = _receipt("native_workspace_containment_required", "workspace-contained-v1")


def _resident_answering(monkeypatch: pytest.MonkeyPatch, payload: dict[str, Any], asked: list[Any]) -> None:
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=object(),
        capabilities=SimpleNamespace(
            features={"resident-protocol-v2", route_module.HOOK_DECISION_CONTAINMENT_ROUTE_FEATURE}
        ),
    )
    monkeypatch.setattr(shared, "native_runtime_status", lambda: status)
    monkeypatch.setattr(shared, "record_resident", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(shared, "_resolve_digest_home", lambda _home: Path("/tmp/hook-decision-home"))
    monkeypatch.setattr(shared, "ensure_resident_prerequisite", lambda _home: True)

    def transport(*, request: dict[str, Any], required_feature: str, **_kwargs: object) -> dict[str, Any]:
        asked.append((required_feature, request["query"]))
        return {
            "schema": "guard-hook-decision-result.v1",
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + shared._canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": payload,
        }

    monkeypatch.setattr(route_module, "_resident_request", transport)


@pytest.mark.parametrize("route", ["none", "sink", "grant"])
def test_a_bound_route_is_decoded_behind_its_capability(monkeypatch: pytest.MonkeyPatch, route: str) -> None:
    asked: list[Any] = []
    _resident_answering(monkeypatch, {"kind": "containment_route", "route": route}, asked)
    result = {
        "decision": "deny",
        "minimum_action": "review",
        "policy_action": "review",
        "reason_code": OUTSIDE,
        "reason": "ignored",
        "action": {"action_type": "shell", "command": "ignored"},
    }
    answer = route_module.native_containment_route(
        result, event_name="PreToolUse", recording_only=False, guard_home=None
    )
    assert answer == route
    # Only the facts the route depends on are sent.
    assert asked == [
        (
            route_module.HOOK_DECISION_CONTAINMENT_ROUTE_FEATURE,
            {
                "kind": "containment_route",
                "inputs": {
                    "event_name": "PreToolUse",
                    "recording_only": False,
                    "minimum_action": "review",
                    "policy_action": "review",
                    "reason_code": OUTSIDE,
                    "action_type": "shell",
                },
            },
        )
    ]


@pytest.mark.parametrize("route", ["none", "sink", "grant"])
def test_the_route_stamped_on_the_edge_needs_no_second_round_trip(monkeypatch: pytest.MonkeyPatch, route: str) -> None:
    asked: list[Any] = []
    _resident_answering(monkeypatch, {"kind": "containment_route", "route": "none"}, asked)
    edge = {"containment_route": route}
    answer = route_module.edge_containment_route(
        edge, {"minimum_action": "allow"}, event_name="PreToolUse", recording_only=False, guard_home=None
    )
    assert (answer, asked) == (route, [])


@pytest.mark.parametrize("stamped", [None, "allow", ["sink"]])
def test_an_edge_without_a_route_asks_the_resident(monkeypatch: pytest.MonkeyPatch, stamped: object) -> None:
    asked: list[Any] = []
    _resident_answering(monkeypatch, {"kind": "containment_route", "route": "sink"}, asked)
    edge = {} if stamped is None else {"containment_route": stamped}
    answer = route_module.edge_containment_route(
        edge, {"minimum_action": "sandbox-required"}, event_name="PreToolUse", recording_only=False, guard_home=None
    )
    assert answer == "sink"
    assert [query["kind"] for _feature, query in asked] == ["containment_route"]


def test_a_spent_hook_deadline_is_an_outage_without_asking(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[Any] = []
    _resident_answering(monkeypatch, {"kind": "containment_route", "route": "none"}, asked)
    with pytest.raises(NativeHookDecisionError):
        route_module.native_containment_route(
            {}, event_name="PreToolUse", recording_only=False, guard_home=None, deadline=time.monotonic() - 1
        )
    with pytest.raises(NativeHookDecisionError):
        route_module.native_containment_sink(
            _PYTEST, harness="claude-code", bridge=False, payload=_SHELL_CALL, guard_home=None, deadline=0.0
        )
    assert asked == []


def test_the_query_waits_no_longer_than_the_hook_allows(monkeypatch: pytest.MonkeyPatch) -> None:
    timeouts: list[float] = []

    def decide(operation: Any, *_args: object) -> dict[str, Any]:
        timeouts.append(operation.timeout_seconds)
        return {"kind": "containment_route", "route": "none"}

    monkeypatch.setattr(route_module, "resident_decide", decide)
    route_module.native_containment_route({}, event_name="PreToolUse", recording_only=False, guard_home=None)
    route_module.native_containment_route(
        {}, event_name="PreToolUse", recording_only=False, guard_home=None, deadline=time.monotonic() + 0.5
    )
    assert timeouts[0] == route_module._OPERATION.timeout_seconds
    assert 0 < timeouts[1] <= 0.5


def test_the_sink_query_sends_the_receipt_call_and_host(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[Any] = []
    _resident_answering(
        monkeypatch, {"kind": "containment_sink", "profile": "pytest-readonly-v2", "kept_because": None}, asked
    )
    monkeypatch.setattr(route_module, "host_platform", lambda: "windows")
    payload = {"hookEventName": "PreToolUse", "toolName": "Bash", "toolInput": {"command": "pytest -q"}}
    sink = route_module.native_containment_sink(
        {**_PYTEST, "reason": "ignored"}, harness="codex", bridge=True, payload=payload, guard_home=None
    )
    assert sink == route_module.ContainmentSink("pytest-readonly-v2", None)
    assert asked[0][1] == {
        "kind": "containment_sink",
        "inputs": {
            "harness": "codex",
            "platform": "windows",
            "bridge": True,
            "receipt_only": False,
            "event_name": "PreToolUse",
            "tool_name": "Bash",
            "command_is_text": True,
            "decision": "deny",
            "policy_action": "sandbox-required",
            "reason_code": "native_pytest_readonly_containment_required",
            "required_execution_profile": "pytest-readonly-v2",
            "observe_mode": False,
        },
    }


@pytest.mark.parametrize(
    "payload",
    [
        {"kind": "containment_route"},
        {"kind": "containment_route", "route": "allow"},
        {"kind": "containment_route", "route": ["sink"]},
        {"kind": "containment_route", "route": "sink", "extra": True},
        {"kind": "containment_sink", "route": "sink"},
    ],
)
def test_a_malformed_route_is_an_outage_not_a_route(monkeypatch: pytest.MonkeyPatch, payload: dict[str, Any]) -> None:
    _resident_answering(monkeypatch, payload, [])
    with pytest.raises(NativeHookDecisionError):
        route_module.native_containment_route(
            {"minimum_action": "sandbox-required"}, event_name="PreToolUse", recording_only=False, guard_home=None
        )


@pytest.mark.parametrize(
    "payload",
    [
        {"kind": "containment_sink", "profile": None, "kept_because": None},
        {"kind": "containment_sink", "profile": None, "kept_because": "because"},
        {"kind": "containment_sink", "profile": None, "kept_because": ["receipt_only"]},
        # The sink never runs a profile the receipt does not name.
        {"kind": "containment_sink", "profile": "workspace-contained-v1", "kept_because": None},
        {"kind": "containment_sink", "profile": "pytest-readonly-v2", "kept_because": "receipt_only"},
        {"kind": "containment_sink", "profile": "pytest-readonly-v2"},
        {"kind": "containment_route", "profile": "pytest-readonly-v2", "kept_because": None},
    ],
)
def test_a_malformed_sink_answer_is_an_outage(monkeypatch: pytest.MonkeyPatch, payload: dict[str, Any]) -> None:
    _resident_answering(monkeypatch, payload, [])
    with pytest.raises(NativeHookDecisionError):
        route_module.native_containment_sink(
            _PYTEST, harness="claude-code", bridge=False, payload=_SHELL_CALL, guard_home=None
        )


def test_a_harness_that_is_not_text_is_never_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[Any] = []
    _resident_answering(monkeypatch, {"kind": "containment_sink", "profile": None, "kept_because": "x"}, asked)
    with pytest.raises(NativeHookDecisionError):
        route_module.native_containment_sink(
            _PYTEST,
            harness=None,  # type: ignore[arg-type]
            bridge=False,
            payload=_SHELL_CALL,
            guard_home=None,
        )
    assert asked == []


@pytest.mark.parametrize(
    ("platform", "host"), [("darwin", "macos"), ("linux", "linux"), ("win32", "windows"), ("freebsd14", "other")]
)
def test_the_host_is_named_for_the_resident(monkeypatch: pytest.MonkeyPatch, platform: str, host: str) -> None:
    monkeypatch.setattr(route_module.sys, "platform", platform)
    assert route_module.host_platform() == host


def _route(home: Path, result: dict[str, object], *, event: object = "PreToolUse", watch: bool = False) -> str:
    return route_module.native_containment_route(result, event_name=event, recording_only=watch, guard_home=home)


def _sink(
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    host: str,
    receipt: dict[str, object],
    *,
    harness: str = "claude-code",
    bridge: bool = False,
    payload: dict[str, object] | None = None,
) -> route_module.ContainmentSink:
    monkeypatch.setattr(route_module, "host_platform", lambda: host)
    return route_module.native_containment_sink(
        receipt, harness=harness, bridge=bridge, payload=_SHELL_CALL if payload is None else payload, guard_home=home
    )


def _review(**changes: object) -> dict[str, object]:
    return {"decision": "deny", "minimum_action": "review", "policy_action": "review", "reason_code": OUTSIDE} | changes


def test_a_review_keeps_allow_once_and_always_allow(
    native_approval_reuse_runtime: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An ordinary review is not routed, so its card keeps Allow once and
    # Always allow; the sink never takes a review receipt in its place.
    home = native_approval_reuse_runtime
    assert _route(home, _review(reason_code="native_unrecognized_command")) == "none"
    assert _route(home, _review(minimum_action="require-reapproval", policy_action="require-reapproval")) == "none"
    review_receipt = {**_PYTEST, "policy_action": "review"}
    assert _sink(home, monkeypatch, "macos", review_receipt).kept_because == "not_sandbox_required"


def test_the_resident_route_matches_the_retired_python_edge(native_approval_reuse_runtime: Path) -> None:
    home = native_approval_reuse_runtime
    contained = {"minimum_action": "sandbox-required", "policy_action": "sandbox-required"}
    assert _route(home, contained) == "sink"
    assert _route(home, contained, watch=True) == "none"
    assert _route(home, contained, event="PostToolUse") == "none"
    assert _route(home, contained, event=None) == "none"
    assert _route(home, _review()) == "grant"
    assert _route(home, _review(action={"action_type": "shell"})) == "grant"
    assert _route(home, _review(), watch=True) == "none"
    # Only a review the saved-approval path could also override reaches the grant.
    for result in (
        _review(reason_code="native_policy_review"),
        _review(minimum_action="allow"),
        _review(policy_action="require-reapproval"),
        _review(action={"action_type": "package"}),
        _review(action={"action_type": "guard_control"}),
        _review(action={"action_type": "guard-control-operation"}),
        _review(action={"action_type": ["shell"]}),
    ):
        assert _route(home, result) == "none", result


def test_macos_runs_every_profile_and_linux_only_the_workspace_sandbox(
    native_approval_reuse_runtime: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = native_approval_reuse_runtime
    git = _receipt("native_git_readonly_containment_required", "git-readonly-v1")
    for receipt in (_PYTEST, _WORKSPACE, git):
        assert _sink(home, monkeypatch, "macos", receipt).profile == receipt["required_execution_profile"]
    assert _sink(home, monkeypatch, "linux", _WORKSPACE).profile == "workspace-contained-v1"
    assert _sink(home, monkeypatch, "linux", _PYTEST) == (None, "platform_has_no_sink")


@pytest.mark.parametrize(
    ("reason", "profile"),
    [
        ("native_python_eval_readonly_containment_required", "python-eval-readonly-v1"),
        ("native_node_eval_readonly_containment_required", "node-eval-readonly-v1"),
        ("native_bun_eval_readonly_containment_required", "node-eval-readonly-v1"),
        ("native_node_build_output_containment_required", "node-build-output-v1"),
        ("native_node_tool_readonly_containment_required", "node-tool-readonly-v1"),
        ("native_pytest_readonly_containment_required", "pytest-readonly-v2"),
    ],
)
def test_windows_routes_the_profiles_it_has_a_runner_for(
    native_approval_reuse_runtime: Path, monkeypatch: pytest.MonkeyPatch, reason: str, profile: str
) -> None:
    home = native_approval_reuse_runtime
    receipt = _receipt(reason, profile)
    assert _sink(home, monkeypatch, "windows", receipt).profile == profile
    assert _sink(home, monkeypatch, "windows", receipt, harness="codex", bridge=True).profile == profile
    # The sink command is quoted only for Git Bash and Codex's PowerShell.
    assert _sink(home, monkeypatch, "windows", receipt, harness="zcode") == (None, "platform_has_no_sink")


def test_a_host_without_a_sink_keeps_the_receipt_and_says_so(
    native_approval_reuse_runtime: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = native_approval_reuse_runtime
    package = _receipt("native_package_test_readonly_containment_required", "package-test-readonly-v1")
    for host, receipt in (("windows", _WORKSPACE), ("windows", package), ("other", _PYTEST), ("other", _WORKSPACE)):
        assert _sink(home, monkeypatch, host, receipt) == (None, "platform_has_no_sink"), (host, receipt)


def test_the_resident_sink_matches_the_retired_python_gate(
    native_approval_reuse_runtime: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = native_approval_reuse_runtime
    cases: list[tuple[dict[str, Any], str]] = [
        ({"payload": {**_SHELL_CALL, "guard_containment_receipt_only": True}}, "receipt_only"),
        ({"harness": "cursor"}, "harness_not_routed"),
        ({"harness": "omp"}, "harness_not_routed"),
        # Only the Codex bridge, which confirmed the release applies updatedInput, routes Codex.
        ({"harness": "codex"}, "harness_not_routed"),
        ({"receipt": {**_PYTEST, "decision": "allow"}}, "not_sandbox_required"),
        ({"receipt": {**_PYTEST, "policy_action": "block"}}, "not_sandbox_required"),
        ({"receipt": {**_PYTEST, "observe_mode": True}}, "observe_mode"),
        ({"receipt": {**_PYTEST, "required_execution_profile": "wrong"}}, "profile_mismatch"),
        ({"receipt": {**_PYTEST, "reason_code": "native_destructive_command"}}, "profile_mismatch"),
        ({"payload": {**_SHELL_CALL, "hook_event_name": "PostToolUse"}}, "not_shell_call"),
        ({"payload": {**_SHELL_CALL, "tool_name": "Read"}}, "not_shell_call"),
        ({"payload": {**_SHELL_CALL, "tool_input": []}}, "not_shell_call"),
        ({"payload": {**_SHELL_CALL, "tool_input": {"command": 12}}}, "not_shell_call"),
    ]
    for change, kept_because in cases:
        options = {"receipt": _PYTEST, **change}
        receipt = options.pop("receipt")
        assert _sink(home, monkeypatch, "macos", receipt, **options) == (None, kept_because), change
    assert _sink(home, monkeypatch, "macos", _PYTEST, harness="codex", bridge=True).profile == "pytest-readonly-v2"
    camel = {"hookEventName": "pre_tool_use", "toolName": "run_command", "toolInput": {"command": "pytest"}}
    assert _sink(home, monkeypatch, "macos", _PYTEST, harness="zcode", payload=camel).profile == "pytest-readonly-v2"
