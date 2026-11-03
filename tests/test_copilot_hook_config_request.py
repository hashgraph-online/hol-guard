"""The Copilot hook config shim asks the native `copilot_hook_config` kind and applies index plans."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_runner_authority as authority
from codex_plugin_scanner.guard.adapters import copilot_hook_config as config
from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import bounded_hook_script_path

_EVENTS = ("userPromptSubmitted", "preToolUse", "postToolUse", "permissionRequest", "permissionRequestV2")
_INTERPRETER = "/nonexistent-guard/bin/python3"


def _fake(monkeypatch: pytest.MonkeyPatch, *answers: object) -> list[dict[str, object]]:
    sent: list[dict[str, object]] = []
    queue = list(answers)

    def fake_native(kind: str, request: dict[str, object], **_: object) -> object:
        assert kind == "copilot_hook_config"
        sent.append(json.loads(json.dumps(request)))
        answer = queue.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(authority, "native_runner_authority", fake_native)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.cursor_hook_config.isolated_cursor_hook_python", lambda: _INTERPRETER
    )
    return sent


def _events(**kept: list[int]) -> list[object]:
    return [[event, kept.get(event, [])] for event in _EVENTS]


def _job(events: object, **extra: object) -> dict[str, object]:
    return {"events": events, "bash": "guard bash", "powershell": "guard pwsh", **extra}


def test_one_request_carries_both_files_and_the_isolated_bridge(monkeypatch: pytest.MonkeyPatch) -> None:
    hooks: dict[str, object] = {"preToolUse": [{"command": "user"}]}
    payload: dict[str, object] = {"z": [1], "version": 2, "a": []}
    sent = _fake(
        monkeypatch,
        {"jobs": [_job(_events(preToolUse=[0])), _job(_events(), version=True, hooks=[0, 2])]},
    )

    config_plan, workspace_plan = config.plan_copilot_hooks(
        Path("/nonexistent-guard/home"), (hooks, ("py", "a b")), (payload, ("py", "--workspace", "w"))
    )

    assert sent == [
        {
            "op": "plan",
            "interpreter": _INTERPRETER,
            "script": str(bounded_hook_script_path(Path("/nonexistent-guard/home"), "copilot")),
            "jobs": [
                {"parts": ["py", "a b"], "hooks": hooks},
                {"parts": ["py", "--workspace", "w"], "payload": payload, "keys": ["z", "version", "a"]},
            ],
        }
    ]
    assert (config_plan.bash, config_plan.powershell) == ("guard bash", "guard pwsh")
    assert workspace_plan is not None
    assert workspace_plan.payload == {"version": 2, "hooks": {"z": [1], "a": []}}
    assert list(workspace_plan.hooks) == ["z", "a"]


def test_plans_keep_user_entries_by_identity_and_order(monkeypatch: pytest.MonkeyPatch) -> None:
    user = {"z": 1, "command": "user", "a": 2}
    hooks: dict[str, object] = {"sessionStart": ["kept"], "preToolUse": [{"command": "guard old"}, user]}
    _fake(
        monkeypatch,
        {"jobs": [_job(_events(preToolUse=[1]))]},
        {"jobs": [_job(_events(preToolUse=[0]))]},
    )

    plan, workspace_plan = config.plan_copilot_hooks(Path("/g"), (hooks, ()), None)
    entry: dict[str, object] = {"bash": plan.bash}
    plan.install(entry)

    assert workspace_plan is None
    assert list(hooks) == ["sessionStart", "preToolUse", *[event for event in _EVENTS if event != "preToolUse"]]
    managed = hooks["preToolUse"]
    assert isinstance(managed, list) and managed == [user, entry] and managed[0] is user
    assert all(hooks[event] == [entry] for event in _EVENTS if event != "preToolUse")

    plan, _ = config.plan_copilot_hooks(Path("/g"), (hooks, ()), None)
    plan.uninstall()
    assert hooks == {"sessionStart": ["kept"], "preToolUse": [user]}


def test_a_nested_workspace_hooks_object_is_kept_with_a_default_version(monkeypatch: pytest.MonkeyPatch) -> None:
    payload: dict[str, object] = {"version": "3", "hooks": {"preToolUse": [{"command": "guard"}], "x": "y"}}
    _fake(monkeypatch, {"jobs": [_job(_events()), _job(_events(), version=False, hooks=None)]})

    _, workspace_plan = config.plan_copilot_hooks(Path("/g"), ({}, ()), (payload, ()))

    assert workspace_plan is not None
    workspace_plan.uninstall()
    assert workspace_plan.payload == {"version": 1, "hooks": {"x": "y"}}


_WORKSPACE = {"version": 1, "hooks": {"preToolUse": [{"command": "user"}]}}


@pytest.mark.parametrize(
    ("answer", "workspace"),
    [
        ({}, None),
        ({"jobs": []}, None),
        ({"jobs": [_job(_events())], "extra": 1}, None),
        ({"jobs": [{"events": _events(), "bash": "b"}]}, None),
        ({"jobs": [_job(_events(), version=True, hooks=None)]}, None),
        ({"jobs": [_job(_events(preToolUse=[0, 0]))]}, None),
        ({"jobs": [_job(_events(), bash=1)]}, None),
        ({"jobs": [_job("not a list")]}, None),
        ({"jobs": [_job([["preToolUse", []], ["preToolUse", []]])]}, None),
        ({"jobs": [_job([["preToolUse"]])]}, None),
        ({"jobs": [_job([])]}, None),
        ({"jobs": [_job(_events()[:-1])]}, None),
        ({"jobs": [_job([*_events()[:-1], ["sessionStart", []]])]}, None),
        ({"jobs": [_job(_events()[::-1])]}, None),
        ({"jobs": [_job(_events()), _job(_events(preToolUse=[True]), version=True, hooks=None)]}, _WORKSPACE),
        ({"jobs": [_job(_events()), _job(_events(preToolUse=[1]), version=True, hooks=None)]}, _WORKSPACE),
        ({"jobs": [_job(_events()), _job(_events(preToolUse=[-1]), version=True, hooks=None)]}, _WORKSPACE),
        ({"jobs": [_job(_events()), _job(_events(), version=1, hooks=None)]}, _WORKSPACE),
        ({"jobs": [_job(_events()), _job(_events(), version=True)]}, _WORKSPACE),
        ({"jobs": [_job(_events()), _job(_events(), version=True, hooks=[0])]}, _WORKSPACE),
        ({"jobs": [_job(_events()), _job(_events(), version=False, hooks=[1, 1])]}, {"a": [], "b": []}),
        ({"jobs": [_job(_events()), _job(_events(), version=True, hooks=[])]}, {"a": []}),
        ({"jobs": [_job(_events()), _job(_events(), version=False, hooks=None)]}, {"hooks": []}),
    ],
)
def test_a_malformed_answer_fails_closed(
    monkeypatch: pytest.MonkeyPatch, answer: object, workspace: dict[str, object] | None
) -> None:
    _fake(monkeypatch, answer)

    with pytest.raises(config.CopilotHookOwnershipError, match="hol-guard doctor copilot"):
        config.plan_copilot_hooks(
            Path("/g"),
            ({"preToolUse": [{"command": "user"}]}, ()),
            None if workspace is None else (json.loads(json.dumps(workspace)), ()),
        )


def test_an_unavailable_runtime_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake(monkeypatch, authority.NativeRunnerAuthorityError("native_runner_authority_unavailable"))

    with pytest.raises(config.CopilotHookOwnershipError, match="did not answer") as raised:
        config.plan_copilot_hooks(Path("/g"), ({}, ()), None)

    assert isinstance(raised.value.__cause__, authority.NativeRunnerAuthorityError)
