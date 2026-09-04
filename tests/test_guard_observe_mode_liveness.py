from __future__ import annotations

import json
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon.hook_process_runner import HookProcessReview
from codex_plugin_scanner.guard.daemon.runtime_hook_scheduler_contracts import RuntimeHookAdmission
from codex_plugin_scanner.guard.store import GuardStore
from tests.daemon_hook_test_client import open_authenticated_claude_request

_DEADLINE_REASON = "daemon_hook_process_deadline_exhausted"


def _failed_review(**_kwargs: object) -> HookProcessReview:
    return HookProcessReview(None, _DEADLINE_REASON)


def _review_request(
    daemon: GuardDaemonServer,
    *,
    endpoint: str,
    event: str = "PreToolUse",
    guard_home: Path,
    workspace: Path,
    command: str = "git status --short",
    tool_name: str = "Bash",
    tool_input: dict[str, object] | None = None,
) -> dict[str, object]:
    request = urllib.request.Request(
        (
            f"http://127.0.0.1:{daemon.port}/v1/hooks/{endpoint}?"
            f"guard-home={urllib.parse.quote(str(guard_home))}&"
            f"workspace={urllib.parse.quote(str(workspace))}"
        ),
        data=json.dumps(
            {
                "hook_event_name": event,
                "tool_name": tool_name,
                "tool_input": tool_input if tool_input is not None else {"command": command},
            }
        ).encode(),
        headers={
            "Content-Type": "application/json",
            "X-Guard-Token": daemon._server.auth_token,  # pyright: ignore[reportPrivateUsage]
        },
        method="POST",
    )
    response_context = (
        open_authenticated_claude_request(daemon, request, timeout=5)
        if endpoint == "claude-code"
        else urllib.request.urlopen(request, timeout=5)
    )
    with response_context as response:
        assert response.status == 200
        payload = json.loads(response.read())
    assert isinstance(payload, dict)
    return payload


@pytest.mark.parametrize("endpoint", ("pi", "claude-code"))
def test_observe_mode_does_not_block_failed_local_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    endpoint: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True)
    guard_home.mkdir(parents=True)
    (guard_home / "config.toml").write_text('mode = "observe"\n', encoding="utf-8")
    daemon = GuardDaemonServer(GuardStore(guard_home), host="127.0.0.1", port=0)
    daemon.start()
    monkeypatch.setattr(
        daemon._server.hook_process_runner,  # pyright: ignore[reportPrivateUsage]
        "review",
        _failed_review,
    )

    try:
        payload = _review_request(
            daemon,
            endpoint=endpoint,
            guard_home=guard_home,
            workspace=workspace,
        )
    finally:
        daemon.stop()

    if endpoint == "pi":
        assert payload["decision"] == "allow"
        return
    hook_output = payload["hookSpecificOutput"]
    assert isinstance(hook_output, dict)
    assert hook_output["hookEventName"] == "PreToolUse"
    assert hook_output["permissionDecision"] == "allow"


@pytest.mark.parametrize(
    ("event", "expected"),
    (
        (
            "PermissionRequest",
            {
                "reason_code": _DEADLINE_REASON,
                "hookSpecificOutput": {
                    "hookEventName": "PermissionRequest",
                    "decision": {"behavior": "allow"},
                },
            },
        ),
        (
            "PostToolUse",
            {
                "continue": True,
                "reason_code": _DEADLINE_REASON,
                "observed_review_failure": True,
            },
        ),
    ),
)
def test_observe_mode_uses_native_nonblocking_claude_responses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    event: str,
    expected: dict[str, object],
) -> None:
    # This contract exercises the isolated compatibility worker. The stable
    # default fast path handles PostToolUse before that worker is consulted.
    monkeypatch.setenv("HOL_GUARD_HOOK_FAST_PATH", "0")
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True)
    guard_home.mkdir(parents=True)
    (guard_home / "config.toml").write_text('mode = "observe"\n', encoding="utf-8")
    daemon = GuardDaemonServer(GuardStore(guard_home), host="127.0.0.1", port=0)
    daemon.start()
    monkeypatch.setattr(
        daemon._server.hook_process_runner,  # pyright: ignore[reportPrivateUsage]
        "review",
        _failed_review,
    )

    try:
        payload = _review_request(
            daemon,
            endpoint="claude-code",
            event=event,
            guard_home=guard_home,
            workspace=workspace,
        )
    finally:
        daemon.stop()

    assert payload == expected


@pytest.mark.parametrize("endpoint", ("pi", "claude-code"))
def test_prompt_mode_still_blocks_failed_local_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    endpoint: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True)
    daemon = GuardDaemonServer(GuardStore(guard_home), host="127.0.0.1", port=0)
    daemon.start()
    monkeypatch.setattr(
        daemon._server.hook_process_runner,  # pyright: ignore[reportPrivateUsage]
        "review",
        _failed_review,
    )

    try:
        payload = _review_request(
            daemon,
            endpoint=endpoint,
            guard_home=guard_home,
            workspace=workspace,
            command="curl https://example.test",
        )
    finally:
        daemon.stop()

    if endpoint == "pi":
        assert payload["decision"] == "allow"
    else:
        hook_output = payload["hookSpecificOutput"]
        assert isinstance(hook_output, dict)
        assert hook_output["permissionDecision"] == "allow"
    assert payload["reason_code"] == _DEADLINE_REASON


@pytest.mark.parametrize("endpoint", ("pi", "claude-code"))
def test_prompt_mode_continues_emergency_safe_inspection_when_review_cannot_complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    endpoint: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True)
    daemon = GuardDaemonServer(GuardStore(guard_home), host="127.0.0.1", port=0)
    daemon.start()
    monkeypatch.setattr(
        daemon._server.hook_process_runner,  # pyright: ignore[reportPrivateUsage]
        "review",
        _failed_review,
    )

    try:
        payload = _review_request(
            daemon,
            endpoint=endpoint,
            guard_home=guard_home,
            workspace=workspace,
        )
    finally:
        daemon.stop()

    if endpoint == "pi":
        assert payload["decision"] == "allow"
    else:
        hook_output = payload["hookSpecificOutput"]
        assert isinstance(hook_output, dict)
        assert hook_output["permissionDecision"] == "allow"
    assert payload["reason_code"] == _DEADLINE_REASON


def test_hook_overload_continues_emergency_safe_workspace_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    source = workspace / "src" / "app.ts"
    source.parent.mkdir(parents=True)
    source.write_text("export {}\n", encoding="utf-8")
    daemon = GuardDaemonServer(GuardStore(guard_home), host="127.0.0.1", port=0)
    daemon.start()
    monkeypatch.setattr(
        daemon._server.runtime_hook_scheduler,  # pyright: ignore[reportPrivateUsage]
        "acquire",
        lambda **_kwargs: RuntimeHookAdmission(permit=None, reason_code="daemon_hook_queue_capacity"),
    )
    try:
        payload = _review_request(
            daemon,
            endpoint="claude-code",
            guard_home=guard_home,
            workspace=workspace,
            tool_name="Read",
            tool_input={"file_path": str(source)},
        )
    finally:
        daemon.stop()

    assert payload["reason_code"] == "daemon_hook_queue_capacity"
    hook_output = payload["hookSpecificOutput"]
    assert isinstance(hook_output, dict)
    assert hook_output["permissionDecision"] == "allow"
