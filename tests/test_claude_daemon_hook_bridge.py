"""What the Claude hook launcher still decides, and the render helpers behind it.

The launcher runs the runtime's own `claude-hook-bridge` command; the daemon
request, its recovery and its retry live there and are tested in
`rust/crates/guard-runtime/src/claude_hook_bridge_tests.rs`. What is left here
is the fail-closed answer an install without a runtime gets, and the program
the launcher names for the runtime to recover the daemon with.
"""

from __future__ import annotations

import io
import json
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import claude_daemon_hook_bridge as bridge


@pytest.fixture
def without_a_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    """An install whose native runtime is missing or too old for the bridge."""

    monkeypatch.setattr(bridge, "_native_bridge_executable", lambda _home: None)


def _run(tmp_path: Path, *, query: str = "guard-home=/missing") -> int:
    return bridge.main(
        state_path=tmp_path / "daemon-state.json",
        fallback_daemon_url="http://127.0.0.1:5474",
        fallback_command=("fallback",),
        query=query,
    )


@pytest.mark.usefixtures("without_a_runtime")
def test_a_hook_without_a_runtime_denies_rather_than_evaluating_in_python(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(bridge.sys, "stdin", io.StringIO('{"hook_event_name":"PreToolUse","tool_name":"Bash"}'))

    assert _run(tmp_path) == 0

    output = json.loads(capsys.readouterr().out)["hookSpecificOutput"]
    assert output["permissionDecision"] == "deny"
    assert bridge._NATIVE_RUNTIME_UNAVAILABLE in output["permissionDecisionReason"]


@pytest.mark.usefixtures("without_a_runtime")
@pytest.mark.parametrize(
    "event", ["PreToolUse", "PermissionRequest", "UserPromptSubmit", "PostToolUse", "Stop", "Notification"]
)
def test_an_oversized_hook_without_a_runtime_keeps_its_event_denial(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    event: str,
) -> None:
    monkeypatch.setattr(bridge, "_MAX_HOOK_INPUT_BYTES", 1)
    monkeypatch.setattr(bridge.sys, "stdin", io.StringIO("x" * 64))
    # The body is cut off before the event name can be read out of it, so the
    # denial is held to what the truncated prefix says the event was.
    monkeypatch.setattr(bridge, "_event_name", lambda _text: event)

    assert _run(tmp_path) == 0

    payload = json.loads(capsys.readouterr().out)
    if event.startswith("Permission"):
        assert payload["hookSpecificOutput"]["decision"]["behavior"] == "deny"
    elif event in {"UserPromptSubmit", "PostToolUse", "Stop"}:
        assert payload["decision"] == "block"
    else:
        assert payload["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
        assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "exceeded the safe size limit" in json.dumps(payload)


def test_native_spawn_error_denies_the_tool_instead_of_failing_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(bridge, "_native_bridge_executable", lambda _home: tmp_path / "vanished-runtime")
    monkeypatch.setattr(bridge.sys, "stdin", io.StringIO('{"hook_event_name":"PreToolUse","tool_name":"Bash"}'))

    def cannot_launch(*_args: object, **_kwargs: object) -> None:
        raise PermissionError("cannot execute native runtime")

    monkeypatch.setattr(bridge.subprocess, "run", cannot_launch)
    assert _run(tmp_path) == 0
    response = json.loads(capsys.readouterr().out)
    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert bridge._NATIVE_RUNTIME_UNAVAILABLE in response["hookSpecificOutput"]["permissionDecisionReason"]


def test_native_probe_budget_is_shared_with_one_bounded_retry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[float] = []
    started = time.monotonic()

    def unavailable(_feature: str, *, guard_home: Path, deadline_monotonic: float) -> None:
        assert guard_home == tmp_path
        calls.append(deadline_monotonic)
        return None

    sleeps: list[float] = []
    monkeypatch.setattr(bridge.time, "sleep", sleeps.append)
    monkeypatch.setattr(bridge, "native_hook_bridge_executable", unavailable)
    assert bridge._native_bridge_executable(tmp_path) is None
    assert len(calls) == 2
    assert len(sleeps) == 1 and 0.2 <= sleeps[0] <= 0.26
    assert calls[0] == calls[1]
    assert started < calls[0] <= time.monotonic() + 1.5


@pytest.mark.parametrize("status", [1, 3, 126, 127])
def test_native_child_nonblocking_error_is_converted_to_blocking_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    from types import SimpleNamespace

    monkeypatch.setattr(bridge, "_native_bridge_executable", lambda _home: tmp_path / "runtime")
    monkeypatch.setattr(bridge.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(returncode=status))
    assert _run(tmp_path) == 2


@pytest.mark.usefixtures("without_a_runtime")
def test_missing_native_prompt_authority_blocks_unreviewed_prompt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        bridge.sys, "stdin", io.StringIO('{"hook_event_name":"UserPromptSubmit","prompt":"read my tokens"}')
    )
    assert _run(tmp_path) == 0
    response = json.loads(capsys.readouterr().out)
    assert response["decision"] == "block"
    assert bridge._NATIVE_RUNTIME_UNAVAILABLE in response["reason"]


def test_the_launcher_hands_the_runtime_this_call_s_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The native command gets the same config an installed one carries.

    An older install's hook command was written before the runtime shipped, so
    it carries no config of its own; the launcher rebuilds it here, including
    the recovery command the runtime runs when no daemon answers.
    """

    native = tmp_path / "hol-guard-runtime"
    guard_home = tmp_path / "guard home"
    guard_home.mkdir()
    seen: dict[str, object] = {}

    class _Completed:
        returncode = 0

    def fake_run(argv: tuple[str, ...], **kwargs: object) -> _Completed:
        seen["argv"] = argv
        seen["kwargs"] = kwargs
        return _Completed()

    monkeypatch.setattr(bridge, "_native_bridge_executable", lambda _home: native)
    monkeypatch.setattr(bridge.subprocess, "run", fake_run)

    assert (
        bridge.main(
            state_path=guard_home / "daemon-state.json",
            fallback_daemon_url="http://127.0.0.1:5474",
            fallback_command=("fallback", "--harness", "claude"),
            query=f"guard-home={guard_home.as_posix()}",
        )
        == 0
    )

    argv = seen["argv"]
    assert argv[0] == str(native)
    assert argv[2] == bridge.CLAUDE_GUARD_DAEMON_HOOK_MARKER
    config = json.loads(argv[3])
    assert config["state_path"] == str(guard_home / "daemon-state.json")
    assert config["fallback_daemon_url"] == "http://127.0.0.1:5474"
    assert config["fallback_command"] == ["fallback", "--harness", "claude"]
    assert config["query"] == f"guard-home={guard_home.as_posix()}"
    assert config["recovery_launcher"] == {
        "executable": bridge.sys.executable,
        "package_root": str(Path(bridge.__file__).resolve().parents[3]),
    }
    assert "recovery_command" not in config
    # The child reads the hook body and writes the verdict itself.
    assert seen["kwargs"] == {"check": False}


def test_a_query_naming_another_guard_home_still_reaches_the_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The runtime refuses that query; the launcher does not pre-empt it."""

    native = tmp_path / "hol-guard-runtime"
    seen: dict[str, object] = {}

    class _Completed:
        returncode = 0

    monkeypatch.setattr(bridge, "_native_bridge_executable", lambda _home: native)
    monkeypatch.setattr(bridge.subprocess, "run", lambda argv, **_kwargs: (seen.update(argv=argv), _Completed())[1])

    assert _run(tmp_path, query="guard-home=/somewhere/else") == 0

    config = json.loads(seen["argv"][3])
    assert config["query"] == "guard-home=/somewhere/else"


@pytest.mark.usefixtures("without_a_runtime")
@pytest.mark.parametrize("event", ["PreToolUse", "PermissionRequest", "PermissionDenied"])
def test_a_tool_without_a_runtime_is_never_granted_permission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], event: str
) -> None:
    body = {"hook_event_name": event, "tool_name": "Read", "tool_input": {"file_path": "src/app.ts"}}
    monkeypatch.setattr(bridge.sys, "stdin", io.StringIO(json.dumps(body)))

    assert _run(tmp_path) == 0

    output = json.loads(capsys.readouterr().out)["hookSpecificOutput"]
    if event == "PreToolUse":
        assert output["permissionDecision"] == "deny"
    else:
        assert output["decision"]["behavior"] == "deny"
    assert bridge._NATIVE_RUNTIME_UNAVAILABLE in json.dumps(output)


def test_a_frozen_core_names_itself_as_the_recovery_program(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import frozen_runtime_commands, stable_guard_cli

    monkeypatch.setattr(frozen_runtime_commands, "is_frozen_guard_runtime", lambda: True)
    monkeypatch.setattr(stable_guard_cli, "resolve_frozen_guard_cli", lambda: "/opt/guard/hol-guard")

    assert bridge._recovery_launcher() == {"executable": "/opt/guard/hol-guard", "frozen": True}


def test_remaining_hint_preserves_unicode_and_omits_itself_when_it_will_not_fit() -> None:
    from scripts.daemon_hook_client import (
        _MAX_HOOK_REQUEST_BYTES,
        _with_remaining_hint,
    )

    prompt = "é" * 200_000
    original = json.dumps(
        {"hook_event_name": "PreToolUse", "prompt": prompt},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    ascii_form = json.dumps(json.loads(original), ensure_ascii=True, separators=(",", ":"))
    assert len(original.encode("utf-8")) < _MAX_HOOK_REQUEST_BYTES < len(ascii_form.encode("utf-8"))
    hinted = _with_remaining_hint(original, time.monotonic() + 5)
    parsed = json.loads(hinted)
    assert parsed["prompt"] == prompt
    assert "guard_remaining_ms" in parsed
    assert "\\u00e9" not in hinted
    assert len(hinted.encode("utf-8")) <= _MAX_HOOK_REQUEST_BYTES

    prefix = '{"hook_event_name":"PreToolUse","blob":"'
    suffix = '"}'
    room = _MAX_HOOK_REQUEST_BYTES - len(prefix.encode("utf-8")) - len(suffix.encode("utf-8"))
    packed = prefix + ("a" * room) + suffix
    assert len(packed.encode("utf-8")) == _MAX_HOOK_REQUEST_BYTES
    assert _with_remaining_hint(packed, time.monotonic() + 5) == packed
