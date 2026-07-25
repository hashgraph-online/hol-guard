from __future__ import annotations

import io
import json
from collections.abc import Callable, Mapping, Sequence
from contextlib import redirect_stdout
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.adapters import bounded_cli_hook_bridge
from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult


def _runner_result(result: BoundedHookProcessResult) -> Callable[..., BoundedHookProcessResult]:
    def run(
        command: Sequence[str],
        *,
        input_text: str,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: float,
        output_limit: int = 1_000_000,
    ) -> BoundedHookProcessResult:
        del command, input_text, cwd, environment, timeout_seconds, output_limit
        return result

    return run


def _json_object(text: str) -> dict[str, object]:
    payload = cast(object, json.loads(text))
    assert isinstance(payload, dict)
    return {str(key): value for key, value in cast(dict[object, object], payload).items()}


def _config(tmp_path: Path, *, harness: str) -> dict[str, object]:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    return {
        "python_executable": "python",
        "package_root": str(tmp_path),
        "guard_home": str(guard_home),
        "cli_args": ["guard", "hook", "--harness", harness],
        "harness": harness,
        "timeout_seconds": 3,
    }


@pytest.mark.parametrize(
    ("harness", "expected"),
    [
        ("copilot", {"permissionDecision": "deny"}),
        ("grok", {"decision": "deny"}),
        ("hermes", {"decision": "deny"}),
        ("openclaw", {"decision": "deny"}),
    ],
)
def test_timeout_emits_successful_native_deny(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    harness: str,
    expected: dict[str, str],
) -> None:
    monkeypatch.setattr(
        bounded_cli_hook_bridge,
        "run_isolated_hook_process",
        _runner_result(BoundedHookProcessResult(None, "", False, True)),
    )
    output = io.StringIO()
    with redirect_stdout(output):
        returncode = bounded_cli_hook_bridge.run_bounded_cli_hook(
            _config(tmp_path, harness=harness),
            input_text=json.dumps({"hook_event_name": "PreToolUse"}),
        )

    payload = _json_object(output.getvalue())
    assert returncode == 0
    for key, value in expected.items():
        assert payload[key] == value


@pytest.mark.parametrize("harness", ["kimi", "zcode"])
def test_claude_shaped_timeout_emits_deny_and_block_exit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    harness: str,
) -> None:
    monkeypatch.setattr(
        bounded_cli_hook_bridge,
        "run_isolated_hook_process",
        _runner_result(BoundedHookProcessResult(None, "", False, True)),
    )
    output = io.StringIO()
    with redirect_stdout(output):
        returncode = bounded_cli_hook_bridge.run_bounded_cli_hook(
            _config(tmp_path, harness=harness),
            input_text=json.dumps({"hookEventName": "PreToolUse"}),
        )

    payload = _json_object(output.getvalue())
    assert returncode == 2
    hook_output = payload["hookSpecificOutput"]
    assert isinstance(hook_output, dict)
    assert hook_output["permissionDecision"] == "deny"


def test_success_preserves_child_stdout_and_returncode(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        bounded_cli_hook_bridge,
        "run_isolated_hook_process",
        _runner_result(BoundedHookProcessResult(2, '{"decision":"deny"}\n', False, False)),
    )
    output = io.StringIO()
    with redirect_stdout(output):
        returncode = bounded_cli_hook_bridge.run_bounded_cli_hook(
            _config(tmp_path, harness="grok"),
            input_text="{}",
        )

    assert returncode == 2
    assert output.getvalue() == '{"decision":"deny"}\n'


def test_empty_failed_child_is_converted_to_native_deny(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        bounded_cli_hook_bridge,
        "run_isolated_hook_process",
        _runner_result(BoundedHookProcessResult(1, "", False, False)),
    )
    output = io.StringIO()
    with redirect_stdout(output):
        returncode = bounded_cli_hook_bridge.run_bounded_cli_hook(
            _config(tmp_path, harness="copilot"),
            input_text="{}",
        )

    assert returncode == 0
    assert _json_object(output.getvalue())["permissionDecision"] == "deny"


def test_malformed_success_is_converted_to_native_deny(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        bounded_cli_hook_bridge,
        "run_isolated_hook_process",
        _runner_result(BoundedHookProcessResult(0, "not-json\n", False, False)),
    )
    output = io.StringIO()
    with redirect_stdout(output):
        returncode = bounded_cli_hook_bridge.run_bounded_cli_hook(
            _config(tmp_path, harness="grok"),
            input_text="{}",
        )

    assert returncode == 0
    assert _json_object(output.getvalue())["decision"] == "deny"


def test_copilot_permission_timeout_uses_permission_request_contract(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        bounded_cli_hook_bridge,
        "run_isolated_hook_process",
        _runner_result(BoundedHookProcessResult(None, "", False, True)),
    )
    output = io.StringIO()
    with redirect_stdout(output):
        returncode = bounded_cli_hook_bridge.run_bounded_cli_hook(
            _config(tmp_path, harness="copilot"),
            input_text=json.dumps({"hookEventName": "PermissionRequest"}),
        )

    assert returncode == 0
    assert _json_object(output.getvalue())["behavior"] == "deny"


def test_oversized_input_uses_configured_harness_native_deny(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = _config(tmp_path, harness="copilot")
    monkeypatch.setattr(bounded_cli_hook_bridge, "_bounded_stdin", lambda: None)
    output = io.StringIO()

    with redirect_stdout(output):
        returncode = bounded_cli_hook_bridge.main_from_argv([json.dumps(config)])

    assert returncode == 0
    assert _json_object(output.getvalue())["permissionDecision"] == "deny"
