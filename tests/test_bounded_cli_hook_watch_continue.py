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
        "cli_args": [
            "guard",
            "hook",
            "--guard-home",
            str(guard_home),
            "--harness",
            harness,
        ],
        "harness": harness,
        "timeout_seconds": 3,
    }


def test_timeout_allows_grok_when_watch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        bounded_cli_hook_bridge,
        "run_isolated_hook_process",
        _runner_result(BoundedHookProcessResult(None, "", False, True)),
    )
    config = _config(tmp_path, harness="grok")
    guard_home = Path(str(config["guard_home"]))
    (guard_home / "config.toml").write_text(
        'protection_posture = "watch"\nmode = "observe"\n',
        encoding="utf-8",
    )
    output = io.StringIO()
    with redirect_stdout(output):
        returncode = bounded_cli_hook_bridge.run_bounded_cli_hook(
            config,
            input_text=json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Write",
                    "tool_input": {"path": "foo.txt", "contents": "x"},
                }
            ),
        )

    payload = _json_object(output.getvalue())
    assert returncode == 0
    assert payload == {"decision": "allow"}


def test_pretty_printed_hook_json_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    pretty = json.dumps({"decision": "allow", "policy_action": "warn"}, indent=2) + "\n"
    monkeypatch.setattr(
        bounded_cli_hook_bridge,
        "run_isolated_hook_process",
        _runner_result(BoundedHookProcessResult(0, pretty, False, False)),
    )
    output = io.StringIO()
    with redirect_stdout(output):
        returncode = bounded_cli_hook_bridge.run_bounded_cli_hook(
            _config(tmp_path, harness="grok"),
            input_text=json.dumps({"hook_event_name": "PreToolUse"}),
        )

    payload = _json_object(output.getvalue())
    assert returncode == 0
    assert payload == {"decision": "allow", "policy_action": "warn"}


def test_timeout_denies_grok_when_watch_has_expired(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        bounded_cli_hook_bridge,
        "run_isolated_hook_process",
        _runner_result(BoundedHookProcessResult(None, "", False, True)),
    )
    config = _config(tmp_path, harness="grok")
    guard_home = Path(str(config["guard_home"]))
    (guard_home / "config.toml").write_text(
        'protection_posture = "watch"\n'
        'mode = "observe"\n'
        "watch_auto_revert_hours = 24\n"
        'watch_entered_at = "2020-01-01T00:00:00+00:00"\n',
        encoding="utf-8",
    )
    output = io.StringIO()
    with redirect_stdout(output):
        returncode = bounded_cli_hook_bridge.run_bounded_cli_hook(
            config,
            input_text=json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Write",
                    "tool_input": {"path": "foo.txt", "contents": "x"},
                }
            ),
        )

    payload = _json_object(output.getvalue())
    assert returncode == 0
    assert payload["decision"] == "deny"


def test_oversized_input_allows_grok_when_watch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = _config(tmp_path, harness="grok")
    guard_home = Path(str(config["guard_home"]))
    (guard_home / "config.toml").write_text(
        'protection_posture = "watch"\nmode = "observe"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(bounded_cli_hook_bridge, "_read_bounded_stdin", lambda: (None, "{}"))
    output = io.StringIO()
    with redirect_stdout(output):
        returncode = bounded_cli_hook_bridge.main_from_argv([json.dumps(config)])

    payload = _json_object(output.getvalue())
    assert returncode == 0
    assert payload == {"decision": "allow"}


def test_oversized_input_preserves_kimi_event_when_watch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = _config(tmp_path, harness="kimi")
    guard_home = Path(str(config["guard_home"]))
    (guard_home / "config.toml").write_text(
        'protection_posture = "watch"\nmode = "observe"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        bounded_cli_hook_bridge,
        "_read_bounded_stdin",
        lambda: (None, '{"hook_event_name":"UserPromptSubmit"'),
    )
    output = io.StringIO()
    with redirect_stdout(output):
        returncode = bounded_cli_hook_bridge.main_from_argv([json.dumps(config)])

    payload = _json_object(output.getvalue())
    assert returncode == 0
    hook_output = payload["hookSpecificOutput"]
    assert isinstance(hook_output, dict)
    assert hook_output["hookEventName"] == "UserPromptSubmit"
    assert hook_output["permissionDecision"] == "allow"
