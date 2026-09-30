from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.adapters import bounded_cli_hook_bridge, bounded_cli_hook_daemon
from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult

from .bounded_cli_hook_test_support import config as _config
from .bounded_cli_hook_test_support import json_object as _json_object
from .bounded_cli_hook_test_support import runner_result as _runner_result


@pytest.mark.parametrize(
    ("harness", "expected"),
    [
        ("copilot", {"permissionDecision": "allow"}),
        ("grok", {"decision": "allow"}),
        ("hermes", {"decision": "allow"}),
        ("openclaw", {"decision": "allow"}),
    ],
)
def test_timeout_continues_when_review_cannot_finish(
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


def test_timeout_allows_emergency_safe_read(
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
            _config(tmp_path, harness="kimi"),
            input_text=json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Read",
                    "tool_input": {"file_path": "src/app.ts"},
                }
            ),
        )

    payload = _json_object(output.getvalue())
    assert returncode == 0
    hook_output = payload["hookSpecificOutput"]
    assert isinstance(hook_output, dict)
    assert hook_output["permissionDecision"] == "allow"


@pytest.mark.parametrize("harness", ["kimi", "zcode", "devin"])
def test_claude_shaped_timeout_continues_when_review_cannot_finish(
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
    assert returncode == 0
    hook_output = payload["hookSpecificOutput"]
    assert isinstance(hook_output, dict)
    assert hook_output["permissionDecision"] == "allow"


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


def test_empty_failed_child_continues_when_review_cannot_finish(
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
    assert _json_object(output.getvalue())["permissionDecision"] == "allow"


def test_malformed_success_continues_when_review_cannot_finish(
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
    assert _json_object(output.getvalue())["decision"] == "allow"


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
    monkeypatch.setattr(bounded_cli_hook_bridge, "_read_bounded_stdin", lambda: (None, "{}"))
    output = io.StringIO()

    with redirect_stdout(output):
        returncode = bounded_cli_hook_bridge.main_from_argv([json.dumps(config)])

    assert returncode == 0
    assert _json_object(output.getvalue())["permissionDecision"] == "deny"


def test_invalid_frozen_args_deny_before_daemon_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = _config(tmp_path, harness="grok")
    config["cli_args"] = ["-c", "echo bypassed"]
    config["frozen_launcher"] = True
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "frozen", True, raising=False)

    def forbidden_daemon(**kwargs: object) -> object:
        del kwargs
        raise AssertionError("invalid frozen arguments must not reach the daemon")

    monkeypatch.setattr(bounded_cli_hook_daemon, "try_daemon_hook", forbidden_daemon)
    output = io.StringIO()
    with redirect_stdout(output):
        returncode = bounded_cli_hook_bridge.run_bounded_cli_hook(config, input_text="{}")

    assert returncode == 0
    assert _json_object(output.getvalue())["decision"] == "deny"


def test_frozen_path_resolution_failure_denies_before_daemon_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = _config(tmp_path, harness="grok")
    config["frozen_launcher"] = True
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "frozen", True, raising=False)

    def fail_resolve(self: Path, *, strict: bool = False) -> Path:
        del self, strict
        raise RuntimeError("symlink loop")

    def forbidden_daemon(**kwargs: object) -> object:
        del kwargs
        raise AssertionError("unresolved frozen paths must not reach the daemon")

    monkeypatch.setattr(bounded_cli_hook_bridge.Path, "resolve", fail_resolve)
    monkeypatch.setattr(bounded_cli_hook_daemon, "try_daemon_hook", forbidden_daemon)
    output = io.StringIO()
    with redirect_stdout(output):
        returncode = bounded_cli_hook_bridge.run_bounded_cli_hook(config, input_text="{}")

    assert returncode == 0
    assert _json_object(output.getvalue())["decision"] == "deny"


def test_valid_frozen_args_retain_daemon_fast_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = _config(tmp_path, harness="grok")
    config["frozen_launcher"] = True
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "frozen", True, raising=False)
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "executable", "/app/hol-guard")
    monkeypatch.setattr(
        bounded_cli_hook_daemon,
        "try_daemon_hook",
        lambda **kwargs: ('{"decision":"allow"}\n', "", 0),
    )

    def forbidden_runner(*args: object, **kwargs: object) -> BoundedHookProcessResult:
        del args, kwargs
        raise AssertionError("valid daemon result must avoid fallback startup")

    monkeypatch.setattr(bounded_cli_hook_bridge, "run_isolated_hook_process", forbidden_runner)
    output = io.StringIO()
    with redirect_stdout(output):
        returncode = bounded_cli_hook_bridge.run_bounded_cli_hook(config, input_text="{}")

    assert returncode == 0
    assert _json_object(output.getvalue())["decision"] == "allow"


def test_relative_frozen_guard_home_denies_before_daemon_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = _config(tmp_path, harness="grok")
    cli_args = cast(list[str], config["cli_args"])
    cli_args[3] = "guard-home"
    config["frozen_launcher"] = True
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "frozen", True, raising=False)

    def forbidden_daemon(**kwargs: object) -> object:
        del kwargs
        raise AssertionError("relative frozen Guard home must not reach the daemon")

    monkeypatch.setattr(bounded_cli_hook_daemon, "try_daemon_hook", forbidden_daemon)
    output = io.StringIO()
    with redirect_stdout(output):
        returncode = bounded_cli_hook_bridge.run_bounded_cli_hook(config, input_text="{}")

    assert returncode == 0
    assert _json_object(output.getvalue())["decision"] == "deny"


def test_relative_configured_guard_home_denies_before_daemon_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = _config(tmp_path, harness="grok")
    config["guard_home"] = "guard-home"
    cli_args = cast(list[str], config["cli_args"])
    cli_args[3] = "guard-home"
    config["frozen_launcher"] = True
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "frozen", True, raising=False)

    def forbidden_daemon(**kwargs: object) -> object:
        del kwargs
        raise AssertionError("relative configured Guard home must not reach the daemon")

    monkeypatch.setattr(bounded_cli_hook_daemon, "try_daemon_hook", forbidden_daemon)
    output = io.StringIO()
    with redirect_stdout(output):
        returncode = bounded_cli_hook_bridge.run_bounded_cli_hook(config, input_text="{}")

    assert returncode == 0
    assert _json_object(output.getvalue())["decision"] == "deny"
