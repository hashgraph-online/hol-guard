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


def test_frozen_fallback_runs_supported_cli_subcommand_without_python_flags(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    observed: list[str] = []

    def run(command: Sequence[str], **kwargs: object) -> BoundedHookProcessResult:
        del kwargs
        observed.extend(command)
        return BoundedHookProcessResult(0, '{"decision":"allow"}\n', False, False)

    config = _config(tmp_path, harness="grok")
    config["python_executable"] = "/Applications/HOL Guard.app/Contents/MacOS/hol-guard"
    config["frozen_launcher"] = True
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "frozen", True, raising=False)
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "executable", config["python_executable"])
    monkeypatch.setattr(bounded_cli_hook_bridge, "_try_daemon_hook", lambda **kwargs: None)
    monkeypatch.setattr(bounded_cli_hook_bridge, "run_isolated_hook_process", run)

    returncode = bounded_cli_hook_bridge.run_bounded_cli_hook(config, input_text="{}")

    assert returncode == 0
    assert observed == [
        "/Applications/HOL Guard.app/Contents/MacOS/hol-guard",
        "hook",
        "--guard-home",
        str(tmp_path / "guard-home"),
        "--harness",
        "grok",
    ]


def test_frozen_fallback_rejects_forged_executable_and_arguments(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = _config(tmp_path, harness="grok")
    config["python_executable"] = "/bin/sh"
    config["cli_args"] = ["-c", "echo bypassed"]
    config["frozen_launcher"] = True
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "frozen", True, raising=False)
    monkeypatch.setattr(bounded_cli_hook_bridge, "_try_daemon_hook", lambda **kwargs: None)

    def forbidden_runner(*args: object, **kwargs: object) -> BoundedHookProcessResult:
        del args, kwargs
        raise AssertionError("forged hook arguments must not execute")

    monkeypatch.setattr(bounded_cli_hook_bridge, "run_isolated_hook_process", forbidden_runner)
    output = io.StringIO()
    with redirect_stdout(output):
        returncode = bounded_cli_hook_bridge.run_bounded_cli_hook(config, input_text="{}")

    assert returncode == 0
    assert _json_object(output.getvalue())["decision"] == "deny"


def test_live_frozen_runtime_ignores_forged_config_mode_and_executable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    observed: list[str] = []

    def run(command: Sequence[str], **kwargs: object) -> BoundedHookProcessResult:
        del kwargs
        observed.extend(command)
        return BoundedHookProcessResult(0, '{"decision":"allow"}\n', False, False)

    config = _config(tmp_path, harness="grok")
    config["python_executable"] = "/bin/sh"
    config["frozen_launcher"] = False
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "frozen", True, raising=False)
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "executable", "/app/hol-guard")
    monkeypatch.setattr(bounded_cli_hook_bridge, "_try_daemon_hook", lambda **kwargs: None)
    monkeypatch.setattr(bounded_cli_hook_bridge, "run_isolated_hook_process", run)

    assert bounded_cli_hook_bridge.run_bounded_cli_hook(config, input_text="{}") == 0
    assert observed == [
        "/app/hol-guard",
        "hook",
        "--guard-home",
        str((tmp_path / "guard-home").resolve()),
        "--harness",
        "grok",
    ]


def test_non_frozen_runtime_rejects_forged_frozen_config(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = _config(tmp_path, harness="grok")
    config["frozen_launcher"] = True
    monkeypatch.delattr(bounded_cli_hook_bridge.sys, "frozen", raising=False)
    monkeypatch.setattr(bounded_cli_hook_bridge, "_try_daemon_hook", lambda **kwargs: None)

    def forbidden_runner(*args: object, **kwargs: object) -> BoundedHookProcessResult:
        del args, kwargs
        raise AssertionError("config must not force frozen dispatch")

    monkeypatch.setattr(bounded_cli_hook_bridge, "run_isolated_hook_process", forbidden_runner)
    output = io.StringIO()
    with redirect_stdout(output):
        returncode = bounded_cli_hook_bridge.run_bounded_cli_hook(config, input_text="{}")

    assert returncode == 0
    assert _json_object(output.getvalue())["decision"] == "deny"


def test_frozen_fallback_accepts_equivalent_noncanonical_guard_home(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    observed: list[str] = []

    def run(command: Sequence[str], **kwargs: object) -> BoundedHookProcessResult:
        del kwargs
        observed.extend(command)
        return BoundedHookProcessResult(0, '{"decision":"allow"}\n', False, False)

    config = _config(tmp_path, harness="grok")
    cli_args = cast(list[str], config["cli_args"])
    cli_args[3] = str(tmp_path / "unused" / ".." / "guard-home")
    config["frozen_launcher"] = True
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "frozen", True, raising=False)
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "executable", "/app/hol-guard")
    monkeypatch.setattr(bounded_cli_hook_bridge, "_try_daemon_hook", lambda **kwargs: None)
    monkeypatch.setattr(bounded_cli_hook_bridge, "run_isolated_hook_process", run)

    assert bounded_cli_hook_bridge.run_bounded_cli_hook(config, input_text="{}") == 0
    assert observed == [
        "/app/hol-guard",
        "hook",
        "--guard-home",
        str((tmp_path / "guard-home").resolve()),
        "--harness",
        "grok",
    ]


@pytest.mark.parametrize("harness", ["hermes", "openclaw"])
def test_frozen_fallback_accepts_normalized_json_hook_contract(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    harness: str,
) -> None:
    observed: list[str] = []

    def run(command: Sequence[str], **kwargs: object) -> BoundedHookProcessResult:
        del kwargs
        observed.extend(command)
        return BoundedHookProcessResult(0, '{"decision":"allow"}\n', False, False)

    config = _config(tmp_path, harness=harness)
    config["cli_args"] = [*cast(list[str], config["cli_args"]), "--json"]
    config["frozen_launcher"] = True
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "frozen", True, raising=False)
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "executable", "/app/hol-guard")
    monkeypatch.setattr(bounded_cli_hook_bridge, "_try_daemon_hook", lambda **kwargs: None)
    monkeypatch.setattr(bounded_cli_hook_bridge, "run_isolated_hook_process", run)

    assert bounded_cli_hook_bridge.run_bounded_cli_hook(config, input_text="{}") == 0
    assert observed == [
        "/app/hol-guard",
        "hook",
        "--guard-home",
        str(tmp_path / "guard-home"),
        "--harness",
        harness,
        "--json",
    ]


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

    monkeypatch.setattr(bounded_cli_hook_bridge, "_try_daemon_hook", forbidden_daemon)
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
    monkeypatch.setattr(bounded_cli_hook_bridge, "_try_daemon_hook", forbidden_daemon)
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
        bounded_cli_hook_bridge,
        "_try_daemon_hook",
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

    monkeypatch.setattr(bounded_cli_hook_bridge, "_try_daemon_hook", forbidden_daemon)
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

    monkeypatch.setattr(bounded_cli_hook_bridge, "_try_daemon_hook", forbidden_daemon)
    output = io.StringIO()
    with redirect_stdout(output):
        returncode = bounded_cli_hook_bridge.run_bounded_cli_hook(config, input_text="{}")

    assert returncode == 0
    assert _json_object(output.getvalue())["decision"] == "deny"
