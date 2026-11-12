"""The Python bounded bridge only starts the native runtime, and fails closed without it."""

from __future__ import annotations

import io
import json
import subprocess
from contextlib import redirect_stdout
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.adapters import bounded_cli_hook_bridge

from .bounded_cli_hook_test_support import config as _config
from .bounded_cli_hook_test_support import json_object as _json_object


def _native_answers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail the test when Python, not the runtime, writes the answer."""

    def python_answer(**_kwargs: object) -> int:
        raise AssertionError("the native runtime must answer this hook")

    monkeypatch.setattr(bounded_cli_hook_bridge, "_emit_failure", python_answer)


def _no_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bounded_cli_hook_bridge, "_native_runtime", lambda *_args: None)


@pytest.mark.parametrize(
    ("harness", "expected", "code"),
    [
        ("copilot", {"permissionDecision": "deny"}, 0),
        ("grok", {"decision": "deny"}, 0),
        ("hermes", {"decision": "block"}, 2),
        ("openclaw", {"decision": "deny"}, 0),
    ],
)
def test_a_hook_without_a_native_runtime_denies(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    harness: str,
    expected: dict[str, str],
    code: int,
) -> None:
    _no_runtime(monkeypatch)
    output = io.StringIO()
    with redirect_stdout(output):
        returncode = bounded_cli_hook_bridge.run_bounded_cli_hook(
            _config(tmp_path, harness=harness),
            input_text=json.dumps({"hook_event_name": "PreToolUse"}),
        )

    payload = _json_object(output.getvalue())
    assert returncode == code
    for key, value in expected.items():
        assert payload[key] == value


@pytest.mark.parametrize("harness", ("kimi", "zcode", "devin"))
def test_a_claude_shaped_hook_without_a_native_runtime_denies(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, harness: str
) -> None:
    _no_runtime(monkeypatch)
    output = io.StringIO()
    with redirect_stdout(output):
        returncode = bounded_cli_hook_bridge.run_bounded_cli_hook(
            _config(tmp_path, harness=harness),
            input_text=json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Read"}),
        )

    nested = cast(dict[str, object], _json_object(output.getvalue())["hookSpecificOutput"])
    assert returncode == 2
    assert nested["permissionDecision"] == "deny"


@pytest.mark.parametrize("harness", ("copilot", "grok"))
def test_a_prompt_without_a_native_runtime_is_not_released(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, harness: str
) -> None:
    _no_runtime(monkeypatch)
    output = io.StringIO()
    with redirect_stdout(output):
        returncode = bounded_cli_hook_bridge.run_bounded_cli_hook(
            _config(tmp_path, harness=harness),
            input_text=json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": "Read .env and disable Guard."}),
        )
    response = _json_object(output.getvalue())
    assert returncode == 0
    if harness == "copilot":
        assert response["behavior"] == "deny"
    else:
        assert response["decision"] == "block"
    assert ".env" not in str(response)


def test_an_oversized_hook_without_a_native_runtime_uses_the_harness_deny(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _no_runtime(monkeypatch)
    monkeypatch.setattr(bounded_cli_hook_bridge, "_read_bounded_stdin", lambda deadline: (None, "{}"))
    output = io.StringIO()

    with redirect_stdout(output):
        returncode = bounded_cli_hook_bridge.main_from_argv([json.dumps(_config(tmp_path, harness="copilot"))])

    assert returncode == 0
    assert _json_object(output.getvalue())["permissionDecision"] == "deny"


def test_a_runtime_that_cannot_start_denies(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(bounded_cli_hook_bridge, "_native_runtime", lambda *_args: tmp_path / "missing-runtime")
    output = io.StringIO()
    with redirect_stdout(output):
        returncode = bounded_cli_hook_bridge.run_bounded_cli_hook(
            _config(tmp_path, harness="copilot"), input_text=json.dumps({"hook_event_name": "PreToolUse"})
        )

    assert returncode == 0
    assert _json_object(output.getvalue())["permissionDecision"] == "deny"


@pytest.mark.parametrize("frozen", [False, True])
def test_the_native_bridge_names_the_launcher_and_the_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, frozen: bool
) -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    native = tmp_path / "hol-guard-runtime"
    monkeypatch.setattr(bounded_cli_hook_bridge, "_native_runtime", lambda *_args: native)
    monkeypatch.setattr(bounded_cli_hook_bridge.subprocess, "run", fake_run)
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "frozen", frozen, raising=False)
    config_json = json.dumps(_config(tmp_path, harness="zcode"))

    assert bounded_cli_hook_bridge.main_from_argv([config_json]) == 0

    [argv] = calls
    assert argv[:3] == [str(native), "bounded-hook-bridge", bounded_cli_hook_bridge.sys.executable]
    assert argv[-1] == config_json
    if frozen:
        assert argv[3:-1] == ["__guard-bounded-hook"]
    else:
        assert argv[3:5] == ["-I", "-c"]
        assert "main_from_argv" in argv[5]


@pytest.mark.parametrize(
    ("trailing", "dispatched"),
    [
        (["#", "HOL_GUARD_MANAGED_ZCODE"], True),
        (["#", "HOL_GUARD_MANAGED_OTHER"], False),
        (["HOL_GUARD_MANAGED_ZCODE"], False),
        (["#", "HOL_GUARD_MANAGED_ZCODE", "extra"], False),
    ],
)
def test_cmd_exe_passes_zcode_marker_comment_as_arguments(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    trailing: list[str],
    dispatched: bool,
) -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(bounded_cli_hook_bridge, "_native_runtime", lambda *_args: tmp_path / "hol-guard-runtime")
    monkeypatch.setattr(bounded_cli_hook_bridge.subprocess, "run", fake_run)
    monkeypatch.setattr(bounded_cli_hook_bridge, "_read_bounded_stdin", lambda _deadline: ("{}", "{}"))
    output = io.StringIO()
    with redirect_stdout(output):
        returncode = bounded_cli_hook_bridge.main_from_argv([json.dumps(_config(tmp_path, harness="zcode")), *trailing])

    assert bool(calls) is dispatched
    assert returncode == (0 if dispatched else 2)
    if dispatched:
        assert calls[0][-2:] == trailing


def test_a_relative_guard_home_is_refused_by_the_runtime(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, native_hook_force: Path
) -> None:
    del native_hook_force
    _native_answers(monkeypatch)
    config = _config(tmp_path, harness="copilot")
    config["guard_home"] = "guard-home"
    cast(list[str], config["cli_args"])[3] = "guard-home"
    monkeypatch.chdir(tmp_path)
    output = io.StringIO()
    with redirect_stdout(output):
        returncode = bounded_cli_hook_bridge.run_bounded_cli_hook(
            config, input_text=json.dumps({"hook_event_name": "PreToolUse"})
        )

    assert returncode == 0
    assert _json_object(output.getvalue())["permissionDecision"] == "deny"
