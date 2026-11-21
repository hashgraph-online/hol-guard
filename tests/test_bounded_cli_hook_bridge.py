"""The bounded hook command names the native runtime, and the frozen client only starts it."""

from __future__ import annotations

import io
import json
import subprocess
import sys
from contextlib import redirect_stdout
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard import bounded_cli_hook_bridge, native_caller, native_hook_bridge
from codex_plugin_scanner.guard.bounded_cli_hook_native import NATIVE_BOUNDED_HOOK_COMMAND
from codex_plugin_scanner.guard.harness_context import HarnessContext

from .bounded_cli_hook_test_support import config as _config
from .bounded_cli_hook_test_support import json_object as _json_object
from .bounded_cli_hook_test_support import run_hook as _run_hook
from .native_bounded_runtime import hook_config_argv, use_bounded_runtime


def _runtime(monkeypatch: pytest.MonkeyPatch, path: Path | None) -> None:
    monkeypatch.setattr(native_hook_bridge, "native_hook_bridge_executable", lambda *_args, **_kwargs: path)


def _main(argv: list[str]) -> tuple[int, str]:
    output = io.StringIO()
    with redirect_stdout(output):
        returncode = bounded_cli_hook_bridge.main_from_argv(argv)
    return returncode, output.getvalue()


@pytest.mark.parametrize("harness", ["copilot", "grok", "hermes", "openclaw"])
def test_a_hook_without_a_native_runtime_is_blocked_with_a_repair_hint(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path, harness: str
) -> None:
    _runtime(monkeypatch, None)

    returncode, output = _main([json.dumps(_config(tmp_path, harness=harness))])

    assert returncode == 2
    assert output == ""
    assert "hol-guard repair" in capsys.readouterr().err


@pytest.mark.parametrize("argv", [["not json"], ["[]"], ["{}", "extra"], []])
def test_a_malformed_config_is_blocked(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], argv: list[str]
) -> None:
    started: list[object] = []
    monkeypatch.setattr(bounded_cli_hook_bridge.subprocess, "run", lambda *args, **_kwargs: started.append(args))

    returncode, output = _main(argv)

    assert started == []
    assert returncode == 2
    assert output == ""
    assert "hol-guard repair" in capsys.readouterr().err


def test_a_runtime_that_cannot_start_is_blocked(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    _runtime(monkeypatch, tmp_path / "missing-runtime")

    returncode, output = _main([json.dumps(_config(tmp_path, harness="copilot"))])

    assert returncode == 2
    assert output == ""
    assert "hol-guard repair" in capsys.readouterr().err


def test_the_runtime_gets_the_config_with_the_time_left(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    native = tmp_path / "hol-guard-runtime"
    _runtime(monkeypatch, native)
    monkeypatch.setattr(bounded_cli_hook_bridge.subprocess, "run", fake_run)
    hook_config = {**_config(tmp_path, harness="zcode"), "timeout_seconds": 1}

    assert _main([json.dumps(hook_config)])[0] == 0

    [argv] = calls
    assert argv[:2] == [str(native), NATIVE_BOUNDED_HOOK_COMMAND]
    assert len(argv) == 3
    sent = _json_object(argv[2])
    timeout = cast(float, sent.pop("timeout_seconds"))
    assert 0 < timeout <= 1
    assert sent == {key: value for key, value in hook_config.items() if key != "timeout_seconds"}


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
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, trailing: list[str], dispatched: bool
) -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    _runtime(monkeypatch, tmp_path / "hol-guard-runtime")
    monkeypatch.setattr(bounded_cli_hook_bridge.subprocess, "run", fake_run)

    _main([json.dumps(_config(tmp_path, harness="zcode")), *trailing])

    assert bool(calls) is dispatched
    if dispatched:
        assert calls[0][-2:] == trailing


def _command(tmp_path: Path, harness: str) -> tuple[str, ...]:
    context = HarnessContext(home_dir=tmp_path / "h", workspace_dir=None, guard_home=tmp_path / "g")
    return hook_config_argv(context, harness, ["guard", "hook", "--harness", harness])


def test_install_without_a_native_runtime_asks_for_repair(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(native_caller, "_native_runtime", lambda: None)

    with pytest.raises(RuntimeError, match="hol-guard repair"):
        _command(tmp_path, "copilot")


def test_install_names_the_native_runtime_and_the_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    native = tmp_path / "hol-guard-runtime"
    use_bounded_runtime(monkeypatch, native)

    argv = _command(tmp_path, "devin")

    assert argv[:2] == (str(native), NATIVE_BOUNDED_HOOK_COMMAND)
    config = _json_object(argv[2])
    assert config["harness"] == "devin"
    assert config["frozen_launcher"] is False
    assert config["python_executable"] == sys.executable


def test_a_relative_guard_home_is_refused_by_the_runtime(
    monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str], tmp_path: Path, native_hook_force: Path
) -> None:
    del native_hook_force

    def python_answer(_harness: str) -> int:
        raise AssertionError("the native runtime must answer this hook")

    monkeypatch.setattr(bounded_cli_hook_bridge, "_refuse", python_answer)
    config = _config(tmp_path, harness="copilot")
    config["guard_home"] = "guard-home"
    cast(list[str], config["cli_args"])[3] = "guard-home"
    monkeypatch.chdir(tmp_path)
    returncode = _run_hook(monkeypatch, config, json.dumps({"hook_event_name": "PreToolUse"}))

    assert returncode == 0
    assert _json_object(capfd.readouterr().out)["permissionDecision"] == "deny"


def test_a_hook_the_runtime_cannot_answer_is_blocked_with_a_repair_message(
    capfd: pytest.CaptureFixture[str],
) -> None:
    assert bounded_cli_hook_bridge._refuse("copilot") == 2

    captured = capfd.readouterr()
    assert captured.out == ""
    assert captured.err.strip() == bounded_cli_hook_bridge.RUNTIME_MISSING
    assert "hol-guard repair" in captured.err


def test_the_hook_failure_shim_returns_only_a_well_formed_native_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import native_runner_authority
    from codex_plugin_scanner.guard.hook_failure_bridge import native_hook_failure

    seen: list[tuple[str, dict[str, object]]] = []
    answers: list[object] = [
        {"document": "{}", "exit_code": 0},
        {"document": "{}"},
        {"document": "{}", "exit_code": True},
    ]

    def answer(kind: str, args: dict[str, object], *_rest: object, **_keywords: object) -> object:
        seen.append((kind, args))
        return answers.pop(0)

    monkeypatch.setattr(native_runner_authority, "native_runner_authority", answer)

    assert native_hook_failure("kimi", "PreToolUse", "why") == ("{}", 0)
    assert seen == [("hook_failure", {"harness": "kimi", "event_name": "PreToolUse", "reason": "why"})]
    assert native_hook_failure("kimi", "PreToolUse", "why") is None
    assert native_hook_failure("kimi", "PreToolUse", "why") is None

    def unavailable(*_args: object, **_keywords: object) -> object:
        raise RuntimeError("no runtime")

    monkeypatch.setattr(native_runner_authority, "native_runner_authority", unavailable)
    assert native_hook_failure("kimi", "PreToolUse", "why") is None
