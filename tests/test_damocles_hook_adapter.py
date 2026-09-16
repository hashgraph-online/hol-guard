from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path
from types import SimpleNamespace


MODULE_PATH = Path(__file__).parents[1] / "examples/integrations/damocles/hol_guard_pretool.py"
SPEC = importlib.util.spec_from_file_location("damocles_hol_guard_pretool", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _payload(command: str = "git status") -> dict[str, object]:
    return {"event": "tool_call", "tool_name": "Bash", "input": {"command": command}}


def _completed(stdout: str, returncode: int = 0) -> SimpleNamespace:
    return SimpleNamespace(stdout=stdout, returncode=returncode)


def test_explicitly_benign_allow_returns_ask() -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_: object) -> SimpleNamespace:
        calls.append(argv)
        return _completed('{"minimum_action":"allow","classification":{"explicitly_benign":true}}')

    result = MODULE.evaluate_tool_call(
        _payload(),
        which=lambda _: "/usr/local/bin/hol-guard",
        run=fake_run,
    )

    assert result == {"decision": "ask"}
    assert calls == [["/usr/local/bin/hol-guard", "command", "test", "git status", "--json"]]


def test_review_denies() -> None:
    result = MODULE.evaluate_tool_call(
        _payload(),
        which=lambda _: "/usr/local/bin/hol-guard",
        run=lambda *_args, **_kwargs: _completed(
            '{"minimum_action":"review","classification":{"explicitly_benign":false}}'
        ),
    )

    assert result == {"decision": "deny", "reason": "HOL_GUARD_NOT_EXPLICITLY_BENIGN"}


def test_missing_guard_denies() -> None:
    assert MODULE.evaluate_tool_call(_payload(), which=lambda _: None) == {
        "decision": "deny",
        "reason": "HOL_GUARD_UNAVAILABLE",
    }


def test_invalid_json_denies() -> None:
    result = MODULE.evaluate_tool_call(
        _payload(),
        which=lambda _: "/usr/local/bin/hol-guard",
        run=lambda *_args, **_kwargs: _completed("{"),
    )

    assert result == {"decision": "deny", "reason": "HOL_GUARD_INVALID_JSON"}


def test_nonzero_exit_denies() -> None:
    result = MODULE.evaluate_tool_call(
        _payload(),
        which=lambda _: "/usr/local/bin/hol-guard",
        run=lambda *_args, **_kwargs: _completed("", returncode=1),
    )

    assert result == {"decision": "deny", "reason": "HOL_GUARD_INSPECTION_FAILED"}


def test_timeout_denies() -> None:
    def fake_run(*_args: object, **_kwargs: object) -> SimpleNamespace:
        raise subprocess.TimeoutExpired(cmd="hol-guard", timeout=10)

    result = MODULE.evaluate_tool_call(
        _payload(),
        which=lambda _: "/usr/local/bin/hol-guard",
        run=fake_run,
    )

    assert result == {"decision": "deny", "reason": "HOL_GUARD_INSPECTION_FAILED"}


def test_empty_command_denies() -> None:
    assert MODULE.evaluate_tool_call(_payload("")) == {
        "decision": "deny",
        "reason": "HOL_GUARD_EMPTY_COMMAND",
    }


def test_non_bash_tool_does_not_override_normal_flow() -> None:
    payload = {"event": "tool_call", "tool_name": "Read", "input": {}}
    assert MODULE.evaluate_tool_call(payload) == {"decision": "ask"}


def test_windows_uses_resolved_executable_without_shell() -> None:
    seen: dict[str, object] = {}

    def fake_run(argv: list[str], **kwargs: object) -> SimpleNamespace:
        seen["argv"] = argv
        seen["kwargs"] = kwargs
        return _completed('{"minimum_action":"allow","classification":{"explicitly_benign":true}}')

    result = MODULE.evaluate_tool_call(
        _payload("dir"),
        which=lambda _: r"C:\\Python\\Scripts\\hol-guard.exe",
        run=fake_run,
    )

    assert result == {"decision": "ask"}
    assert seen["argv"] == [
        r"C:\\Python\\Scripts\\hol-guard.exe",
        "command",
        "test",
        "dir",
        "--json",
    ]
    assert "shell" not in seen["kwargs"]
