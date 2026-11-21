"""The Python side of the native-hook exit code: the request it sends and the outage table.

The verdict-to-exit-code table is native; its cases live in
`rust/crates/guard-runtime/src/hook_exit_code_op_tests.rs`.
"""

import json
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import native_hook_exit_code as module
from codex_plugin_scanner.guard.cli.native_hook_exit_code import native_hook_verdict_exit_code

_TARGET = "codex_plugin_scanner.guard.mdm.runtime_request.runtime_answer"


class _Runtime:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, answer: dict[str, object] | None) -> None:
        self.answer = answer
        self.requests: list[dict[str, object]] = []
        monkeypatch.setattr(_TARGET, self)

    def __call__(self, feature, command, request, *, output_limit, timeout_seconds=None, **_):
        assert feature == "native-hook-exit-code-v1" and command == "hook-exit-code"
        assert isinstance(request, str)
        self.requests.append(json.loads(request))
        return self.answer


@pytest.fixture(autouse=True)
def _protection_is_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HOL_GUARD_HOME", raising=False)
    monkeypatch.setattr(sys, "argv", ["hol-guard"])


def test_the_runtime_answer_is_the_exit_code(monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = _Runtime(monkeypatch, {"exit_code": 1})
    assert native_hook_verdict_exit_code("codex", "block", "PostToolUse") == 1
    assert runtime.requests == [
        {"harness": "codex", "policy_action": "block", "event_name": "PostToolUse", "recording_only": False}
    ]


@pytest.mark.parametrize(
    "answer", [None, {}, {"exit_code": "2"}, {"exit_code": True}, {"exit_code": -1}, {"exit_code": 256}]
)
def test_without_the_runtime_the_outage_table_answers_as_the_runtime_would(
    monkeypatch: pytest.MonkeyPatch, answer: dict[str, object] | None
) -> None:
    _Runtime(monkeypatch, answer)
    blocking = ("review", "require-reapproval", "sandbox-required", "block", "unheard-of", None)
    for action in blocking:
        assert native_hook_verdict_exit_code("opencode", action, "PreToolUse") == 1
        assert native_hook_verdict_exit_code("cursor", action, "PreToolUse") == 2
        assert native_hook_verdict_exit_code("grok", action) == 2
        assert native_hook_verdict_exit_code("codex", action, "PreToolUse") == 0
        assert native_hook_verdict_exit_code("codex", action, "PostToolUse") == 1
        assert native_hook_verdict_exit_code("unknown-harness", action) == 1
    for action in ("allow", "warn"):
        for harness in ("opencode", "cursor", "grok", "codex", "unknown-harness"):
            assert native_hook_verdict_exit_code(harness, action, "PostToolUse") == 0
    assert native_hook_verdict_exit_code("zcode", "review", "PreToolUse") == 0
    assert native_hook_verdict_exit_code("zcode", "block", "PreToolUse") == 2


def test_an_action_json_cannot_carry_is_sent_as_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = _Runtime(monkeypatch, {"exit_code": 2})
    assert native_hook_verdict_exit_code("cursor", float("nan")) == 2
    assert native_hook_verdict_exit_code("cursor", object()) == 2
    assert [request["policy_action"] for request in runtime.requests] == [None, None]


def test_grok_sends_whether_protection_is_off(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    runtime = _Runtime(monkeypatch, {"exit_code": 0})
    monkeypatch.setenv("HOL_GUARD_HOME", str(tmp_path / ".hol-guard"))
    monkeypatch.setattr(module, "_grok_recording_only", lambda: True)
    assert native_hook_verdict_exit_code("grok", "block") == 0
    assert runtime.requests[-1]["recording_only"] is True
    assert native_hook_verdict_exit_code("codex", "block", "PreToolUse") == 0
    assert runtime.requests[-1]["recording_only"] is False


def test_an_unreadable_grok_config_keeps_protection_on(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from codex_plugin_scanner.guard import config
    from codex_plugin_scanner.guard.config_file_io import ConfigFileTrustError

    def untrusted(_guard_home: Path) -> None:
        raise ConfigFileTrustError("config_untrusted")

    runtime = _Runtime(monkeypatch, {"exit_code": 2})
    monkeypatch.setenv("HOL_GUARD_HOME", str(tmp_path / ".hol-guard"))
    monkeypatch.setattr(config, "load_guard_config", untrusted)
    assert native_hook_verdict_exit_code("grok", "block") == 2
    assert runtime.requests[-1]["recording_only"] is False


def test_grok_names_the_guard_home_from_its_argument(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from types import SimpleNamespace

    from codex_plugin_scanner.guard import config

    runtime = _Runtime(monkeypatch, {"exit_code": 0})
    monkeypatch.setattr(sys, "argv", ["hol-guard", "--guard-home", str(tmp_path / ".hol-guard")])
    monkeypatch.setattr(
        config, "load_guard_config", lambda _home: SimpleNamespace(protection_posture="watch", mode="enforce")
    )
    assert native_hook_verdict_exit_code("grok", "block") == 0
    assert runtime.requests[-1]["recording_only"] is True
