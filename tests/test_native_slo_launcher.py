from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import native_slo_launcher


def test_launcher_reads_the_registered_argv_including_literal_arguments(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    argv = ("/tmp/python executable", "-c", "HOL_GUARD_CLAUDE_DAEMON_HOOK", "literal;not-shell")
    path.write_text(
        json.dumps(
            {"hooks": {"PostToolUse": [{"hooks": [{"type": "command", "command": argv[0], "args": list(argv[1:])}]}]}}
        )
    )
    assert native_slo_launcher.registered_claude_argv(path, "PostToolUse") == argv
    with pytest.raises(RuntimeError, match="missing or ambiguous"):
        native_slo_launcher.registered_claude_argv(path, "PreToolUse")


def test_launcher_times_registered_process_and_checks_route_and_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []
    metrics = SimpleNamespace(snapshot=lambda: {"routes": {"native_resident": 1}})
    session = SimpleNamespace(
        root=tmp_path,
        workspace=tmp_path,
        daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=SimpleNamespace(metrics=metrics))),
    )
    response = {"policy_action": "allow", "hookSpecificOutput": {"hookEventName": "PostToolUse"}}
    completed = SimpleNamespace(
        returncode=0,
        timed_out=False,
        containment_failed=False,
        output_limit_exceeded=False,
        stdout=json.dumps(response),
    )

    def run(argv: tuple[str, ...], **kwargs: object) -> SimpleNamespace:
        calls.append(argv)
        assert "HOL_GUARD_NATIVE" not in kwargs["environment"]
        assert json.loads(kwargs["input_text"])["hook_event_name"] == "PostToolUse"
        return completed

    monkeypatch.setattr(native_slo_launcher, "run_isolated_hook_process", run)
    monkeypatch.setattr(
        native_slo_launcher,
        "wait_for_route_corpus",
        lambda *_args, **_kwargs: {
            "routes": {"native_resident": 2},
        },
    )
    argv = ("/tmp/registered-python", "-c", "registered-code")
    assert native_slo_launcher._observe_launcher(session, argv, sample=0, case="benign") >= 0
    assert calls == [argv]
    completed.returncode = 9
    with pytest.raises(RuntimeError, match="did not complete"):
        native_slo_launcher._observe_launcher(session, argv, sample=0, case="benign")
    completed.returncode = 0
    monkeypatch.setattr(
        native_slo_launcher,
        "wait_for_route_corpus",
        lambda *_args, **_kwargs: {
            "routes": {"native_resident": 1, "native_fail_safe": 1},
        },
    )
    with pytest.raises(RuntimeError, match="native resident authority"):
        native_slo_launcher._observe_launcher(session, argv, sample=0, case="benign")
