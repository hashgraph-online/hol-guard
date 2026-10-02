"""Every event verifies the same native source tree without fixture rebuilds."""

from __future__ import annotations

import sys

import pytest

from scripts.ci import verify_native_command_program as verifier


@pytest.mark.parametrize("event", ["pull_request", "push", "schedule", "workflow_dispatch"])
@pytest.mark.parametrize("base", [None, "a" * 40])
def test_every_event_stages_then_strictly_verifies_current_sources(monkeypatch, event, base):
    compiler = "rust/target/release/guard-command-source"
    arguments = ["verify", "--compiler", compiler]
    if base:
        arguments += ["--changed-from", base]
    monkeypatch.setenv("GITHUB_EVENT_NAME", event)
    monkeypatch.setattr(sys, "argv", arguments)
    calls = []
    monkeypatch.setattr(verifier, "_run", calls.append)
    assert verifier.main() == 0
    generate = [sys.executable, "scripts/build_native_command_program.py", "--compiler", compiler]
    assert calls == [generate, [*generate, "--check"]]
    assert all(command[0] not in {"cargo", "git"} for command in calls)


@pytest.mark.parametrize("failed_stage", [0, 1])
def test_compilation_or_verification_failure_is_not_retried_or_ignored(monkeypatch, failed_stage):
    monkeypatch.setattr(sys, "argv", ["verify", "--compiler", "compiler"])
    calls = []

    def execute(command):
        calls.append(command)
        if len(calls) - 1 == failed_stage:
            raise SystemExit(37)

    monkeypatch.setattr(verifier, "_run", execute)
    with pytest.raises(SystemExit) as failure:
        verifier.main()
    assert failure.value.code == 37
    assert len(calls) == failed_stage + 1


def test_unavailable_pr_base_cannot_change_full_source_validation(monkeypatch):
    # Full-tree compilation has no Git-diff selection. Missing history cannot
    # make any source disappear from validation or select a permissive mode.
    monkeypatch.setattr(sys, "argv", ["verify", "--compiler", "compiler", "--changed-from", "b" * 40])
    calls = []
    monkeypatch.setattr(verifier, "_run", calls.append)
    assert verifier.main() == 0
    assert len(calls) == 2
    assert calls[-1][-1] == "--check"
