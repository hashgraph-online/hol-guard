"""Native verification prepares the same source-bound build on every event."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from scripts import build_guard_resources
from scripts.ci import verify_native_command_program as verifier


@pytest.mark.parametrize("event", ["pull_request", "push", "schedule", "workflow_dispatch"])
@pytest.mark.parametrize("base", [None, "a" * 40])
def test_verifier_does_not_defer_or_change_behavior_by_event(
    monkeypatch: pytest.MonkeyPatch, event: str, base: str | None
) -> None:
    """PR metadata cannot waive current compiler, resource or embedded checks."""
    monkeypatch.setenv("GITHUB_EVENT_NAME", event)
    monkeypatch.setenv("HOL_DEFER_ARTIFACT_FRESHNESS", "1")
    compiler = Path("rust/target/release/guard-command-source")
    arguments = ["verify_native_command_program.py", "--compiler", str(compiler)]
    if base:
        arguments += ["--changed-from", base]
    monkeypatch.setattr(sys, "argv", arguments)
    calls = []
    monkeypatch.setattr(build_guard_resources, "prepare", lambda root, **kwargs: calls.append((root, kwargs)))
    assert verifier.main() == 0
    assert calls == [(verifier.ROOT, {"compiler": compiler})]


def test_verifier_propagates_failed_build_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing or invalid output remains a failure, including on source-only PRs."""
    monkeypatch.setattr(sys, "argv", ["verify_native_command_program.py", "--compiler", "compiler"])

    def fail(*args, **kwargs):
        raise ValueError("native compiler embeds a stale program")

    monkeypatch.setattr(build_guard_resources, "prepare", fail)
    with pytest.raises(ValueError, match="stale program"):
        verifier.main()
