"""Every event verifies the same native source tree without fixture rebuilds."""

from __future__ import annotations

import sys

import pytest

from scripts.ci import verify_native_command_program as verifier


@pytest.fixture(autouse=True)
def isolate_workflow_environment(monkeypatch):
    """Mocked compilers must never mutate the real GitHub Actions environment."""
    monkeypatch.delenv("GITHUB_ENV", raising=False)


@pytest.mark.parametrize("event", ["pull_request", "push", "schedule", "workflow_dispatch"])
@pytest.mark.parametrize("base", [None, "a" * 40])
def test_every_event_stages_then_strictly_verifies_current_sources(monkeypatch, event, base):
    """Verify every event stages then strictly verifies current sources."""
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
    """Verify compilation or verification failure is not retried or ignored."""
    monkeypatch.setattr(sys, "argv", ["verify", "--compiler", "compiler"])
    calls = []

    def execute(command):
        """Capture invoked commands and simulate the subprocess outcome required by this case."""
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
    """Verify unavailable pr base cannot change full source validation."""
    monkeypatch.setattr(sys, "argv", ["verify", "--compiler", "compiler", "--changed-from", "b" * 40])
    calls = []
    monkeypatch.setattr(verifier, "_run", calls.append)
    assert verifier.main() == 0
    assert len(calls) == 2
    assert calls[-1][-1] == "--check"


@pytest.mark.parametrize("failed_stage", [0, 1])
def test_failed_validation_does_not_export_compiler(monkeypatch, tmp_path, failed_stage):
    """Only successfully verified compilers may reach subsequent packaging steps."""
    compiler = tmp_path / "compiler"
    compiler.write_bytes(b"fixture")
    environment = tmp_path / "github-env"
    environment.write_text("EXISTING=value\n")
    monkeypatch.setenv("GITHUB_ENV", str(environment))
    monkeypatch.setattr(sys, "argv", ["verify", "--compiler", str(compiler)])
    calls = []

    def execute(command):
        calls.append(command)
        if len(calls) - 1 == failed_stage:
            raise SystemExit(37)

    monkeypatch.setattr(verifier, "_run", execute)
    with pytest.raises(SystemExit, match="37"):
        verifier.main()
    assert environment.read_text() == "EXISTING=value\n"


def test_successful_validation_exports_absolute_compiler_path(monkeypatch, tmp_path):
    """Export a real resolved path without changing the compiler sent to validation."""
    compiler = tmp_path / "compiler"
    compiler.write_bytes(b"fixture")
    environment = tmp_path / "github-env"
    environment.write_text("EXISTING=value\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_ENV", str(environment))
    monkeypatch.setattr(sys, "argv", ["verify", "--compiler", "compiler"])
    calls = []
    monkeypatch.setattr(verifier, "_run", calls.append)
    assert verifier.main() == 0
    assert calls[0][-1] == "compiler"
    assert calls[1] == [*calls[0], "--check"]
    assert environment.read_text() == f"EXISTING=value\nHOL_GUARD_BUILD_SOURCE_COMPILER={compiler}\n"
