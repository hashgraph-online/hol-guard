"""A chain of checks and Git steps runs the checks contained, then the proven steps."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import restricted_workspace as workspace_sink
from codex_plugin_scanner.guard.runtime.restricted_pytest import RestrictedPytestError
from tests.test_guard_restricted_workspace import payload, plan, receipt


@pytest.fixture(autouse=True)
def macos_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(workspace_sink, "_host_backend", lambda: "macos-seatbelt")


PUBLISH_COMMAND = "npm test && git init -q && git status --short"
PUBLISH_SUFFIX = "git init -q && git status --short"


def publish_receipt(**changes: object) -> dict[str, object]:
    return receipt(reason=workspace_sink.WORKSPACE_PUBLISH_REASON, **changes)


def run_publish(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    published: dict[str, object],
    *,
    checks_exit: int = 0,
    suffix_verdict: dict[str, object] | None = None,
    first: dict[str, object] | None = None,
) -> tuple[int, list[str], list[object]]:
    """Run the publish chain with a fake sandbox; return its exit, launches and authorizations."""
    launched: list[str] = []
    asked: list[object] = []
    monkeypatch.setattr(
        workspace_sink,
        "restricted_native",
        lambda operation, fields, expected: "(version 1)" if operation == "macos_profile" else published,
    )
    monkeypatch.setattr(workspace_sink, "trusted_git_binary_for_cwd", lambda cwd: None)
    monkeypatch.setattr(workspace_sink, "_restricted_environment", lambda source, **kwargs: {})
    monkeypatch.setattr(
        workspace_sink, "_run_backend_process", lambda argv, **kwargs: launched.append(argv[-1]) or checks_exit
    )

    def authorize(request: dict[str, object]) -> dict[str, object]:
        command = request["tool_input"]["command"]  # type: ignore[index]
        asked.append(command)
        if command == PUBLISH_SUFFIX:
            return suffix_verdict or {"decision": "allow", "policy_action": "allow"}
        return publish_receipt()

    exit_code = workspace_sink.run_workspace_contained(
        payload(PUBLISH_COMMAND),
        workspace=tmp_path,
        cwd=tmp_path,
        authorize=authorize,
        first_receipt=first or publish_receipt(),
        timeout_seconds=30,
    )
    return exit_code, launched, asked


def test_checks_run_contained_then_the_proven_git_steps_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    published = plan(tmp_path, "npm test", native_suffix=PUBLISH_SUFFIX)
    exit_code, launched, asked = run_publish(monkeypatch, tmp_path, published)
    assert exit_code == 0
    assert launched == ["npm test"]
    # The Git steps are proven again on their own after the checks ran.
    assert asked == [PUBLISH_COMMAND, PUBLISH_SUFFIX]
    assert (tmp_path / ".git").is_dir()


def test_failed_checks_never_reach_the_git_steps(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    published = plan(tmp_path, "npm test", native_suffix=PUBLISH_SUFFIX)
    exit_code, _, asked = run_publish(monkeypatch, tmp_path, published, checks_exit=3)
    assert exit_code == 3
    assert asked == [PUBLISH_COMMAND]
    assert not (tmp_path / ".git").exists()


@pytest.mark.parametrize(
    "verdict",
    [
        {"decision": "deny", "policy_action": "review"},
        {"decision": "allow", "policy_action": "allow", "observe_mode": True},
        {"decision": "deny", "policy_action": "sandbox-required"},
    ],
)
def test_git_steps_that_no_longer_pass_do_not_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, verdict: dict[str, object]
) -> None:
    published = plan(tmp_path, "npm test", native_suffix=PUBLISH_SUFFIX)
    with pytest.raises(RestrictedPytestError):
        run_publish(monkeypatch, tmp_path, published, suffix_verdict=verdict)
    assert not (tmp_path / ".git").exists()


@pytest.mark.parametrize(
    ("published", "first"),
    [
        # A split plan needs the split receipt, and the reverse.
        ({"native_suffix": PUBLISH_SUFFIX}, receipt()),
        ({}, None),
        # The checks and the steps must rebuild the authorized command exactly.
        ({"native_suffix": "git status --short"}, None),
        ({"native_suffix": "git push origin main"}, None),
        ({"native_suffix": PUBLISH_SUFFIX, "prefix_command": "npm test"}, None),
        ({"native_suffix": PUBLISH_SUFFIX, "bootstrap_git": ["-b", "main"]}, None),
    ],
)
def test_a_split_that_differs_from_the_receipt_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    published: dict[str, object],
    first: dict[str, object] | None,
) -> None:
    with pytest.raises(RestrictedPytestError):
        run_publish(monkeypatch, tmp_path, plan(tmp_path, "npm test", **published), first=first)
    assert not (tmp_path / ".git").exists()


def test_git_steps_never_resolve_through_workspace_or_relative_path_entries(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    planted = tmp_path / "bin"
    planted.mkdir()
    marker = tmp_path / "planted-ran"
    script = planted / "git"
    script.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
    script.chmod(0o755)
    host_path = workspace_sink.os.environ.get("PATH", "")
    monkeypatch.setenv("PATH", f"{planted}:bin:.:{host_path}")
    monkeypatch.chdir(tmp_path)
    published = plan(tmp_path, "npm test", native_suffix=PUBLISH_SUFFIX)
    exit_code, _, _ = run_publish(monkeypatch, tmp_path, published)
    assert exit_code == 0
    assert not marker.exists()
    assert (tmp_path / ".git").is_dir()


def test_outside_search_path_keeps_only_absolute_entries_outside_the_workspace(tmp_path: Path) -> None:
    inside = tmp_path / "node_modules" / ".bin"
    search_path = f"/usr/bin::.:bin:{tmp_path}:{inside}:{tmp_path}/../{tmp_path.name}/x:/bin"
    assert workspace_sink._outside_search_path(search_path, tmp_path) == "/usr/bin:/bin"
