"""Keep PR freshness discovery bounded and fail closed."""

from __future__ import annotations

import subprocess

import pytest

from tests.support import extension_freshness


def test_git_inspection_has_a_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[list[str], dict[str, object]]] = []

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, "ok\n", "")

    monkeypatch.setattr(extension_freshness.subprocess, "run", run)

    result = extension_freshness._git("rev-parse", "HEAD")

    assert result.returncode == 0
    assert calls == [
        (
            ["git", "rev-parse", "HEAD"],
            {
                "cwd": extension_freshness.ROOT,
                "check": False,
                "capture_output": True,
                "text": True,
                "timeout": 30,
            },
        )
    ]


@pytest.mark.parametrize("error", [OSError("private"), subprocess.TimeoutExpired("git", 30)])
def test_git_inspection_errors_become_bounded_failures(monkeypatch: pytest.MonkeyPatch, error: Exception) -> None:
    def run(_command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise error

    monkeypatch.setattr(extension_freshness.subprocess, "run", run)

    result = extension_freshness._git("merge-base", "HEAD", "origin/main")

    assert result.returncode == 1
    assert "private" not in result.stderr


def test_pull_request_without_a_base_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HOL_GUARD_BASE_SHA", raising=False)
    monkeypatch.delenv("GITHUB_BASE_SHA", raising=False)
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setattr(
        extension_freshness,
        "_git",
        lambda *_arguments: subprocess.CompletedProcess([], 1, "", "git unavailable"),
    )

    with pytest.raises(RuntimeError, match="pull-request base revision"):
        extension_freshness._projection_base_sha()


def test_pull_request_diff_fetch_failure_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOL_GUARD_BASE_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_BASE_REF", "main")
    monkeypatch.setattr(
        extension_freshness,
        "_git",
        lambda *_arguments: subprocess.CompletedProcess([], 1, "", "git unavailable"),
    )

    with pytest.raises(RuntimeError, match="pull-request diff"):
        extension_freshness._pr_diff_paths()


def test_pull_request_diff_uses_captured_base_not_moving_branch_tip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base_sha = "a" * 40
    calls: list[tuple[str, ...]] = []
    monkeypatch.setenv("HOL_GUARD_BASE_SHA", base_sha)
    monkeypatch.setenv("GITHUB_BASE_REF", "main")

    def git(*arguments: str) -> subprocess.CompletedProcess[str]:
        calls.append(arguments)
        return subprocess.CompletedProcess(
            ["git", *arguments],
            0,
            "tests/guard_command_decision_diff.py\n",
            "",
        )

    monkeypatch.setattr(extension_freshness, "_git", git)

    assert extension_freshness._pr_diff_paths() == ["tests/guard_command_decision_diff.py"]
    assert calls == [("diff", "--name-only", base_sha, "HEAD")]


def test_pull_request_diff_fetches_captured_base_when_checkout_is_shallow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base_sha = "a" * 40
    calls: list[tuple[str, ...]] = []
    monkeypatch.setenv("HOL_GUARD_BASE_SHA", base_sha)
    monkeypatch.setenv("GITHUB_BASE_REF", "main")
    responses = iter(
        (
            subprocess.CompletedProcess([], 128, "", "missing base"),
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 0, "tests/guard_command_decision_diff.py\n", ""),
        )
    )

    def git(*arguments: str) -> subprocess.CompletedProcess[str]:
        calls.append(arguments)
        return next(responses)

    monkeypatch.setattr(extension_freshness, "_git", git)

    assert extension_freshness._pr_diff_paths() == ["tests/guard_command_decision_diff.py"]
    assert calls == [
        ("diff", "--name-only", base_sha, "HEAD"),
        ("fetch", "--depth=1", "origin", base_sha),
        ("diff", "--name-only", base_sha, "HEAD"),
    ]
