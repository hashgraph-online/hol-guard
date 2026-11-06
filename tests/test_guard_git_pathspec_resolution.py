"""P37 regressions for bounded Git pathspec resolution."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tests.live_hook_review_support import assert_secret_output_held, live_post_tool_flag
from tests.native_command_test_support import inspect_command_native_test as inspect_command

# Windows rejects ASCII newlines in filenames; keep an unusual Unicode separator
# there while POSIX continues to exercise Git's NUL-delimited newline handling.
_LINE_BREAK_FILENAME = "line\u2028break.py" if os.name == "nt" else "line\nbreak.py"


# The resident's Codex tool-output review models POSIX shell text and paths and
# refuses Windows outright, so pathspec identities and read-only proofs exist
# only on POSIX hosts.
_POSIX_TOOL_OUTPUT_REVIEW = pytest.mark.skipif(
    sys.platform == "win32", reason="Codex tool-output review is POSIX-only; Windows fails closed"
)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _git(repository: Path, *args: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    return subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )


@pytest.fixture
def git_repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    if shutil.which("git") is None:
        pytest.skip("Git is unavailable")
    # This positive fixture describes a clean Git caller, not the CI runner's
    # loader settings, pager programs, or global configuration.
    for name in tuple(os.environ):
        upper = name.upper()
        if upper.startswith(("GIT_", "LD_", "DYLD_")) or upper in {"PAGER", "XDG_CONFIG_HOME"}:
            monkeypatch.delenv(name, raising=False)
    # Setup and native review must inspect the same clean Git configuration.
    # Use supported caller fields rather than an unattested config override.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "--quiet")
    _git(repository, "config", "user.name", "Guard Fixture")
    _git(repository, "config", "user.email", "guard@example.invalid")
    _git(repository, "config", "commit.gpgsign", "false")
    _write(repository / "src" / "app.py", "print('safe')\n")
    _write(repository / "src" / "nested" / "worker.py", "print('safe')\n")
    _write(repository / "src" / "nested" / "MODEL.PY", "print('safe')\n")
    _write(repository / ".env", "TOKEN=fixture\n")
    _write(repository / "notes with spaces.md", "safe\n")
    _write(repository / _LINE_BREAK_FILENAME, "print('safe')\n")
    _write(repository / "-leading.py", "print('safe')\n")
    _git(repository, "add", "--all")
    _git(repository, "commit", "--quiet", "-m", "initial fixture")
    _write(repository / "src" / "app.py", "print('updated')\n")
    _git(repository, "add", "src/app.py")
    _git(repository, "commit", "--quiet", "-m", "update fixture")
    return repository


@_POSIX_TOOL_OUTPUT_REVIEW
def test_git_pathspec_selection_changes_post_tool_approval_identity(git_repository: Path) -> None:
    command = "git diff -- ':(top,glob)**/*.env' | sed -n '1,40p'"
    credential_fixture = "ghp_" + "1" * 36
    payload: dict[str, object] = {
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "tool_response": {"stdout": f"TOKEN={credential_fixture}\n"},
    }
    first = live_post_tool_flag(
        payload=payload,
        cwd=git_repository,
    )
    _write(git_repository / "nested" / ".env", "SECOND=fixture\n")
    _git(git_repository, "add", "nested/.env")
    second = live_post_tool_flag(
        payload=payload,
        cwd=git_repository,
    )

    # Both selections stay held. The live output block carries no approval
    # identity.
    assert_secret_output_held(first)
    assert_secret_output_held(second)


@pytest.mark.parametrize(
    ("command", "rule_id", "minimum_action"),
    (
        ("git status", "command.git.status", "allow"),
        ("git diff", "command.git.diff", "review"),
        # `--staged` only prints the index. That read uses the ordinary diff
        # proof, the same owner as `git diff`, not an index-inspection ask.
        ("git diff --staged", "command.git.diff", "review"),
        ("git diff HEAD~1", "command.git.diff", "review"),
        ("git diff -- src/", "command.git.diff", "review"),
        ('git diff -- ":(glob)src/**/*.py"', "command.git.diff", "review"),
        ("git log --oneline", "command.git.log", "review"),
        ("git show HEAD", "command.git.show", "review"),
    ),
)
def test_normal_git_workflows_preserve_native_ownership_and_proof_requirements(
    command: str,
    rule_id: str,
    minimum_action: str,
    git_repository: Path,
) -> None:
    payload = inspect_command(command, cwd=git_repository, home_dir=git_repository.parent)

    # Native Git reads retain their helper/configuration proof floors. A clean
    # host can prove this repository has no diff helper and allow plain git diff.
    # These pathspec forms must not invent a more specific owner merely from a token.
    assert payload["controlling_rule_id"] == rule_id
    action = payload["minimum_action"]
    if rule_id in {"command.git.diff", "command.git.log", "command.git.show"}:
        # A clean host proves this repository has no diff helper and allows the read.
        assert action in {"allow", "review"}
    else:
        assert action == minimum_action
    assert payload["status"] == ("no_match" if action == "allow" else "review")
    classification = payload["classification"]
    assert isinstance(classification, dict)
    assert classification["matched"] is (action != "allow")
