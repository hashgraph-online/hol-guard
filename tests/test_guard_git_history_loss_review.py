"""Git commands that throw away committed history reach the user.

The workspace sandbox write-denies the repository configuration and the `.git`
trees a later host Git reads, but it leaves `.git/logs/refs` and
`.git/refs/tags` writable. A contained `git reflog expire` still truncates the
reflog a mistaken `git reset --hard` is recovered from, and a contained
`git tag -d` still deletes the tag. Routing those into the sandbox hides the
loss behind a silent allow, so they keep their review while reading a reflog
and listing, creating or verifying a tag stay contained.

A harness that runs its own sandbox is told to re-run the command there
rather than being handed an allow, and a host with no sandbox at all reviews
every contained command. The forms that stay out of the user's way through
containment are therefore asserted as "not put to the user", and only where a
control command proves containment is reachable.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tests.live_hook_review_support import live_decision, live_shell_review, quietly_allowed

HARNESSES = ("pi", "codex", "claude-code")

# A contained command this change does not touch: it reaches the user exactly
# where containment is unavailable.
SANDBOX_CONTROL = "git add ."

HISTORY_LOSS = (
    "git reflog expire --expire=now --all",
    "git reflog expire --expire-unreachable=now --all",
    "git reflog delete HEAD@{0}",
    "git reflog drop HEAD",
    "git tag -d v1.0.0",
    "git tag --delete v1.0.0",
    "git tag -f v1.0.0 HEAD",
    "git tag --force v1.0.0 HEAD",
    # Git resolves an unambiguous prefix of a long option, so the shortened
    # spellings drop and move tags exactly as the full ones do.
    "git tag --del v1.0.0",
    "git tag --delet v1.0.0",
    "git tag --forc v1.0.0 HEAD",
)

# Reads that never needed the sandbox, so they are quiet on every host.
HISTORY_READS = (
    "git reflog",
    "git reflog show HEAD",
    "git reflog -n 5",
    "git tag -l",
)

# Forms that stay quiet by running contained.
HISTORY_KEPT_CONTAINED = (
    "git tag",
    "git tag --sort=-creatordate",
    "git tag v1.0.0",
    "git tag -a v1.0.0 -m release",
    "git tag -v v1.0.0",
    # Options that only read tags share letters with the losing ones without
    # abbreviating them.
    "git tag --format=%(refname)",
)


@pytest.fixture
def repository(live_hook_root: Path) -> Path:
    """A workspace that is a real repository, as an agent session runs in."""

    workspace = live_hook_root / "home" / "projects" / "current"
    workspace.mkdir(parents=True)
    _ = subprocess.run(
        ["git", "init", "--quiet", str(workspace)],
        check=True,
        capture_output=True,
        text=True,
    )
    return workspace


def _review(command: str, *, repository: Path, harness: str) -> dict[str, object]:
    return live_shell_review(
        command,
        home_dir=repository.parent.parent,
        cwd=repository,
        harness=harness,
        tool_name="Bash",
    )


def _requires_containment(repository: Path, harness: str) -> None:
    control = _review(SANDBOX_CONTROL, repository=repository, harness=harness)
    if live_decision(control) != "allow":
        pytest.skip(f"containment unavailable here: {control.get('reason_code')}")


@pytest.mark.parametrize("command", HISTORY_LOSS)
@pytest.mark.parametrize("harness", HARNESSES)
def test_a_command_that_drops_committed_history_asks_the_user(
    repository: Path,
    command: str,
    harness: str,
) -> None:
    result = _review(command, repository=repository, harness=harness)

    assert not quietly_allowed(result), f"{command} ran without review"
    # Containment answers an allow: the sandbox would let the loss through.
    assert live_decision(result) in {"ask", "deny"}, result.get("reason_code")


@pytest.mark.parametrize("command", HISTORY_READS)
@pytest.mark.parametrize("harness", HARNESSES)
def test_reading_history_stays_out_of_the_users_way(
    repository: Path,
    command: str,
    harness: str,
) -> None:
    result = _review(command, repository=repository, harness=harness)

    assert quietly_allowed(result), result.get("reason_code")


@pytest.mark.parametrize("command", HISTORY_KEPT_CONTAINED)
@pytest.mark.parametrize("harness", HARNESSES)
def test_listing_and_adding_a_tag_still_run_contained(
    repository: Path,
    command: str,
    harness: str,
) -> None:
    _requires_containment(repository, harness)

    result = _review(command, repository=repository, harness=harness)

    assert live_decision(result) == "allow", result.get("reason_code")
