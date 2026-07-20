"""Least-privilege GitHub capability and interaction floors."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.github_capability_contract import (
    GitHubCommandCapability,
    github_assessment,
)
from codex_plugin_scanner.guard.runtime.github_capability_interaction import github_capability_action_class
from codex_plugin_scanner.guard.runtime.github_command_capabilities import classify_github_cli
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    classify_github_shell_capabilities,
    extract_sensitive_tool_action_request,
)

_EXPECTED_FLOORS = {
    "read_local": "allow",
    "read_remote": "allow",
    "write_local": "review",
    "maintain_remote": "review",
    "content_remote": "review",
    "merge_remote": "require-reapproval",
    "publish_remote": "require-reapproval",
    "workflow_remote": "require-reapproval",
    "force_remote": "block",
    "delete_remote": "require-reapproval",
    "secret_remote": "block",
    "access_remote": "require-reapproval",
    "mutate_remote": "require-reapproval",
    "unknown": "require-reapproval",
}


@pytest.mark.parametrize(
    ("args", "capabilities", "workflow_authorizable"),
    (
        (("pr", "view", "17"), ("read_remote",), False),
        (
            (
                "api",
                "graphql",
                "-f",
                'query=mutation { resolveReviewThread(input: {threadId: "T"}) { thread { id } } }',
            ),
            ("maintain_remote",),
            True,
        ),
        (("pr", "review", "17", "--approve"), ("content_remote",), False),
        (("pr", "merge", "17"), ("merge_remote",), False),
        (("pr", "merge", "17", "--delete-branch"), ("merge_remote", "delete_remote"), False),
        (("api", "repos/o/r/pulls/17/merge", "-X", "PUT"), ("merge_remote",), False),
        (("release", "create", "v1"), ("publish_remote",), False),
        (("api", "repos/o/r/releases", "-X", "POST", "-f", "tag_name=v1"), ("publish_remote",), False),
        (("workflow", "run", "ci.yml"), ("workflow_remote",), False),
        (
            ("api", "repos/o/r/actions/workflows/ci.yml/dispatches", "-X", "POST", "-f", "ref=main"),
            ("workflow_remote",),
            False,
        ),
        (("variable", "set", "MODE", "--body", "strict"), ("workflow_remote",), False),
        (("repo", "sync", "--force"), ("force_remote",), False),
        (("repo", "set-default", "o/r"), ("write_local",), False),
        (("ssh-key", "list"), ("read_remote",), False),
        (("gpg-key", "delete", "KEY_ID"), ("delete_remote", "access_remote"), False),
        (("secret", "set", "TOKEN"), ("secret_remote",), False),
        (("api", "repos/o/r/actions/secrets/TOKEN", "-X", "PUT", "-f", "encrypted_value=x"), ("secret_remote",), False),
        (("repo", "edit", "--visibility", "private"), ("access_remote",), False),
        (("api", "repos/o/r/collaborators/alice", "-X", "PUT"), ("access_remote",), False),
        (
            ("api", "repos/o/r/issues/comments/17", "-X", "DELETE"),
            ("content_remote", "delete_remote"),
            False,
        ),
        (
            (
                "api",
                "graphql",
                "-f",
                "query=mutation { resolveReviewThread(input: {}) { thread { id } } "
                + "removeOutsideCollaborator(input: {}) { clientMutationId } }",
            ),
            ("maintain_remote", "delete_remote", "access_remote"),
            False,
        ),
    ),
)
def test_capability_sets_preserve_every_effect(
    args: tuple[str, ...],
    capabilities: tuple[GitHubCommandCapability, ...],
    workflow_authorizable: bool,
) -> None:
    assessment = classify_github_cli(args)

    assert assessment.capabilities == capabilities
    assert assessment.action_floor == _EXPECTED_FLOORS[assessment.capability]
    assert assessment.workflow_authorizable is workflow_authorizable


@pytest.mark.parametrize(("capability", "expected"), tuple(_EXPECTED_FLOORS.items()))
def test_every_capability_has_an_explicit_floor(capability: GitHubCommandCapability, expected: str) -> None:
    assessment = github_assessment(capability, "test.reason", "test detail")

    assert assessment.action_floor == expected


@pytest.mark.parametrize("capability", ("read_local", "read_remote"))
def test_read_capabilities_cannot_be_rendered_as_review_actions(capability: GitHubCommandCapability) -> None:
    assessment = github_assessment(capability, "test.read", "test read")

    with pytest.raises(ValueError, match="read-only"):
        _ = github_capability_action_class(assessment)


def test_admin_merge_action_class_is_preserved_with_branch_deletion() -> None:
    assessment = classify_github_cli(("pr", "merge", "123", "--admin", "--delete-branch"))

    assert assessment.capabilities == ("admin_merge_remote", "delete_remote")
    assert github_capability_action_class(assessment) == "GitHub administrator pull-request merge command"


@pytest.mark.parametrize(
    ("command", "capabilities"),
    (
        ("gh pr view 1; gh pr lock 1", ("read_remote", "maintain_remote")),
        ("gh pr lock 1; gh pr view 1", ("read_remote", "maintain_remote")),
        ("gh pr view 1; gh repo delete o/r --yes", ("read_remote", "delete_remote")),
        ("gh repo delete o/r --yes; gh pr view 1", ("read_remote", "delete_remote")),
        ("sh -c 'gh pr lock 1; gh pr view 1'", ("read_remote", "maintain_remote")),
    ),
)
def test_shell_composition_preserves_read_and_mutating_capabilities(
    tmp_path: Path,
    command: str,
    capabilities: tuple[GitHubCommandCapability, ...],
) -> None:
    assessment = classify_github_shell_capabilities(command, home_dir=tmp_path)

    assert assessment is not None
    assert assessment.capabilities == capabilities
    assert assessment.workflow_authorizable is False


def test_local_write_cannot_mask_remote_secret_capability(tmp_path: Path) -> None:
    assessment = classify_github_shell_capabilities(
        "gh repo set-default o/r; gh secret set TOKEN --body value",
        home_dir=tmp_path,
    )

    assert assessment is not None
    assert assessment.capabilities == ("write_local", "secret_remote")
    assert assessment.capability == "secret_remote"


@pytest.mark.parametrize(
    ("command", "capabilities", "primary"),
    (
        ("gh secret set TOKEN --body value > result.txt", ("write_local", "secret_remote"), "secret_remote"),
        ("gh repo delete o/r --yes > result.txt", ("write_local", "delete_remote"), "delete_remote"),
        (
            "gh pr merge 17 --delete-branch > result.txt",
            ("write_local", "merge_remote", "delete_remote"),
            "delete_remote",
        ),
    ),
)
def test_redirection_retains_the_underlying_remote_capability(
    tmp_path: Path,
    command: str,
    capabilities: tuple[GitHubCommandCapability, ...],
    primary: GitHubCommandCapability,
) -> None:
    assessment = classify_github_shell_capabilities(command, home_dir=tmp_path)

    assert assessment is not None
    assert assessment.capabilities == capabilities
    assert assessment.capability == primary


@pytest.mark.parametrize(
    "command",
    (
        "gh pr review 17 --approve",
        "gh pr merge 17 --squash",
        "gh release create v1 --notes-file notes.md",
        "gh workflow run ci.yml",
        "gh repo sync --force",
        "gh issue delete 17 --yes",
        "gh secret set TOKEN --body value",
        "gh repo edit --visibility private",
    ),
)
def test_no_remote_mutation_is_prompt_free(tmp_path: Path, command: str) -> None:
    match = extract_sensitive_tool_action_request("Bash", {"command": command}, cwd=tmp_path)

    assert match is not None


@pytest.mark.parametrize(
    "command",
    (
        "git push origin --delete obsolete",
        "git branch -D obsolete",
    ),
)
def test_branch_deletion_keeps_a_destructive_floor(tmp_path: Path, command: str) -> None:
    match = extract_sensitive_tool_action_request("Bash", {"command": command}, cwd=tmp_path)

    assert match is not None
    assert match.action_class == "git destructive command"
