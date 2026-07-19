"""Classify GitHub CLI commands by their observable security capability.

The classifier uses reviewed command sets for prompt-free reads and routine
mutations. A new or aliased ``gh`` command therefore cannot inherit trusted
status merely because it is followed by an output formatter in a shell pipeline.
"""

from __future__ import annotations

from collections.abc import Sequence

from .github_capability_contract import (
    GitHubCommandAssessment,
    GitHubCommandCapability,
    github_assessment,
)
from .github_rest_capabilities import classify_github_api

_READ_ONLY_SUBCOMMANDS: dict[str, frozenset[str]] = {
    "issue": frozenset({"list", "status", "view"}),
    "pr": frozenset({"checks", "diff", "list", "status", "view"}),
    "release": frozenset({"list", "view"}),
    "repo": frozenset({"list", "view"}),
    "run": frozenset({"list", "view", "watch"}),
    "workflow": frozenset({"list", "view"}),
}

_CONTENT_SUBCOMMANDS: dict[str, frozenset[str]] = {
    "issue": frozenset(
        {
            "close",
            "comment",
            "create",
            "develop",
            "edit",
            "reopen",
            "transfer",
        }
    ),
    "pr": frozenset(
        {
            "close",
            "comment",
            "create",
            "edit",
            "reopen",
            "review",
        }
    ),
    "repo": frozenset({"create", "fork", "rename", "set-default", "sync"}),
}
_MAINTENANCE_SUBCOMMANDS: dict[str, frozenset[str]] = {
    "issue": frozenset({"lock", "pin", "unlock", "unpin"}),
    "pr": frozenset({"lock", "ready", "unlock"}),
}
_WORKFLOW_SUBCOMMANDS: dict[str, frozenset[str]] = {
    "run": frozenset({"cancel", "rerun"}),
    "workflow": frozenset({"disable", "enable", "run"}),
}
_PUBLISH_SUBCOMMANDS = frozenset({"create", "edit", "upload"})
_DELETE_GROUPS = frozenset({"cache", "codespace", "issue", "label", "pr", "release", "repo", "run", "variable"})
_SECRET_GROUPS = frozenset({"secret"})
_ACCESS_GROUPS = frozenset({"gpg-key", "ssh-key"})
_OTHER_MUTATING_GROUPS = frozenset({"cache", "codespace", "label", "variable"})
_READ_ONLY_TOP_LEVEL = frozenset({"search", "status"})
_LOCAL_TOP_LEVEL = frozenset({"completion", "help", "version"})
_GROUP_OPTIONS_WITH_VALUES = frozenset({"-R", "--repo"})
_GROUP_BOOLEAN_OPTIONS = frozenset({"--help"})
_GLOBAL_OPTIONS_WITH_VALUES = frozenset({"--hostname", "--repo", "-R"})


def classify_github_cli(args: Sequence[str]) -> GitHubCommandAssessment:
    """Classify arguments following the ``gh`` executable.

    Unknown extensions and aliases are deliberately not assumed to be reads.
    """

    normalized = [str(arg) for arg in args]
    if not normalized:
        return _assessment("unknown", "github.command.missing", "The GitHub CLI subcommand is missing.")
    normalized = _strip_global_options(normalized)
    if not normalized:
        return _assessment(
            "unknown",
            "github.command.missing",
            "The GitHub CLI subcommand is missing after global options.",
        )
    top_level = normalized[0].lower()
    if top_level in {"--version", "-v"}:
        return _assessment("read_local", "github.command.local-metadata", "The command reads local CLI metadata.")
    if top_level in {"--help", "-h"}:
        return _assessment("read_local", "github.command.local-help", "The command displays local CLI help.")
    if top_level == "api":
        return classify_github_api(normalized[1:])
    if top_level in _LOCAL_TOP_LEVEL:
        return _assessment("read_local", "github.command.local-metadata", "The command reads local CLI metadata.")
    if top_level == "auth" and len(normalized) > 1:
        auth_subcommand = normalized[1].lower()
        if auth_subcommand == "token" or (
            auth_subcommand == "status" and _has_any_option(normalized[2:], "--show-token", "-t")
        ):
            return _assessment(
                "secret_remote",
                "github.command.auth-token-read",
                "The command reads a GitHub authentication token.",
            )
        if auth_subcommand == "status":
            return _assessment(
                "read_local",
                "github.command.local-auth-read",
                "The command reads local CLI auth state.",
            )
    if top_level in _READ_ONLY_TOP_LEVEL:
        return _assessment(
            "read_remote",
            "github.command.proven-read",
            "The command is a known read-only GitHub operation.",
        )
    if top_level in _SECRET_GROUPS:
        return _assessment(
            "secret_remote",
            "github.command.secret-mutation",
            "The command changes GitHub secrets.",
        )
    if top_level in _ACCESS_GROUPS:
        return _assessment(
            "access_remote",
            "github.command.access-mutation",
            "The command changes GitHub access credentials.",
        )
    if top_level in _OTHER_MUTATING_GROUPS:
        subcommand = _group_subcommand(normalized[1:])
        if subcommand == "delete":
            return _assessment(
                "delete_remote",
                "github.command.delete-mutation",
                "The command deletes GitHub-hosted state.",
            )
        capability: GitHubCommandCapability = "mutate_remote"
        if top_level == "label":
            capability = "content_remote"
        elif top_level == "variable":
            capability = "workflow_remote"
        return _assessment(
            capability,
            "github.command.remote-mutation",
            "The command changes GitHub-hosted state.",
        )
    if top_level in _READ_ONLY_SUBCOMMANDS:
        subcommand = _group_subcommand(normalized[1:])
        if subcommand is None:
            return _assessment(
                "unknown",
                "github.command.unresolved-subcommand",
                "The GitHub CLI subcommand could not be resolved statically.",
            )
        if subcommand == "help":
            return _assessment("read_local", "github.command.local-help", "The command displays local CLI help.")
        if subcommand in _READ_ONLY_SUBCOMMANDS[top_level]:
            return _assessment(
                "read_remote",
                "github.command.proven-read",
                "The command is a known read-only GitHub operation.",
            )
        tail = normalized[2:]
        if subcommand == "delete" and top_level in _DELETE_GROUPS:
            return _assessment(
                "delete_remote",
                "github.command.delete-mutation",
                "The command deletes GitHub-hosted state.",
            )
        if top_level == "pr" and subcommand == "merge":
            capabilities: tuple[GitHubCommandCapability, ...] = ("merge_remote",)
            if _has_option(tail, "--delete-branch"):
                capabilities = ("merge_remote", "delete_remote")
            return _assessment(
                capabilities,
                "github.command.pr-merge",
                "The command merges a pull request and may also delete its branch.",
            )
        if top_level == "release" and subcommand in _PUBLISH_SUBCOMMANDS:
            return _assessment(
                "publish_remote",
                "github.command.release-publication",
                "The command publishes or changes a GitHub release artifact.",
            )
        if subcommand in _WORKFLOW_SUBCOMMANDS.get(top_level, frozenset()):
            return _assessment(
                "workflow_remote",
                "github.command.workflow-mutation",
                "The command starts or changes a GitHub workflow.",
            )
        if top_level == "repo" and subcommand == "edit":
            return _assessment(
                "access_remote",
                "github.command.repository-access-mutation",
                "Repository settings can change access or protection boundaries.",
            )
        if top_level == "repo" and subcommand == "set-default":
            return _assessment(
                "write_local",
                "github.command.local-default-write",
                "The command changes local GitHub CLI repository configuration.",
            )
        if top_level == "repo" and subcommand == "sync" and _has_option(tail, "--force"):
            return _assessment(
                "force_remote",
                "github.command.force-mutation",
                "The command forcefully changes remote repository state.",
            )
        if subcommand in _MAINTENANCE_SUBCOMMANDS.get(top_level, frozenset()):
            return _assessment(
                "maintain_remote",
                "github.command.bounded-maintenance",
                "The command performs a statically bounded maintenance operation.",
            )
        if subcommand in _CONTENT_SUBCOMMANDS.get(top_level, frozenset()):
            return _assessment(
                "content_remote",
                "github.command.content-mutation",
                "The command changes GitHub-hosted content.",
            )
        return _assessment(
            "unknown",
            "github.command.unrecognized-subcommand",
            "The GitHub CLI subcommand is not in the reviewed read-only set.",
        )
    return _assessment(
        "unknown",
        "github.command.extension-or-alias",
        "The GitHub CLI command may be an extension or alias and cannot be classified statically.",
    )


def _has_option(args: Sequence[str], option: str) -> bool:
    return any(token == option or token.startswith(f"{option}=") for token in args)


def _has_any_option(args: Sequence[str], *options: str) -> bool:
    return any(_has_option(args, option) for option in options)


def _strip_global_options(args: list[str]) -> list[str]:
    index = 0
    while index < len(args):
        token = args[index]
        option_name, separator, _value = token.partition("=")
        if option_name not in _GLOBAL_OPTIONS_WITH_VALUES:
            break
        if separator:
            index += 1
            continue
        if index + 1 >= len(args):
            return []
        index += 2
    return args[index:]


def _group_subcommand(args: Sequence[str]) -> str | None:
    index = 0
    while index < len(args):
        token = args[index]
        option_name, separator, _value = token.partition("=")
        if token == "--":
            index += 1
            break
        if option_name in _GROUP_OPTIONS_WITH_VALUES:
            if separator:
                index += 1
                continue
            if index + 1 >= len(args):
                return None
            index += 2
            continue
        if token in _GROUP_BOOLEAN_OPTIONS:
            return "help"
        if token.startswith("-"):
            return None
        return token.lower()
    return args[index].lower() if index < len(args) else None


def _assessment(
    capability: GitHubCommandCapability | tuple[GitHubCommandCapability, ...],
    reason_code: str,
    detail: str,
) -> GitHubCommandAssessment:
    return github_assessment(capability, reason_code, detail)
