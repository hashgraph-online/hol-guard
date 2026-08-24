"""Classify GitHub CLI commands by their observable security capability.

The classifier uses reviewed command sets for prompt-free reads and routine
mutations. A new or aliased ``gh`` command therefore cannot inherit trusted
status merely because it is followed by an output formatter in a shell pipeline.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Literal

from .github_capability_contract import (
    GitHubCommandAssessment,
    GitHubCommandCapability,
    github_assessment,
)
from .github_rest_capabilities import classify_github_api
from .github_routine_merge import ROUTINE_SQUASH_MERGE_DETAIL, is_routine_squash_merge

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
    "repo": frozenset({"create", "fork", "rename", "sync"}),
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
_REPOSITORY_COMPONENT = re.compile(r"[A-Za-z0-9_.-]+")
_READ_SHORT_BOOLEAN_FLAGS: dict[tuple[str, str], frozenset[str]] = {
    ("issue", "list"): frozenset({"w"}),
    ("issue", "view"): frozenset({"c", "w"}),
    ("pr", "checks"): frozenset({"w"}),
    ("pr", "diff"): frozenset({"w"}),
    ("pr", "list"): frozenset({"d", "w"}),
    ("pr", "status"): frozenset({"c"}),
    ("pr", "view"): frozenset({"c", "w"}),
    ("release", "view"): frozenset({"w"}),
    ("repo", "view"): frozenset({"w"}),
    ("run", "list"): frozenset({"a"}),
    ("run", "view"): frozenset({"v", "w"}),
    ("workflow", "list"): frozenset({"a"}),
    ("workflow", "view"): frozenset({"w", "y"}),
}
_READ_SHORT_VALUE_FLAGS: dict[tuple[str, str], frozenset[str]] = {
    ("issue", "list"): frozenset({"A", "L", "S", "a", "l", "m", "s"}),
    ("pr", "checks"): frozenset({"i"}),
    ("pr", "diff"): frozenset({"e"}),
    ("pr", "list"): frozenset({"A", "B", "H", "L", "S", "a", "l", "s"}),
    ("release", "list"): frozenset({"L", "O"}),
    ("repo", "list"): frozenset({"L", "l"}),
    ("repo", "view"): frozenset({"b"}),
    ("run", "list"): frozenset({"L", "b", "c", "e", "s", "u", "w"}),
    ("run", "view"): frozenset({"a", "j"}),
    ("run", "watch"): frozenset({"i"}),
    ("workflow", "list"): frozenset({"L"}),
    ("workflow", "view"): frozenset({"r"}),
}
_INHERITED_READ_SHORT_VALUE_FLAGS = frozenset({"q", "t"})


def classify_github_cli(args: Sequence[str]) -> GitHubCommandAssessment:
    """Classify arguments following the ``gh`` executable.

    Unknown extensions and aliases are deliberately not assumed to be reads.
    """

    normalized = [str(arg) for arg in args]
    original = tuple(normalized)
    if not normalized:
        return _assessment("unknown", "github.command.missing", "The GitHub CLI subcommand is missing.")
    if _alternate_hostname_requested(original):
        return _assessment(
            "unknown",
            "github.command.alternate-host",
            "An alternate GitHub host requires explicit review.",
        )
    if _unsafe_repository_selector_requested(original):
        return _assessment(
            "unknown",
            "github.command.untrusted-repository-selector",
            "An alternate, dynamic, or malformed GitHub repository selector requires explicit review.",
        )
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
        if auth_subcommand in {"login", "logout", "switch", "refresh", "setup-git"}:
            return _assessment(
                "write_local",
                "github.command.local-auth-write",
                "The command changes local GitHub CLI authentication.",
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
        subcommand = _group_subcommand(normalized[1:])
        if subcommand == "help":
            return _assessment("read_local", "github.command.local-help", "The command displays local CLI help.")
        if subcommand == "list":
            return _assessment(
                "read_remote",
                "github.command.proven-access-read",
                "The command reads public-key metadata from GitHub.",
            )
        access_capabilities: GitHubCommandCapability | tuple[GitHubCommandCapability, ...] = "access_remote"
        if subcommand == "delete":
            access_capabilities = ("delete_remote", "access_remote")
        return _assessment(
            access_capabilities,
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
            if is_routine_squash_merge(tail):
                return _assessment(
                    "routine_merge_remote",
                    "github.command.pr-routine-squash-merge",
                    ROUTINE_SQUASH_MERGE_DETAIL,
                )
            admin_state = _boolean_option_state(tail, "--admin")
            if admin_state == "invalid":
                return _assessment(
                    "unknown",
                    "github.command.invalid-admin-option",
                    "The administrator merge option has an invalid Boolean value.",
                )
            admin_merge = admin_state == "true"
            merge_capability: GitHubCommandCapability = "admin_merge_remote" if admin_merge else "merge_remote"
            capabilities: tuple[GitHubCommandCapability, ...] = (merge_capability,)
            if _has_option(tail, "--delete-branch"):
                capabilities = (*capabilities, "delete_remote")
            return _assessment(
                capabilities,
                "github.command.pr-admin-merge" if admin_merge else "github.command.pr-merge",
                (
                    "The command uses administrator privileges to merge a pull request."
                    if admin_merge
                    else "The command merges a pull request and may also delete its branch."
                ),
            )
        if top_level == "release" and subcommand in _PUBLISH_SUBCOMMANDS:
            return _assessment(
                "publish_remote",
                "github.command.release-publication",
                "The command publishes or changes a GitHub release artifact.",
            )
        if subcommand in _WORKFLOW_SUBCOMMANDS.get(top_level, frozenset()):
            if top_level == "run" and subcommand == "rerun" and _is_routine_failed_run_rerun(original, tail):
                return _assessment(
                    "routine_workflow_remote",
                    "github.command.routine-failed-run-rerun",
                    "The command retries only failed jobs from one numeric GitHub Actions run.",
                )
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
        if top_level == "pr" and subcommand == "create" and _pr_create_has_static_inline_content(tail):
            return _assessment(
                "propose_remote",
                "github.command.pr-proposal",
                "The command creates a pull-request proposal without merging or changing repository controls.",
            )
        if subcommand in _MAINTENANCE_SUBCOMMANDS.get(top_level, frozenset()):
            if _has_dynamic_value(original):
                return _assessment(
                    "unknown",
                    "github.command.dynamic-maintenance-target",
                    "The maintenance target cannot be resolved statically.",
                )
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


def _pr_create_has_static_inline_content(args: Sequence[str]) -> bool:
    content_derived_options = (
        "--body-file",
        "--template",
        "--fill",
        "--fill-first",
        "--fill-verbose",
        "--recover",
        "--web",
        "--editor",
        "--dry-run",
    )
    if any(_has_option(args, option) for option in content_derived_options):
        return False
    if any(_has_short_option(args, option) for option in ("-F", "-T")):
        return False
    if any(_has_short_boolean_option(args, option) for option in ("-e", "-f", "-w")):
        return False
    return _has_explicit_option_value(args, "--title", "-t") and _has_explicit_option_value(
        args,
        "--body",
        "-b",
    )


def static_markdown_pr_body_file_operand(args: Sequence[str]) -> str | None:
    """Return one unambiguous Markdown body file from a static PR proposal."""

    incompatible_options = (
        "--body",
        "--template",
        "--fill",
        "--fill-first",
        "--fill-verbose",
        "--recover",
        "--web",
        "--editor",
        "--dry-run",
    )
    if any(_has_option(args, option) for option in incompatible_options):
        return None
    if any(_has_short_option(args, option) for option in ("-T", "-b")):
        return None
    if any(_has_short_boolean_option(args, option) for option in ("-e", "-f", "-w")):
        return None
    if not _has_explicit_option_value(args, "--title", "-t"):
        return None
    body_files: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if token in {"--body-file", "-F"}:
            if index + 1 >= len(args):
                return None
            body_files.append(args[index + 1])
            index += 2
            continue
        if token.startswith("--body-file="):
            body_files.append(token.partition("=")[2])
        elif token.startswith("-F") and len(token) > 2:
            body_files.append(token[2:])
        index += 1
    if len(body_files) != 1:
        return None
    body_file = body_files[0]
    shell_expansion_markers = ("$", "`", "*", "?", "[", "]", "{", "}", "(", ")", "<", ">", "^", "#")
    if (
        not body_file
        or body_file == "-"
        or body_file.startswith("=")
        or body_file.startswith("~//")
        or any(marker in body_file for marker in shell_expansion_markers)
        or ("~" in body_file and not body_file.startswith("~/"))
    ):
        return None
    if not body_file.lower().endswith((".md", ".markdown")):
        return None
    return body_file


def _has_short_option(args: Sequence[str], option: str) -> bool:
    return any(token == option or (token.startswith(option) and len(token) > len(option)) for token in args)


def _has_short_boolean_option(args: Sequence[str], option: str) -> bool:
    long_value_options = frozenset(
        {
            "--assignee",
            "--base",
            "--body",
            "--body-file",
            "--head",
            "--label",
            "--milestone",
            "--project",
            "--recover",
            "--repo",
            "--reviewer",
            "--template",
            "--title",
        }
    )
    short_value_options = frozenset("aBbFHlmprRTt")
    option_name = option.removeprefix("-")
    index = 0
    while index < len(args):
        token = args[index]
        is_short_value_option = len(token) == 2 and token.startswith("-") and token[1] in short_value_options
        if token in long_value_options or is_short_value_option:
            index += 2
            continue
        if any(token.startswith(f"{value_option}=") for value_option in long_value_options):
            index += 1
            continue
        if token == option:
            return True
        if not token.startswith("-") or token.startswith("--") or len(token) < 3:
            index += 1
            continue
        cluster = token[1:]
        if cluster[0] not in short_value_options and option_name in cluster:
            return True
        index += 1
    return False


def _has_explicit_option_value(args: Sequence[str], long_option: str, short_option: str) -> bool:
    for index, token in enumerate(args):
        if token in {long_option, short_option}:
            if index + 1 < len(args) and args[index + 1]:
                return True
            continue
        if token.startswith(f"{long_option}="):
            return bool(token.partition("=")[2])
        if token.startswith(short_option) and len(token) > len(short_option):
            return True
    return False


def _has_dynamic_value(args: Sequence[str]) -> bool:
    return any("$" in token or "`" in token or token.startswith("@") for token in args)


def _is_routine_failed_run_rerun(original: tuple[str, ...], args: Sequence[str]) -> bool:
    """Accept one numeric run, one static repository, and exactly ``--failed``."""

    if not any(
        token in {"--repo", "-R"} or token.startswith(("--repo=", "-R=")) or (token.startswith("-R") and len(token) > 2)
        for token in original
    ):
        return False
    run_id: str | None = None
    failed = False
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--failed":
            if failed:
                return False
            failed = True
        elif token in {"--repo", "-R"}:
            if index + 1 >= len(args):
                return False
            index += 1
        elif token.startswith(("--repo=", "-R=")) or (token.startswith("-R") and len(token) > 2):
            pass
        elif run_id is None and token.isascii() and token.isdigit() and 0 < len(token) <= 20 and int(token) > 0:
            run_id = token
        else:
            return False
        index += 1
    return run_id is not None and failed


def _alternate_hostname_requested(args: tuple[str, ...]) -> bool:
    hostnames: list[str] = []
    for index, token in enumerate(args):
        if index > 0 and token.startswith("-h") and token != "--help":
            hostname = token[2:] if token != "-h" else (args[index + 1] if index + 1 < len(args) else "")
            hostnames.append(hostname)
        if token.startswith("--hostname="):
            hostnames.append(token.partition("=")[2])
        if token == "--hostname":
            hostnames.append(args[index + 1] if index + 1 < len(args) else "")
    return any(hostname.casefold() != "github.com" for hostname in hostnames) or len(set(hostnames)) > 1


def _unsafe_repository_selector_requested(args: tuple[str, ...]) -> bool:
    selectors: list[str] = []
    malformed_cluster = False
    command_args = _strip_global_options(list(args))
    command_key: tuple[str, str] = (command_args[0], command_args[1]) if len(command_args) >= 2 else ("", "")
    boolean_flags = _READ_SHORT_BOOLEAN_FLAGS.get(command_key, frozenset())
    value_flags = _READ_SHORT_VALUE_FLAGS.get(command_key, frozenset()) | _INHERITED_READ_SHORT_VALUE_FLAGS
    index = 0
    while index < len(args):
        token = args[index]
        if token.startswith("--repo="):
            selectors.append(token.partition("=")[2])
        elif token == "--repo" or token == "-R":
            selectors.append(args[index + 1] if index + 1 < len(args) else "")
            index += 1
        elif len(token) > 2 and token.startswith("-") and token[1] in value_flags:
            pass
        elif token.startswith("-") and not token.startswith("--") and "R" in token[1:]:
            cluster = token[1:]
            prefix, _separator, attached_selector = cluster.partition("R")
            if any(flag in value_flags for flag in prefix):
                pass
            elif not prefix or all(flag in boolean_flags for flag in prefix):
                if attached_selector:
                    selectors.append(attached_selector)
                else:
                    selectors.append(args[index + 1] if index + 1 < len(args) else "")
                    index += 1
            else:
                malformed_cluster = True
        index += 1
    return (
        malformed_cluster
        or len(selectors) > 1
        or any(not _github_repository_selector_is_safe(selector) for selector in selectors)
    )


def _github_repository_selector_is_safe(selector: str) -> bool:
    if any(marker in selector for marker in ("$", "`", "$(", "${")):
        return False
    parts = selector.split("/")
    if len(parts) == 3:
        if parts[0].casefold() != "github.com":
            return False
        parts = parts[1:]
    return len(parts) == 2 and all(_REPOSITORY_COMPONENT.fullmatch(part) for part in parts)


def _strip_global_options(args: list[str]) -> list[str]:
    index = 0
    while index < len(args):
        token = args[index]
        if token.startswith("-R") and token != "-R":
            index += 1
            continue
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


def _boolean_option_state(
    args: Sequence[str],
    option: str,
) -> Literal["absent", "true", "false", "invalid"]:
    state: Literal["absent", "true", "false", "invalid"] = "absent"
    for token in args:
        if token == "--":
            break
        if token == option:
            state = "true"
            continue
        prefix = f"{option}="
        if not token.startswith(prefix):
            continue
        value = token.removeprefix(prefix)
        if value in {"1", "t", "T", "TRUE", "true", "True"}:
            state = "true"
        elif value in {"0", "f", "F", "FALSE", "false", "False"}:
            state = "false"
        else:
            return "invalid"
    return state


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
