"""Classify GitHub CLI commands by their observable security capability.

The classifier uses reviewed command sets for prompt-free reads and routine
mutations. A new or aliased ``gh`` command therefore cannot inherit trusted
status merely because it is followed by an output formatter in a shell pipeline.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

GitHubCommandCapability = Literal[
    "read_local",
    "read_remote",
    "maintain_remote",
    "mutate_remote",
    "write_local",
    "unknown",
]


@dataclass(frozen=True, slots=True)
class GitHubCommandAssessment:
    """A stable capability decision for one ``gh`` invocation."""

    capability: GitHubCommandCapability
    reason_code: str
    detail: str


_READ_ONLY_SUBCOMMANDS: dict[str, frozenset[str]] = {
    "issue": frozenset({"list", "status", "view"}),
    "pr": frozenset({"checks", "diff", "list", "status", "view"}),
    "release": frozenset({"list", "view"}),
    "repo": frozenset({"list", "view"}),
    "run": frozenset({"list", "view", "watch"}),
    "workflow": frozenset({"list", "view"}),
}

_MUTATING_SUBCOMMANDS: dict[str, frozenset[str]] = {
    "issue": frozenset(
        {
            "close",
            "comment",
            "create",
            "delete",
            "develop",
            "edit",
            "lock",
            "pin",
            "reopen",
            "transfer",
            "unlock",
            "unpin",
        }
    ),
    "pr": frozenset(
        {
            "close",
            "comment",
            "create",
            "edit",
            "lock",
            "merge",
            "ready",
            "reopen",
            "review",
            "unlock",
        }
    ),
    "release": frozenset({"create", "delete", "edit", "upload"}),
    "repo": frozenset({"archive", "create", "delete", "edit", "fork", "rename", "set-default", "sync"}),
    "run": frozenset({"cancel", "delete", "rerun"}),
    "workflow": frozenset({"disable", "enable", "run"}),
}
_MAINTENANCE_SUBCOMMANDS: dict[str, frozenset[str]] = {"pr": frozenset({"merge"})}

_HIGH_IMPACT_SUBCOMMANDS: dict[str, frozenset[str]] = {
    "release": frozenset({"delete"}),
    "repo": frozenset({"archive", "delete", "rename"}),
    "workflow": frozenset({"disable"}),
}

_HIGH_IMPACT_GROUPS = frozenset({"gpg-key", "secret", "ssh-key"})
_ROUTINE_MUTATING_GROUPS = frozenset({"cache", "codespace", "label", "variable"})
_READ_ONLY_TOP_LEVEL = frozenset({"search", "status"})
_LOCAL_TOP_LEVEL = frozenset({"completion", "help", "version"})
_LOCAL_AUTH_SUBCOMMANDS = frozenset({"status", "token"})
_GROUP_OPTIONS_WITH_VALUES = frozenset({"-R", "--repo"})
_GROUP_BOOLEAN_OPTIONS = frozenset({"--help"})
_GLOBAL_OPTIONS_WITH_VALUES = frozenset({"--hostname", "--repo", "-R"})
_API_OPTIONS_WITH_VALUES = frozenset(
    {
        "--cache",
        "--field",
        "--header",
        "--hostname",
        "--input",
        "--jq",
        "--method",
        "--preview",
        "--raw-field",
        "--template",
        "-F",
        "-H",
        "-X",
        "-f",
        "-h",
        "-p",
    }
)
_API_BOOLEAN_OPTIONS = frozenset({"--include", "--paginate", "--silent", "--slurp", "--verbose", "-i"})
_METHOD_OVERRIDE_HEADER = re.compile(r"\Ax-http-method-override\s*:", re.IGNORECASE)
_STATIC_ENDPOINT = re.compile(r"\A[A-Za-z0-9_./{}:+,@=-]+\Z")


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
        return _classify_api(normalized[1:])
    if any(token in {"--help", "-h"} for token in normalized[1:]):
        return _assessment("read_local", "github.command.local-help", "The command displays local CLI help.")
    if top_level in _LOCAL_TOP_LEVEL:
        return _assessment("read_local", "github.command.local-metadata", "The command reads local CLI metadata.")
    if top_level == "auth" and len(normalized) > 1 and normalized[1].lower() in _LOCAL_AUTH_SUBCOMMANDS:
        return _assessment("read_local", "github.command.local-auth-read", "The command reads local CLI auth state.")
    if top_level in _READ_ONLY_TOP_LEVEL:
        return _assessment(
            "read_remote",
            "github.command.proven-read",
            "The command is a known read-only GitHub operation.",
        )
    if top_level in _HIGH_IMPACT_GROUPS:
        return _assessment(
            "mutate_remote",
            "github.command.high-impact-mutation",
            "The command changes GitHub credentials or secrets.",
        )
    if top_level in _ROUTINE_MUTATING_GROUPS:
        if _group_subcommand(normalized[1:]) == "delete":
            return _assessment(
                "mutate_remote",
                "github.command.high-impact-mutation",
                "The command deletes GitHub-hosted state.",
            )
        return _assessment(
            "maintain_remote",
            "github.command.routine-mutation",
            "The command performs a known routine GitHub mutation.",
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
        if _is_high_impact_command(top_level, subcommand, normalized[2:]):
            return _assessment(
                "mutate_remote",
                "github.command.high-impact-mutation",
                "The command performs an explicitly high-impact GitHub mutation.",
            )
        if subcommand in _MAINTENANCE_SUBCOMMANDS.get(top_level, frozenset()):
            return _assessment(
                "maintain_remote",
                "github.command.pr-maintenance",
                "The command performs a statically proven pull-request maintenance operation.",
            )
        if subcommand in _MUTATING_SUBCOMMANDS[top_level]:
            return _assessment(
                "maintain_remote",
                "github.command.routine-mutation",
                "The command performs a known routine GitHub mutation.",
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


def _is_high_impact_command(top_level: str, subcommand: str, args: Sequence[str]) -> bool:
    if subcommand == "delete":
        return True
    if subcommand in _HIGH_IMPACT_SUBCOMMANDS.get(top_level, frozenset()):
        return True
    if top_level == "pr" and subcommand == "merge":
        return _has_option(args, "--admin")
    if top_level == "repo" and subcommand == "edit":
        return _has_option(args, "--visibility")
    if top_level == "repo" and subcommand == "sync":
        return _has_option(args, "--force")
    return False


def _has_option(args: Sequence[str], option: str) -> bool:
    return any(token == option or token.startswith(f"{option}=") for token in args)


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


@dataclass(frozen=True, slots=True)
class _ApiArguments:
    endpoint: str
    method: str | None
    fields: tuple[tuple[str, str], ...]
    headers: tuple[str, ...]
    has_input: bool


def _classify_api(args: Sequence[str]) -> GitHubCommandAssessment:
    parsed = _parse_api_arguments(args)
    if isinstance(parsed, GitHubCommandAssessment):
        return parsed
    if not _STATIC_ENDPOINT.fullmatch(parsed.endpoint) or parsed.endpoint.startswith("-"):
        return _assessment(
            "unknown",
            "github.api.dynamic-endpoint",
            "The GitHub API endpoint cannot be resolved statically.",
        )
    if parsed.has_input:
        return _assessment(
            "unknown",
            "github.api.input-body",
            "A GitHub API body loaded from a file or standard input cannot be classified statically.",
        )
    if any(_METHOD_OVERRIDE_HEADER.search(header) for header in parsed.headers):
        return _assessment(
            "unknown",
            "github.api.method-override",
            "An HTTP method-override header prevents reliable API capability classification.",
        )
    method = parsed.method.upper() if parsed.method is not None else None
    if parsed.endpoint.lower() == "graphql":
        return _classify_graphql(parsed, method=method)
    if method is not None and method not in {"GET", "HEAD"}:
        if _api_request_is_high_impact(parsed, method=method):
            return _assessment(
                "mutate_remote",
                "github.api.high-impact-mutation",
                "The GitHub API request performs an explicitly high-impact operation.",
            )
        return _assessment(
            "maintain_remote",
            "github.api.routine-mutation",
            "The GitHub API request performs a statically understood routine mutation.",
        )
    if any(_field_value_is_external(value) for _name, value in parsed.fields):
        return _assessment(
            "unknown",
            "github.api.external-field-value",
            "A GitHub API field loaded from external data cannot be classified statically.",
        )
    if parsed.fields and method is None:
        if _api_request_is_high_impact(parsed, method="POST"):
            return _assessment(
                "mutate_remote",
                "github.api.high-impact-mutation",
                "The GitHub API request performs an explicitly high-impact operation.",
            )
        return _assessment(
            "maintain_remote",
            "github.api.routine-mutation",
            "GitHub API fields select a statically understood routine mutation.",
        )
    return _assessment("read_remote", "github.api.proven-get", "The GitHub API request is a statically proven read.")


def _api_request_is_high_impact(parsed: _ApiArguments, *, method: str) -> bool:
    endpoint = parsed.endpoint.strip("/").lower()
    segments = tuple(segment for segment in endpoint.split("/") if segment)
    if method == "DELETE":
        return True
    if len(segments) < 3 or segments[0] != "repos":
        return any(segment in {"secrets", "keys"} for segment in segments)
    resource = segments[3:]
    if not resource:
        return method in {"DELETE", "PATCH"}
    if resource[0] in {"keys", "rulesets", "secrets"}:
        return True
    if resource[:2] in {("actions", "permissions"), ("git", "refs")}:
        return True
    if resource[0] == "branches" and "protection" in resource:
        return True
    if resource[0] in {"collaborators", "hooks"}:
        return True
    return resource[0] == "transfer"


def _parse_api_arguments(args: Sequence[str]) -> _ApiArguments | GitHubCommandAssessment:
    endpoint: str | None = None
    method: str | None = None
    fields: list[tuple[str, str]] = []
    headers: list[str] = []
    has_input = False
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            index += 1
            if index >= len(args) or endpoint is not None:
                return _api_parse_failure()
            endpoint = args[index]
            index += 1
            if index != len(args):
                return _api_parse_failure()
            break
        option_name, separator, attached_value = token.partition("=")
        if not separator and len(token) > 2 and token[:2] in {"-f", "-F", "-H", "-X", "-h", "-p"}:
            option_name = token[:2]
            separator = "attached"
            attached_value = token[2:]
        if option_name in _API_BOOLEAN_OPTIONS:
            if separator:
                return _api_parse_failure()
            index += 1
            continue
        if option_name in _API_OPTIONS_WITH_VALUES:
            if separator:
                value = attached_value
                consumed = 1
            elif index + 1 < len(args):
                value = args[index + 1]
                consumed = 2
            else:
                return _api_parse_failure()
            if option_name in {"-X", "--method"}:
                method = value
            elif option_name in {"-f", "-F", "--field", "--raw-field"}:
                name, field_separator, field_value = value.partition("=")
                if not field_separator or not name:
                    return _api_parse_failure()
                fields.append((name, field_value))
            elif option_name in {"-H", "--header"}:
                headers.append(value)
            elif option_name == "--input":
                has_input = True
            index += consumed
            continue
        if token.startswith("-"):
            return _api_parse_failure()
        if endpoint is not None:
            return _api_parse_failure()
        endpoint = token
        index += 1
    if endpoint is None:
        return _api_parse_failure()
    return _ApiArguments(endpoint, method, tuple(fields), tuple(headers), has_input)


def _classify_graphql(parsed: _ApiArguments, *, method: str | None) -> GitHubCommandAssessment:
    if method is not None:
        return _assessment(
            "unknown",
            "github.graphql.method-override",
            "A GraphQL method override prevents reliable operation classification.",
        )
    query_values = [value for name, value in parsed.fields if name == "query"]
    if len(query_values) != 1:
        return _assessment(
            "unknown",
            "github.graphql.query-count",
            "Exactly one static GraphQL query is required for prompt-free classification.",
        )
    if any(name == "query" and value != query_values[0] for name, value in parsed.fields):
        return _assessment("unknown", "github.graphql.query-count", "Multiple GraphQL operations are ambiguous.")
    if any(_field_value_is_external(value) for _name, value in parsed.fields):
        return _assessment(
            "unknown",
            "github.graphql.external-value",
            "GraphQL query or variable data loaded from an external source cannot be classified statically.",
        )
    return _classify_graphql_document(query_values[0])


def _classify_graphql_document(document: str) -> GitHubCommandAssessment:
    from .github_graphql_capabilities import classify_graphql_document

    capability, reason_code, detail = classify_graphql_document(document)
    return _assessment(capability, reason_code, detail)


def _field_value_is_external(value: str) -> bool:
    stripped = value.strip()
    return stripped.startswith("@") or _contains_dynamic_shell_text(stripped)


def _contains_dynamic_shell_text(value: str) -> bool:
    return any(marker in value for marker in ("$(", "`", "${", "$'", '$"'))


def _api_parse_failure() -> GitHubCommandAssessment:
    return _assessment(
        "unknown",
        "github.api.unrecognized-arguments",
        "The GitHub API arguments cannot be classified statically.",
    )


def _assessment(
    capability: GitHubCommandCapability,
    reason_code: str,
    detail: str,
) -> GitHubCommandAssessment:
    return GitHubCommandAssessment(capability=capability, reason_code=reason_code, detail=detail)
