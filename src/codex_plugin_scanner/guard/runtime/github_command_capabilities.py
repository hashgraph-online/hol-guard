"""Classify GitHub CLI commands by their observable security capability.

The classifier intentionally uses positive allowlists for prompt-free reads.  A
new or aliased ``gh`` command therefore cannot inherit read-only status merely
because it is followed by an output formatter in a shell pipeline.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

GitHubCommandCapability = Literal[
    "read_local",
    "read_remote",
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

_ALWAYS_MUTATING_GROUPS = frozenset({"cache", "codespace", "gpg-key", "label", "secret", "ssh-key", "variable"})
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
_GRAPHQL_NAME = re.compile(r"\b[_A-Za-z][_0-9A-Za-z]*\b")
_GRAPHQL_ALIAS = re.compile(r"\b(?P<name>[_A-Za-z][_0-9A-Za-z]*)\s*:")


def classify_github_cli(args: Sequence[str]) -> GitHubCommandAssessment:
    """Classify arguments following the ``gh`` executable.

    Unknown extensions and aliases are deliberately not assumed to be reads.
    """

    normalized = [str(arg) for arg in args]
    if not normalized:
        return _assessment("unknown", "github.command.missing", "The GitHub CLI subcommand is missing.")
    has_dynamic_arguments = any(_contains_dynamic_shell_text(arg) for arg in normalized)

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
        if has_dynamic_arguments:
            return _dynamic_argument_assessment()
        return _assessment(
            "read_remote",
            "github.command.proven-read",
            "The command is a known read-only GitHub operation.",
        )
    if top_level in _ALWAYS_MUTATING_GROUPS:
        return _assessment(
            "mutate_remote",
            "github.command.remote-mutation",
            "The command group can change GitHub-hosted state.",
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
            if has_dynamic_arguments:
                return _dynamic_argument_assessment()
            return _assessment(
                "read_remote",
                "github.command.proven-read",
                "The command is a known read-only GitHub operation.",
            )
        if subcommand in _MUTATING_SUBCOMMANDS[top_level]:
            return _assessment(
                "mutate_remote",
                "github.command.remote-mutation",
                "The command can change GitHub-hosted state.",
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
    if method is not None and method not in {"GET", "HEAD"}:
        return _assessment(
            "mutate_remote",
            "github.api.mutating-method",
            "The GitHub API request uses a method that can change remote state.",
        )
    if parsed.endpoint.lower() == "graphql":
        return _classify_graphql(parsed, method=method)
    if any(_field_value_is_external(value) for _name, value in parsed.fields):
        return _assessment(
            "unknown",
            "github.api.external-field-value",
            "A GitHub API field loaded from external data cannot be classified statically.",
        )
    if parsed.fields and method is None:
        return _assessment(
            "mutate_remote",
            "github.api.implicit-write-method",
            "GitHub API fields select a write-capable request method unless GET is explicit.",
        )
    return _assessment("read_remote", "github.api.proven-get", "The GitHub API request is a statically proven read.")


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
    sanitized = _strip_graphql_strings_and_comments(document)
    suspicious_aliases = [
        match.group("name")
        for match in _GRAPHQL_ALIAS.finditer(sanitized)
        if "mutation" in match.group("name").lower() or "subscription" in match.group("name").lower()
    ]
    if suspicious_aliases:
        return _assessment(
            "unknown",
            "github.graphql.suspicious-alias",
            "A GraphQL alias resembles an operation type and is not classified automatically.",
        )
    operations = _top_level_graphql_operations(sanitized)
    if operations is None:
        return _assessment("unknown", "github.graphql.invalid-document", "The GraphQL document is not balanced.")
    if not operations:
        return _assessment("unknown", "github.graphql.missing-operation", "No static GraphQL operation was found.")
    if len(operations) != 1:
        return _assessment(
            "unknown",
            "github.graphql.multiple-operations",
            "Multiple GraphQL operations or a batched document cannot be classified automatically.",
        )
    operation = operations[0]
    if operation in {"mutation", "subscription"}:
        return _assessment(
            "mutate_remote",
            "github.graphql.remote-mutation",
            "The GraphQL operation can change or subscribe to GitHub-hosted state.",
        )
    return _assessment("read_remote", "github.graphql.proven-query", "The GraphQL document is a single static query.")


def _top_level_graphql_operations(document: str) -> list[str] | None:
    operations: list[str] = []
    depth = 0
    pending_definition = False
    index = 0
    while index < len(document):
        character = document[index]
        if character == "{":
            if depth == 0:
                if not pending_definition:
                    operations.append("query")
                pending_definition = False
            depth += 1
            index += 1
            continue
        if character == "}":
            if depth == 0:
                return None
            depth -= 1
            index += 1
            continue
        if depth == 0:
            name_match = _GRAPHQL_NAME.match(document, index)
            if name_match is not None:
                name = name_match.group(0).lower()
                if name in {"query", "mutation", "subscription"}:
                    operations.append(name)
                    pending_definition = True
                elif name == "fragment":
                    pending_definition = True
                index = name_match.end()
                continue
        index += 1
    return operations if depth == 0 else None


def _strip_graphql_strings_and_comments(document: str) -> str:
    output: list[str] = []
    index = 0
    while index < len(document):
        if document.startswith('"""', index):
            end = document.find('"""', index + 3)
            if end == -1:
                return ""
            output.extend(" " * (end + 3 - index))
            index = end + 3
            continue
        character = document[index]
        if character == '"':
            output.append(" ")
            index += 1
            escaped = False
            while index < len(document):
                current = document[index]
                output.append(" ")
                index += 1
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == '"':
                    break
            continue
        if character == "#":
            while index < len(document) and document[index] not in "\r\n":
                output.append(" ")
                index += 1
            continue
        output.append(character)
        index += 1
    return "".join(output)


def _field_value_is_external(value: str) -> bool:
    stripped = value.strip()
    return stripped.startswith("@") or _contains_dynamic_shell_text(stripped)


def _contains_dynamic_shell_text(value: str) -> bool:
    return any(marker in value for marker in ("$(", "`", "${", "$'", '$"'))


def _dynamic_argument_assessment() -> GitHubCommandAssessment:
    return _assessment(
        "unknown",
        "github.command.dynamic-argument",
        "The GitHub CLI invocation contains an argument that cannot be classified statically.",
    )


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
