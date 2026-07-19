"""Conservative capability classification for static ``gh api`` requests."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from .github_capability_contract import GitHubCommandAssessment, GitHubCommandCapability, github_assessment

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


@dataclass(frozen=True, slots=True)
class GitHubApiArguments:
    endpoint: str
    method: str | None
    fields: tuple[tuple[str, str], ...]
    headers: tuple[str, ...]
    has_input: bool


def classify_github_api(args: Sequence[str]) -> GitHubCommandAssessment:
    parsed = _parse_api_arguments(args)
    if isinstance(parsed, GitHubCommandAssessment):
        return parsed
    if not _STATIC_ENDPOINT.fullmatch(parsed.endpoint) or parsed.endpoint.startswith("-"):
        return github_assessment(
            "unknown",
            "github.api.dynamic-endpoint",
            "The GitHub API endpoint cannot be resolved statically.",
        )
    if parsed.has_input:
        return github_assessment(
            "unknown",
            "github.api.input-body",
            "A GitHub API body loaded from a file or standard input cannot be classified statically.",
        )
    if any(_METHOD_OVERRIDE_HEADER.search(header) for header in parsed.headers):
        return github_assessment(
            "unknown",
            "github.api.method-override",
            "An HTTP method-override header prevents reliable API capability classification.",
        )
    method = parsed.method.upper() if parsed.method is not None else None
    if parsed.endpoint.lower() == "graphql":
        return _classify_graphql(parsed, method=method)
    if any(_field_value_is_external(value) for _name, value in parsed.fields):
        return github_assessment(
            "unknown",
            "github.api.external-field-value",
            "A GitHub API field loaded from external data cannot be classified statically.",
        )
    if method is None:
        method = "POST" if parsed.fields else "GET"
    if method in {"GET", "HEAD"}:
        return github_assessment(
            "read_remote",
            "github.api.proven-get",
            "The GitHub API request is a statically proven read.",
        )
    capabilities = _mutation_capabilities(parsed, method=method)
    return github_assessment(
        capabilities,
        _mutation_reason(capabilities),
        "The GitHub API request performs a statically classified remote mutation.",
    )


def _mutation_capabilities(
    parsed: GitHubApiArguments,
    *,
    method: str,
) -> tuple[GitHubCommandCapability, ...]:
    endpoint = parsed.endpoint.strip("/").lower()
    segments = tuple(segment for segment in endpoint.split("/") if segment)
    capabilities: set[GitHubCommandCapability] = set()
    if method == "DELETE":
        capabilities.add("delete_remote")
    if _is_merge_endpoint(segments):
        capabilities.add("merge_remote")
    if _is_workflow_endpoint(segments):
        capabilities.add("workflow_remote")
    if _is_publish_endpoint(segments):
        capabilities.add("publish_remote")
    if any(segment == "secrets" for segment in segments) or _is_runner_token_endpoint(segments):
        capabilities.add("secret_remote")
    if _is_access_endpoint(segments) or (method == "PATCH" and _is_repository_endpoint(segments)):
        capabilities.add("access_remote")
    if _is_force_request(segments, parsed.fields):
        capabilities.add("force_remote")
    if _is_content_endpoint(segments) and not _is_merge_endpoint(segments):
        capabilities.add("content_remote")
    if _is_maintenance_endpoint(segments):
        capabilities.add("maintain_remote")
    if not capabilities:
        capabilities.add("mutate_remote")
    return tuple(capabilities)


def _is_merge_endpoint(segments: tuple[str, ...]) -> bool:
    return "merges" in segments or ("pulls" in segments and segments[-1:] == ("merge",))


def _is_workflow_endpoint(segments: tuple[str, ...]) -> bool:
    if "contents" in segments:
        contents_index = segments.index("contents")
        if segments[contents_index + 1 : contents_index + 3] == (".github", "workflows"):
            return True
    if "actions" in segments or "workflows" in segments:
        return any(
            segment in {"cancel", "disable", "dispatches", "enable", "rerun", "rerun-failed-jobs"}
            for segment in segments
        )
    return len(segments) >= 4 and segments[0] == "repos" and segments[3] == "dispatches"


def _is_publish_endpoint(segments: tuple[str, ...]) -> bool:
    return "releases" in segments or "release-assets" in segments


def _is_runner_token_endpoint(segments: tuple[str, ...]) -> bool:
    return "runners" in segments and segments[-1:] in {("registration-token",), ("remove-token",)}


def _is_access_endpoint(segments: tuple[str, ...]) -> bool:
    access_markers = {"collaborators", "memberships", "permissions", "protection", "rulesets"}
    return bool(access_markers.intersection(segments)) or any(
        segment in {"deployments", "hooks", "keys", "transfer"} for segment in segments
    )


def _is_repository_endpoint(segments: tuple[str, ...]) -> bool:
    return len(segments) == 3 and segments[0] == "repos"


def _is_force_request(segments: tuple[str, ...], fields: tuple[tuple[str, str], ...]) -> bool:
    return "refs" in segments and any(name.lower() == "force" and value.lower() == "true" for name, value in fields)


def _is_content_endpoint(segments: tuple[str, ...]) -> bool:
    if "contents" in segments:
        contents_index = segments.index("contents")
        return segments[contents_index + 1 : contents_index + 3] != (".github", "workflows")
    return bool({"comments", "discussions", "gists", "issues", "labels", "milestones", "pulls"}.intersection(segments))


def _is_maintenance_endpoint(segments: tuple[str, ...]) -> bool:
    return "threads" in segments and segments[-1:] in {("resolve",), ("unresolve",)}


def _mutation_reason(capabilities: tuple[GitHubCommandCapability, ...]) -> str:
    if len(capabilities) != 1:
        return "github.api.mixed-mutation"
    return f"github.api.{capabilities[0].replace('_remote', '').replace('_', '-')}"


def _parse_api_arguments(args: Sequence[str]) -> GitHubApiArguments | GitHubCommandAssessment:
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
        if token.startswith("-") or endpoint is not None:
            return _api_parse_failure()
        endpoint = token
        index += 1
    if endpoint is None:
        return _api_parse_failure()
    return GitHubApiArguments(endpoint, method, tuple(fields), tuple(headers), has_input)


def _classify_graphql(parsed: GitHubApiArguments, *, method: str | None) -> GitHubCommandAssessment:
    if method is not None:
        return github_assessment(
            "unknown",
            "github.graphql.method-override",
            "A GraphQL method override prevents reliable operation classification.",
        )
    query_values = [value for name, value in parsed.fields if name == "query"]
    if len(query_values) != 1:
        return github_assessment(
            "unknown",
            "github.graphql.query-count",
            "Exactly one static GraphQL query is required for classification.",
        )
    if any(_field_value_is_external(value) for _name, value in parsed.fields):
        return github_assessment(
            "unknown",
            "github.graphql.external-value",
            "GraphQL query or variable data loaded from an external source cannot be classified statically.",
        )
    from .github_graphql_capabilities import classify_graphql_document

    return classify_graphql_document(query_values[0])


def _field_value_is_external(value: str) -> bool:
    stripped = value.strip()
    return stripped.startswith("@") or any(marker in stripped for marker in ("$(", "`", "${", "$'", '$"'))


def _api_parse_failure() -> GitHubCommandAssessment:
    return github_assessment(
        "unknown",
        "github.api.unrecognized-arguments",
        "The GitHub API arguments cannot be classified statically.",
    )
