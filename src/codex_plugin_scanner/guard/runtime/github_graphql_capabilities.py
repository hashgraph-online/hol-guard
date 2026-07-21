"""Conservative capability classification for static GitHub GraphQL documents."""

from __future__ import annotations

import re

from .github_capability_contract import GitHubCommandAssessment, GitHubCommandCapability, github_assessment

_GRAPHQL_NAME = re.compile(r"\b[_A-Za-z][_0-9A-Za-z]*\b")
_GRAPHQL_ALIAS = re.compile(r"\b(?P<name>[_A-Za-z][_0-9A-Za-z]*)\s*:")
_MAINTENANCE_MUTATIONS = frozenset(
    {
        "minimizeComment",
        "resolveReviewThread",
        "unminimizeComment",
        "unresolveReviewThread",
    }
)
_MERGE_MUTATIONS = frozenset(
    {
        "disablePullRequestAutoMerge",
        "enablePullRequestAutoMerge",
        "mergePullRequest",
        "updatePullRequestBranch",
    }
)
_CONTENT_MUTATIONS = frozenset(
    {
        "addComment",
        "addProjectV2DraftIssue",
        "addProjectV2ItemById",
        "addPullRequestReview",
        "addPullRequestReviewComment",
        "addPullRequestReviewThread",
        "closeDiscussion",
        "closeIssue",
        "convertPullRequestToDraft",
        "createDiscussion",
        "createIssue",
        "createPullRequest",
        "markDiscussionCommentAsAnswer",
        "markPullRequestReadyForReview",
        "reopenDiscussion",
        "reopenIssue",
        "submitPullRequestReview",
        "unmarkDiscussionCommentAsAnswer",
        "updateDiscussion",
        "updateDiscussionComment",
        "updateIssue",
        "updateIssueComment",
        "updateProjectV2ItemFieldValue",
        "updatePullRequest",
        "updatePullRequestReview",
        "updatePullRequestReviewComment",
    }
)


def classify_graphql_document(document: str) -> GitHubCommandAssessment:
    """Classify one static GraphQL document, allowing only narrow review maintenance."""

    sanitized = _strip_strings_and_comments(document)
    suspicious_aliases = [
        match.group("name")
        for match in _GRAPHQL_ALIAS.finditer(sanitized)
        if "mutation" in match.group("name").lower() or "subscription" in match.group("name").lower()
    ]
    if suspicious_aliases:
        return github_assessment(
            "unknown",
            "github.graphql.suspicious-alias",
            "A GraphQL alias resembles an operation type and is not classified automatically.",
        )
    has_fragment_definition = re.search(r"\bfragment\b", sanitized) is not None
    if has_fragment_definition and re.search(r"\bmutation\b", sanitized) is not None:
        return github_assessment(
            "mutate_remote",
            "github.graphql.remote-mutation",
            "GraphQL mutations with fragment definitions require confirmation.",
        )
    operations = _top_level_operations(sanitized)
    if operations is None:
        return github_assessment("unknown", "github.graphql.invalid-document", "The GraphQL document is not balanced.")
    if not operations:
        return github_assessment(
            "unknown",
            "github.graphql.missing-operation",
            "No static GraphQL operation was found.",
        )
    if len(operations) != 1:
        return github_assessment(
            "unknown",
            "github.graphql.multiple-operations",
            "Multiple GraphQL operations or a batched document cannot be classified automatically.",
        )
    operation = operations[0]
    if operation == "mutation":
        root_fields = _root_fields(sanitized)
        capabilities: tuple[GitHubCommandCapability, ...] = tuple(
            capability for field in root_fields or () for capability in _graphql_mutation_capabilities(field)
        )
        if has_fragment_definition or not capabilities:
            capabilities = ("mutate_remote",)
        return github_assessment(
            capabilities,
            "github.graphql.mixed-mutation" if len(set(capabilities)) > 1 else _graphql_reason(capabilities[0]),
            "The GraphQL operation contains statically classified mutation root fields.",
        )
    if operation == "subscription":
        return github_assessment(
            "mutate_remote",
            "github.graphql.remote-mutation",
            "The GraphQL operation can change or subscribe to GitHub-hosted state.",
        )
    return github_assessment(
        "read_remote",
        "github.graphql.proven-query",
        "The GraphQL document is a single static query.",
    )


def _graphql_mutation_capabilities(field: str) -> tuple[GitHubCommandCapability, ...]:
    if field in _MAINTENANCE_MUTATIONS:
        return ("maintain_remote",)
    if field in _MERGE_MUTATIONS:
        return ("merge_remote",)
    if field in _CONTENT_MUTATIONS:
        return ("content_remote",)
    lowered = field.lower()
    capabilities: list[GitHubCommandCapability] = []
    if lowered.startswith("delete") or lowered.startswith("remove"):
        capabilities.append("delete_remote")
    if any(marker in lowered for marker in ("secret", "token")):
        capabilities.append("secret_remote")
    if any(marker in lowered for marker in ("collaborator", "deploykey", "permission", "repository")):
        capabilities.append("access_remote")
    if "workflow" in lowered:
        capabilities.append("workflow_remote")
    if "release" in lowered:
        capabilities.append("publish_remote")
    return tuple(capabilities) or ("mutate_remote",)


def _graphql_reason(capability: GitHubCommandCapability) -> str:
    return f"github.graphql.{capability.replace('_remote', '').replace('_', '-')}"


def _root_fields(document: str) -> tuple[str, ...] | None:
    selection_start = _selection_start(document)
    if selection_start is None:
        return None
    fields: list[str] = []
    depth = 1
    parenthesis_depth = 0
    index = selection_start + 1
    while index < len(document) and depth > 0:
        character = document[index]
        if character == "(":
            parenthesis_depth += 1
            index += 1
            continue
        if character == ")":
            if parenthesis_depth == 0:
                return None
            parenthesis_depth -= 1
            index += 1
            continue
        if character == "{":
            depth += 1
            index += 1
            continue
        if character == "}":
            depth -= 1
            index += 1
            continue
        if depth != 1 or parenthesis_depth != 0 or character.isspace() or character == ",":
            index += 1
            continue
        if document.startswith("...", index):
            return None
        name_match = _GRAPHQL_NAME.match(document, index)
        if name_match is None:
            return None
        field_name = name_match.group(0)
        index = name_match.end()
        while index < len(document) and document[index].isspace():
            index += 1
        if index < len(document) and document[index] == ":":
            index += 1
            while index < len(document) and document[index].isspace():
                index += 1
            field_match = _GRAPHQL_NAME.match(document, index)
            if field_match is None:
                return None
            field_name = field_match.group(0)
            index = field_match.end()
        fields.append(field_name)
    if depth != 0 or parenthesis_depth != 0:
        return None
    return tuple(fields)


def _selection_start(document: str) -> int | None:
    parenthesis_depth = 0
    for index, character in enumerate(document):
        if character == "(":
            parenthesis_depth += 1
        elif character == ")":
            if parenthesis_depth == 0:
                return None
            parenthesis_depth -= 1
        elif character == "{" and parenthesis_depth == 0:
            return index
    return None


def _top_level_operations(document: str) -> list[str] | None:
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


def _strip_strings_and_comments(document: str) -> str:
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
