"""Conservative capability classification for static GitHub GraphQL documents."""

from __future__ import annotations

import re
from typing import Literal

GitHubGraphQLCapability = Literal["read_remote", "maintain_remote", "mutate_remote", "unknown"]
GitHubGraphQLAssessment = tuple[GitHubGraphQLCapability, str, str]

_GRAPHQL_NAME = re.compile(r"\b[_A-Za-z][_0-9A-Za-z]*\b")
_GRAPHQL_ALIAS = re.compile(r"\b(?P<name>[_A-Za-z][_0-9A-Za-z]*)\s*:")
_HIGH_IMPACT_MUTATIONS = frozenset(
    {
        "archiveRepository",
        "createBranchProtectionRule",
        "createRef",
        "createRepositoryRuleset",
        "deleteRef",
        "deleteBranchProtectionRule",
        "deleteRepository",
        "deleteRepositoryRuleset",
        "deleteRelease",
        "transferRepository",
        "unarchiveRepository",
        "updateRef",
        "updateBranchProtectionRule",
        "updateRepository",
        "updateRepositoryRuleset",
    }
)
_HIGH_IMPACT_MUTATION_NAME = re.compile(
    r"(?:credential|deploykey|enterprise|gpg.*key|hook|ipallowlist|secret|signingkey|ssh.*key|token)",
    re.IGNORECASE,
)


def classify_graphql_document(document: str) -> GitHubGraphQLAssessment:
    """Classify one static GraphQL document, allowing only narrow review maintenance."""

    sanitized = _strip_strings_and_comments(document)
    suspicious_aliases = [
        match.group("name")
        for match in _GRAPHQL_ALIAS.finditer(sanitized)
        if "mutation" in match.group("name").lower() or "subscription" in match.group("name").lower()
    ]
    if suspicious_aliases:
        return (
            "unknown",
            "github.graphql.suspicious-alias",
            "A GraphQL alias resembles an operation type and is not classified automatically.",
        )
    has_fragment_definition = re.search(r"\bfragment\b", sanitized) is not None
    if has_fragment_definition and re.search(r"\bmutation\b", sanitized) is not None:
        return (
            "mutate_remote",
            "github.graphql.remote-mutation",
            "GraphQL mutations with fragment definitions require confirmation.",
        )
    operations = _top_level_operations(sanitized)
    if operations is None:
        return "unknown", "github.graphql.invalid-document", "The GraphQL document is not balanced."
    if not operations:
        return "unknown", "github.graphql.missing-operation", "No static GraphQL operation was found."
    if len(operations) != 1:
        return (
            "unknown",
            "github.graphql.multiple-operations",
            "Multiple GraphQL operations or a batched document cannot be classified automatically.",
        )
    operation = operations[0]
    if operation == "mutation":
        root_fields = _root_fields(sanitized)
        if (
            not has_fragment_definition
            and root_fields
            and not any(_mutation_is_high_impact(field) for field in root_fields)
        ):
            return (
                "maintain_remote",
                "github.graphql.routine-mutation",
                "The GraphQL mutation contains only statically understood routine root fields.",
            )
        return (
            "mutate_remote",
            "github.graphql.remote-mutation",
            "The GraphQL operation can change GitHub-hosted state.",
        )
    if operation == "subscription":
        return (
            "mutate_remote",
            "github.graphql.remote-mutation",
            "The GraphQL operation can change or subscribe to GitHub-hosted state.",
        )
    return "read_remote", "github.graphql.proven-query", "The GraphQL document is a single static query."


def _mutation_is_high_impact(field: str) -> bool:
    return (
        field.startswith("delete")
        or field in _HIGH_IMPACT_MUTATIONS
        or _HIGH_IMPACT_MUTATION_NAME.search(field) is not None
    )


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
