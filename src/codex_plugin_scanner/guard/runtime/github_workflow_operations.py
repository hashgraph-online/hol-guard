"""Strict operation records for workflow-authorizable GitHub maintenance."""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Final, Literal

from ..workflow_capabilities import canonical_framed_payload
from .command_model import CanonicalCommand
from .github_command_capabilities import classify_github_cli

GitHubWorkflowOperationKind = Literal[
    "resolve-review-thread",
    "unresolve-review-thread",
    "lock-issue",
    "unlock-issue",
    "pin-issue",
    "unpin-issue",
    "lock-pr",
    "unlock-pr",
    "mark-pr-ready",
    "mark-pr-draft",
]

_GRAPHQL_OPERATIONS: Final[dict[str, GitHubWorkflowOperationKind]] = {
    "resolveReviewThread": "resolve-review-thread",
    "unresolveReviewThread": "unresolve-review-thread",
}
_RESOURCE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@+-]{0,255}")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_GRAPHQL_ROOT = re.compile(r"[,{]\s*([A-Za-z][A-Za-z0-9]*)\s*\(")
_GRAPHQL_THREAD_DEFINITION = re.compile(r"\bmutation(?:\s+[A-Za-z][A-Za-z0-9]*)?\s*\(\s*\$threadId\s*:\s*ID!\s*\)")
_GRAPHQL_THREAD_INPUT = re.compile(r"\binput\s*:\s*\{\s*threadId\s*:\s*\$threadId\s*\}")
_RESOURCE_TYPES_BY_KIND: Final[dict[GitHubWorkflowOperationKind, str]] = {
    "resolve-review-thread": "github-review-thread",
    "unresolve-review-thread": "github-review-thread",
    "lock-issue": "github-issue",
    "unlock-issue": "github-issue",
    "pin-issue": "github-issue",
    "unpin-issue": "github-issue",
    "lock-pr": "github-pr",
    "unlock-pr": "github-pr",
    "mark-pr-ready": "github-pr",
    "mark-pr-draft": "github-pr",
}


@dataclass(frozen=True, slots=True)
class GitHubWorkflowOperation:
    kind: GitHubWorkflowOperationKind
    resource_type: str
    resource_id: str
    repository: str
    command_identity: str
    operation_digest: str

    def __post_init__(self) -> None:
        if self.resource_type != _RESOURCE_TYPES_BY_KIND.get(self.kind):
            raise ValueError("GitHub workflow operation resource type mismatch")
        if _RESOURCE_ID.fullmatch(self.resource_id) is None:
            raise ValueError("GitHub workflow operation resource is invalid")
        if _normalized_repository(self.repository) != self.repository:
            raise ValueError("GitHub workflow operation repository is invalid")
        expected = _operation_digest(
            command_identity=self.command_identity,
            kind=self.kind,
            repository=self.repository,
            resource_id=self.resource_id,
            resource_type=self.resource_type,
        )
        if not hmac.compare_digest(self.operation_digest, expected):
            raise ValueError("GitHub workflow operation digest mismatch")


def parse_github_workflow_operation(
    command: CanonicalCommand,
    *,
    repository: str | None = None,
    expected_executable: str = "gh",
) -> GitHubWorkflowOperation | None:
    """Return one exact eligible operation, or ``None`` for every ambiguity."""

    if (
        command.confidence != "exact"
        or len(command.segments) != 1
        or command.redirects
        or command.embedded_commands
        or command.wrapper_chain
        or command.normalized_text.rstrip().endswith("&")
    ):
        return None
    segment = command.segments[0]
    executable = segment.executable or ""
    if executable != expected_executable or segment.path_overridden or segment.wrapper_chain:
        return None
    normalized_repository = _normalized_repository(repository)
    operation = _graphql_operation(segment.arguments, repository=normalized_repository) or _cli_operation(
        segment.arguments,
        expected_repository=normalized_repository,
    )
    if operation is None:
        return None
    kind, resource_type, resource_id, repository = operation
    assessment = classify_github_cli(segment.arguments)
    if assessment.capabilities != ("maintain_remote",) or not assessment.workflow_authorizable:
        return None
    return GitHubWorkflowOperation(
        kind=kind,
        resource_type=resource_type,
        resource_id=resource_id,
        repository=repository,
        command_identity=command.security_identity,
        operation_digest=_operation_digest(
            command_identity=command.security_identity,
            kind=kind,
            repository=repository,
            resource_id=resource_id,
            resource_type=resource_type,
        ),
    )


def _graphql_operation(
    arguments: tuple[str, ...],
    *,
    repository: str | None,
) -> tuple[GitHubWorkflowOperationKind, str, str, str] | None:
    if arguments[:2] != ("api", "graphql"):
        return None
    if repository is None:
        return None
    fields = _field_values(arguments[2:])
    query, thread_id = fields.get("query"), fields.get("threadId")
    if (
        set(fields) != {"query", "threadId"}
        or query is None
        or thread_id is None
        or _RESOURCE_ID.fullmatch(thread_id) is None
    ):
        return None
    if (
        len(re.findall(r"\bmutation\b", query)) != 1
        or _GRAPHQL_THREAD_DEFINITION.fullmatch(query[: query.find("{")].strip()) is None
        or len(_GRAPHQL_THREAD_INPUT.findall(query)) != 1
        or query.count("$threadId") != 2
        or re.search(r"\$(?!threadId\b)", query) is not None
        or any(marker in query for marker in ("$(`", "${", "`", '"', "#"))
    ):
        return None
    matches = [name for name in _GRAPHQL_OPERATIONS for _match in re.finditer(rf"\b{name}\s*\(", query)]
    roots = tuple(match.group(1) for match in _GRAPHQL_ROOT.finditer(query))
    if len(matches) != 1 or roots != (matches[0],):
        return None
    kind = _GRAPHQL_OPERATIONS[matches[0]]
    return kind, "github-review-thread", thread_id, repository


def _cli_operation(
    arguments: tuple[str, ...],
    *,
    expected_repository: str | None,
) -> tuple[GitHubWorkflowOperationKind, str, str, str] | None:
    if len(arguments) < 5 or arguments[0] not in {"issue", "pr"}:
        return None
    group, action, resource_id = arguments[:3]
    allowed: dict[tuple[str, str], GitHubWorkflowOperationKind] = {
        ("issue", "lock"): "lock-issue",
        ("issue", "unlock"): "unlock-issue",
        ("issue", "pin"): "pin-issue",
        ("issue", "unpin"): "unpin-issue",
        ("pr", "lock"): "lock-pr",
        ("pr", "unlock"): "unlock-pr",
    }
    if (group, action) == ("pr", "ready"):
        return _pr_ready_operation(arguments, expected_repository=expected_repository)
    kind = allowed.get((group, action))
    if kind is not None and resource_id.isdecimal():
        tail = arguments[3:]
        if len(tail) != 2 or tail[0] not in {"--repo", "-R"}:
            return None
        repository = _normalized_repository(tail[1])
        if repository is None or (expected_repository is not None and repository != expected_repository):
            return None
        return kind, f"github-{group}", resource_id, repository
    return None


def _pr_ready_operation(
    arguments: tuple[str, ...],
    *,
    expected_repository: str | None,
) -> tuple[GitHubWorkflowOperationKind, str, str, str] | None:
    if len(arguments) not in {5, 6} or arguments[:2] != ("pr", "ready") or not arguments[2].isdecimal():
        return None
    pull_number = arguments[2]
    ready_args = arguments[3:-2]
    if arguments[-2] not in {"--repo", "-R"}:
        return None
    repository = _normalized_repository(arguments[-1])
    if repository is None or (expected_repository is not None and repository != expected_repository):
        return None
    if not ready_args:
        return "mark-pr-ready", "github-pr", pull_number, repository
    if ready_args != ("--undo",):
        return None
    return "mark-pr-draft", "github-pr", pull_number, repository


def _field_values(arguments: tuple[str, ...]) -> dict[str, str]:
    values: dict[str, str] = {}
    index = 0
    while index < len(arguments):
        flag = arguments[index]
        if flag not in {"-f", "--raw-field"} or index + 1 >= len(arguments):
            return {}
        field = arguments[index + 1]
        if "=" not in field:
            return {}
        key, value = field.split("=", 1)
        if not key or key in values or not value:
            return {}
        values[key] = value
        index += 2
    return values


def _normalized_repository(repository: str | None) -> str | None:
    if repository is None:
        return None
    normalized = repository.strip().lower()
    return normalized if _REPOSITORY.fullmatch(normalized) is not None else None


def _operation_digest(
    *,
    command_identity: str,
    kind: GitHubWorkflowOperationKind,
    repository: str,
    resource_id: str,
    resource_type: str,
) -> str:
    payload = {
        "command_identity": command_identity,
        "kind": kind,
        "repository": repository,
        "resource_id": resource_id,
        "resource_type": resource_type,
    }
    return hashlib.sha256(canonical_framed_payload("github-workflow-operation", payload)).hexdigest()


__all__ = ("GitHubWorkflowOperation", "GitHubWorkflowOperationKind", "parse_github_workflow_operation")
