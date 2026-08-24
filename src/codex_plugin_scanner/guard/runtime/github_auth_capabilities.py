"""GitHub CLI authentication capability classification."""

from __future__ import annotations

from collections.abc import Sequence

from .github_capability_contract import GitHubCommandAssessment, github_assessment


def classify_github_auth(normalized: Sequence[str]) -> GitHubCommandAssessment | None:
    """Return the capability for one ``gh auth`` invocation, if classified."""

    if len(normalized) < 2 or normalized[0].lower() != "auth":
        return None
    auth_subcommand = normalized[1].lower()
    if auth_subcommand == "token" or (
        auth_subcommand == "status"
        and any(
            token == option or token.startswith(f"{option}=")
            for token in normalized[2:]
            for option in ("--show-token", "-t")
        )
    ):
        return github_assessment(
            "secret_remote",
            "github.command.auth-token-read",
            "The command reads a GitHub authentication token.",
        )
    if auth_subcommand == "status":
        return github_assessment(
            "read_local",
            "github.command.local-auth-read",
            "The command reads local CLI auth state.",
        )
    if auth_subcommand in {"login", "logout", "switch", "refresh", "setup-git"}:
        return github_assessment(
            "write_local",
            "github.command.local-auth-write",
            "The command changes local GitHub CLI authentication.",
        )
    return None
