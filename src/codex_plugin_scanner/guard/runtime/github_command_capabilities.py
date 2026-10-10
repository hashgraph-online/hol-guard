"""Thin fail-closed bridge to the native GitHub CLI capability classifier.

The Rust command model owns every GitHub CLI classification. When the resident
cannot answer, the capability is ``unknown`` (review floor), never a Python
re-derivation.
"""

from __future__ import annotations

from collections.abc import Sequence

from .github_capability_contract import GitHubCommandAssessment, github_assessment


def classify_github_cli(args: Sequence[str]) -> GitHubCommandAssessment:
    """Return the native assessment for GitHub CLI arguments (without ``gh``)."""

    from ..native_github_cli import github_cli_classify_native

    native = github_cli_classify_native(tuple(args))
    if native is None:
        return github_assessment(
            "unknown",
            "github.native.unavailable",
            "The native GitHub command classifier is unavailable, so the command is unverified.",
        )
    try:
        return GitHubCommandAssessment(
            capability=native.capability,  # type: ignore[arg-type]
            reason_code=native.reason_code,
            detail=native.detail,
            capabilities=tuple(native.capabilities),  # type: ignore[arg-type]
        )
    except ValueError:
        return github_assessment(
            "unknown",
            "github.native.malformed",
            "The native GitHub command classifier returned an unrecognized capability.",
        )


def static_markdown_pr_body_file_operand(args: Sequence[str]) -> str | None:
    """Return the native static Markdown body file operand, or ``None`` (not proven safe)."""

    from ..native_github_cli import github_cli_classify_native

    native = github_cli_classify_native(tuple(args))
    return None if native is None else native.pr_body_file_operand


__all__ = ["classify_github_cli", "static_markdown_pr_body_file_operand"]
