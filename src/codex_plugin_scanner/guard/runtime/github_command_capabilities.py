"""Thin fail-closed bridge to the native GitHub CLI capability classifier.

The Rust command model owns every GitHub CLI classification. When the resident
cannot answer, the capability is ``unknown`` (review floor), never a Python
re-derivation.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, cast

from .github_capability_contract import GitHubCommandAssessment, GitHubCommandCapability, github_assessment

if TYPE_CHECKING:
    from ..native_github_cli import NativeGitHubCliClassification


_CACHE_LIMIT = 512
_NATIVE_CACHE: dict[tuple[str, ...], NativeGitHubCliClassification] = {}


def _native_classification(args: Sequence[str]) -> NativeGitHubCliClassification | None:
    """Return the native classification, memoizing only successful answers.

    The classification is a pure function of the arguments, and several callers
    classify the same command in one evaluation. Failures are never cached, so
    an unavailable resident still fails closed on every call.
    """

    from ..native_github_cli import github_cli_classify_native

    key = tuple(args)
    cached = _NATIVE_CACHE.get(key)
    if cached is not None:
        return cached
    native = github_cli_classify_native(key)
    if native is not None:
        if len(_NATIVE_CACHE) >= _CACHE_LIMIT:
            _NATIVE_CACHE.clear()
        _NATIVE_CACHE[key] = native
    return native


def classify_github_cli(args: Sequence[str]) -> GitHubCommandAssessment:
    """Return the native assessment for GitHub CLI arguments (without ``gh``)."""

    native = _native_classification(args)
    if native is None:
        return github_assessment(
            "unknown",
            "github.native.unavailable",
            "The native GitHub command classifier is unavailable, so the command is unverified.",
        )
    try:
        return GitHubCommandAssessment(
            # The contract's __post_init__ rejects any value outside the capability set.
            capability=cast(GitHubCommandCapability, native.capability),
            reason_code=native.reason_code,
            detail=native.detail,
            capabilities=tuple(cast(GitHubCommandCapability, item) for item in native.capabilities),
        )
    except ValueError:
        return github_assessment(
            "unknown",
            "github.native.malformed",
            "The native GitHub command classifier returned an unrecognized capability.",
        )


def static_markdown_pr_body_file_operand(args: Sequence[str]) -> str | None:
    """Return the native static Markdown body file operand, or ``None`` (not proven safe)."""

    native = _native_classification(args)
    return None if native is None else native.pr_body_file_operand


__all__ = ["classify_github_cli", "static_markdown_pr_body_file_operand"]
