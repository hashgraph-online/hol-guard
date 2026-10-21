"""Test-only entry point for the resident's GitHub CLI capability classifier.

The Rust command model owns every GitHub CLI classification
(``rust/crates/guard-command/src/github_command_capabilities.rs``). Production
code calls the resident through
``codex_plugin_scanner.guard.native_github_cli``; nothing in ``src/`` turns that
classification into a :class:`GitHubCommandAssessment` any more.

These helpers exist so the capability suites can keep asserting the assessment
shape without a production module whose only callers are tests. When the
resident cannot answer, the capability is ``unknown`` (the review floor), never
a Python re-derivation.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, cast

from codex_plugin_scanner.guard.runtime.github_capability_contract import (
    GitHubCommandAssessment,
    GitHubCommandCapability,
    github_assessment,
)

if TYPE_CHECKING:
    from codex_plugin_scanner.guard.native_github_cli import NativeGitHubCliClassification

_ASSESSMENT_CACHE_LIMIT = 512
_ASSESSMENT_CACHE: dict[tuple[str, ...], GitHubCommandAssessment] = {}


def reset_github_capability_cache() -> None:
    """Drop every memoized assessment so a test can re-observe the resident."""

    _ASSESSMENT_CACHE.clear()


def _classification(args: tuple[str, ...]) -> NativeGitHubCliClassification | None:
    """Return the resident's classification for ``args``, or ``None``."""

    # Resolve the classifier per call. The capability suites monkeypatch
    # `native_github_cli.github_cli_classify_native`, and the offline stub
    # replaces the whole module in `sys.modules`; an import-time binding would
    # see neither.
    from codex_plugin_scanner.guard.native_github_cli import github_cli_classify_native

    return github_cli_classify_native(args)


def github_cli_assessment(args: Sequence[str]) -> GitHubCommandAssessment:
    """Return the native assessment for GitHub CLI arguments (without ``gh``).

    Only an assessment the contract accepted is memoized. An unavailable
    resident and a malformed classification both fail closed to ``unknown`` on
    every call, so a later good answer for the same arguments is still seen.
    """

    key = tuple(args)
    cached = _ASSESSMENT_CACHE.get(key)
    if cached is not None:
        return cached
    native = _classification(key)
    if native is None:
        return github_assessment(
            "unknown",
            "github.native.unavailable",
            "The native GitHub command classifier is unavailable, so the command is unverified.",
        )
    try:
        assessment = GitHubCommandAssessment(
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
    if len(_ASSESSMENT_CACHE) >= _ASSESSMENT_CACHE_LIMIT:
        _ASSESSMENT_CACHE.clear()
    _ASSESSMENT_CACHE[key] = assessment
    return assessment


__all__ = ["github_cli_assessment", "reset_github_capability_cache"]
