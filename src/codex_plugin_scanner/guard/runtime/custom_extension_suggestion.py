"""Decide which observed CLIs are worth offering as custom extensions.

The native runtime ranks each tool, classifies its path and says whether its
name is a common utility; Python only asks. When the resident cannot answer,
a tool is ranked hidden, its path class is ``unknown``, and it is treated as
a common utility so no identity is derived for it. That last failure is
reported to ``track_local_cli_identity_failures`` so grant callers fail closed.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TypedDict

from ..native_context import _resolve_digest_home, native_context_digest
from ..native_local_cli_identity import record_local_cli_identity_failure

_VERDICT_KEYS = frozenset({"score", "suggestable", "path_class", "common_utility", "reject_message"})
# The native request carries observed counts as signed 64-bit integers.
_COUNT_LIMIT = 2**62
NATIVE_UNAVAILABLE_MESSAGE = "Guard could not check this tool right now. Try again in a moment."


class SuggestionTool(TypedDict):
    name: str
    kind: str
    source_path: str | None
    observed_count: int
    help_status: str | None
    surface: str


class SuggestionVerdict(TypedDict):
    score: int
    suggestable: bool
    path_class: str
    common_utility: bool
    reject_message: str


def suggestion_tool(
    *,
    name: str,
    kind: str = "executable",
    source_path: str | None = None,
    observed_count: int = 0,
    help_status: str | None = None,
    surface: str = "cli",
) -> SuggestionTool:
    return {
        "name": name,
        "kind": kind,
        "source_path": source_path,
        "observed_count": max(-_COUNT_LIMIT, min(observed_count, _COUNT_LIMIT)),
        "help_status": help_status,
        "surface": surface,
    }


def suggestion_verdicts(tools: Sequence[SuggestionTool]) -> list[SuggestionVerdict] | None:
    """Return one verdict per tool, in order, or ``None`` when the resident cannot answer."""

    if not tools:
        return []
    result = native_context_digest(
        "custom_extension_suggestion",
        {"tools": list(tools)},
        guard_home=_resolve_digest_home(None),
    )
    if not isinstance(result, dict) or result.get("status") != "ok":
        return None
    verdicts = result.get("custom_extension_suggestion")
    if not isinstance(verdicts, list) or len(verdicts) != len(tools):
        return None
    if not all(_valid_verdict(verdict) for verdict in verdicts):
        return None
    return verdicts


def common_utility_verdict(name: str) -> SuggestionVerdict | None:
    """Return the native verdict for a bare tool name, or ``None`` when the resident cannot answer."""

    return _single(suggestion_tool(name=name))


def is_common_shell_utility(name: str) -> bool:
    verdict = common_utility_verdict(name)
    if verdict is None:
        record_local_cli_identity_failure("native_custom_extension_suggestion_unavailable")
        return True
    return verdict["common_utility"]


def observation_path_class(source_path: str | None) -> str:
    """Return a path class token that can be stored without the raw path."""

    if not source_path:
        return "unknown"
    verdict = _single(suggestion_tool(name="", source_path=source_path))
    return "unknown" if verdict is None else verdict["path_class"]


def common_utility_reject_message(name: str) -> str:
    """Return operator-facing copy when a pasted command is a common tool."""

    verdict = common_utility_verdict(name)
    if verdict is None:
        return NATIVE_UNAVAILABLE_MESSAGE
    return verdict["reject_message"]


def _single(tool: SuggestionTool) -> SuggestionVerdict | None:
    verdicts = suggestion_verdicts([tool])
    return None if verdicts is None else verdicts[0]


def _valid_verdict(verdict: object) -> bool:
    return (
        isinstance(verdict, dict)
        and set(verdict) == _VERDICT_KEYS
        and type(verdict["score"]) is int
        and verdict["score"] >= 0
        and isinstance(verdict["suggestable"], bool)
        and isinstance(verdict["path_class"], str)
        and isinstance(verdict["common_utility"], bool)
        and isinstance(verdict["reject_message"], str)
    )
