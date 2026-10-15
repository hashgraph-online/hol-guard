"""Memory pattern fingerprints and lookup candidates from the native runtime.

The resident's ``memory_pattern`` kind groups repeated human decisions on the
same behavior (``npm install lodash`` and ``npm i lodash`` share one
fingerprint) and names the remembered-decision ids a policy lookup probes after
the direct artifact: the shell-domain exact-command ids, then
``memory:<harness>:<kind>:<fingerprint>``. This module only projects the
request fields and checks the result's shape; it never rebuilds a fingerprint.
"""

from __future__ import annotations

from pathlib import Path
from typing import NamedTuple

from .native_context import _resolve_digest_home, native_context_digest, native_context_failure_reason

_KINDS = frozenset(
    {
        "command_pattern",
        "package_install_pattern",
        "mcp_tool_pattern",
        "file_read_pattern",
        "generic_artifact_pattern",
    }
)
_EXACT_ID_PREFIXES = ("memory:exact-shell-command:", "memory:exact-command:")


class NativeMemoryPatternError(RuntimeError):
    """The native runtime did not return a usable memory-pattern verdict."""


class MemoryPattern(NamedTuple):
    fingerprint: str
    kind: str
    components: dict[str, str]


class MemoryPatternVerdict(NamedTuple):
    pattern: MemoryPattern | None
    exact_artifact_ids: tuple[str, ...]
    memory_artifact_id: str | None


def _text_or_none(value: object) -> str | None:
    return value if isinstance(value, str) else None


def memory_pattern_verdict(
    *,
    command: str | None,
    artifact_type: str | None,
    artifact_id: str | None,
    artifact_name: str | None,
    harness: str | None,
    guard_home: Path | None = None,
) -> MemoryPatternVerdict:
    """Ask the resident for the decision's fingerprint and lookup candidates.

    ``guard_home`` is the querying store's home; without one the bound or
    default home answers. Raises :class:`NativeMemoryPatternError` when the
    resident is unavailable or its answer is malformed; callers decide whether
    that fails closed.
    """

    result = native_context_digest(
        "memory_pattern",
        {
            "command": _text_or_none(command),
            "artifact_type": _text_or_none(artifact_type),
            "artifact_id": _text_or_none(artifact_id),
            "artifact_name": _text_or_none(artifact_name),
            "harness": _text_or_none(harness),
        },
        guard_home=_resolve_digest_home(guard_home),
    )
    if not isinstance(result, dict) or result.get("status") != "ok":
        raise NativeMemoryPatternError(f"native_memory_pattern_unavailable: {_failure_reason(result)}")
    verdict = _parse_verdict(result.get("memory_pattern"))
    if verdict is None:
        raise NativeMemoryPatternError("native_memory_pattern_malformed")
    return verdict


def _failure_reason(result: object) -> str:
    """The transport's reason for no answer, or the resident's error code."""

    if result is None:
        return native_context_failure_reason() or "native_context_unavailable"
    if isinstance(result, dict) and isinstance(result.get("code"), str):
        return result["code"]
    return "native_memory_pattern_status_invalid"


def _parse_verdict(value: object) -> MemoryPatternVerdict | None:
    if not isinstance(value, dict) or set(value) != {"pattern", "exact_artifact_ids", "memory_artifact_id"}:
        return None
    exact_ids = value["exact_artifact_ids"]
    if (
        not isinstance(exact_ids, list)
        or len(exact_ids) > len(_EXACT_ID_PREFIXES)
        or not all(isinstance(item, str) and item.startswith(_EXACT_ID_PREFIXES) for item in exact_ids)
        or len(set(exact_ids)) != len(exact_ids)
    ):
        return None
    memory_id = value["memory_artifact_id"]
    if memory_id is not None and not (isinstance(memory_id, str) and memory_id.startswith("memory:")):
        return None
    raw_pattern = value["pattern"]
    pattern = None
    if raw_pattern is not None:
        pattern = _parse_pattern(raw_pattern)
        if pattern is None:
            return None
    elif memory_id is not None:
        return None
    return MemoryPatternVerdict(pattern, tuple(exact_ids), memory_id)


def _parse_pattern(value: object) -> MemoryPattern | None:
    if not isinstance(value, dict) or set(value) != {"fingerprint", "kind", "components"}:
        return None
    fingerprint = value["fingerprint"]
    kind = value["kind"]
    raw_components = value["components"]
    if not isinstance(kind, str) or kind not in _KINDS:
        return None
    # A pattern whose dimensions are all empty is the bare kind.
    if not isinstance(fingerprint, str) or fingerprint.split(":", 1)[0] != kind:
        return None
    if not isinstance(raw_components, list):
        return None
    components: dict[str, str] = {}
    for pair in raw_components:
        if (
            not isinstance(pair, list)
            or len(pair) != 2
            or not all(isinstance(item, str) for item in pair)
            or pair[0] in components
        ):
            return None
        components[pair[0]] = pair[1]
    return MemoryPattern(fingerprint, kind, components)


__all__ = ["MemoryPattern", "MemoryPatternVerdict", "NativeMemoryPatternError", "memory_pattern_verdict"]
