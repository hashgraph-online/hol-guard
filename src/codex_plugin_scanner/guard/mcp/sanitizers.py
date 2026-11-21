"""Default-deny sanitizers for guard-mcp.v1 MCP output.

The native runtime owns the allowlist: every field not in it is dropped, and
each value is length-capped, stripped of control characters, Unicode
normalized, and enum-validated before it reaches an MCP response. Fetch text
is also held to ``MAX_FETCH_TEXT_BYTES`` of UTF-8.
"""

from __future__ import annotations

from typing import Any

from .schemas import MAX_FETCH_TEXT_BYTES

_KIND = "mcp_output"
_FIELDS = frozenset(
    {
        "id",
        "title",
        "kind",
        "harness",
        "decision",
        "changedSinceLastApproval",
        "text",
        "truncated",
        "cliAvailable",
        "receiptCount",
        "inventoryCount",
        "cliVersion",
    }
)


class MCPOutputUnavailableError(RuntimeError):
    """The native runtime could not sanitize MCP output, so none is returned."""


def _bounded_value(key: str, value: object) -> object:
    # Text is cut well past each output limit before it crosses to the runtime,
    # so normalization still sees enough characters to fill the field. Enum
    # values are never normalized, and a cut this long stays an invalid name.
    if not isinstance(value, str):
        return value
    if key == "text":
        return value[: 8 * MAX_FETCH_TEXT_BYTES]
    return value[:4096]


def _bounded(raw: dict[str, object]) -> dict[str, object]:
    bounded = {
        key: _bounded_value(key, value)
        for key, value in raw.items()
        if key in _FIELDS and isinstance(value, (str, bool, int, float))
    }
    if isinstance(text := raw.get("text"), str) and len(text) > 8 * MAX_FETCH_TEXT_BYTES:
        bounded["truncated"] = True
    return bounded


def _sanitized(field: str, raw: object, answer_key: str) -> Any:
    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        answer = native_runner_authority(_KIND, {field: raw})
    except NativeRunnerAuthorityError as error:
        raise MCPOutputUnavailableError(_KIND) from error
    return answer.get(answer_key)


def _checked_object(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise MCPOutputUnavailableError(_KIND)
    return value


def sanitize_search_results(raw: list[dict[str, object]]) -> list[dict[str, object]]:
    results = _sanitized("search", [_bounded(item) for item in raw], "results")
    if not isinstance(results, list) or len(results) != len(raw):
        raise MCPOutputUnavailableError(_KIND)
    return [_checked_object(item) for item in results]


def sanitize_search_result(raw: dict[str, object]) -> dict[str, object]:
    return sanitize_search_results([raw])[0]


def sanitize_fetch_result(raw: dict[str, object]) -> dict[str, object]:
    return _checked_object(_sanitized("fetch", _bounded(raw), "result"))


def sanitize_status_result(raw: dict[str, object]) -> dict[str, object]:
    return _checked_object(_sanitized("status", _bounded(raw), "status"))
