"""Resident bridge for the ``command_expression_validate`` op.

Rust owns the command-pattern dialect. Python used to compile the same globs
and regexes a second time with its own engine while a document was validated,
so an author could be told a pattern was fine and have enforcement refuse it
later. This module ships the expressions a document carries and reports the
first one the runtime's engine will not compile.

No pattern is compiled here, so an unavailable resident fails closed rather
than answering from a second dialect.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from uuid import uuid4

from .native_command_policy_decision import CONDITION_FIELDS
from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload

COMMAND_EXPRESSION_VALIDATION_FEATURE = "command-expression-validation-v1"
_OPERATION = "command_expression_validate"
_REQUEST_SCHEMA = "guard-command-expression-validation-request.v1"
_RESULT_SCHEMA = "guard-command-expression-validation-result.v1"
_TIMEOUT_SECONDS = 10.0
_MAX_REQUEST_BYTES = 6 * 1024 * 1024 - 64 * 1024
_MAX_EXPRESSIONS = 4096
UNAVAILABLE = "native_command_expression_validation_unavailable"
TOO_LARGE = "native_command_expression_validation_too_large"
_REFUSAL_PREFIX = "native_command_expression_validation_"


class CommandExpressionValidationUnavailableError(ValueError):
    """The document was not validated; no pattern was compiled in Python."""

    def __init__(self, code: str = UNAVAILABLE) -> None:
        super().__init__(code)
        self.code = code

    @property
    def refused(self) -> bool:
        """Whether the request was refused, rather than the runtime being absent."""

        return self.code != UNAVAILABLE


def _wire_expression(expression: Mapping[str, object]) -> dict[str, object]:
    conditions = expression.get("conditions")
    return {
        "combinator": expression.get("combinator"),
        "conditions": [
            {field: condition.get(field) for field in CONDITION_FIELDS}
            for condition in (conditions if isinstance(conditions, Sequence) else ())
            if isinstance(condition, Mapping)
        ],
    }


def _decoded(payload: object) -> tuple[int, str] | None:
    """``(index, code)`` for the first refused expression, or ``None``."""

    if not isinstance(payload, dict) or set(payload) != {"invalid"}:
        raise CommandExpressionValidationUnavailableError
    invalid = payload["invalid"]
    if invalid is None:
        return None
    if (
        not isinstance(invalid, dict)
        or set(invalid) != {"index", "code"}
        or not isinstance(invalid["index"], int)
        or isinstance(invalid["index"], bool)
        or invalid["index"] < 0
        or not isinstance(invalid["code"], str)
        or not invalid["code"]
    ):
        raise CommandExpressionValidationUnavailableError
    return invalid["index"], invalid["code"]


def _raise_refusal(response: dict[str, object] | None, request: dict[str, object]) -> None:
    """Re-raise the resident's own refusal code when the reply carries one."""

    if response is None:
        return
    try:
        digest = "sha256:" + _canonical_request_sha256(request)
    except (TypeError, ValueError):
        return
    if response.get("request_id") != request["request_id"] or response.get("request_sha256") != digest:
        return
    code = response.get("code")
    if response.get("status") == "error" and isinstance(code, str) and code.startswith(_REFUSAL_PREFIX):
        raise CommandExpressionValidationUnavailableError(code)


def native_command_expression_validation(
    expressions: Sequence[Mapping[str, object]],
    *,
    guard_home: Path | None = None,
) -> tuple[int, str] | None:
    """Compile every expression in the resident; raise when it cannot answer."""

    if len(expressions) > _MAX_EXPRESSIONS:
        raise CommandExpressionValidationUnavailableError(TOO_LARGE)
    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"command-expression-validation-{uuid4().hex}",
        "expressions": [_wire_expression(expression) for expression in expressions],
    }
    try:
        encoded = len(json.dumps(wire).encode("utf-8"))
    except (TypeError, ValueError):
        raise CommandExpressionValidationUnavailableError from None
    if encoded > _MAX_REQUEST_BYTES:
        raise CommandExpressionValidationUnavailableError(TOO_LARGE)
    home = Path(_resolve_digest_home(guard_home))
    if not ensure_resident_prerequisite(home):
        raise CommandExpressionValidationUnavailableError
    try:
        response = _resident_request(
            operation=_OPERATION,
            request=wire,
            guard_home=home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=COMMAND_EXPRESSION_VALIDATION_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError, OSError, RuntimeError):
        raise CommandExpressionValidationUnavailableError from None
    payload = _payload(response, wire, home)
    if payload is None:
        _raise_refusal(response, wire)
    return _decoded(payload)


__all__ = [
    "COMMAND_EXPRESSION_VALIDATION_FEATURE",
    "TOO_LARGE",
    "UNAVAILABLE",
    "CommandExpressionValidationUnavailableError",
    "native_command_expression_validation",
]
