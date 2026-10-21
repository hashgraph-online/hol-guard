"""Bind reviewed literal vectors with the native grammar the detectors use."""

from __future__ import annotations

from ..native_reviewed_invocation_bindings import (
    ReviewedInvocationBindingsUnavailableError,
    ReviewedOperation,
    ReviewedRow,
    native_reviewed_invocation_bindings,
)
from .errors import BuilderError
from .models import Discovery, Operation

_MESSAGES = {
    "safe_variant_conflict": "A safe invocation overlaps a native explicitly blocked operation.",
    "safe_variant_option": "Safe invocations must use explicitly discovered option names and arity.",
    "safe_variant_scope": "Native parsing assigns this safe invocation to another or ambiguous operation.",
}


def _operation(operation: Operation) -> ReviewedOperation:
    return (
        operation.operation_id,
        operation.path,
        tuple(operation.flags),
        tuple(operation.options_with_values),
    )


def validate_native_bindings(
    discovery: Discovery,
    rows: tuple[tuple[Operation, tuple[str, ...]], ...],
    blocked_ids: frozenset[str],
) -> None:
    if not rows:
        return
    reviewed: tuple[ReviewedRow, ...] = tuple((owner.operation_id, argv) for owner, argv in rows)
    try:
        refusal = native_reviewed_invocation_bindings(
            discovery.metadata.executable,
            tuple(_operation(operation) for operation in discovery.operations),
            reviewed,
            tuple(blocked_ids),
        )
    except ReviewedInvocationBindingsUnavailableError as error:
        raise BuilderError(
            "native_unavailable", "Native command validation is unavailable; repair the runtime."
        ) from error
    if refusal is None:
        return
    _index, code = refusal
    message = _MESSAGES.get(code)
    if message is None:
        raise BuilderError("native_unavailable", "Native command validation is unavailable; repair the runtime.")
    raise BuilderError(code, message)
