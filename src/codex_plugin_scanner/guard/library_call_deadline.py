"""The caller's monotonic deadline for the current resident library request."""

from contextvars import ContextVar

LIBRARY_CALL_DEADLINE: ContextVar[float | None] = ContextVar("library_call_deadline", default=None)
