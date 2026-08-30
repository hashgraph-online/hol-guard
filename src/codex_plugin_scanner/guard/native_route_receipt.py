"""Per-request provenance for native hook authority decisions."""

from __future__ import annotations

from contextvars import ContextVar
from typing import Literal, TypeAlias, TypeVar

NativeHookRoute: TypeAlias = Literal["native_resident", "native_oneshot", "native_fail_safe"]
HookDecisionRoute: TypeAlias = Literal[
    "native_resident",
    "native_oneshot",
    "native_fail_safe",
    "python_semantic",
]

_NATIVE_HOOK_ROUTE: ContextVar[HookDecisionRoute | None] = ContextVar(
    "hol_guard_native_hook_route",
    default=None,
)
_T = TypeVar("_T")


def reset_native_hook_route() -> None:
    _NATIVE_HOOK_ROUTE.set(None)


def record_native_hook_route(route: NativeHookRoute) -> None:
    if _NATIVE_HOOK_ROUTE.get() == "python_semantic":
        return
    _NATIVE_HOOK_ROUTE.set(route)


def record_native_hook_result(route: NativeHookRoute, result: _T) -> _T:
    """Attach route provenance while preserving the decision result's type."""
    record_native_hook_route(route)
    return result


def record_python_semantic_hook_route() -> None:
    _NATIVE_HOOK_ROUTE.set("python_semantic")


def native_hook_route() -> HookDecisionRoute | None:
    return _NATIVE_HOOK_ROUTE.get()


__all__ = [
    "native_hook_route",
    "record_native_hook_result",
    "record_native_hook_route",
    "record_python_semantic_hook_route",
    "reset_native_hook_route",
]
