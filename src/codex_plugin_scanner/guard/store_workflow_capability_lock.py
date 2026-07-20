"""Cross-process serialization for workflow-capability control transitions."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from functools import wraps
from typing import Concatenate, ParamSpec, Protocol, TypeVar, cast

_P = ParamSpec("_P")
_R = TypeVar("_R")
_T = TypeVar("_T")


class _WorkflowCapabilityLockBoundary(Protocol):
    def hold_workflow_capability_authority_lock(self) -> AbstractContextManager[None]: ...


def serialized_workflow_capability_authority(
    method: Callable[Concatenate[_T, _P], _R],
) -> Callable[Concatenate[_T, _P], _R]:
    @wraps(method)
    def wrapped(self: _T, *args: _P.args, **kwargs: _P.kwargs) -> _R:
        boundary = cast(_WorkflowCapabilityLockBoundary, cast(object, self))
        with boundary.hold_workflow_capability_authority_lock():
            return method(self, *args, **kwargs)

    return wrapped
