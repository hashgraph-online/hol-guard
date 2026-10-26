"""Bind a call's store guard home for native context digests, then reset it."""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any, TypeVar, cast

_BoundFunction = TypeVar("_BoundFunction", bound=Callable[..., Any])


def binds_store_guard_home(function: _BoundFunction) -> _BoundFunction:
    """Bind the keyword ``store``'s guard home for the call and always reset it."""

    @functools.wraps(function)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        from .native_context import bound_context_digest_home

        with bound_context_digest_home(getattr(kwargs.get("store"), "guard_home", None)):
            return function(*args, **kwargs)

    return cast(_BoundFunction, wrapper)
