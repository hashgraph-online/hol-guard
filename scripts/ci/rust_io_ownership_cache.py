"""Reuse immutable analysis inputs only for the lifetime of one ownership check."""

from __future__ import annotations

import ast
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
from pathlib import Path
from typing import ParamSpec, TypeVar, cast

P = ParamSpec("P")
T = TypeVar("T")
_VALUES: ContextVar[dict[tuple[object, ...], object] | None] = ContextVar("ownership_analysis_cache", default=None)
_MISSING = object()


@contextmanager
def analysis_cache() -> Iterator[None]:
    """Keep one read-only analysis pass fast, never reuse results across passes.

    Nested checks own separate caches. Exceptions also discard the cache; a
    subsequent validation must reread source and recompute every decision.
    """
    values: dict[tuple[object, ...], object] = {}
    token = _VALUES.set(values)
    try:
        yield
    finally:
        values.clear()
        _VALUES.reset(token)


def cached(function: Callable[P, T]) -> Callable[P, T]:
    """Memoize pure lookups inside an explicit analysis scope, including misses."""

    @wraps(function)
    def call(*args: P.args, **kwargs: P.kwargs) -> T:
        values = _VALUES.get()
        if values is None:
            return function(*args, **kwargs)
        key = (function, args, tuple(sorted(kwargs.items())))
        try:
            hash(key)
        except TypeError:
            # External record implementations need not be hashable.
            return function(*args, **kwargs)
        result = values.get(key, _MISSING)
        if result is _MISSING:
            result = function(*args, **kwargs)
            values[key] = result
        return cast(T, result)

    return call


@cached
def parsed_module(path: Path) -> ast.Module:
    """Share the same AST between the inventory and call-graph resolver."""
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise RuntimeError(f"could not inspect {path}") from error
    return ast.parse(source, filename=str(path))
