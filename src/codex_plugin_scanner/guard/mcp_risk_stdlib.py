"""Finite CPython dependency leaves used by the reviewed MCP risk helpers.

An attrgetter is an immutable native callable. The re sentinel is a particular
mutable Python object; its identity, numeric payload, aliases and state all bind.
No leaf invokes a getter, conversion override, reduction hook or new descriptor.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from operator import attrgetter
from types import GetSetDescriptorType
from typing import cast

from .mcp_authority_binding import UnsupportedAuthorityValueError

State = tuple[object, ...]
Inspector = Callable[[object, frozenset[int], list[int]], State]
Digester = Callable[[object, list[int]], bytes]

_MISSING = object()
_RE_NAMESPACE: dict[str, object] = re.__dict__
_ZERO = _RE_NAMESPACE.get("_zero_sentinel", _MISSING)
_ZERO_TYPE = _RE_NAMESPACE.get("_ZeroSentinel", _MISSING)
_ZERO_DICT = (
    type.__getattribute__(cast(type[int], _ZERO_TYPE), "__dict__").get("__dict__") if type(_ZERO_TYPE) is type else None
)


def is_re_zero_sentinel(value: object) -> bool:
    return _ZERO is not _MISSING and value is _ZERO


def stdlib_leaf_state(
    value: object,
    parents: frozenset[int],
    budget: list[int],
    *,
    inspect_class: Inspector,
    plain_digest: Digester,
) -> State | None:
    if type(value) is attrgetter:
        # Exact C type: no instance dict, mutator or subclassing support.
        # Property/class binding separately notices replacement of the getter.
        return ("attrgetter", id(attrgetter), id(value))
    if not is_re_zero_sentinel(value):
        return None
    if (
        type(_ZERO_TYPE) is not type
        or type(value) is not _ZERO_TYPE
        or _RE_NAMESPACE.get("_zero_sentinel", _MISSING) is not _ZERO
        or _RE_NAMESPACE.get("_ZeroSentinel", _MISSING) is not _ZERO_TYPE
        or type(_ZERO_DICT) is not GetSetDescriptorType
    ):
        raise UnsupportedAuthorityValueError
    sentinel_type = cast(type[int], _ZERO_TYPE)
    mro = type.__getattribute__(sentinel_type, "__mro__")
    if len(mro) != 3 or mro[0] is not sentinel_type or mro[1] is not int or mro[2] is not object:
        raise UnsupportedAuthorityValueError
    stored = int.__int__(cast(int, value))
    if stored != 0:
        raise UnsupportedAuthorityValueError
    # Inspect class dispatch before instance data. The captured native descriptor
    # reads the original dict even if a callback replaces the class's __dict__.
    class_state = inspect_class(sentinel_type, parents, budget)
    instance_data = GetSetDescriptorType.__get__(cast(GetSetDescriptorType, _ZERO_DICT), value, sentinel_type)
    if type(instance_data) is not dict:
        raise UnsupportedAuthorityValueError
    return (
        "re_zero_sentinel",
        id(value),
        id(sentinel_type),
        stored,
        class_state,
        plain_digest(instance_data, budget),
    )
