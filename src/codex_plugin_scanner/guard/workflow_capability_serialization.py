"""Bound malformed contract traversal before recursive dataclass encoding."""

from collections.abc import Iterable
from dataclasses import fields, is_dataclass
from typing import cast


def validate_serializable_contract(value: object, *, ancestors: frozenset[int] = frozenset(), depth: int = 0) -> None:
    if depth > 64:
        raise ValueError("workflow contract exceeds serialization depth")
    if type(value) in (str, int, float, bool, type(None)):
        return
    identity = id(value)
    if identity in ancestors:
        raise ValueError("workflow contract contains a cycle")
    ancestors = ancestors | {identity}
    children: Iterable[object]
    if is_dataclass(value) and not isinstance(value, type):
        children = (cast(object, getattr(value, field.name)) for field in fields(value))
    elif type(value) in (list, tuple):
        children = iter(cast(list[object] | tuple[object, ...], value))
    elif type(value) is dict:
        children = iter(cast(dict[object, object], value).values())
    else:
        raise TypeError("workflow contract contains a non-JSON value")
    for child in children:
        validate_serializable_contract(child, ancestors=ancestors, depth=depth + 1)
