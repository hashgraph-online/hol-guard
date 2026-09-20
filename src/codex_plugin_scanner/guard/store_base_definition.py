"""Preserve the public module identity of partitioned StoreBase definitions."""

from __future__ import annotations

from typing import Protocol, TypeVar


class _ModuleIdentity(Protocol):
    __module__: str


_DefinitionT = TypeVar("_DefinitionT", bound=_ModuleIdentity)


def preserve_store_base_module(definition: _DefinitionT) -> _DefinitionT:
    """Keep the original object and its facade-based import and pickle identity."""
    definition.__module__ = "codex_plugin_scanner.guard.store_base"
    return definition
