"""Implementation definitions reexported by the StoreBase facade."""

from __future__ import annotations

from .store_base_definition import preserve_store_base_module as _preserve_module


@_preserve_module
def _chunks(values: Sequence[_ChunkT], size: int) -> Iterator[list[_ChunkT]]:
    for index in range(0, len(values), size):
        yield list(values[index : index + size])


# Bind dependencies after declarations so each owner can be imported first.
from .store_base import Iterator, Sequence, _ChunkT  # noqa: E402
