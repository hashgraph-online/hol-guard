"""Owned catalog values and a digest cache invalidated by every replacement.

JSON storage prevents a caller from mutating a nested schema through an alias.
The proxy can replace individual definitions or an entire catalog generation;
both invalidate the complete-catalog digest, including changes to sibling tools.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator, Mapping, MutableMapping


class ToolCatalog(MutableMapping[str, dict[str, object]]):
    """A catalog whose published definition values cannot change in place."""

    def __init__(self, definitions: Mapping[str, Mapping[str, object]] | None = None) -> None:
        self._definitions: dict[str, str] = {}
        self._fingerprint: tuple[str, str] | None = None
        if definitions is not None:
            for name, definition in definitions.items():
                self[name] = dict(definition)

    def __getitem__(self, name: str) -> dict[str, object]:
        # Only the selected definition is decoded on the ordinary call path.
        return json.loads(self._definitions[name])

    def __setitem__(self, name: str, definition: dict[str, object]) -> None:
        encoded = json.dumps(definition, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        self._definitions[name] = encoded
        self._fingerprint = None

    def __delitem__(self, name: str) -> None:
        del self._definitions[name]
        self._fingerprint = None

    def __iter__(self) -> Iterator[str]:
        return iter(self._definitions)

    def __len__(self) -> int:
        return len(self._definitions)

    def fingerprint(self, state: str, compute: Callable[[], str]) -> str:
        cached = self._fingerprint
        if cached is None or cached[0] != state:
            cached = (state, compute())
            self._fingerprint = cached
        return cached[1]
