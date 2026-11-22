"""Native store snapshot of the values a custom Extension continuity commit is built from."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

ContinuityPayload = dict[str, object] | list[object] | None


class _NativeStore(Protocol):
    def _native_store_call(
        self, method: str, args: Mapping[str, object], *, busy_timeout_seconds: float | None = None
    ) -> Any: ...


class CustomExtensionContinuityRowUnreadableError(ValueError):
    """A continuity row holds text that is not JSON, so no plan may be built on it."""


@dataclass(frozen=True)
class CustomExtensionContinuityRows:
    """The local CLI authority revision and the continuity rows, from one snapshot.

    A missing row, or one that is neither an object nor an array, is ``None``,
    as ``get_sync_payload`` answers for it.
    """

    revision: int
    state: ContinuityPayload
    removals: ContinuityPayload

    @classmethod
    def from_native(cls, answer: object) -> CustomExtensionContinuityRows:
        if not isinstance(answer, dict):
            raise RuntimeError("native custom_extension_continuity_rows returned no answer")
        unreadable = answer.get("unreadable")
        if unreadable:
            roles = ",".join(str(role) for role in unreadable) if isinstance(unreadable, list) else "rows"
            raise CustomExtensionContinuityRowUnreadableError(f"custom_extension_continuity_unreadable:{roles}")
        revision = answer.get("revision")
        if type(revision) is not int or set(answer) != {"revision", "state_json", "removals_json", "unreadable"}:
            raise RuntimeError("native custom_extension_continuity_rows returned no answer")
        return cls(
            revision=revision,
            state=_payload(answer["state_json"]),
            removals=_payload(answer["removals_json"]),
        )


def _payload(text: object) -> ContinuityPayload:
    """Parse the stored text the native store handed back, keeping its key order."""

    if text is None:
        return None
    if not isinstance(text, str):
        raise RuntimeError("native custom_extension_continuity_rows returned no answer")
    try:
        value = json.loads(text)
    except ValueError as error:
        raise RuntimeError("native custom_extension_continuity_rows returned no answer") from error
    if not isinstance(value, (dict, list)):
        raise RuntimeError("native custom_extension_continuity_rows returned no answer")
    return value


class StoreCustomExtensionContinuityRowsMixin:
    """The continuity inputs, read by the native store in one snapshot."""

    def custom_extension_continuity_rows(self: _NativeStore) -> CustomExtensionContinuityRows:
        return CustomExtensionContinuityRows.from_native(
            self._native_store_call("custom_extension_continuity_rows", {})
        )


__all__ = [
    "CustomExtensionContinuityRowUnreadableError",
    "CustomExtensionContinuityRows",
    "StoreCustomExtensionContinuityRowsMixin",
]
