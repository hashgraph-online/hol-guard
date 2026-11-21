"""Native store methods for the rows behind the local Cloud Review settings page."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol


class _NativeStore(Protocol):
    @property
    def guard_source(self) -> str: ...

    def _native_store_call(
        self, method: str, args: Mapping[str, object], *, busy_timeout_seconds: float | None = None
    ) -> Any: ...


def _binding_arg(binding: object) -> object:
    """A mapping as a plain dict; anything else unchanged, so the native store refuses it."""

    if isinstance(binding, Mapping):
        return dict(binding)
    return binding


class StoreCloudReviewSettingsMixin:
    """The Cloud Review sync view and the settings recovery row, kept by the native store."""

    def cloud_review_settings_state(self: _NativeStore, *, binding: Mapping[str, object] | None) -> dict[str, Any]:
        """The Cloud Review sync row for this store's source and the recovery error for ``binding``.

        ``sync`` is the stored row, or an empty object. ``sync_reconnect_required``
        says whether its last error asks for a new sign-in. ``recovery_error`` is
        the error an unfinished settings change left for the same binding.
        """

        answer = self._native_store_call(
            "cloud_review_settings_state",
            {"source": self.guard_source, "binding": _binding_arg(binding)},
        )
        sync = answer.get("sync") if isinstance(answer, dict) else None
        if not isinstance(sync, dict):
            raise RuntimeError("native Cloud Review settings state returned no answer")
        return {
            "sync": dict(sync),
            "sync_reconnect_required": answer.get("sync_reconnect_required") is True,
            "recovery_error": answer.get("recovery_error"),
        }

    def record_cloud_review_recovery(
        self: _NativeStore, *, binding: Mapping[str, object] | None, error: str | None, now: str
    ) -> None:
        """Record the error an unfinished settings change left; ``None`` records that it finished."""

        self._native_store_call(
            "record_cloud_review_recovery",
            {"binding": _binding_arg(binding), "error": error, "now": now},
        )
