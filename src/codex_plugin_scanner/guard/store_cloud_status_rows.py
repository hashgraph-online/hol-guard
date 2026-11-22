"""Native store snapshot of the rows the Guard Cloud status views read."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol


class _NativeStore(Protocol):
    def _native_store_call(
        self, method: str, args: Mapping[str, object], *, busy_timeout_seconds: float | None = None
    ) -> Any: ...


def _object(value: object) -> dict[str, object]:
    return dict(value) if isinstance(value, dict) else {}


@dataclass(frozen=True)
class CloudStatusRows:
    """The Guard Cloud status rows; a missing row, or one that is not an object, is empty."""

    sync_summary: dict[str, object] = field(default_factory=dict)
    alert_preferences: dict[str, object] = field(default_factory=dict)
    policy_bundle_last_error: dict[str, object] = field(default_factory=dict)
    headless_app_sync_summary: dict[str, object] = field(default_factory=dict)
    guard_cloud_review_sync_state: dict[str, object] = field(default_factory=dict)
    receipt_sync_cursor: dict[str, object] = field(default_factory=dict)
    runtime_session_summary: dict[str, object] = field(default_factory=dict)
    guard_events_v1_summary: dict[str, object] = field(default_factory=dict)
    cloud_auth_expired: bool = False
    last_sync_at: str | None = None
    latest_cloud_sync: dict[str, object] = field(default_factory=dict)

    @classmethod
    def from_native(cls, answer: object) -> CloudStatusRows:
        rows = answer.get("rows") if isinstance(answer, dict) else None
        if not isinstance(answer, dict) or not isinstance(rows, dict):
            raise RuntimeError("native cloud_status_rows returned no answer")
        last_sync_at = answer.get("last_sync_at")
        return cls(
            sync_summary=_object(rows.get("sync_summary")),
            alert_preferences=_object(rows.get("alert_preferences")),
            policy_bundle_last_error=_object(rows.get("policy_bundle_last_error")),
            headless_app_sync_summary=_object(rows.get("headless_app_sync_summary")),
            guard_cloud_review_sync_state=_object(rows.get("guard_cloud_review_sync_state")),
            receipt_sync_cursor=_object(rows.get("receipt_sync_cursor")),
            runtime_session_summary=_object(rows.get("runtime_session_summary")),
            guard_events_v1_summary=_object(rows.get("guard_events_v1_summary")),
            cloud_auth_expired=answer.get("cloud_auth_expired") is True,
            last_sync_at=last_sync_at if isinstance(last_sync_at, str) else None,
            latest_cloud_sync=_object(answer.get("latest_cloud_sync")),
        )


class StoreCloudStatusRowsMixin:
    """The Guard Cloud status rows, read by the native store in one snapshot."""

    def cloud_status_rows(self: _NativeStore) -> CloudStatusRows:
        """Every Guard Cloud status row, whether one records an expired sign-in,
        the last sync time and the latest Guard Cloud sync."""

        return CloudStatusRows.from_native(self._native_store_call("cloud_status_rows", {}))


__all__ = ["CloudStatusRows", "StoreCloudStatusRowsMixin"]
