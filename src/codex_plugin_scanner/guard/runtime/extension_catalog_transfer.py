"""Strict negotiated v2 transfer; only verified completion reports success."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .extension_catalog_pages import PreparedCatalogView, native_call


def catalog_sync_plan(
    *,
    view: PreparedCatalogView,
    runtime_sync_url: str,
    runtime_response: dict[str, object],
    session_payload: dict[str, object],
) -> dict[str, Any]:
    """Obtain the native-validated destination and limits for this view."""
    return native_call(
        view.guard_home,
        action="sync_plan",
        token=view.token,
        runtime_sync_url=runtime_sync_url,
        runtime_response=runtime_response,
        session_payload=session_payload,
    )


def _sync_catalog_view(
    *,
    runtime_sync_url: str,
    runtime_response: dict[str, object],
    session_payload: dict[str, object],
    view: PreparedCatalogView,
    send: Callable[[str, bytes], object],
) -> dict[str, object]:
    """Send one immutable observed view with replay-stable bounded requests.

    Transport may retry identical request bytes. No complete is sent after a
    page/transport/verification failure. Each fresh attempt starts at begin;
    receiver idempotency handles lost acknowledgements and concurrent attempts.

    The native runtime judges the handshake signal, the advertised limits, the
    upload origin and every acknowledgement; this module only moves bytes.
    """
    plan = catalog_sync_plan(
        view=view,
        runtime_sync_url=runtime_sync_url,
        runtime_response=runtime_response,
        session_payload=session_payload,
    )
    expected = plan["expected_digest"]
    if plan["catalog_known"]:
        return {"extension_catalog_sync_status": "already_known", "extension_catalog_sync_digest": expected}
    url = plan["upload_url"]

    # Manifest binds enforcement identity and observation time independently of
    # content-only discovery identity. A new observation cannot reuse an old key.
    def request(operation: str, ordinal: int | None = None) -> None:
        native_call(
            view.guard_home,
            action="sync_ack",
            token=view.token,
            response=send(url, view.request_bytes(operation, ordinal)),
            completing=operation == "complete",
        )

    request("begin")
    for ordinal in range(plan["page_count"]):
        request("page", ordinal)
    request("complete")
    return {"extension_catalog_sync_status": "uploaded", "extension_catalog_sync_digest": expected}


def sync_catalog_view(*, view: PreparedCatalogView, **kwargs) -> dict[str, object]:
    with view.pinned():
        return _sync_catalog_view(view=view, **kwargs)
