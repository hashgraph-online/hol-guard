"""Build one receipt's cloud sync payload through the batch builder the upload uses."""

from __future__ import annotations

from datetime import datetime, timezone

from codex_plugin_scanner.guard.runtime.cloud_request_native import cloud_sync_receipt_payloads


def cloud_sync_receipt_payload(
    receipt: dict[str, object],
    *,
    device_id: str,
    device_name: str,
    redaction_level: str = "full",
) -> dict[str, object]:
    return cloud_sync_receipt_payloads(
        [receipt],
        device_id=device_id,
        device_name=device_name,
        redaction_level=redaction_level,
        now=datetime.now(timezone.utc).isoformat(),
    )[0]
