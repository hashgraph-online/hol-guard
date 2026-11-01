"""Build one receipt's cloud sync payload through the batch builder the runner ships."""

from __future__ import annotations

from codex_plugin_scanner.guard.runtime.runner import _cloud_sync_receipts_payload


def cloud_sync_receipt_payload(
    receipt: dict[str, object],
    *,
    device_id: str,
    device_name: str,
    redaction_level: str = "full",
) -> dict[str, object]:
    return _cloud_sync_receipts_payload(
        [receipt], device_id=device_id, device_name=device_name, redaction_level=redaction_level
    )[0]
