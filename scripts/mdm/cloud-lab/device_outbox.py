from __future__ import annotations

import hashlib

from device_support import (
    MAX_DEAD_LETTERS,
    MAX_OUTBOX_ITEMS,
    PERMANENT_STATUSES,
    PROVEN_DUPLICATE_CODES,
    TRANSIENT_STATUSES,
    response_error_code,
)
from lab_common import json_bytes

from codex_plugin_scanner.guard.mdm.cloud_control import ContractError, iso


class DeviceOutboxMixin:
    """Durable FIFO evidence delivery and bounded dead-letter handling."""

    def _queue(self, channel: str, payload: dict[str, object]) -> None:
        queue = self.outbox[channel]
        if not isinstance(queue, list):
            raise ContractError("device_outbox_invalid")
        if len(queue) >= MAX_OUTBOX_ITEMS:
            raise ContractError("device_outbox_full")
        queue.append(payload)
        self._save("outbox", self.outbox)

    def _dead_letter(
        self,
        channel: str,
        payload: object,
        status: int,
        error_code: str,
    ) -> None:
        dead_letters = self.outbox["deadLetters"]
        if not isinstance(dead_letters, list):
            raise ContractError("device_outbox_invalid")
        dead_letters.append(
            {
                "channel": channel,
                "status": status,
                "error": error_code,
                "payloadHash": hashlib.sha256(json_bytes(payload)).hexdigest(),
                "observedAt": iso(self._now()),
            }
        )
        del dead_letters[:-MAX_DEAD_LETTERS]

    def flush(self) -> None:
        if self.faults.get("holdOutbox") is True:
            return
        channels = (
            ("acks", "/runtime/v1/acknowledgements"),
            ("health", "/runtime/v1/health"),
            ("results", "/runtime/v1/remediation-results"),
        )
        for channel, path in channels:
            queue = self.outbox[channel]
            if not isinstance(queue, list):
                raise ContractError("device_outbox_invalid")
            remaining: list[object] = []
            blocked = False
            for item in queue:
                if blocked:
                    remaining.append(item)
                    continue
                status, _, response = self.request("POST", path, item)
                error_code = response_error_code(response)
                if status in {200, 202, 204}:
                    continue
                if status == 409 and error_code in PROVEN_DUPLICATE_CODES:
                    continue
                if status in PERMANENT_STATUSES:
                    self._dead_letter(channel, item, status, error_code)
                    continue
                remaining.append(item)
                blocked = True
                if status not in TRANSIENT_STATUSES and status not in {401, 403, 409}:
                    self.meta["lastSyncError"] = error_code
            self.outbox[channel] = remaining
        self._save("outbox", self.outbox)
        self._save("meta", self.meta)
