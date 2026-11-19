"""Calls the native ``cloud-bundle-sync`` and ``cloud-event-sync`` commands.

The native runtime fetches, verifies and saves the workspace's signed
supply-chain and network protection bundles, and uploads the local Guard event
queue, the receipts and pain signals, under the machine's managed network policy. This
module only sends the request and raises its answer as the sync error classes
the CLI already reports.
"""

from __future__ import annotations

import dataclasses
import json
import os
from collections.abc import Mapping
from pathlib import Path

CLOUD_BUNDLE_SYNC_COMMAND = "cloud-bundle-sync"
CLOUD_BUNDLE_SYNC_FEATURE = "cloud-bundle-sync-v1"
CLOUD_EVENT_SYNC_COMMAND = "cloud-event-sync"
CLOUD_EVENT_SYNC_FEATURE = "cloud-event-sync-v1"
CLOUD_RECEIPT_UPLOAD_FEATURE = "cloud-receipt-upload-v1"
# One fetch may take five minutes with retries; a sync is an index, its
# partitions, the full bundle and the network bundle.
_TIMEOUT_SECONDS = 900.0
_OUTPUT_LIMIT_BYTES = 4 * 1024 * 1024
_UNAVAILABLE_MESSAGE = "Guard {subject} needs a newer Guard native runtime. Run: hol-guard update"


def cloud_bundle_sync(
    guard_home: Path,
    action: str,
    *,
    auth_context: Mapping[str, object] | None = None,
) -> object:
    """The native sync's result for ``action``, or its failure as the matching error."""

    return run_native_cloud_sync(
        CLOUD_BUNDLE_SYNC_COMMAND,
        CLOUD_BUNDLE_SYNC_FEATURE,
        guard_home,
        action,
        auth_context=auth_context,
        subject="bundle sync",
    )


def cloud_event_sync(
    guard_home: Path,
    action: str,
    *,
    auth_context: Mapping[str, object] | None = None,
    session: Mapping[str, object] | None = None,
) -> object:
    """The native result for ``action``: ``guard_events``, ``pain_signals`` or ``runtime_session``."""

    return run_native_cloud_sync(
        CLOUD_EVENT_SYNC_COMMAND,
        CLOUD_EVENT_SYNC_FEATURE,
        guard_home,
        action,
        auth_context=auth_context,
        subject="event sync",
        extra=None if session is None else {"session": dict(session)},
    )


def cloud_receipt_upload(
    guard_home: Path,
    upload: Mapping[str, object],
    *,
    auth_context: Mapping[str, object] | None = None,
) -> object:
    """Upload the local receipts natively and return what Guard Cloud answered."""

    return run_native_cloud_sync(
        CLOUD_EVENT_SYNC_COMMAND,
        CLOUD_RECEIPT_UPLOAD_FEATURE,
        guard_home,
        "receipts",
        auth_context=auth_context,
        subject="receipt sync",
        extra={"upload": dict(upload)},
    )


@dataclasses.dataclass(frozen=True)
class ReceiptUploadAnswer:
    """What Guard Cloud answered across the receipt batches of one sync."""

    now: str
    synced_at: object
    receipts: int
    receipts_stored: int
    advisories: list[dict[str, object]]
    policy_bundle_provided: bool
    policy_bundle_malformed: bool
    policy_bundle: dict[str, object] | None
    policy_bundle_sync_payload: dict[str, object] | None
    policy_bundle_delivery_provided: bool
    policy_bundle_delivery: object
    alert_preferences: dict[str, object] | None
    review_verification_keys: object
    receipt_cursor_rowid: int | None
    receipt_cursor_backfill: bool
    receipts_skipped: int = 0

    @classmethod
    def from_native(cls, answer: Mapping[str, object]) -> ReceiptUploadAnswer:
        bundle = answer.get("policy_bundle")
        bundle = bundle if isinstance(bundle, dict) else {}
        sync_payload = bundle.get("sync_payload")
        sync_payload = sync_payload if isinstance(sync_payload, dict) else None
        policy_bundle = None if sync_payload is None else sync_payload.get("policyBundle")
        advisories = answer.get("advisories")
        preferences = answer.get("alert_preferences")
        cursor = answer.get("receipt_cursor_rowid")
        now = answer.get("now")
        if not isinstance(now, str) or not now:
            raise RuntimeError("Guard Cloud sync returned an invalid response payload.")
        return cls(
            now=now,
            synced_at=answer.get("synced_at"),
            receipts=_count(answer.get("receipts")),
            receipts_stored=_count(answer.get("receipts_stored")),
            advisories=[item for item in advisories if isinstance(item, dict)] if isinstance(advisories, list) else [],
            policy_bundle_provided=bundle.get("provided") is True,
            policy_bundle_malformed=bundle.get("malformed") is True,
            policy_bundle=policy_bundle if isinstance(policy_bundle, dict) else None,
            policy_bundle_sync_payload=sync_payload,
            policy_bundle_delivery_provided=bundle.get("delivery_provided") is True,
            policy_bundle_delivery=bundle.get("delivery"),
            alert_preferences=preferences if isinstance(preferences, dict) else None,
            review_verification_keys=answer.get("review_verification_keys"),
            receipt_cursor_rowid=cursor if isinstance(cursor, int) and not isinstance(cursor, bool) else None,
            receipt_cursor_backfill=answer.get("receipt_cursor_backfill") is True,
            receipts_skipped=_count(answer.get("receipts_skipped")),
        )


def _count(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def run_native_cloud_sync(
    command: str,
    feature: str,
    guard_home: Path,
    action: str,
    *,
    auth_context: Mapping[str, object] | None,
    subject: str,
    extra: Mapping[str, object] | None = None,
) -> object:
    """Send one request to a native Cloud sync command and raise its failure."""

    from ..codex_hook_launch_runtime import run_isolated_hook_process
    from ..native_runtime import native_runtime_status

    status = native_runtime_status()
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or feature not in status.capabilities.features
    ):
        raise RuntimeError(_UNAVAILABLE_MESSAGE.format(subject=subject))
    runtime = status.identity.path
    request: dict[str, object] = {**(extra or {}), "action": action, "guardHome": str(guard_home)}
    supplied = auth_context if auth_context is not None else _test_auth_context()
    if supplied is not None:
        request["authContext"] = _json_auth_context(supplied)
    completed = run_isolated_hook_process(
        (str(runtime), command, "--stdin"),
        input_text=json.dumps(request, sort_keys=True, separators=(",", ":")),
        cwd=runtime.parent,
        environment=dict(os.environ),
        timeout_seconds=_TIMEOUT_SECONDS,
        output_limit=_OUTPUT_LIMIT_BYTES,
    )
    if (
        completed.returncode != 0
        or completed.timed_out
        or completed.output_limit_exceeded
        or completed.containment_failed
    ):
        raise RuntimeError(f"The Guard native runtime did not answer the {subject}.")
    try:
        response = json.loads(completed.stdout)
    except ValueError as error:
        raise RuntimeError(f"The Guard native runtime did not answer the {subject}.") from error
    if not isinstance(response, dict):
        raise RuntimeError(f"The Guard native runtime did not answer the {subject}.")
    if response.get("ok") is True:
        return response.get("result")
    raise _failure(response, subject)


def _failure(response: Mapping[str, object], subject: str) -> RuntimeError:
    from .runner import (
        GuardSyncAuthorizationExpiredError,
        GuardSyncEndpointUntrustedError,
        GuardSyncNotAvailableError,
        GuardSyncNotConfiguredError,
    )

    message = response.get("error")
    text = message if isinstance(message, str) and message else f"Guard {subject} failed."
    outcome = response.get("outcome")
    if outcome == "endpoint_untrusted":
        return GuardSyncEndpointUntrustedError(text)
    if outcome == "not_configured":
        return GuardSyncNotConfiguredError(text)
    if outcome == "auth_expired":
        return GuardSyncAuthorizationExpiredError(text)
    if outcome == "not_available":
        return GuardSyncNotAvailableError(text, retryable=response.get("retryable") is True)
    return RuntimeError(text)


def _json_auth_context(supplied: Mapping[str, object]) -> dict[str, object]:
    """A resolved sign-in carries its DPoP key as a dataclass; send it as a plain object."""
    return {
        key: dataclasses.asdict(value) if dataclasses.is_dataclass(value) and not isinstance(value, type) else value
        for key, value in supplied.items()
    }


def _test_auth_context() -> dict[str, object] | None:
    """The hermetic sign-in a test installed on the runner, under pytest only."""

    if not os.environ.get("PYTEST_CURRENT_TEST"):
        return None
    from . import runner

    override = getattr(runner, "_test_sync_auth_context_override", None)
    return dict(override) if isinstance(override, dict) else None
