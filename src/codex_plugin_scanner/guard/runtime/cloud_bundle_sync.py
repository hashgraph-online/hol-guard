"""Calls the native ``cloud-bundle-sync`` and ``cloud-event-sync`` commands.

The native runtime fetches, verifies and saves the workspace's signed
supply-chain and network protection bundles, and uploads the local Guard event
queue, the receipts and pain signals, under the machine's managed network policy. This
module only sends the request and raises its answer as the sync error classes
the CLI already reports.
"""

from __future__ import annotations

import dataclasses
import http.client
import io
import json
import os
import tempfile
import urllib.error
from collections.abc import Mapping
from email.message import Message
from pathlib import Path
from typing import NoReturn

CLOUD_BUNDLE_SYNC_COMMAND = "cloud-bundle-sync"
CLOUD_BUNDLE_SYNC_FEATURE = "cloud-bundle-sync-v1"
CLOUD_EVENT_SYNC_COMMAND = "cloud-event-sync"
CLOUD_EVENT_SYNC_FEATURE = "cloud-event-sync-v1"
CLOUD_RECEIPT_UPLOAD_FEATURE = "cloud-receipt-upload-v1"
CLOUD_JSON_REQUEST_FEATURE = "cloud-json-request-v4"
CLOUD_OAUTH_REFRESH_FEATURE = "cloud-oauth-refresh-v1"
CLOUD_OAUTH_REFRESH_CIRCUIT_FEATURE = "cloud-oauth-refresh-circuit-v1"
# One fetch may take five minutes with retries; a sync is an index, its
# partitions, the full bundle and the network bundle.
_TIMEOUT_SECONDS = 900.0
_OUTPUT_LIMIT_BYTES = 4 * 1024 * 1024
# Bodies above this go to the native command in a private file rather than on
# its stdin, which is capped at 6 MiB.
_INLINE_BODY_LIMIT_BYTES = 256 * 1024
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


def cloud_oauth_refresh(call: Mapping[str, object]) -> dict[str, object]:
    """Exchange a Guard OAuth refresh grant natively and return how it ended.

    ``call`` carries ``tokenEndpoint``, ``clientId``, ``refreshToken`` and
    ``dpopKey`` (``privateKeyPem``, ``publicJwk``, ``algorithm``). The answer's
    ``outcome`` is ``refreshed`` (with the token response as ``payload``),
    ``rate_limited`` (with ``retryAfterSeconds``), ``dead_grant``,
    ``rejected``, ``unusable``, ``unreachable`` or ``failed`` (with a
    ``reason``). The exchange reads no Guard home.
    """

    from ..config import resolve_guard_home

    answer = run_native_cloud_sync(
        CLOUD_EVENT_SYNC_COMMAND,
        CLOUD_OAUTH_REFRESH_FEATURE,
        resolve_guard_home(),
        "oauth_refresh",
        auth_context=None,
        subject="Guard OAuth token refresh",
        extra={"oauthRefresh": dict(call)},
    )
    if not isinstance(answer, dict) or not isinstance(answer.get("outcome"), str):
        raise RuntimeError("The Guard native runtime did not answer the Guard OAuth token refresh.")
    return answer


def cloud_oauth_refresh_circuit(guard_home: Path, call: Mapping[str, object]) -> dict[str, object]:
    """Read or record the Guard OAuth refresh circuit natively.

    ``call`` names an ``op``: ``check``, ``record_dead_grant``,
    ``record_rate_limit``, ``notice_sent`` or ``clear``, with the
    ``refreshToken``, ``failureKind``, ``retryAfterSeconds`` or
    ``fingerprint`` it needs. The circuit is local state; no request leaves
    the machine.
    """

    answer = run_native_cloud_sync(
        CLOUD_EVENT_SYNC_COMMAND,
        CLOUD_OAUTH_REFRESH_CIRCUIT_FEATURE,
        guard_home,
        "oauth_refresh_circuit",
        auth_context=None,
        subject="Guard OAuth refresh circuit",
        extra={"oauthRefreshCircuit": dict(call)},
    )
    if not isinstance(answer, dict):
        raise RuntimeError("The Guard native runtime did not answer the Guard OAuth refresh circuit.")
    return answer


def cloud_json_request(
    auth_context: Mapping[str, object],
    *,
    url: str,
    body: bytes | None,
    timeout_seconds: float,
    retry_timeout_seconds: float,
) -> dict[str, object]:
    """POST ``body`` to ``url`` (GET when it is ``None``) with the resolved sign-in.

    Return Guard Cloud's object answer.

    The native runtime signs and sends the request under the managed network
    policy. An HTTP refusal is raised as the ``HTTPError`` and a failure with no
    answer as the ``URLError`` the callers already handle.
    """

    from ..config import resolve_guard_home

    answer = _native_cloud_request(
        auth_context,
        resolve_guard_home(),
        url=url,
        body=body,
        timeout_seconds=timeout_seconds,
        retry_timeout_seconds=retry_timeout_seconds,
        raw=False,
    )
    return cloud_json_answer(url, answer)


def cloud_raw_request(
    auth_context: Mapping[str, object],
    guard_home: Path,
    *,
    url: str,
    body: bytes | None,
    timeout_seconds: float,
    retry_timeout_seconds: float,
    max_response_bytes: int | None = None,
) -> tuple[int, bytes]:
    """:func:`cloud_json_request` that returns the 2xx status and body unread.

    For an endpoint that may answer ``204 No Content`` or whose body the caller
    parses under its own limits. Failures are raised the same way, and a body
    longer than ``max_response_bytes`` raises :class:`CloudResponseOversizedError`.
    """

    answer = _native_cloud_request(
        auth_context,
        guard_home,
        url=url,
        body=body,
        timeout_seconds=timeout_seconds,
        retry_timeout_seconds=retry_timeout_seconds,
        raw=True,
        max_response_bytes=max_response_bytes,
    )
    return cloud_raw_answer(url, answer)


def _native_cloud_request(
    auth_context: Mapping[str, object],
    guard_home: Path,
    *,
    url: str,
    body: bytes | None,
    timeout_seconds: float,
    retry_timeout_seconds: float,
    raw: bool,
    max_response_bytes: int | None = None,
) -> object:
    request: dict[str, object] = {
        "url": url,
        "method": "GET" if body is None else "POST",
        "timeoutSeconds": float(timeout_seconds),
        "retryTimeoutSeconds": float(retry_timeout_seconds),
    }
    if raw:
        request["answer"] = "raw"
    if max_response_bytes is not None:
        request["maxResponseBytes"] = int(max_response_bytes)
    body_file: str | None = None
    try:
        if body is not None and len(body) > _INLINE_BODY_LIMIT_BYTES:
            descriptor, body_file = tempfile.mkstemp(prefix="hol-guard-cloud-", suffix=".json")
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(body)
            request["bodyFile"] = body_file
        elif body is not None:
            request["body"] = body.decode("utf-8")
        return run_native_cloud_sync(
            CLOUD_EVENT_SYNC_COMMAND,
            CLOUD_JSON_REQUEST_FEATURE,
            guard_home,
            "request",
            auth_context=auth_context,
            subject="Cloud request",
            extra={"request": request},
        )
    finally:
        if body_file is not None:
            Path(body_file).unlink(missing_ok=True)


class CloudResponseOversizedError(RuntimeError):
    """A raw Guard Cloud response was longer than the caller's limit."""


def cloud_json_answer(url: str, answer: object) -> dict[str, object]:
    """Guard Cloud's object answer from the native ``request`` result, or its failure raised."""

    if not isinstance(answer, dict):
        raise RuntimeError("Guard Cloud sync returned an invalid response payload.")
    response = answer.get("response")
    if isinstance(response, dict):
        return response
    _raise_cloud_failure(url, answer)


def cloud_raw_answer(url: str, answer: object) -> tuple[int, bytes]:
    """The status and body from a native ``raw`` request result, or its failure raised."""

    if not isinstance(answer, dict):
        raise RuntimeError("Guard Cloud sync returned an invalid response payload.")
    raw = answer.get("raw")
    if isinstance(raw, dict):
        if raw.get("oversized") is True:
            raise CloudResponseOversizedError("Guard Cloud returned a response larger than the caller reads.")
        status = raw.get("status")
        body = raw.get("body")
        if isinstance(status, int) and not isinstance(status, bool) and isinstance(body, str):
            return status, body.encode("utf-8")
        raise RuntimeError("Guard Cloud sync returned an invalid response payload.")
    _raise_cloud_failure(url, answer)


def _raise_cloud_failure(url: str, answer: Mapping[str, object]) -> NoReturn:
    raise cloud_failure(url, answer)


def cloud_failure(url: str, answer: Mapping[str, object]) -> Exception:
    """The ``HTTPError`` or ``URLError`` a native ``refusal`` or ``transport`` answer stands for."""

    refusal = answer.get("refusal")
    if isinstance(refusal, dict) and isinstance(refusal.get("status"), int):
        headers = Message()
        raw_headers = refusal.get("headers")
        for name, value in (raw_headers if isinstance(raw_headers, dict) else {}).items():
            if isinstance(name, str) and isinstance(value, str):
                headers[name] = value
        body = refusal.get("body")
        payload = body.encode("utf-8") if isinstance(body, str) else b""
        status = refusal["status"]
        reason = http.client.responses.get(status, "")
        return urllib.error.HTTPError(url, status, reason, headers, io.BytesIO(payload))
    transport = answer.get("transport")
    if isinstance(transport, dict):
        reason = transport.get("reason")
        text = reason if isinstance(reason, str) else ""
        if transport.get("timeout") is True:
            return urllib.error.URLError(TimeoutError(text))
        if transport.get("outage") is True:
            return urllib.error.URLError(ConnectionError(text))
        return urllib.error.URLError(text)
    return RuntimeError("Guard Cloud sync returned an invalid response payload.")


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
