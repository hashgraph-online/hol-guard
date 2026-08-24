"""Pure protocol helpers shared by Guard command queue transports."""

from __future__ import annotations

import urllib.error
from collections.abc import Mapping
from datetime import datetime, timezone
from urllib.parse import urlparse, urlunparse

from .exact_cloud_review import EXACT_CLOUD_REVIEW_PROTOCOL_VERSION
from .exact_cloud_review_transport import exact_result, uses_exact_transport
from .time_support import parse_utc_timestamp


def command_api_url(sync_url: object, path: str, *, base_path: str = "/api/guard/commands") -> str:
    parsed = urlparse(str(sync_url))
    normalized_path = path if path.startswith("/") else f"/{path}"
    return urlunparse((parsed.scheme, parsed.netloc, f"{base_path}{normalized_path}", "", "", ""))


def job_id(job: Mapping[str, object]) -> str:
    value = job.get("id")
    if not isinstance(value, str) or not value:
        raise RuntimeError("Guard command job is missing an id.")
    return value


def lease_id(job: Mapping[str, object]) -> str:
    value = job.get("leaseId")
    if not isinstance(value, str) or not value:
        raise RuntimeError("Guard command job is missing a lease id.")
    return value


def pending_result_is_stale(job: Mapping[str, object]) -> bool:
    now = datetime.now(timezone.utc)
    for key in ("leaseExpiresAt", "expiresAt"):
        expires_at = parse_utc_timestamp(job.get(key))
        if expires_at is not None and expires_at <= now:
            return True
    return False


def retry_wait_seconds(poll_interval: float, error_backoff: float, error_streak: int) -> float:
    retry_base = max(poll_interval, 0.1)
    retry_cap = max(error_backoff, 0.1)
    retry_exponent = min(max(0, error_streak - 1), 30)
    return min(retry_cap, retry_base * (2**retry_exponent))


def redacted_error(error: BaseException, *, http_formatter, os_formatter) -> str:
    if isinstance(error, urllib.error.HTTPError):
        try:
            return str(http_formatter(error))
        except Exception:
            return f"HTTP Error {error.code}: {error.reason}"
    if isinstance(error, OSError):
        return str(os_formatter(error))
    return str(error)


def result_payload(job: dict[str, object], execution: dict[str, object]) -> dict[str, object]:
    protocol = {"protocolVersion": EXACT_CLOUD_REVIEW_PROTOCOL_VERSION} if uses_exact_transport(job) else {}
    if execution.get("waitingLocalConfirm") is True:
        sanitized = dict(execution)
        sanitized.pop("waitingLocalConfirm", None)
        return {
            **protocol,
            "leaseId": lease_id(job),
            "idempotencyKey": f"{job_id(job)}:{lease_id(job)}:waiting_local_confirm",
            "status": "waiting_local_confirm",
            "result": sanitized,
        }
    failure_code = execution.get("failureCode")
    if isinstance(failure_code, str) and failure_code:
        return {
            **protocol,
            "leaseId": lease_id(job),
            "idempotencyKey": f"{job_id(job)}:{lease_id(job)}:failed",
            "status": "failed",
            "failureCode": failure_code,
            "failureMessage": str(execution.get("failureMessage") or failure_code),
        }
    return {
        **protocol,
        "leaseId": lease_id(job),
        "idempotencyKey": f"{job_id(job)}:{lease_id(job)}:succeeded",
        "status": "succeeded",
        "result": exact_result(job, execution) if uses_exact_transport(job) else execution,
    }


__all__ = [
    "command_api_url",
    "job_id",
    "lease_id",
    "pending_result_is_stale",
    "redacted_error",
    "result_payload",
    "retry_wait_seconds",
]
