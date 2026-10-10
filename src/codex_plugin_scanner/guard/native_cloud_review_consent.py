"""Cloud Review consent is native-owned; SDK state is never a fallback grant."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Literal, TypedDict, cast

from .native_resident_client import native_resident_client_request
from .native_runtime import _isolated_environment, _native_error, native_runtime_status


class NativeCloudReviewConsentState(TypedDict):
    schema: str
    version: int
    status: Literal["enabled", "disabled", "expired"]
    revision: int
    revocation_epoch: int
    issued_at_ms: int
    expires_at_ms: int
    native: bool


class NativeCloudReviewConsentError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def native_cloud_review_consent(
    guard_home: Path,
    operation: Literal["read", "enable", "disable"],
    *,
    password: str | None = None,
    totp_code: str | None = None,
    ttl_seconds: int | None = None,
) -> NativeCloudReviewConsentState:
    status = native_runtime_status()
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or "resident-protocol-v2" not in status.capabilities.features
        or "native-cloud-review-consent-v1" not in status.capabilities.features
    ):
        raise NativeCloudReviewConsentError("native_cloud_review_consent_unavailable")
    request: dict[str, object] = {
        "schema": "guard-native-cloud-review-consent-request.v1",
        "version": 1,
        "operation": operation,
    }
    if operation == "enable":
        factors = {}
        if password is not None:
            factors["password"] = password
        if totp_code is not None:
            factors["totp_code"] = totp_code
        request["approval_gate_input"] = factors
        if ttl_seconds is not None:
            request["ttl_seconds"] = ttl_seconds
    elif password is not None or totp_code is not None or ttl_seconds is not None:
        raise NativeCloudReviewConsentError("native_cloud_review_consent_request_invalid")
    encoded = json.dumps(
        {"operation": "cloud_review_consent_v1", "deadline_budget_ms": 9000, "request": request},
        separators=(",", ":"),
    ).encode("utf-8")
    if len(encoded) > 4096:
        raise NativeCloudReviewConsentError("native_cloud_review_consent_request_invalid")
    output = native_resident_client_request(
        executable=status.identity.path,
        guard_home=guard_home,
        environment=_isolated_environment(),
        payload=encoded,
        deadline_monotonic=time.monotonic() + 9.0,
    )
    if output is None:
        raise NativeCloudReviewConsentError("native_cloud_review_consent_unavailable")
    try:
        result = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeCloudReviewConsentError("native_cloud_review_consent_invalid") from error
    code = _native_error(result)
    if code is not None:
        raise NativeCloudReviewConsentError(code)
    if (
        not isinstance(result, dict)
        or set(result)
        != {
            "schema",
            "version",
            "status",
            "revision",
            "revocation_epoch",
            "issued_at_ms",
            "expires_at_ms",
            "native",
        }
        or result["schema"] != "guard-native-cloud-review-consent-result.v1"
        or type(result["version"]) is not int
        or result["version"] != 1
        or result["native"] is not True
        or not isinstance(result["status"], str)
        or result["status"] not in {"enabled", "disabled", "expired"}
        or any(
            type(result[field]) is not int or not 0 <= result[field] <= 2**53 - 1
            for field in ("revision", "revocation_epoch", "issued_at_ms", "expires_at_ms")
        )
        or any(result[field] > 253402300799999 for field in ("issued_at_ms", "expires_at_ms"))
        or (
            result["status"] in {"enabled", "expired"}
            and (result["revision"] == 0 or result["expires_at_ms"] <= result["issued_at_ms"])
        )
        or (operation == "enable" and result["status"] != "enabled")
        or (operation == "disable" and result["status"] != "disabled")
    ):
        raise NativeCloudReviewConsentError("native_cloud_review_consent_invalid")
    return cast(NativeCloudReviewConsentState, result)
