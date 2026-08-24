"""Opt-in, signed authority for exact Cloud Review decisions.

This module deliberately does not know how policy bundles or decision memory
work.  A valid capability can only resolve the one pending request named by a
signed Cloud review receipt.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from ..review_contracts import GuardReviewContractError, GuardReviewOAuthMetadata, guard_review_oauth_metadata
from ..stable_json import stable_json_serialize
from .exact_cloud_review_diagnostics import enrich_exact_cloud_review_status
from .time_support import parse_utc_timestamp

if TYPE_CHECKING:
    from ..store import GuardStore
    from .command_capability import AuthorizedCommandJob

EXACT_CLOUD_REVIEW_OPERATION = "guard.review.resolveExact"
EXACT_CLOUD_REVIEW_SCHEMA_VERSION = 1
EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY = "guard_exact_cloud_review_capability_v1"
EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY = "guard_exact_cloud_review_revocation_v1"
EXACT_CLOUD_REVIEW_MAX_TTL_SECONDS = 365 * 24 * 60 * 60
EXACT_CLOUD_REVIEW_DEFAULT_TTL_SECONDS = 30 * 24 * 60 * 60
EXACT_CLOUD_REVIEW_REQUEST_TTL_SECONDS = 10 * 60


class ExactCloudReviewError(ValueError):
    """Stable rejection for the exact Cloud Review authority boundary."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code: str = code


@dataclass(frozen=True, slots=True)
class ExactCloudReviewResolution:
    action: str
    receipt_id: str
    request_id: str
    resolved_request: dict[str, object]


def _now(now: str | None = None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    parsed = parse_utc_timestamp(now)
    if parsed is None:
        raise ExactCloudReviewError("cloud_review_current_time_invalid")
    return parsed


def _text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _canonical(payload: dict[str, object]) -> bytes:
    return stable_json_serialize(payload).encode("utf-8")


def _signing_material(store: GuardStore, *, create: bool) -> tuple[bytes, str]:
    key, key_id = store._policy_integrity_secret_material(create=create)
    if key is None or key_id is None:
        raise ExactCloudReviewError("cloud_review_signing_key_unavailable")
    return key, key_id


def _sign(store: GuardStore, payload: dict[str, object], *, create_key: bool) -> dict[str, object]:
    key, key_id = _signing_material(store, create=create_key)
    unsigned = {**payload, "keyId": key_id}
    signature = hmac.new(key, _canonical(unsigned), hashlib.sha256).hexdigest()
    return {**unsigned, "signature": signature}


def _verify(store: GuardStore, payload: object) -> dict[str, object]:
    if not isinstance(payload, dict):
        raise ExactCloudReviewError("cloud_review_capability_missing")
    signature = _text(payload.get("signature"))
    if signature is None:
        raise ExactCloudReviewError("cloud_review_capability_signature_missing")
    unsigned = {str(key): value for key, value in payload.items() if key != "signature"}
    key, key_id = _signing_material(store, create=False)
    if unsigned.get("keyId") != key_id:
        raise ExactCloudReviewError("cloud_review_capability_key_mismatch")
    expected = hmac.new(key, _canonical(unsigned), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise ExactCloudReviewError("cloud_review_capability_signature_invalid")
    return unsigned


def _capability_digest(capability: dict[str, object]) -> str:
    return hashlib.sha256(_canonical(capability)).hexdigest()


def _oauth_metadata(store: GuardStore) -> GuardReviewOAuthMetadata:
    oauth_state = store.get_sync_payload("oauth_local_credentials")
    if not isinstance(oauth_state, dict) or _text(oauth_state.get("device_id")) is None:
        raise ExactCloudReviewError("cloud_review_device_binding_missing")
    try:
        oauth = guard_review_oauth_metadata(store, require_device_dpop_binding=True)
    except GuardReviewContractError as error:
        raise ExactCloudReviewError(f"cloud_review_{error}") from error
    if oauth.grant_id is None:
        raise ExactCloudReviewError("cloud_review_grant_binding_missing")
    return oauth


def _oauth_binding(store: GuardStore) -> dict[str, object]:
    oauth = _oauth_metadata(store)
    return {
        "deviceId": oauth.device_id,
        "dpopThumbprint": oauth.dpop_thumbprint,
        "grantId": oauth.grant_id,
        "installationId": oauth.installation_id,
        "machineId": oauth.machine_id,
        "runtimeId": oauth.runtime_id,
        "workspaceId": oauth.workspace_id,
    }


def _oauth_state(store: GuardStore) -> dict[str, object]:
    payload = store.get_sync_payload("oauth_local_credentials")
    if not isinstance(payload, dict):
        raise ExactCloudReviewError("cloud_review_oauth_state_missing")
    return payload


def _audit(store: GuardStore, event_name: str, payload: dict[str, object], *, now: datetime) -> None:
    with suppress(OSError, RuntimeError, ValueError):
        store.add_event(event_name, payload, now.isoformat())


def _reject(store: GuardStore, code: str, *, now: datetime) -> ExactCloudReviewError:
    event_name = "cloud_review.exact_expired" if code.endswith("expired") else "cloud_review.exact_rejected"
    _audit(store, event_name, {"code": code, "operation": EXACT_CLOUD_REVIEW_OPERATION}, now=now)
    return ExactCloudReviewError(code)


def _exact_action(value: object) -> str | None:
    """Exact review accepts only the v1 signed decision wire, not aliases."""

    if value == "allow_once":
        return "allow"
    if value == "block":
        return "block"
    return None


def _request_expires_at(request: dict[str, object]) -> datetime | None:
    observed_at = parse_utc_timestamp(request.get("last_seen_at") or request.get("created_at"))
    return None if observed_at is None else observed_at + timedelta(seconds=EXACT_CLOUD_REVIEW_REQUEST_TTL_SECONDS)


def _request_is_current(request: dict[str, object], *, now: datetime) -> bool:
    expires_at = _request_expires_at(request)
    if expires_at is None:
        return False
    return expires_at - timedelta(seconds=EXACT_CLOUD_REVIEW_REQUEST_TTL_SECONDS) <= now < expires_at


def enable_exact_cloud_review(
    store: GuardStore,
    *,
    issuer: str = "local-cli",
    ttl_seconds: int = EXACT_CLOUD_REVIEW_DEFAULT_TTL_SECONDS,
    now: str | None = None,
) -> dict[str, object]:
    """Record explicit local consent for signed one-request Cloud reviews."""

    issued_at = _now(now)
    if not _text(issuer):
        raise ExactCloudReviewError("cloud_review_capability_issuer_required")
    if type(ttl_seconds) is not int or not 0 < ttl_seconds <= EXACT_CLOUD_REVIEW_MAX_TTL_SECONDS:
        raise ExactCloudReviewError("cloud_review_capability_ttl_invalid")
    binding = _oauth_binding(store)
    capability = _sign(
        store,
        {
            "expiresAt": (issued_at + timedelta(seconds=ttl_seconds)).isoformat(),
            "issuedAt": issued_at.isoformat(),
            "issuer": issuer,
            "nonce": secrets.token_urlsafe(24),
            "operation": EXACT_CLOUD_REVIEW_OPERATION,
            "version": EXACT_CLOUD_REVIEW_SCHEMA_VERSION,
            **binding,
        },
        create_key=True,
    )
    store.replace_exact_cloud_review_state(
        capability=capability,
        revocation=None,
        now=issued_at.isoformat(),
        event_name="cloud_review.exact_capability_issued",
        event_payload={"operation": EXACT_CLOUD_REVIEW_OPERATION, "workspace_id": binding["workspaceId"]},
    )
    return exact_cloud_review_status(store, now=issued_at.isoformat())


def disable_exact_cloud_review(
    store: GuardStore,
    *,
    issuer: str = "local-cli",
    now: str | None = None,
) -> dict[str, object]:
    """Persist revocation before removing the usable local capability."""

    revoked_at = _now(now)
    if not _text(issuer):
        raise ExactCloudReviewError("cloud_review_capability_issuer_required")
    raw = store.get_sync_payload(EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY)
    try:
        capability = _verify(store, raw)
    except ExactCloudReviewError:
        capability_digest = None
    else:
        capability_digest = _capability_digest(capability)
    revocation = _sign(
        store,
        {
            "capabilityDigest": capability_digest,
            "issuer": issuer,
            "revokedAt": revoked_at.isoformat(),
            "version": EXACT_CLOUD_REVIEW_SCHEMA_VERSION,
        },
        create_key=True,
    )
    replaced = store.replace_exact_cloud_review_state(
        capability=None,
        revocation=revocation,
        now=revoked_at.isoformat(),
        event_name="cloud_review.exact_capability_revoked",
        event_payload={"operation": EXACT_CLOUD_REVIEW_OPERATION, "reason": "local_disable"},
        expected_capability=raw,
        require_expected_capability=True,
    )
    if not replaced:
        raise ExactCloudReviewError("cloud_review_capability_changed")
    return exact_cloud_review_status(store, now=revoked_at.isoformat())


def _verified_capability(
    store: GuardStore,
    *,
    now: str | None = None,
    revoke_binding_drift: bool = True,
) -> dict[str, object]:
    capability = _verify(store, store.get_sync_payload(EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY))
    if capability.get("version") != EXACT_CLOUD_REVIEW_SCHEMA_VERSION:
        raise ExactCloudReviewError("cloud_review_capability_version_unsupported")
    if capability.get("operation") != EXACT_CLOUD_REVIEW_OPERATION:
        raise ExactCloudReviewError("cloud_review_capability_operation_invalid")
    if _text(capability.get("issuer")) is None or _text(capability.get("nonce")) is None:
        raise ExactCloudReviewError("cloud_review_capability_invalid")
    issued_at = parse_utc_timestamp(capability.get("issuedAt"))
    expires_at = parse_utc_timestamp(capability.get("expiresAt"))
    current = _now(now)
    if issued_at is None or expires_at is None or expires_at <= issued_at:
        raise ExactCloudReviewError("cloud_review_capability_time_invalid")
    if issued_at > current + timedelta(minutes=5):
        raise ExactCloudReviewError("cloud_review_capability_issued_in_future")
    if expires_at - issued_at > timedelta(seconds=EXACT_CLOUD_REVIEW_MAX_TTL_SECONDS):
        raise ExactCloudReviewError("cloud_review_capability_ttl_invalid")
    if expires_at <= current:
        raise ExactCloudReviewError("cloud_review_capability_expired")
    if any(capability.get(key) != value for key, value in _oauth_binding(store).items()):
        if revoke_binding_drift:
            _revoke_binding_drift(store, capability, now=current)
        raise ExactCloudReviewError("cloud_review_capability_binding_mismatch")
    revocation = store.get_sync_payload(EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY)
    if revocation is not None:
        if not isinstance(revocation, dict):
            raise ExactCloudReviewError("cloud_review_capability_revocation_invalid")
        verified_revocation = _verify(store, revocation)
        if (
            verified_revocation.get("version") != EXACT_CLOUD_REVIEW_SCHEMA_VERSION
            or parse_utc_timestamp(verified_revocation.get("revokedAt")) is None
        ):
            raise ExactCloudReviewError("cloud_review_capability_revocation_invalid")
        digest = verified_revocation.get("capabilityDigest")
        if digest is not None and not isinstance(digest, str):
            raise ExactCloudReviewError("cloud_review_capability_revocation_invalid")
        if digest is None or digest == _capability_digest(capability):
            raise ExactCloudReviewError("cloud_review_capability_revoked")
    return capability


def _revoke_binding_drift(store: GuardStore, capability: dict[str, object], *, now: datetime) -> None:
    raw_capability = store.get_sync_payload(EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY)
    if not isinstance(raw_capability, dict):
        return
    revocation = _sign(
        store,
        {
            "capabilityDigest": _capability_digest(capability),
            "issuer": "binding-drift",
            "revokedAt": now.isoformat(),
            "version": EXACT_CLOUD_REVIEW_SCHEMA_VERSION,
        },
        create_key=False,
    )
    store.replace_exact_cloud_review_state(
        capability=None,
        revocation=revocation,
        now=now.isoformat(),
        event_name="cloud_review.exact_capability_revoked",
        event_payload={"operation": EXACT_CLOUD_REVIEW_OPERATION, "reason": "oauth_binding_drift"},
        expected_capability=raw_capability,
        require_expected_capability=True,
    )


def exact_cloud_review_operations(store: GuardStore, *, now: str | None = None) -> tuple[str, ...]:
    try:
        _verified_capability(store, now=now)
    except (AttributeError, ExactCloudReviewError):
        return ()
    return (EXACT_CLOUD_REVIEW_OPERATION,)


def exact_cloud_review_status(store: GuardStore, *, now: str | None = None) -> dict[str, object]:
    try:
        capability = _verified_capability(store, now=now)
    except (AttributeError, ExactCloudReviewError) as error:
        reason = error.code if isinstance(error, ExactCloudReviewError) else "cloud_review_capability_missing"
        return enrich_exact_cloud_review_status(
            store,
            {
                "capability_valid": False,
                "disable_command": "hol-guard cloud-review disable --confirm disable",
                "enable_command": "hol-guard cloud-review enable",
                "enabled": False,
                "operation": EXACT_CLOUD_REVIEW_OPERATION,
                "reason": reason,
            },
        )
    return enrich_exact_cloud_review_status(
        store,
        {
            "capability_valid": True,
            "disable_command": "hol-guard cloud-review disable --confirm disable",
            "enable_command": "hol-guard cloud-review enable",
            "enabled": True,
            "expires_at": capability["expiresAt"],
            "issued_at": capability["issuedAt"],
            "operation": EXACT_CLOUD_REVIEW_OPERATION,
            "reason": None,
            "workspace_id": capability["workspaceId"],
        },
    )


def authorize_exact_cloud_review_job(
    store: GuardStore,
    job: Mapping[str, object],
    *,
    schema_versions: Mapping[str, int],
    now: str | None = None,
) -> AuthorizedCommandJob:
    """Authorize the dedicated operation without borrowing command permissions."""

    from .command_capability import (
        AuthorizedCommandJob,
        CommandCapabilityError,
        _command_job_seen,
        command_job_identity,
    )

    try:
        capability = _verified_capability(store, now=now)
        identity = command_job_identity(
            job,
            schema_versions={EXACT_CLOUD_REVIEW_OPERATION: schema_versions[EXACT_CLOUD_REVIEW_OPERATION]},
        )
        expires_at = parse_utc_timestamp(identity.get("expiresAt"))
        if expires_at is None or expires_at <= _now(now):
            raise ExactCloudReviewError("remote_exact_job_expired")
        if expires_at > _now(now) + timedelta(hours=24):
            raise ExactCloudReviewError("remote_exact_job_expiry_too_distant")
        if identity["deviceId"] != capability["deviceId"]:
            raise ExactCloudReviewError("remote_exact_job_wrong_target")
        if identity["workspaceId"] != capability["workspaceId"]:
            raise ExactCloudReviewError("remote_exact_job_wrong_workspace")
        payload = job.get("payload")
        remote_approval = payload.get("remoteApproval") if isinstance(payload, Mapping) else None
        if not isinstance(remote_approval, Mapping):
            raise ExactCloudReviewError("remote_exact_job_invalid")
        if remote_approval.get("grantId") != capability["grantId"]:
            raise ExactCloudReviewError("remote_exact_job_wrong_grant")
        if remote_approval.get("capabilityId") != _capability_digest(capability):
            raise ExactCloudReviewError("remote_exact_job_capability_mismatch")
        if _command_job_seen(store, identity, now=now):
            raise ExactCloudReviewError("remote_exact_job_replayed")
    except (ExactCloudReviewError, KeyError) as error:
        code = error.code if isinstance(error, ExactCloudReviewError) else "remote_exact_job_invalid"
        raise CommandCapabilityError(code) from error
    return AuthorizedCommandJob(
        identity=identity,
        operation=EXACT_CLOUD_REVIEW_OPERATION,
        requires_local_approval=False,
    )


from .exact_cloud_review_apply import apply_exact_cloud_review  # noqa: E402, F401
