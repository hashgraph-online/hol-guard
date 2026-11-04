"""Opt-in, signed authority for exact Cloud Review decisions.

This module deliberately does not know how policy bundles or decision memory
work.  A valid capability can only resolve the one pending request named by a
signed Cloud review receipt.
"""

from __future__ import annotations

import secrets
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, cast

from ..review_contracts import (
    GuardReviewContractError,
    GuardReviewOAuthMetadata,
    guard_review_oauth_metadata,
    remote_approval_uses_workspace_admin_mfa,
)
from .exact_cloud_review_diagnostics import enrich_exact_cloud_review_status
from .time_support import parse_utc_timestamp

if TYPE_CHECKING:
    from ..store import GuardStore
    from .command_capability import AuthorizedCommandJob

EXACT_CLOUD_REVIEW_OPERATION = "guard.review.resolveExact"
EXACT_CLOUD_REVIEW_PROTOCOL_VERSION = 2
EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY = "guard_exact_cloud_review_capability"
EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY = "guard_exact_cloud_review_revocation"
EXACT_CLOUD_REVIEW_MAX_TTL_SECONDS = 365 * 24 * 60 * 60
EXACT_CLOUD_REVIEW_DEFAULT_TTL_SECONDS = 30 * 24 * 60 * 60
_FEATURE = "native-exact-cloud-review-v1"
_COMMAND = "exact-cloud-review"
_UNAVAILABLE = "native_exact_cloud_review_unavailable"
# The runtime's answer when the capability reached the binding check and the
# caller had no binding to send; the caller raises its own reason instead.
_BINDING_UNREADABLE = "binding_unreadable"


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


def _clock(now: str | None) -> str:
    return datetime.now(timezone.utc).isoformat() if now is None else now


def _answer(request: dict[str, object]) -> dict[str, object]:
    """What the runtime says about the signed consent; it signs and checks it."""

    from ..mdm.runtime_request import runtime_answer

    answer = runtime_answer(_FEATURE, _COMMAND, request, output_limit=1 << 20, timeout_seconds=10.0)
    if answer is None:
        raise ExactCloudReviewError(_UNAVAILABLE)
    return answer


def _ask(request: dict[str, object], member: str) -> dict[str, object]:
    answer = _answer(request)
    error = answer.get("error")
    if isinstance(error, str):
        raise ExactCloudReviewError(error)
    value = answer.get(member)
    if not isinstance(value, dict):
        raise ExactCloudReviewError(_UNAVAILABLE)
    return cast("dict[str, object]", value)


def _signing_key(store: GuardStore, envelope: object, *, create: bool = False) -> dict[str, object]:
    """The local key, read only for an envelope it could check."""

    if not create and not isinstance(envelope, dict):
        return {"key": None, "key_id": None}
    from .command_capability import _signing_material_for_resident

    key, key_id = _signing_material_for_resident(store, create=create)
    return {"key": key, "key_id": key_id}


def _sign(store: GuardStore, payload: dict[str, object], *, create_key: bool) -> dict[str, object]:
    request = {"op": "sign", **_signing_key(store, None, create=create_key), "payload": payload}
    return _ask(request, "envelope")


def _verify(store: GuardStore, payload: object) -> dict[str, object]:
    return _ask({"op": "verify", **_signing_key(store, payload), "envelope": payload}, "unsigned")


def _capability_digest(capability: dict[str, object]) -> str:
    answer = _answer({"op": "digest", "payload": capability})
    digest = answer.get("digest")
    if not isinstance(digest, str):
        raise ExactCloudReviewError(_UNAVAILABLE)
    return digest


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
    """Exact review accepts only the signed one-time decision vocabulary."""

    if value == "allow_once":
        return "allow"
    if value == "block":
        return "block"
    return None


def _request_is_current(request: dict[str, object], *, now: datetime) -> bool:
    del now
    return str(request.get("status") or "pending") == "pending"


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
    raw = store.get_sync_payload(EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY)
    binding: dict[str, object] | None = None
    binding_error: Exception | None = None
    if isinstance(raw, dict):
        # Read here, raised only if the runtime reaches the binding check.
        try:
            binding = _oauth_binding(store)
        except Exception as error:
            binding_error = error
    answer = _answer(
        {
            "op": "capability",
            **_signing_key(store, raw),
            "capability": raw,
            "revocation": store.get_sync_payload(EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY),
            "binding": binding,
            "now": _clock(now),
        }
    )
    error = answer.get("error")
    if error == _BINDING_UNREADABLE and binding_error is not None:
        raise binding_error
    drift_digest = answer.get("drift_digest")
    if isinstance(drift_digest, str) and revoke_binding_drift:
        _revoke_binding_drift(store, drift_digest, now=_now(_clock(now)))
    if isinstance(error, str):
        raise ExactCloudReviewError(error)
    capability = answer.get("capability")
    if not isinstance(capability, dict):
        raise ExactCloudReviewError(_UNAVAILABLE)
    return cast("dict[str, object]", capability)


def _revoke_binding_drift(store: GuardStore, capability_digest: str, *, now: datetime) -> None:
    raw_capability = store.get_sync_payload(EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY)
    if not isinstance(raw_capability, dict):
        return
    revocation = _sign(
        store,
        {
            "capabilityDigest": capability_digest,
            "issuer": "binding-drift",
            "revokedAt": now.isoformat(),
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
    if store.get_sync_payload(EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY) is not None:
        return ()
    try:
        _verified_capability(store, now=now)
        return (EXACT_CLOUD_REVIEW_OPERATION,)
    except (AttributeError, ExactCloudReviewError):
        pass
    if store.get_sync_payload(EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY) is not None:
        return ()
    try:
        _oauth_metadata(store)
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
    now: str | None = None,
) -> AuthorizedCommandJob:
    """Authorize the dedicated operation without borrowing command permissions."""

    from .command_capability import (
        AuthorizedCommandJob,
        CommandCapabilityError,
        CommandCapabilityUnavailableError,
        _command_job_seen,
    )
    from .native_workspace_review_queue import (
        NativeWorkspaceReviewQueueError,
        native_workspace_review_payload,
        require_native_workspace_review_authority,
    )

    try:
        identity = _exact_job_identity(job, now=now)
        payload = job.get("payload")
        native_command = native_workspace_review_payload(payload)
        if native_command is not None:
            if store.get_sync_payload(EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY) is not None:
                raise ExactCloudReviewError("cloud_review_capability_revoked")
            oauth = _oauth_metadata(store)
            if identity["deviceId"] != oauth.device_id:
                raise ExactCloudReviewError("remote_exact_job_wrong_target")
            if identity["workspaceId"] != oauth.workspace_id:
                raise ExactCloudReviewError("remote_exact_job_wrong_workspace")
            try:
                require_native_workspace_review_authority(store, native_command)
            except NativeWorkspaceReviewQueueError as error:
                raise ExactCloudReviewError(error.code) from error
        else:
            remote_approval = payload.get("remoteApproval") if isinstance(payload, Mapping) else None
            if not isinstance(remote_approval, Mapping):
                raise ExactCloudReviewError("remote_exact_job_invalid")
            approval = {str(key): value for key, value in remote_approval.items() if isinstance(key, str)}
            if remote_approval_uses_workspace_admin_mfa(approval):
                if store.get_sync_payload(EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY) is not None:
                    raise ExactCloudReviewError("cloud_review_capability_revoked")
                oauth = _oauth_metadata(store)
                if identity["deviceId"] != oauth.device_id:
                    raise ExactCloudReviewError("remote_exact_job_wrong_target")
                if identity["workspaceId"] != oauth.workspace_id:
                    raise ExactCloudReviewError("remote_exact_job_wrong_workspace")
                if approval.get("grantId") != oauth.grant_id:
                    raise ExactCloudReviewError("remote_exact_job_wrong_grant")
            else:
                capability = _verified_capability(store, now=now)
                if identity["deviceId"] != capability["deviceId"]:
                    raise ExactCloudReviewError("remote_exact_job_wrong_target")
                if identity["workspaceId"] != capability["workspaceId"]:
                    raise ExactCloudReviewError("remote_exact_job_wrong_workspace")
                if approval.get("grantId") != capability["grantId"]:
                    raise ExactCloudReviewError("remote_exact_job_wrong_grant")
                if approval.get("capabilityId") != _capability_digest(capability):
                    raise ExactCloudReviewError("remote_exact_job_capability_mismatch")
        if native_command is None and _command_job_seen(store, identity, now=now):
            raise ExactCloudReviewError("remote_exact_job_replayed")
    except (
        ExactCloudReviewError,
        NativeWorkspaceReviewQueueError,
        CommandCapabilityUnavailableError,
        KeyError,
    ) as error:
        if isinstance(error, ExactCloudReviewError):
            code = error.code
        elif isinstance(error, CommandCapabilityUnavailableError):
            code = error.reason
        else:
            code = "remote_exact_job_invalid"
        raise CommandCapabilityError(code) from error
    return AuthorizedCommandJob(
        identity=identity,
        operation=EXACT_CLOUD_REVIEW_OPERATION,
        requires_local_approval=False,
    )


def _exact_job_identity(job: Mapping[str, object], *, now: str | None = None) -> dict[str, object]:
    """The leased job's identity, once the runtime has checked its lease."""

    return _ask({"op": "job", "job": dict(job), "now": _clock(now)}, "identity")


from .exact_cloud_review_apply import apply_exact_cloud_review  # noqa: E402, F401
