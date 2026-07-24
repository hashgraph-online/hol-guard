"""Signed, revocable local capability for Guard Cloud commands."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from ..store import GuardStore

COMMAND_CAPABILITY_STATE_KEY = "guard_command_capability_v1"
COMMAND_PENDING_APPROVALS_STATE_KEY = "guard_command_pending_approvals_v1"
COMMAND_LOCAL_APPROVALS_STATE_KEY = "guard_command_local_approvals_v1"
COMMAND_REPLAY_STATE_KEY = "guard_command_replay_state_v1"
COMMAND_QUEUE_RUNTIME_STATE_KEY = "guard_command_queue_state"
COMMAND_CAPABILITY_VERSION = 1
COMMAND_CAPABILITY_MAX_TTL_SECONDS = 365 * 24 * 60 * 60
COMMAND_CAPABILITY_DEFAULT_TTL_SECONDS = 30 * 24 * 60 * 60
COMMAND_REPLAY_MAX_ITEMS = 512
COMMAND_QUEUE_ENABLED_ENV = "GUARD_CLOUD_COMMAND_QUEUE_ENABLED"

READ_ONLY_COMMAND_OPERATIONS: tuple[str, ...] = (
    "guard.packageShims.status",
    "guard.packageShims.test",
    "guard.packageShims.audit",
    "guard.app.status",
    "guard.app.updateCheck",
    "guard.localRequests.snapshot",
)
LOCAL_CONFIRMATION_COMMAND_OPERATIONS: frozenset[str] = frozenset(
    {
        "guard.packageShims.remove",
        "guard.app.remove",
    }
)
STATE_CHANGING_COMMAND_OPERATIONS: frozenset[str] = frozenset(
    {
        "guard.packageShims.repair",
        "guard.packageShims.sync",
        "guard.packageShims.install",
        "guard.app.repair",
        "guard.app.connect",
        "guard.app.update",
        "guard.approval.resolve",
        "guard.liveRequests.reassignQuarantined",
    }
)
REMOTE_STEP_UP_COMMAND_OPERATIONS: frozenset[str] = frozenset(
    {
        "guard.liveRequests.reassignQuarantined",
    }
)
_REVIEW_SYNC_REPAIR_PREREQUISITES = frozenset(
    {
        "guard.approval.resolve",
        "guard.localRequests.snapshot",
    }
)


class CommandCapabilityError(ValueError):
    """Fail-closed command capability or lease validation error."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class AuthorizedCommandJob:
    """Validated local authorization result for one leased job."""

    identity: dict[str, object]
    operation: str
    requires_local_approval: bool


def _now_datetime(now: str | None = None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    parsed = _parse_timestamp(now)
    if parsed is None:
        raise CommandCapabilityError("invalid_current_time")
    return parsed


def command_environment_allows_queue(environ: Mapping[str, str] | None = None) -> bool:
    """Treat the legacy environment setting as an opt-out, never a grant."""

    source = os.environ if environ is None else environ
    value = source.get(COMMAND_QUEUE_ENABLED_ENV)
    if value is None:
        return True
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.strip()
    if normalized.endswith(("Z", "z")):
        normalized = f"{normalized[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _canonical_bytes(payload: Mapping[str, object]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _state_items(payload: object) -> list[dict[str, object]]:
    if not isinstance(payload, dict):
        return []
    raw_items = payload.get("items")
    if not isinstance(raw_items, list):
        return []
    return [{str(key): value for key, value in item.items()} for item in raw_items if isinstance(item, dict)]


def _signing_material(store: GuardStore, *, create: bool) -> tuple[bytes, str]:
    key, key_id = store._policy_integrity_secret_material(create=create)
    if key is None or key_id is None:
        raise CommandCapabilityError("local_signing_key_unavailable")
    return key, key_id


def _signed_payload(store: GuardStore, payload: dict[str, object], *, create_key: bool) -> dict[str, object]:
    key, key_id = _signing_material(store, create=create_key)
    unsigned = {**payload, "keyId": key_id}
    signature = hmac.new(key, _canonical_bytes(unsigned), hashlib.sha256).hexdigest()
    return {**unsigned, "signature": signature}


def _verify_signed_payload(store: GuardStore, payload: object) -> dict[str, object]:
    if not isinstance(payload, dict):
        raise CommandCapabilityError("signed_payload_missing")
    signature = payload.get("signature")
    if not isinstance(signature, str) or not signature:
        raise CommandCapabilityError("signed_payload_missing_signature")
    unsigned = {str(key): value for key, value in payload.items() if key != "signature"}
    key, key_id = _signing_material(store, create=False)
    if unsigned.get("keyId") != key_id:
        raise CommandCapabilityError("signed_payload_key_mismatch")
    expected = hmac.new(key, _canonical_bytes(unsigned), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise CommandCapabilityError("signed_payload_invalid_signature")
    return unsigned


def _oauth_target(store: GuardStore) -> tuple[str, str]:
    # Routine daemon/dashboard checks must stay non-interactive. Explicit
    # connection repair can promote credentials before capability issuance.
    credentials = store.get_oauth_local_credentials(allow_primary=False)
    if not isinstance(credentials, dict):
        raise CommandCapabilityError("cloud_connection_required")
    device_id = credentials.get("machine_id")
    workspace_id = credentials.get("workspace_id")
    if not isinstance(device_id, str) or not device_id:
        raise CommandCapabilityError("cloud_device_binding_missing")
    if not isinstance(workspace_id, str) or not workspace_id:
        raise CommandCapabilityError("cloud_workspace_binding_missing")
    local_device = store.get_device_metadata().get("installation_id")
    if local_device != device_id:
        raise CommandCapabilityError("cloud_device_binding_mismatch")
    return device_id, workspace_id


def issue_command_capability(
    store: GuardStore,
    *,
    operations: tuple[str, ...],
    supported_operations: tuple[str, ...],
    issuer: str = "local-cli",
    ttl_seconds: int = COMMAND_CAPABILITY_DEFAULT_TTL_SECONDS,
    now: str | None = None,
) -> dict[str, object]:
    """Issue and persist an exact local command capability."""

    issued_at = _now_datetime(now)
    if not issuer.strip():
        raise CommandCapabilityError("capability_issuer_required")
    if ttl_seconds <= 0 or ttl_seconds > COMMAND_CAPABILITY_MAX_TTL_SECONDS:
        raise CommandCapabilityError("invalid_capability_ttl")
    supported = frozenset(supported_operations)
    normalized_operations = tuple(sorted(set(operations)))
    if not normalized_operations:
        raise CommandCapabilityError("capability_operations_required")
    if any(operation not in supported for operation in normalized_operations):
        raise CommandCapabilityError("unsupported_capability_operation")
    device_id, workspace_id = _oauth_target(store)
    capability = _signed_payload(
        store,
        {
            "version": COMMAND_CAPABILITY_VERSION,
            "deviceId": device_id,
            "workspaceId": workspace_id,
            "operations": list(normalized_operations),
            "issuer": issuer,
            "issuedAt": issued_at.isoformat(),
            "expiresAt": (issued_at + timedelta(seconds=ttl_seconds)).isoformat(),
            "nonce": secrets.token_urlsafe(24),
        },
        create_key=True,
    )
    store.set_sync_payload(COMMAND_CAPABILITY_STATE_KEY, capability, issued_at.isoformat())
    # Never inherit a result or active lease from the historical always-on
    # queue or from an earlier revoked capability.
    store.delete_sync_payload(COMMAND_QUEUE_RUNTIME_STATE_KEY)
    store.delete_sync_payload(COMMAND_LOCAL_APPROVALS_STATE_KEY)
    store.delete_sync_payload(COMMAND_PENDING_APPROVALS_STATE_KEY)
    _audit(
        store,
        "cloud_command.capability_issued",
        {
            "device_id": device_id,
            "workspace_id": workspace_id,
            "issuer": issuer,
            "operations": list(normalized_operations),
            "expires_at": capability["expiresAt"],
        },
        issued_at.isoformat(),
    )
    return command_capability_status(store, now=issued_at.isoformat())


def _verified_capability(store: GuardStore, *, now: str | None = None) -> dict[str, object]:
    capability = _verify_signed_payload(store, store.get_sync_payload(COMMAND_CAPABILITY_STATE_KEY))
    if capability.get("version") != COMMAND_CAPABILITY_VERSION:
        raise CommandCapabilityError("capability_version_unsupported")
    issuer = capability.get("issuer")
    if not isinstance(issuer, str) or not issuer.strip():
        raise CommandCapabilityError("capability_issuer_invalid")
    issued_at = _parse_timestamp(capability.get("issuedAt"))
    if issued_at is None:
        raise CommandCapabilityError("capability_issued_at_invalid")
    expires_at = _parse_timestamp(capability.get("expiresAt"))
    if expires_at is None:
        raise CommandCapabilityError("capability_expiry_invalid")
    current = _now_datetime(now)
    if issued_at > current + timedelta(minutes=5):
        raise CommandCapabilityError("capability_issued_in_future")
    if expires_at <= issued_at:
        raise CommandCapabilityError("capability_expiry_invalid")
    if expires_at - issued_at > timedelta(seconds=COMMAND_CAPABILITY_MAX_TTL_SECONDS):
        raise CommandCapabilityError("capability_ttl_exceeded")
    if expires_at <= current:
        raise CommandCapabilityError("capability_expired")
    nonce = capability.get("nonce")
    if not isinstance(nonce, str) or not nonce.strip():
        raise CommandCapabilityError("capability_nonce_invalid")
    device_id, workspace_id = _oauth_target(store)
    if capability.get("deviceId") != device_id:
        raise CommandCapabilityError("capability_device_mismatch")
    if capability.get("workspaceId") != workspace_id:
        raise CommandCapabilityError("capability_workspace_mismatch")
    operations = capability.get("operations")
    if (
        not isinstance(operations, list)
        or not operations
        or not all(isinstance(operation, str) and operation for operation in operations)
    ):
        raise CommandCapabilityError("capability_operations_invalid")
    if len(operations) != len(set(operations)):
        raise CommandCapabilityError("capability_operations_invalid")
    classified_operations = (
        set(READ_ONLY_COMMAND_OPERATIONS)
        | set(LOCAL_CONFIRMATION_COMMAND_OPERATIONS)
        | set(STATE_CHANGING_COMMAND_OPERATIONS)
    )
    if any(operation not in classified_operations for operation in operations):
        raise CommandCapabilityError("capability_operation_unsupported")
    expanded_operations = set(operations)
    if _REVIEW_SYNC_REPAIR_PREREQUISITES.issubset(expanded_operations):
        expanded_operations.update(REMOTE_STEP_UP_COMMAND_OPERATIONS)
    return {
        **capability,
        "operations": sorted(expanded_operations),
    }


def command_capability_status(store: GuardStore, *, now: str | None = None) -> dict[str, object]:
    """Return safe capability state for CLI, daemon, and dashboard surfaces."""

    pending_status = [
        {key: item[key] for key in ("id", "operation", "issuer", "expiresAt", "approveCommand") if key in item}
        for item in pending_command_approvals(store, now=now)
    ]
    try:
        capability = _verified_capability(store, now=now)
    except CommandCapabilityError as error:
        return {
            "enabled": False,
            "capability_valid": False,
            "reason": error.code,
            "issuer": None,
            "expires_at": None,
            "operations": [],
            "pending_commands": pending_status,
            "enable_command": "hol-guard commands enable --operations read-only",
            "revoke_command": "hol-guard commands revoke --confirm revoke",
        }
    operations = capability.get("operations")
    environment_allows_queue = command_environment_allows_queue()
    return {
        "enabled": environment_allows_queue,
        "capability_valid": True,
        "reason": None if environment_allows_queue else "command_queue_environment_disabled",
        "issuer": capability.get("issuer"),
        "issued_at": capability.get("issuedAt"),
        "expires_at": capability.get("expiresAt"),
        "device_id": capability.get("deviceId"),
        "workspace_id": capability.get("workspaceId"),
        "operations": [str(operation) for operation in operations] if isinstance(operations, list) else [],
        "pending_commands": pending_status,
        "enable_command": "hol-guard commands enable --operations read-only",
        "revoke_command": "hol-guard commands revoke --confirm revoke",
    }


def command_capability_operations(store: GuardStore, *, now: str | None = None) -> tuple[str, ...]:
    try:
        capability = _verified_capability(store, now=now)
    except CommandCapabilityError:
        return ()
    operations = capability.get("operations")
    return tuple(str(operation) for operation in operations) if isinstance(operations, list) else ()


def revoke_command_capability(
    store: GuardStore, *, issuer: str = "local-cli", now: str | None = None
) -> dict[str, object]:
    revoked_at = _now_datetime(now).isoformat()
    previous = command_capability_status(store, now=revoked_at)
    store.delete_sync_payload(COMMAND_CAPABILITY_STATE_KEY)
    store.delete_sync_payload(COMMAND_LOCAL_APPROVALS_STATE_KEY)
    store.delete_sync_payload(COMMAND_PENDING_APPROVALS_STATE_KEY)
    store.delete_sync_payload(COMMAND_REPLAY_STATE_KEY)
    store.delete_sync_payload(COMMAND_QUEUE_RUNTIME_STATE_KEY)
    _audit(
        store,
        "cloud_command.capability_revoked",
        {
            "issuer": issuer,
            "previous_operations": previous.get("operations", []),
        },
        revoked_at,
    )
    return command_capability_status(store, now=revoked_at)


def command_job_identity(
    job: Mapping[str, object],
    *,
    schema_versions: Mapping[str, int],
) -> dict[str, object]:
    operation = job.get("operation")
    if not isinstance(operation, str) or operation not in schema_versions:
        raise CommandCapabilityError("command_operation_unsupported")
    required_strings = {
        "id": "command_id_missing",
        "deviceId": "command_device_missing",
        "workspaceId": "command_workspace_missing",
        "nonce": "command_nonce_missing",
        "expiresAt": "command_expiry_missing",
        "idempotencyKey": "command_idempotency_key_missing",
    }
    identity: dict[str, object] = {"operation": operation}
    for field, error_code in required_strings.items():
        value = job.get(field)
        if not isinstance(value, str) or not value.strip():
            raise CommandCapabilityError(error_code)
        identity[field] = value.strip()
    schema_version = job.get("schemaVersion")
    if schema_version != schema_versions[operation]:
        raise CommandCapabilityError("command_schema_version_mismatch")
    identity["schemaVersion"] = schema_version
    payload = job.get("payload")
    if not isinstance(payload, dict):
        raise CommandCapabilityError("command_payload_invalid")
    identity["payloadDigest"] = hashlib.sha256(_canonical_bytes(payload)).hexdigest()
    return identity


def authorize_command_job(
    store: GuardStore,
    job: Mapping[str, object],
    *,
    schema_versions: Mapping[str, int],
    now: str | None = None,
) -> AuthorizedCommandJob:
    """Validate capability and complete source-to-target lease bindings."""

    capability = _verified_capability(store, now=now)
    identity = command_job_identity(job, schema_versions=schema_versions)
    operation = str(identity["operation"])
    operations = capability.get("operations")
    if not isinstance(operations, list) or operation not in operations:
        raise CommandCapabilityError("command_operation_not_granted")
    if identity["deviceId"] != capability.get("deviceId"):
        raise CommandCapabilityError("command_device_mismatch")
    if identity["workspaceId"] != capability.get("workspaceId"):
        raise CommandCapabilityError("command_workspace_mismatch")
    expires_at = _parse_timestamp(identity["expiresAt"])
    if expires_at is None:
        raise CommandCapabilityError("command_expiry_invalid")
    current = _now_datetime(now)
    if expires_at <= current:
        raise CommandCapabilityError("command_expired")
    if expires_at > current + timedelta(hours=24):
        raise CommandCapabilityError("command_expiry_too_distant")
    if _command_job_seen(store, identity, now=current.isoformat()):
        raise CommandCapabilityError("command_replayed")
    return AuthorizedCommandJob(
        identity=identity,
        operation=operation,
        requires_local_approval=(
            operation in STATE_CHANGING_COMMAND_OPERATIONS and operation not in REMOTE_STEP_UP_COMMAND_OPERATIONS
        ),
    )


def _identity_digest(identity: Mapping[str, object]) -> str:
    return hashlib.sha256(_canonical_bytes(identity)).hexdigest()


def register_pending_command(
    store: GuardStore,
    authorized: AuthorizedCommandJob,
    job: Mapping[str, object],
    *,
    now: str | None = None,
) -> dict[str, object]:
    recorded_at = _now_datetime(now).isoformat()
    items = _state_items(store.get_sync_payload(COMMAND_PENDING_APPROVALS_STATE_KEY))
    job_id = str(authorized.identity["id"])
    items = [item for item in items if item.get("id") != job_id]
    item = {
        **authorized.identity,
        "issuer": job.get("issuer") if isinstance(job.get("issuer"), str) else "Guard Cloud",
        "recordedAt": recorded_at,
        "approveCommand": f"hol-guard commands approve {job_id} --confirm {job_id}",
    }
    items.append(item)
    store.set_sync_payload(COMMAND_PENDING_APPROVALS_STATE_KEY, {"version": 1, "items": items[-64:]}, recorded_at)
    _audit(
        store,
        "cloud_command.local_approval_required",
        {"job_id": job_id, "operation": authorized.operation, "issuer": item["issuer"]},
        recorded_at,
    )
    return item


def pending_command_approvals(store: GuardStore, *, now: str | None = None) -> list[dict[str, object]]:
    current = _now_datetime(now)
    items = _state_items(store.get_sync_payload(COMMAND_PENDING_APPROVALS_STATE_KEY))
    return [
        dict(item)
        for item in items
        if (expires_at := _parse_timestamp(item.get("expiresAt"))) is not None and expires_at > current
    ]


def approve_pending_command(
    store: GuardStore,
    job_id: str,
    *,
    issuer: str = "local-cli",
    now: str | None = None,
) -> dict[str, object]:
    approved_at = _now_datetime(now)
    pending = next(
        (item for item in pending_command_approvals(store, now=approved_at.isoformat()) if item.get("id") == job_id),
        None,
    )
    if pending is None:
        raise CommandCapabilityError("pending_command_not_found")
    identity = {
        key: pending[key]
        for key in (
            "id",
            "operation",
            "schemaVersion",
            "deviceId",
            "workspaceId",
            "nonce",
            "expiresAt",
            "idempotencyKey",
            "payloadDigest",
        )
    }
    grant = _signed_payload(
        store,
        {
            "version": 1,
            "identity": identity,
            "identityDigest": _identity_digest(identity),
            "issuer": issuer,
            "approvedAt": approved_at.isoformat(),
        },
        create_key=False,
    )
    items = _state_items(store.get_sync_payload(COMMAND_LOCAL_APPROVALS_STATE_KEY))
    items = [item for item in items if item.get("identityDigest") != grant["identityDigest"]]
    items.append(grant)
    store.set_sync_payload(
        COMMAND_LOCAL_APPROVALS_STATE_KEY, {"version": 1, "items": items[-64:]}, approved_at.isoformat()
    )
    _audit(
        store,
        "cloud_command.local_approval_granted",
        {"job_id": job_id, "operation": identity["operation"], "issuer": issuer},
        approved_at.isoformat(),
    )
    return {"approved": True, "job_id": job_id, "operation": identity["operation"], "issuer": issuer}


def consume_local_command_approval(
    store: GuardStore,
    authorized: AuthorizedCommandJob,
    *,
    now: str | None = None,
) -> bool:
    if not authorized.requires_local_approval:
        return True
    items = _state_items(store.get_sync_payload(COMMAND_LOCAL_APPROVALS_STATE_KEY))
    identity_digest = _identity_digest(authorized.identity)
    matched_index: int | None = None
    for index, item in enumerate(items):
        if item.get("identityDigest") != identity_digest:
            continue
        try:
            verified = _verify_signed_payload(store, item)
        except CommandCapabilityError:
            continue
        if verified.get("identity") == authorized.identity:
            matched_index = index
            break
    if matched_index is None:
        return False
    del items[matched_index]
    timestamp = _now_datetime(now).isoformat()
    store.set_sync_payload(COMMAND_LOCAL_APPROVALS_STATE_KEY, {"version": 1, "items": items}, timestamp)
    pending_items = _state_items(store.get_sync_payload(COMMAND_PENDING_APPROVALS_STATE_KEY))
    remaining_pending = [item for item in pending_items if item.get("id") != authorized.identity["id"]]
    store.set_sync_payload(
        COMMAND_PENDING_APPROVALS_STATE_KEY,
        {"version": 1, "items": remaining_pending},
        timestamp,
    )
    return True


def mark_command_job_consumed(
    store: GuardStore,
    authorized: AuthorizedCommandJob,
    *,
    now: str | None = None,
) -> None:
    consumed_at = _now_datetime(now)
    raw_items = _state_items(store.get_sync_payload(COMMAND_REPLAY_STATE_KEY))
    items = [
        item
        for item in raw_items
        if (expires_at := _parse_timestamp(item.get("expiresAt"))) is not None and expires_at > consumed_at
    ]
    items.append(
        {
            "identityDigest": _identity_digest(authorized.identity),
            "jobId": authorized.identity["id"],
            "idempotencyKey": authorized.identity["idempotencyKey"],
            "operation": authorized.operation,
            "expiresAt": authorized.identity["expiresAt"],
            "consumedAt": consumed_at.isoformat(),
        }
    )
    store.set_sync_payload(
        COMMAND_REPLAY_STATE_KEY, {"version": 1, "items": items[-COMMAND_REPLAY_MAX_ITEMS:]}, consumed_at.isoformat()
    )


def _command_job_seen(store: GuardStore, identity: Mapping[str, object], *, now: str | None = None) -> bool:
    current = _now_datetime(now)
    items = _state_items(store.get_sync_payload(COMMAND_REPLAY_STATE_KEY))
    identity_digest = _identity_digest(identity)
    return any(
        (
            item.get("identityDigest") == identity_digest
            or item.get("jobId") == identity["id"]
            or item.get("idempotencyKey") == identity["idempotencyKey"]
        )
        and (expires_at := _parse_timestamp(item.get("expiresAt"))) is not None
        and expires_at > current
        for item in items
    )


def audit_command_decision(
    store: GuardStore,
    event_name: str,
    *,
    job: Mapping[str, object],
    reason: str,
    now: str | None = None,
) -> None:
    timestamp = _now_datetime(now).isoformat()
    _audit(
        store,
        event_name,
        {
            "job_id": job.get("id"),
            "operation": job.get("operation"),
            "idempotency_key": job.get("idempotencyKey"),
            "reason": reason,
        },
        timestamp,
    )


def _audit(store: GuardStore, event_name: str, payload: dict[str, object], now: str) -> None:
    try:
        store.add_event(event_name, payload, now)
    except Exception:
        # Auditing must not widen authorization or crash the daemon. The caller
        # still fails closed based on capability validation.
        return


__all__ = [
    "COMMAND_CAPABILITY_DEFAULT_TTL_SECONDS",
    "COMMAND_CAPABILITY_MAX_TTL_SECONDS",
    "LOCAL_CONFIRMATION_COMMAND_OPERATIONS",
    "READ_ONLY_COMMAND_OPERATIONS",
    "STATE_CHANGING_COMMAND_OPERATIONS",
    "AuthorizedCommandJob",
    "CommandCapabilityError",
    "approve_pending_command",
    "audit_command_decision",
    "authorize_command_job",
    "command_capability_operations",
    "command_capability_status",
    "command_environment_allows_queue",
    "command_job_identity",
    "consume_local_command_approval",
    "issue_command_capability",
    "mark_command_job_consumed",
    "pending_command_approvals",
    "register_pending_command",
    "revoke_command_capability",
]
