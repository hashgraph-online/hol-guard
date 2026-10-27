"""Signed, revocable local capability for Guard Cloud commands."""

from __future__ import annotations

import base64
import os
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..native_command_capability import (
    CommandCapabilityUnavailableError,
    native_command_capability,
)
from ..native_command_envelope import (
    CommandEnvelopeUnavailableError,
    native_command_envelope,
)
from ..portable_command import render_portable_command
from ..review_contracts import GuardReviewContractError, guard_review_oauth_metadata
from ..store import GuardStore
from .command_operation_classification import (
    LOCAL_CONFIRMATION_COMMAND_OPERATIONS,
    POLICY_MEMORY_COMMAND_OPERATIONS,
    READ_ONLY_COMMAND_OPERATIONS,
    STATE_CHANGING_COMMAND_OPERATIONS,
)
from .time_support import parse_utc_timestamp

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


_parse_timestamp = parse_utc_timestamp


def _state_items(payload: object) -> list[dict[str, object]]:
    if not isinstance(payload, dict):
        return []
    raw_items = payload.get("items")
    if not isinstance(raw_items, list):
        return []
    return [{str(key): value for key, value in item.items()} for item in raw_items if isinstance(item, dict)]


def _envelope(
    store: GuardStore,
    action: str,
    payload: object,
    *,
    create_key: bool = False,
) -> object:
    """One signed-envelope answer from the runtime, or its refusal raised.

    The HMAC, the canonical bytes it covers and every comparison against them
    live in the resident. This side reads the key out of the secret store and
    decides when one has to be minted, which is provisioning, not a verdict.
    """

    home = _resident_home(store)
    if action == "digest":
        # The runtime digests the payload alone and never reads the key for
        # this action, so reading the policy integrity secret out of the store
        # and putting it on the socket for every replay row and approval match
        # would spend the secret for nothing.
        key_b64, key_id = None, None
    else:
        key_b64, key_id = _signing_material_for_resident(store, create=create_key)
    try:
        answer = native_command_envelope(
            action=action,
            payload=payload,
            integrity_key_b64=key_b64,
            integrity_key_id=key_id,
            guard_home=home,
        )
    except CommandEnvelopeUnavailableError as error:
        # Every caller of this module already reads a `CommandCapabilityError`
        # as a fail-closed refusal: the queue poll records it on the job result
        # and the CLI prints it as `{"status": "error"}` with exit code 2. A
        # resident that gives no answer is the same refusal, so it reaches them
        # as one and keeps its own code.
        raise CommandCapabilityError(CommandEnvelopeUnavailableError.reason) from error
    if not answer.get("accepted"):
        raise CommandCapabilityError(str(answer.get("reason") or "signed_payload_missing"))
    return answer.get("result")


def _signed_payload(store: GuardStore, payload: dict[str, object], *, create_key: bool) -> dict[str, object]:
    signed = _envelope(store, "sign", payload, create_key=create_key)
    if not isinstance(signed, dict):
        raise CommandCapabilityError(CommandEnvelopeUnavailableError.reason)
    return {str(key): value for key, value in signed.items()}


def _verify_signed_payload(store: GuardStore, payload: object) -> dict[str, object]:
    unsigned = _envelope(store, "verify", payload)
    if not isinstance(unsigned, dict):
        raise CommandCapabilityError(CommandEnvelopeUnavailableError.reason)
    return {str(key): value for key, value in unsigned.items()}


def _oauth_target(store: GuardStore) -> tuple[str, str]:
    # Routine daemon/dashboard checks must stay non-interactive. Explicit
    # connection repair can promote credentials before capability issuance.
    try:
        oauth = guard_review_oauth_metadata(store)
    except GuardReviewContractError as error:
        raise CommandCapabilityError("cloud_connection_required") from error
    if not oauth.machine_id or not oauth.installation_id:
        raise CommandCapabilityError("cloud_connection_required")
    local_installation_id = str(store.get_device_metadata().get("installation_id") or "")
    if local_installation_id != oauth.installation_id:
        raise CommandCapabilityError("cloud_device_binding_mismatch")
    # OAuth machine and local-installation identities remain distinct; the
    # DPoP device ID binds command capabilities.
    device_id = oauth.device_id
    workspace_id = oauth.workspace_id
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
    if set(normalized_operations) - supported or "guard.review.resolveExact" in operations:
        raise CommandCapabilityError("unsupported_capability_operation")
    if POLICY_MEMORY_COMMAND_OPERATIONS & set(normalized_operations) and len(normalized_operations) != 1:
        raise CommandCapabilityError("policy_memory_capability_must_be_isolated")
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


def _resident_home(store: GuardStore) -> Path:
    """The Guard home the resident answers for, or no answer at all."""

    guard_home = getattr(store, "guard_home", None)
    if not isinstance(guard_home, Path):
        raise CommandCapabilityUnavailableError
    return guard_home


def _signing_material_for_resident(store: GuardStore, *, create: bool = False) -> tuple[str | None, str | None]:
    """The local signing secret as the resident takes it, or a missing pair.

    A store with no key is not an error here: the resident answers
    ``local_signing_key_unavailable`` itself, in the same place it would have
    refused a key that does not match the envelope. ``create`` mints the key
    for the one caller that issues a capability; whether the envelope it goes
    on is genuine is still the runtime's answer.
    """

    key, key_id = store._policy_integrity_secret_material(create=create)
    if not isinstance(key, bytes) or not isinstance(key_id, str):
        return None, None
    return base64.urlsafe_b64encode(key).rstrip(b"=").decode("ascii"), key_id


def _binding_for_resident(store: GuardStore) -> tuple[str | None, str | None, str | None]:
    """The device binding the capability must name, or the code that blocked it."""

    try:
        device_id, workspace_id = _oauth_target(store)
    except CommandCapabilityError as error:
        return None, None, error.code
    return device_id, workspace_id, None


def _capability_verdict(
    store: GuardStore,
    *,
    now: str | None = None,
    job: Mapping[str, object] | None = None,
    schema_versions: Mapping[str, int] | None = None,
    replay_identity: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """The resident's verdict on the stored capability and what it was asked.

    Every comparison - the envelope's signature, its clock and binding checks,
    the job's identity and the replay rows - happens in the runtime. This side
    only reads the inputs out of the store.
    """

    home = _resident_home(store)
    key_b64, key_id = _signing_material_for_resident(store)
    device_id, workspace_id, oauth_error = _binding_for_resident(store)
    return native_command_capability(
        capability=store.get_sync_payload(COMMAND_CAPABILITY_STATE_KEY),
        integrity_key_b64=key_b64,
        integrity_key_id=key_id,
        device_id=device_id,
        workspace_id=workspace_id,
        oauth_error=oauth_error,
        now=now if now is not None else datetime.now(timezone.utc).isoformat(),
        job=job,
        schema_versions=dict(schema_versions or {}),
        replay_items=_state_items(store.get_sync_payload(COMMAND_REPLAY_STATE_KEY)),
        replay_identity=replay_identity,
        guard_home=home,
    )


def _granted(verdict: Mapping[str, object]) -> dict[str, object]:
    """The verified capability's own fields, or its refusal code raised."""

    if not verdict.get("capability_valid"):
        raise CommandCapabilityError(str(verdict.get("reason") or "signed_payload_missing"))
    operations = verdict.get("operations")
    return {
        "issuer": verdict.get("issuer"),
        "issuedAt": verdict.get("issued_at"),
        "expiresAt": verdict.get("expires_at"),
        "deviceId": verdict.get("device_id"),
        "workspaceId": verdict.get("workspace_id"),
        "operations": [str(operation) for operation in operations] if isinstance(operations, list) else [],
    }


def _verified_capability(store: GuardStore, *, now: str | None = None) -> dict[str, object]:
    return _granted(_capability_verdict(store, now=now))


def command_capability_status(store: GuardStore, *, now: str | None = None) -> dict[str, object]:
    pending_status = [
        {key: item[key] for key in ("id", "operation", "issuer", "expiresAt", "approveCommand") if key in item}
        for item in pending_command_approvals(store, now=now)
    ]
    try:
        capability = _verified_capability(store, now=now)
    except (CommandCapabilityError, CommandCapabilityUnavailableError) as error:
        # A runtime that gave no verdict reports as plainly as a refused
        # capability: status shows what is enabled, and nothing is.
        reason = error.code if isinstance(error, CommandCapabilityError) else CommandCapabilityUnavailableError.reason
        return {
            "enabled": False,
            "capability_valid": False,
            "reason": reason,
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
    except (CommandCapabilityError, CommandCapabilityUnavailableError):
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


def authorize_command_job(
    store: GuardStore,
    job: Mapping[str, object],
    *,
    schema_versions: Mapping[str, int],
    now: str | None = None,
) -> AuthorizedCommandJob:
    """Validate capability and complete source-to-target lease bindings."""

    verdict = _capability_verdict(store, now=now, job=job, schema_versions=schema_versions)
    _granted(verdict)
    authorization = verdict.get("authorization")
    if not isinstance(authorization, dict):
        raise CommandCapabilityUnavailableError
    if not authorization.get("authorized"):
        raise CommandCapabilityError(str(authorization.get("reason") or "command_operation_unsupported"))
    identity = authorization.get("identity")
    operation = authorization.get("operation")
    if not isinstance(identity, dict) or not isinstance(operation, str):
        raise CommandCapabilityUnavailableError
    return AuthorizedCommandJob(
        identity={str(key): value for key, value in identity.items()},
        operation=operation,
        requires_local_approval=bool(authorization.get("requires_local_approval")),
    )


def _identity_digest(store: GuardStore, identity: Mapping[str, object]) -> str:
    """The digest the replay rows and the approval grants name ``identity`` by.

    It decides which stored grant answers for a job, so the runtime computes
    it over its own canonical bytes rather than this side reproducing them.
    """

    digest = _envelope(store, "digest", dict(identity))
    if not isinstance(digest, str) or not digest:
        raise CommandCapabilityError(CommandEnvelopeUnavailableError.reason)
    return digest


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
        "approveCommand": render_portable_command(["hol-guard", "commands", "approve", job_id, "--confirm", job_id]),
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
            "identityDigest": _identity_digest(store, identity),
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


def command_identity_digest(store: GuardStore, authorized: AuthorizedCommandJob) -> str:
    """The runtime's digest for ``authorized``, for a caller that needs it twice.

    Spending a grant and recording the replay row both name the job by this
    digest. A caller that asks for it once, before it touches either, cannot
    lose an approval to a resident that stops answering between the two.
    """

    return _identity_digest(store, authorized.identity)


def consume_local_command_approval(
    store: GuardStore,
    authorized: AuthorizedCommandJob,
    *,
    now: str | None = None,
    identity_digest: str | None = None,
) -> bool:
    if not authorized.requires_local_approval:
        return True
    items = _state_items(store.get_sync_payload(COMMAND_LOCAL_APPROVALS_STATE_KEY))
    if identity_digest is None:
        identity_digest = _identity_digest(store, authorized.identity)
    matched_index: int | None = None
    for index, item in enumerate(items):
        if item.get("identityDigest") != identity_digest:
            continue
        try:
            verified = _verify_signed_payload(store, item)
        except CommandCapabilityError as error:
            if error.code == CommandEnvelopeUnavailableError.reason:
                # A resident that cannot answer is not a grant that fails to
                # match. Walking on would drop a real approval and ask the user
                # to approve this job a second time.
                raise
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
    identity_digest: str | None = None,
) -> None:
    if identity_digest is None:
        identity_digest = _identity_digest(store, authorized.identity)
    consumed_at = _now_datetime(now)
    raw_items = _state_items(store.get_sync_payload(COMMAND_REPLAY_STATE_KEY))
    items = [
        item
        for item in raw_items
        if (expires_at := _parse_timestamp(item.get("expiresAt"))) is not None and expires_at > consumed_at
    ]
    items.append(
        {
            "identityDigest": identity_digest,
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
    """Whether the replay rows already hold ``identity``, per the runtime.

    A caller that authorized its own operation still asks the runtime this
    question, so one evaluator decides replay for every leased job.
    """

    verdict = _capability_verdict(store, now=now, replay_identity=identity)
    replayed = verdict.get("replayed")
    return replayed if isinstance(replayed, bool) else True


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
    """Best-effort local audit; never raises."""
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
    "consume_local_command_approval",
    "issue_command_capability",
    "mark_command_job_consumed",
    "pending_command_approvals",
    "register_pending_command",
    "revoke_command_capability",
]
