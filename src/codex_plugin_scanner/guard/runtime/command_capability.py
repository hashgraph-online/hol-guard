"""Signed, revocable local capability for Guard Cloud commands."""

from __future__ import annotations

import os
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from ..native_command_capability import (
    CommandCapabilityUnavailableError,
    native_command_capability,
    native_command_capability_issue,
)
from ..native_command_envelope import CommandEnvelopeUnavailableError
from ..native_command_state import (
    CommandStateRefusedError,
    CommandStateUnavailableError,
    native_command_state,
)
from ..portable_command import render_portable_command
from ..review_contracts import GuardReviewContractError, guard_review_oauth_metadata
from ..store import GuardStore
from .command_capability_keys import (
    CommandCapabilityError,
    _envelope,
    _resident_home,
    _signing_material_for_resident,
)
from .time_support import parse_utc_timestamp

COMMAND_CAPABILITY_STATE_KEY = "guard_command_capability_v1"
COMMAND_PENDING_APPROVALS_STATE_KEY = "guard_command_pending_approvals_v1"
COMMAND_LOCAL_APPROVALS_STATE_KEY = "guard_command_local_approvals_v1"
COMMAND_REPLAY_STATE_KEY = "guard_command_replay_state_v1"
COMMAND_QUEUE_RUNTIME_STATE_KEY = "guard_command_queue_state"
COMMAND_CAPABILITY_VERSION = 1
COMMAND_CAPABILITY_DEFAULT_TTL_SECONDS = 30 * 24 * 60 * 60
COMMAND_QUEUE_ENABLED_ENV = "GUARD_CLOUD_COMMAND_QUEUE_ENABLED"


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
    """Issue and persist an exact local command capability.

    ``operations`` carries the ``--operations`` words as typed. The resident
    reads the group name, the comma-joined lists and the spacing, and answers
    with the exact operations the capability may carry or the code that refuses
    it; nothing here decides what a grant can authorize.
    """

    issued_at = _now_datetime(now)
    try:
        issued = native_command_capability_issue(
            requested=operations,
            supported_operations=supported_operations,
            issuer=issuer,
            ttl_seconds=ttl_seconds,
            guard_home=_resident_home(store),
        )
    except CommandCapabilityUnavailableError as error:
        raise CommandCapabilityError(error.reason) from None
    if not issued.get("granted"):
        reason = issued.get("reason")
        raise CommandCapabilityError(str(reason) if reason else "unsupported_capability_operation")
    granted_operations = issued.get("operations")
    if not isinstance(granted_operations, list) or not granted_operations:
        raise CommandCapabilityError("unsupported_capability_operation")
    normalized_operations = tuple(str(operation) for operation in granted_operations)
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
    # The runtime installs it and, in the same transaction, drops any result,
    # lease, grant or waiting job left by an earlier queue or capability.
    _ledger(store, "issue", now=issued_at.isoformat(), capability=capability)
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


def _binding_for_resident(store: GuardStore) -> tuple[str | None, str | None, str | None]:
    """The device binding the capability must name, or the code that blocked it."""

    try:
        device_id, workspace_id = _oauth_target(store)
    except CommandCapabilityError as error:
        return None, None, error.code
    return device_id, workspace_id, None


def _replay_subject(subject: object) -> object:
    """Send the replay lookup only the fields it filters on.

    A job payload can be far larger than the ledger's request limit, and the
    lookup reads nothing but the job id and the idempotency key.
    """

    if not isinstance(subject, Mapping):
        return subject
    return {key: subject[key] for key in ("id", "idempotencyKey") if key in subject}


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
    only reads the inputs out of the store. Replay rows only change a job or
    replay-identity answer, so an operations-only question ships none and a
    job question ships only the rows that could name that job.
    """

    home = _resident_home(store)
    key_b64, key_id = _signing_material_for_resident(store)
    device_id, workspace_id, oauth_error = _binding_for_resident(store)
    current = now if now is not None else datetime.now(timezone.utc).isoformat()
    subject = job if job is not None else replay_identity
    replay_items = (
        _ledger_rows(
            _ledger(
                store,
                "replay_rows",
                now=current,
                subject=_replay_subject(subject),
            )
        )
        if subject is not None
        else []
    )
    return native_command_capability(
        capability=store.get_sync_payload(COMMAND_CAPABILITY_STATE_KEY),
        integrity_key_b64=key_b64,
        integrity_key_id=key_id,
        device_id=device_id,
        workspace_id=workspace_id,
        oauth_error=oauth_error,
        now=current,
        job=job,
        schema_versions=dict(schema_versions or {}),
        replay_items=replay_items,
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
    try:
        waiting = pending_command_approvals(store, now=now)
    except CommandCapabilityError:
        # Status and revocation still answer while the ledger does not; they
        # just cannot list what is waiting.
        waiting = []
    pending_status = [
        {key: item[key] for key in ("id", "operation", "issuer", "expiresAt", "approveCommand") if key in item}
        for item in waiting
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
    # The capability and every ledger row go in one runtime transaction.
    _ledger(store, "clear", now=revoked_at)
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


def _ledger(
    store: GuardStore,
    op: str,
    *,
    now: str,
    signing: bool = False,
    **fields: object,
) -> object:
    """One answer from the runtime's command ledger, or its refusal raised.

    Pending approvals, local grants and replay rows are each read, changed and
    written back whole. The runtime does that in one SQLite transaction, so
    review drain threads and other processes cannot drop each other's rows.
    ``signing`` passes the local signing secret for the operations that sign
    or verify a grant; whether a grant is genuine is the runtime's answer.
    """

    if signing:
        key_b64, key_id = _signing_material_for_resident(store, create=False)
        fields = {**fields, "integrity_key_b64": key_b64, "integrity_key_id": key_id}
    try:
        return native_command_state(_resident_home(store), op, now=now, **fields)
    except CommandStateUnavailableError as error:
        # A ledger that gives no answer is the same fail-closed refusal as a
        # resident that cannot sign: the queue posts it on the job result and
        # the CLI prints it, keeping its own code.
        raise CommandCapabilityError(CommandEnvelopeUnavailableError.reason) from error
    except CommandStateRefusedError as error:
        raise CommandCapabilityError(error.code) from error


def _ledger_rows(answer: object) -> list[dict[str, object]]:
    if not isinstance(answer, list):
        raise CommandCapabilityError(CommandEnvelopeUnavailableError.reason)
    return [{str(key): value for key, value in item.items()} for item in answer if isinstance(item, dict)]


def register_pending_command(
    store: GuardStore,
    authorized: AuthorizedCommandJob,
    job: Mapping[str, object],
    *,
    now: str | None = None,
) -> dict[str, object]:
    recorded_at = _now_datetime(now).isoformat()
    job_id = str(authorized.identity["id"])
    issuer = job.get("issuer") if isinstance(job.get("issuer"), str) else "Guard Cloud"
    item = _ledger(
        store,
        "register_pending",
        now=recorded_at,
        identity=dict(authorized.identity),
        issuer=issuer,
        approve_command=render_portable_command(["hol-guard", "commands", "approve", job_id, "--confirm", job_id]),
    )
    if not isinstance(item, dict):
        raise CommandCapabilityError(CommandEnvelopeUnavailableError.reason)
    _audit(
        store,
        "cloud_command.local_approval_required",
        {"job_id": job_id, "operation": authorized.operation, "issuer": issuer},
        recorded_at,
    )
    return {str(key): value for key, value in item.items()}


def pending_command_approvals(store: GuardStore, *, now: str | None = None) -> list[dict[str, object]]:
    return _ledger_rows(_ledger(store, "pending", now=_now_datetime(now).isoformat()))


def approve_pending_command(
    store: GuardStore,
    job_id: str,
    *,
    issuer: str = "local-cli",
    now: str | None = None,
) -> dict[str, object]:
    approved_at = _now_datetime(now).isoformat()
    approved = _ledger(store, "approve", now=approved_at, signing=True, job_id=job_id, issuer=issuer)
    if not isinstance(approved, dict):
        raise CommandCapabilityError(CommandEnvelopeUnavailableError.reason)
    _audit(
        store,
        "cloud_command.local_approval_granted",
        {"job_id": job_id, "operation": approved.get("operation"), "issuer": issuer},
        approved_at,
    )
    return {str(key): value for key, value in approved.items()}


def command_identity_digest(store: GuardStore, authorized: AuthorizedCommandJob) -> str:
    """The runtime's digest for ``authorized``, for a caller that needs it twice.

    Spending a grant and recording the replay row both name the job by this
    digest. The ledger checks a digest it is handed against its own, so a
    caller that names the job once cannot spend one job's grant for another.
    """

    return _identity_digest(store, authorized.identity)


def consume_local_command_approval(
    store: GuardStore,
    authorized: AuthorizedCommandJob,
    *,
    now: str | None = None,
    identity_digest: str | None = None,
    record_replay: bool = False,
) -> bool:
    """Spend the job's local grant and, when asked, record its replay row.

    The runtime spends the grant and writes the replay row in one
    transaction, so a spent grant always has its replay row. A job that needs
    no local approval only records the row.
    """

    if not authorized.requires_local_approval:
        if record_replay:
            mark_command_job_consumed(store, authorized, now=now, identity_digest=identity_digest)
        return True
    consumed = _ledger(
        store,
        "consume",
        now=_now_datetime(now).isoformat(),
        signing=True,
        identity=dict(authorized.identity),
        identity_digest=identity_digest,
        operation=authorized.operation if record_replay else None,
        record_replay=True if record_replay else None,
    )
    if not isinstance(consumed, bool):
        raise CommandCapabilityError(CommandEnvelopeUnavailableError.reason)
    return consumed


def mark_command_job_consumed(
    store: GuardStore,
    authorized: AuthorizedCommandJob,
    *,
    now: str | None = None,
    identity_digest: str | None = None,
) -> None:
    _ledger(
        store,
        "mark_consumed",
        now=_now_datetime(now).isoformat(),
        identity=dict(authorized.identity),
        identity_digest=identity_digest,
        operation=authorized.operation,
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
