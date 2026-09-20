"""Oauth repair.

Shared state and replaceable dependencies belong to the runner facade.
"""

from __future__ import annotations

from . import runner


def _oauth_refresh_error_message(error: runner.urllib.error.HTTPError) -> str:
    try:
        raw_body = error.read().decode("utf-8")
    except OSError:
        raw_body = ""
    try:
        payload = runner.json.loads(raw_body) if raw_body else None
    except runner.json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict):
        description = runner._optional_string(payload.get("error_description"))
        if description is not None:
            return description
        error_code = runner._optional_string(payload.get("error"))
        if error_code is not None:
            return error_code
    normalized_body = raw_body.strip()
    if normalized_body:
        return normalized_body
    return f"HTTP Error {error.code}: {error.reason}"


def _guard_oauth_reauthorization_message() -> str:
    return "Guard authorization expired. Run `hol-guard connect` to sign in again."


def _guard_oauth_reconnect_after_revoked_message() -> str:
    return (
        "Guard Cloud sign-in on this device is no longer valid. Run `hol-guard connect` to repair it and sign in again."
    )


def _guard_runtime_was_upgraded() -> bool:
    loaded_identity = runner._LOADED_HOL_GUARD_RUNTIME_PACKAGE_IDENTITY
    if loaded_identity is None:
        return True
    return runner._hol_guard_runtime_package_identity() != loaded_identity


def _guard_runtime_upgrade_restart_message() -> str:
    return (
        "HOL Guard was upgraded while this process was running. Restart the agent application "
        "before Guard Cloud access resumes."
    )


def _invalid_grant_oauth_payload(payload: object) -> bool:
    if not isinstance(payload, dict):
        return False
    return runner._invalid_grant_oauth_error_details(
        runner._optional_string(payload.get("error")),
        runner._optional_string(payload.get("error_description")),
    )


def _invalid_grant_oauth_error_details(
    error_code: str | None,
    description: str | None,
) -> bool:
    return error_code == "invalid_grant" or (
        description is not None and "missing, expired, or already consumed" in description.lower()
    )


def _oauth_authorization_error_requires_fresh_sign_in(error: Exception) -> bool:
    message = str(error).strip().lower()
    return (
        "invalid_grant" in message
        or "missing, expired, or already consumed" in message
        or runner._guard_oauth_reconnect_after_revoked_message().lower() in message
    )


def clear_revoked_guard_oauth_sign_in(store: runner.GuardStore) -> bool:
    """Return True when refresh proves the local OAuth grant was revoked and cleared."""
    try:
        with runner._guard_sync_auth_lock(store):
            credentials = store.get_oauth_local_credentials(allow_primary=True)
            if credentials is None:
                return False
            try:
                runner._resolve_guard_sync_auth_context_from_oauth_credentials(store, credentials)
            except runner.GuardSyncAuthorizationExpiredError as error:
                if runner._oauth_authorization_error_requires_fresh_sign_in(error):
                    store._clear_oauth_local_credentials_locked()
                    return True
                return False
    except (RuntimeError, OSError, TimeoutError):
        return False
    return False


def repair_guard_cloud_connect_storage(store: runner.GuardStore) -> dict[str, object]:
    """Repair local OAuth storage without clearing sign-in state."""
    repaired_storage = store.repair_oauth_local_credential_storage_from_primary()
    credentials = store.get_oauth_local_credentials(allow_primary=True)
    repaired_oauth_binding = False
    rebound_review_events = 0
    if credentials is not None:
        repaired_oauth_binding = runner._persist_recovered_oauth_binding(store, credentials)
        binding = store.get_review_event_oauth_binding()
        if binding is not None:
            rebound_review_events = store.refresh_review_event_outbox_binding_for_identity(
                workspace_id=binding["workspace_id"],
                oauth_subject_hash=binding["oauth_subject_hash"],
                machine_id=binding["machine_id"],
                machine_installation_id=binding["machine_installation_id"],
            )
    existing_sign_in_valid = credentials is not None
    return {
        "cleared_stale_sign_in": False,
        "existing_sign_in_valid": existing_sign_in_valid,
        "rebound_review_events": rebound_review_events,
        "repaired_oauth_binding": repaired_oauth_binding,
        "repaired_storage": repaired_storage,
    }


def prepare_guard_cloud_connect_authorization(store: runner.GuardStore) -> dict[str, object]:
    """Repair local OAuth storage and clear revoked sign-in before reconnect."""
    repaired_storage = runner.repair_guard_cloud_connect_storage(store)["repaired_storage"]
    cleared_stale_sign_in = runner.clear_revoked_guard_oauth_sign_in(store)
    existing_sign_in_valid = store.get_oauth_local_credentials(allow_primary=True) is not None
    return {
        "repaired_storage": repaired_storage,
        "cleared_stale_sign_in": cleared_stale_sign_in,
        "existing_sign_in_valid": existing_sign_in_valid,
    }


def _guard_sync_reconnect_message() -> str:
    return "Guard Cloud sync endpoint is not trusted. Run `hol-guard connect` to restore Cloud sync."


def _validate_guard_sync_url(sync_url: str, *, issuer: str | None = None) -> str:
    try:
        return runner.validate_guard_sync_endpoint(sync_url, issuer=issuer)
    except ValueError as error:
        raise runner.GuardSyncEndpointUntrustedError(f"{runner._guard_sync_reconnect_message()} {error}") from error
