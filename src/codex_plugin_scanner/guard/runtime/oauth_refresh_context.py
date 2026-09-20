"""OAuth refresh and authentication with the runtime's current authority hooks."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..cli.oauth_client import GuardDpopKeyMaterial
    from ..oauth_connection_authority import OAuthConnectionSnapshot
    from ..store import GuardStore


def refresh_access_token_once(
    *,
    token_endpoint: str,
    client_id: str,
    refresh_token: str,
    dpop_key_material: GuardDpopKeyMaterial,
    request_validator: Callable[[], None] | None = None,
    completion_validator: Callable[[], None] | None = None,
) -> dict[str, object]:
    from . import runner as api

    if api._guard_runtime_was_upgraded():
        raise api.GuardSyncNotAvailableError(api._guard_runtime_upgrade_restart_message(), retryable=True)
    request_body = api.urllib.parse.urlencode(
        {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": refresh_token,
        }
    ).encode("utf-8")
    dpop_nonce: str | None = None
    nonce_retry_count = 0
    while True:
        try:
            dpop_proof = api._sign_guard_dpop_proof(
                request_url=token_endpoint,
                method="POST",
                dpop_key_material=dpop_key_material,
                nonce=dpop_nonce,
            )
        except (RuntimeError, TypeError, ValueError) as error:
            raise api.GuardSyncAuthorizationExpiredError(
                f"{api._guard_oauth_reauthorization_message()} {error}"
            ) from error
        request = api.urllib.request.Request(
            token_endpoint,
            data=request_body,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "User-Agent": api._GUARD_SYNC_USER_AGENT,
                "DPoP": dpop_proof,
            },
        )
        if request_validator is not None:
            request_validator()
        try:
            with api.managed_urlopen(request, timeout=api._SYNC_HTTP_TIMEOUT_SECONDS) as response:
                payload = api.json.loads(response.read().decode("utf-8"))
        except api.urllib.error.HTTPError as error:
            if completion_validator is not None:
                completion_validator()
            try:
                payload = api._http_error_payload(error) if error.code in {400, 401, 403} else None
                challenge_nonce = api._dpop_nonce_from_http_error(error, payload)
                if challenge_nonce is not None and challenge_nonce != dpop_nonce and nonce_retry_count < 3:
                    dpop_nonce = challenge_nonce
                    nonce_retry_count += 1
                    continue
                if error.code in {400, 401, 403}:
                    if api._invalid_grant_oauth_payload(payload):
                        raise api.GuardSyncAuthorizationExpiredError(
                            api._guard_oauth_reconnect_after_revoked_message()
                        ) from error
                    refresh_error_message = api._oauth_refresh_error_message(error)
                    raise api.GuardSyncAuthorizationExpiredError(
                        f"{api._guard_oauth_reauthorization_message()} {refresh_error_message}"
                    ) from error
                refresh_error_message = api._oauth_refresh_error_message(error)
                raise RuntimeError(f"Guard OAuth token refresh failed: {refresh_error_message}") from error
            finally:
                # Error bodies are part of the completed provider attempt.
                # Run this outside the transport catches, including on nonce retry.
                if completion_validator is not None:
                    completion_validator()
        except OSError as error:
            if completion_validator is not None:
                completion_validator()
            raise RuntimeError(api._sync_url_error_message(error)) from error
        except Exception:
            if completion_validator is not None:
                completion_validator()
            raise
        if request_validator is not None:
            request_validator()
        if not isinstance(payload, dict):
            raise api.GuardSyncAuthorizationExpiredError(api._guard_oauth_reauthorization_message())
        access_token = api._optional_string(payload.get("access_token"))
        token_type = api._optional_string(payload.get("token_type"))
        if access_token is None or token_type is None or token_type.lower() not in {"bearer", "dpop"}:
            raise api.GuardSyncAuthorizationExpiredError(api._guard_oauth_reauthorization_message())
        access_token_expires_at = api._oauth_access_token_expires_at(
            access_token,
            payload=payload,
            now=api.datetime.now(api.timezone.utc),
        )
        return {
            "access_token": access_token,
            "access_token_expires_at": access_token_expires_at,
            "package_firewall_entitlement": api.build_oauth_package_firewall_entitlement(
                payload,
                now=api.datetime.now(api.timezone.utc),
            ),
            "cloud_user_profile": api.extract_cloud_user_profile(payload),
            "had_guard_local_entitlement": isinstance(payload.get("guard_local_entitlement"), dict),
            "refresh_token": api._optional_string(payload.get("refresh_token")) or refresh_token,
        }


def resolve_sync_auth_context(
    store: GuardStore,
    oauth_credentials: dict[str, object],
    *,
    persist_recovered_secret: bool = False,
    force_refresh: bool = False,
    expected_connection: OAuthConnectionSnapshot | None = None,
    required_connection: OAuthConnectionSnapshot | None = None,
    validate_request: Callable[[], None] | None = None,
    connection_observer: Callable[[OAuthConnectionSnapshot], None] | None = None,
) -> dict[str, object]:
    from . import runner as api

    captured = expected_connection or api._guard_oauth_connection_for_credentials(
        store, oauth_credentials, required_connection=required_connection
    )
    if captured.credentials() != oauth_credentials or (
        required_connection is not None and not required_connection.same_authority(captured)
    ):
        raise RuntimeError("The connection changed before authentication could complete.")
    api._require_guard_oauth_connection(store, captured)
    if validate_request is not None:
        validate_request()
    issuer = api._optional_string(oauth_credentials.get("issuer"))
    client_id = api._optional_string(oauth_credentials.get("client_id"))
    refresh_token = api._optional_string(oauth_credentials.get("refresh_token"))
    if issuer is None or client_id is None or refresh_token is None:
        raise api.GuardSyncAuthorizationExpiredError(api._guard_oauth_reauthorization_message())
    dpop_key_material = api._oauth_dpop_key_material(oauth_credentials)
    try:
        oauth_client = api.resolve_guard_oauth_client_config(issuer)
    except ValueError as error:
        raise api.GuardSyncEndpointUntrustedError(f"{api._guard_sync_reconnect_message()} {error}") from error
    cached_access_token = (
        None
        if force_refresh
        else api._cached_oauth_access_token(oauth_credentials, now=api.datetime.now(api.timezone.utc))
    )
    if cached_access_token is not None and not persist_recovered_secret:
        sync_url = api._validate_guard_sync_url(
            api._oauth_sync_url_from_issuer(oauth_client.issuer),
            issuer=oauth_client.issuer,
        )
        api._require_guard_oauth_connection(store, captured)
        if validate_request is not None:
            validate_request()
        if connection_observer is not None:
            connection_observer(captured)
        return {
            "sync_url": sync_url,
            "access_token": cached_access_token,
            "dpop_key_material": dpop_key_material,
        }

    effective_credentials_ref = {"value": oauth_credentials}
    effective_connection_ref = {"value": captured}

    def _validate_attempt() -> None:
        api._require_guard_oauth_connection(store, effective_connection_ref["value"])
        if validate_request is not None:
            validate_request()

    def _reload_current_oauth_credentials() -> api._OAuthRefreshRequest:
        current = store.capture_oauth_connection(allow_recoverable=True)
        if current is None or (required_connection is not None and not required_connection.same_authority(current)):
            raise RuntimeError("The connection changed before authentication could complete.")
        reloaded_credentials = current.credentials()
        next_issuer = api._optional_string(reloaded_credentials.get("issuer"))
        next_client = api._optional_string(reloaded_credentials.get("client_id"))
        next_refresh_token = api._optional_string(reloaded_credentials.get("refresh_token"))
        if next_issuer is None or next_client is None or next_refresh_token is None:
            raise api.GuardSyncAuthorizationExpiredError(api._guard_oauth_reauthorization_message())
        try:
            next_config = api.resolve_guard_oauth_client_config(next_issuer)
        except ValueError as error:
            raise api.GuardSyncEndpointUntrustedError(f"{api._guard_sync_reconnect_message()} {error}") from error
        next_key = api._oauth_dpop_key_material(reloaded_credentials)
        effective_credentials_ref["value"] = reloaded_credentials
        effective_connection_ref["value"] = current
        return api._OAuthRefreshRequest(next_config.token_endpoint, next_client, next_refresh_token, next_key)

    refreshed = api._refresh_guard_oauth_access_token(
        token_endpoint=oauth_client.token_endpoint,
        client_id=client_id,
        refresh_token=refresh_token,
        dpop_key_material=dpop_key_material,
        credential_reloader=_reload_current_oauth_credentials,
        request_validator=_validate_attempt,
        completion_validator=validate_request,
    )
    effective_credentials = effective_credentials_ref["value"]
    _validate_attempt()
    effective_dpop_key_material, committed_connection = api._apply_refreshed_oauth_credentials(
        store=store,
        effective_credentials=effective_credentials,
        refreshed=refreshed,
        refresh_token=refresh_token,
        dpop_key_material=dpop_key_material,
        persist_recovered_secret=persist_recovered_secret,
        force_refresh=force_refresh,
        expected_connection=effective_connection_ref["value"],
    )
    effective_issuer = str(effective_credentials["issuer"])
    sync_url = api._validate_guard_sync_url(
        api._oauth_sync_url_from_issuer(effective_issuer),
        issuer=effective_issuer,
    )
    if required_connection is not None and not required_connection.same_authority(committed_connection):
        raise RuntimeError("The connection changed before authentication could complete.")
    api._require_guard_oauth_connection(store, committed_connection)
    if validate_request is not None:
        validate_request()
    if connection_observer is not None:
        connection_observer(committed_connection)
    return {
        "sync_url": sync_url,
        "access_token": str(refreshed["access_token"]),
        "dpop_key_material": effective_dpop_key_material,
    }
