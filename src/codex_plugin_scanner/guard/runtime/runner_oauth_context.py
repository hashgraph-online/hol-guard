"""Oauth context.

Shared state and replaceable dependencies belong to the runner facade.
"""

from __future__ import annotations

from . import runner


def _resolve_guard_sync_auth_context_from_oauth_credentials(
    store: runner.GuardStore,
    oauth_credentials: dict[str, object],
    *,
    persist_recovered_secret: bool = False,
    force_refresh: bool = False,
) -> dict[str, object]:
    issuer = runner._optional_string(oauth_credentials.get("issuer"))
    client_id = runner._optional_string(oauth_credentials.get("client_id"))
    refresh_token = runner._optional_string(oauth_credentials.get("refresh_token"))
    if issuer is None or client_id is None or refresh_token is None:
        raise runner.GuardSyncAuthorizationExpiredError(runner._guard_oauth_reauthorization_message())
    dpop_key_material = runner._oauth_dpop_key_material(oauth_credentials)
    try:
        oauth_client = runner.resolve_guard_oauth_client_config(issuer)
    except ValueError as error:
        raise runner.GuardSyncEndpointUntrustedError(f"{runner._guard_sync_reconnect_message()} {error}") from error
    cached_access_token = (
        None
        if force_refresh
        else runner._cached_oauth_access_token(oauth_credentials, now=runner.datetime.now(runner.timezone.utc))
    )
    if cached_access_token is not None and not persist_recovered_secret:
        sync_url = runner._validate_guard_sync_url(
            runner._oauth_sync_url_from_issuer(oauth_client.issuer),
            issuer=oauth_client.issuer,
        )
        return {
            "sync_url": sync_url,
            "access_token": cached_access_token,
            "dpop_key_material": dpop_key_material,
        }

    effective_credentials_ref: dict[str, dict[str, object]] = {"value": oauth_credentials}

    def _reload_current_oauth_credentials() -> tuple[str, runner.GuardDpopKeyMaterial] | None:
        reloaded_credentials = store.get_oauth_local_credentials(allow_primary=True)
        if not isinstance(reloaded_credentials, dict):
            return None
        reloaded_refresh_token = runner._optional_string(reloaded_credentials.get("refresh_token"))
        if reloaded_refresh_token is None:
            return None
        effective_credentials_ref["value"] = reloaded_credentials
        return reloaded_refresh_token, runner._oauth_dpop_key_material(reloaded_credentials)

    refreshed = runner._refresh_guard_oauth_access_token(
        token_endpoint=oauth_client.token_endpoint,
        client_id=client_id,
        refresh_token=refresh_token,
        dpop_key_material=dpop_key_material,
        credential_reloader=_reload_current_oauth_credentials,
    )
    effective_credentials = effective_credentials_ref["value"]
    effective_dpop_key_material = runner._apply_refreshed_oauth_credentials(
        store=store,
        effective_credentials=effective_credentials,
        refreshed=refreshed,
        refresh_token=refresh_token,
        dpop_key_material=dpop_key_material,
        persist_recovered_secret=persist_recovered_secret,
        force_refresh=force_refresh,
    )
    sync_url = runner._validate_guard_sync_url(
        runner._oauth_sync_url_from_issuer(oauth_client.issuer),
        issuer=oauth_client.issuer,
    )
    return {
        "sync_url": sync_url,
        "access_token": str(refreshed["access_token"]),
        "dpop_key_material": effective_dpop_key_material,
    }


def _apply_refreshed_oauth_credentials(
    *,
    store: runner.GuardStore,
    effective_credentials: dict[str, object],
    refreshed: dict[str, object],
    refresh_token: str,
    dpop_key_material: runner.GuardDpopKeyMaterial,
    persist_recovered_secret: bool,
    force_refresh: bool,
) -> runner.GuardDpopKeyMaterial:
    """Project the refresh result onto the credential store and return context.

    Removes the wrapper's internal `_effective_*` markers from `refreshed`,
    persists the rotated credentials when state actually changed (using the
    effective snapshot — the one the retry leg may have reloaded), and
    returns the effective DPoP key material for the caller to sign with.
    """
    refreshed.pop("_effective_refresh_token", None)
    effective_dpop_key_material_raw = refreshed.pop("_effective_dpop_key_material", None)
    effective_dpop_key_material = (
        effective_dpop_key_material_raw
        if isinstance(effective_dpop_key_material_raw, runner.GuardDpopKeyMaterial)
        else dpop_key_material
    )
    rotated_refresh_token = str(refreshed["refresh_token"])
    refreshed_entitlement = refreshed.get("package_firewall_entitlement")
    package_firewall_entitlement: dict[str, object] | None = (
        refreshed_entitlement if isinstance(refreshed_entitlement, dict) else None
    )
    refreshed_cloud_user_profile = refreshed.get("cloud_user_profile")
    if not isinstance(refreshed_cloud_user_profile, dict):
        refreshed_cloud_user_profile = None
    had_entitlement = bool(refreshed.get("had_guard_local_entitlement"))
    # When the refresh response includes a guard_local_entitlement but no
    # user_profile, clear the stale profile rather than preserving it.
    # When there's no guard_local_entitlement at all (old server), keep existing.
    # Sources: prefer the refresh response, then the effective (possibly
    # reloaded-by-peer) credentials dict; compare against the same effective
    # snapshot so a peer's newer profile is not treated as a change.
    effective_cloud_user_profile: dict[str, str] | None
    if had_entitlement:
        effective_cloud_user_profile = refreshed_cloud_user_profile
    else:
        effective_cloud_user_profile = refreshed_cloud_user_profile or runner._extract_dict_field(
            effective_credentials, "cloud_user_profile"
        )
    stored_cloud_user_profile = runner._extract_dict_field(effective_credentials, "cloud_user_profile")
    profile_changed = effective_cloud_user_profile != stored_cloud_user_profile
    if (
        force_refresh
        or rotated_refresh_token != refresh_token
        or package_firewall_entitlement is not None
        or profile_changed
        or persist_recovered_secret
    ):
        runner._persist_rotated_oauth_refresh_token(
            store=store,
            credentials=effective_credentials,
            package_firewall_entitlement=package_firewall_entitlement,
            cloud_user_profile=effective_cloud_user_profile,
            refresh_token=rotated_refresh_token,
            access_token=runner._optional_string(refreshed.get("access_token")),
            access_token_expires_at=runner._optional_string(refreshed.get("access_token_expires_at")),
            force_primary_secret_rewrite=force_refresh,
        )
    return effective_dpop_key_material


def _test_sync_auth_context_from_env() -> dict[str, object] | None:
    if not runner.os.environ.get("PYTEST_CURRENT_TEST"):
        return None
    raw = runner.os.environ.get("HOL_GUARD_TEST_SYNC_AUTH_CONTEXT_JSON")
    if raw is None:
        return None
    try:
        payload = runner.json.loads(raw)
    except runner.json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    sync_url = payload.get("sync_url")
    access_token = payload.get("access_token")
    if not isinstance(sync_url, str) or not isinstance(access_token, str):
        return None
    sync_url = runner._validate_guard_sync_url(sync_url)
    return {
        "sync_url": sync_url,
        "access_token": access_token,
        "dpop_key_material": None,
    }


def _resolve_guard_sync_auth_context(
    store: runner.GuardStore,
    *,
    allow_primary_repair: bool = True,
    force_refresh: bool = False,
) -> dict[str, object]:
    if runner._test_sync_auth_context_override is not None:
        override = dict(runner._test_sync_auth_context_override)
        override["sync_url"] = runner._validate_guard_sync_url(runner._auth_context_sync_url(override))
        return override
    env_override = runner._test_sync_auth_context_from_env()
    if env_override is not None:
        return env_override
    with runner._guard_sync_auth_lock(store):
        oauth_health = store.get_oauth_local_credential_health()
        oauth_credentials = store.get_oauth_local_credentials(allow_primary=allow_primary_repair)
        if oauth_credentials is not None:
            try:
                return runner._resolve_guard_sync_auth_context_from_oauth_credentials(
                    store,
                    oauth_credentials,
                    force_refresh=force_refresh,
                )
            except runner.GuardSyncAuthorizationExpiredError as error:
                if not runner._oauth_authorization_error_requires_fresh_sign_in(error):
                    raise
                store._clear_oauth_secret_payload_cache()
                refreshed_credentials = store.get_oauth_local_credentials(allow_primary=allow_primary_repair)
                if refreshed_credentials is None or runner._optional_string(
                    refreshed_credentials.get("refresh_token")
                ) == runner._optional_string(oauth_credentials.get("refresh_token")):
                    raise
                return runner._resolve_guard_sync_auth_context_from_oauth_credentials(
                    store,
                    refreshed_credentials,
                    force_refresh=force_refresh,
                )
        if bool(oauth_health.get("configured")):
            recoverable_credentials = store.get_recoverable_oauth_local_credentials()
            if recoverable_credentials is not None:
                return runner._resolve_guard_sync_auth_context_from_oauth_credentials(
                    store,
                    recoverable_credentials,
                    persist_recovered_secret=allow_primary_repair,
                    force_refresh=force_refresh,
                )
            raise runner.GuardSyncAuthorizationExpiredError(runner._guard_oauth_reauthorization_message())
        raise runner.GuardSyncNotConfiguredError("Guard is not logged in.")
