"""Oauth refresh.

Shared state and replaceable dependencies belong to the runner facade.
"""

from __future__ import annotations

from . import runner


def _refresh_guard_oauth_access_token_once(
    *,
    token_endpoint: str,
    client_id: str,
    refresh_token: str,
    dpop_key_material: runner.GuardDpopKeyMaterial,
) -> dict[str, object]:
    if runner._guard_runtime_was_upgraded():
        raise runner.GuardSyncNotAvailableError(runner._guard_runtime_upgrade_restart_message(), retryable=True)
    request_body = runner.urllib.parse.urlencode(
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
            dpop_proof = runner._sign_guard_dpop_proof(
                request_url=token_endpoint,
                method="POST",
                dpop_key_material=dpop_key_material,
                nonce=dpop_nonce,
            )
        except (RuntimeError, TypeError, ValueError) as error:
            raise runner.GuardSyncAuthorizationExpiredError(
                f"{runner._guard_oauth_reauthorization_message()} {error}"
            ) from error
        request = runner.urllib.request.Request(
            token_endpoint,
            data=request_body,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "User-Agent": runner._GUARD_SYNC_USER_AGENT,
                "DPoP": dpop_proof,
            },
        )
        try:
            with runner.managed_urlopen(request, timeout=runner._SYNC_HTTP_TIMEOUT_SECONDS) as response:
                payload = runner.json.loads(response.read().decode("utf-8"))
        except runner.urllib.error.HTTPError as error:
            payload = runner._http_error_payload(error) if error.code in {400, 401, 403} else None
            challenge_nonce = runner._dpop_nonce_from_http_error(error, payload)
            if challenge_nonce is not None and challenge_nonce != dpop_nonce and nonce_retry_count < 3:
                dpop_nonce = challenge_nonce
                nonce_retry_count += 1
                continue
            if error.code in {400, 401, 403}:
                if runner._invalid_grant_oauth_payload(payload):
                    raise runner.GuardSyncAuthorizationExpiredError(
                        runner._guard_oauth_reconnect_after_revoked_message()
                    ) from error
                refresh_error_message = runner._oauth_refresh_error_message(error)
                raise runner.GuardSyncAuthorizationExpiredError(
                    f"{runner._guard_oauth_reauthorization_message()} {refresh_error_message}"
                ) from error
            refresh_error_message = runner._oauth_refresh_error_message(error)
            raise RuntimeError(f"Guard OAuth token refresh failed: {refresh_error_message}") from error
        except OSError as error:
            raise RuntimeError(runner._sync_url_error_message(error)) from error
        if not isinstance(payload, dict):
            raise runner.GuardSyncAuthorizationExpiredError(runner._guard_oauth_reauthorization_message())
        access_token = runner._optional_string(payload.get("access_token"))
        token_type = runner._optional_string(payload.get("token_type"))
        if access_token is None or token_type is None or token_type.lower() not in {"bearer", "dpop"}:
            raise runner.GuardSyncAuthorizationExpiredError(runner._guard_oauth_reauthorization_message())
        access_token_expires_at = runner._oauth_access_token_expires_at(
            access_token,
            payload=payload,
            now=runner.datetime.now(runner.timezone.utc),
        )
        return {
            "access_token": access_token,
            "access_token_expires_at": access_token_expires_at,
            "package_firewall_entitlement": runner.build_oauth_package_firewall_entitlement(
                payload,
                now=runner.datetime.now(runner.timezone.utc),
            ),
            "cloud_user_profile": runner.extract_cloud_user_profile(payload),
            "had_guard_local_entitlement": isinstance(payload.get("guard_local_entitlement"), dict),
            "refresh_token": runner._optional_string(payload.get("refresh_token")) or refresh_token,
        }


def _oauth_sync_url_from_issuer(issuer: str) -> str:
    oauth_client = runner.resolve_guard_oauth_client_config(issuer)
    return f"{oauth_client.issuer}/api/guard/receipts/sync"


def _oauth_dpop_key_material(credentials: dict[str, object]) -> runner.GuardDpopKeyMaterial:
    dpop_private_key_pem = runner._optional_string(credentials.get("dpop_private_key_pem"))
    dpop_public_jwk = credentials.get("dpop_public_jwk")
    dpop_public_jwk_thumbprint = runner._optional_string(credentials.get("dpop_public_jwk_thumbprint"))
    if dpop_private_key_pem is None or not isinstance(dpop_public_jwk, dict) or dpop_public_jwk_thumbprint is None:
        raise runner.GuardSyncAuthorizationExpiredError(runner._guard_oauth_reauthorization_message())
    return runner.GuardDpopKeyMaterial(
        algorithm="ES256",
        private_key_pem=dpop_private_key_pem,
        public_jwk={str(key): str(value) for key, value in dpop_public_jwk.items()},
        public_jwk_thumbprint=dpop_public_jwk_thumbprint,
    )


def _refresh_guard_oauth_access_token(
    *,
    token_endpoint: str,
    client_id: str,
    refresh_token: str,
    dpop_key_material: runner.GuardDpopKeyMaterial,
    credential_reloader: runner.Callable[[], tuple[str, runner.GuardDpopKeyMaterial] | None] | None = None,
) -> dict[str, object]:
    """Refresh with bounded invalid_grant tolerance.

    A single invalid_grant can be an edge 4xx or a rotation race resolved
    server-side without grant revocation; failing once must not declare the
    local sign-in invalid (which used to trigger credential wipes and stop
    sync). Retry exactly once after a short delay. Before the retry, ask the
    caller for the latest stored credentials — a peer process may have
    rotated the refresh token between attempts. A second invalid_grant is
    treated as genuine revocation and propagates.

    The returned payload includes `_effective_refresh_token` and
    `_effective_dpop_key_material` reflecting whichever credential snapshot
    actually succeeded — so callers can persist and return *those*, not the
    stale inputs.
    """
    last_error: runner.GuardSyncAuthorizationExpiredError | None = None
    attempt_refresh_token = refresh_token
    attempt_dpop_key_material = dpop_key_material
    for attempt in range(runner._OAUTH_INVALID_GRANT_MAX_ATTEMPTS):
        try:
            result = runner._refresh_guard_oauth_access_token_once(
                token_endpoint=token_endpoint,
                client_id=client_id,
                refresh_token=attempt_refresh_token,
                dpop_key_material=attempt_dpop_key_material,
            )
        except runner.GuardSyncAuthorizationExpiredError as error:
            if str(error) != runner._guard_oauth_reconnect_after_revoked_message():
                raise
            last_error = error
            if attempt + 1 >= runner._OAUTH_INVALID_GRANT_MAX_ATTEMPTS:
                break
            runner.time.sleep(runner._OAUTH_INVALID_GRANT_RETRY_DELAY_SECONDS)
            if credential_reloader is None:
                continue
            reloaded = credential_reloader()
            if reloaded is None:
                continue
            attempt_refresh_token, attempt_dpop_key_material = reloaded
            continue
        result["_effective_refresh_token"] = attempt_refresh_token
        result["_effective_dpop_key_material"] = attempt_dpop_key_material
        return result
    if last_error is None:  # pragma: no cover - unreachable when MAX_ATTEMPTS >= 1
        raise runner.GuardSyncAuthorizationExpiredError(runner._guard_oauth_reconnect_after_revoked_message())
    raise last_error


def _persist_recovered_oauth_binding(store: runner.GuardStore, credentials: dict[str, object]) -> bool:
    recovered = runner.oauth_binding_from_credentials(credentials)
    if not recovered or all(runner._optional_string(credentials.get(key)) is not None for key in recovered):
        return False
    refresh_token = runner._optional_string(credentials.get("refresh_token"))
    if refresh_token is None:
        return False
    runner._persist_rotated_oauth_refresh_token(
        store=store,
        credentials={
            **credentials,
            **{key: runner._optional_string(credentials.get(key)) or value for key, value in recovered.items()},
        },
        refresh_token=refresh_token,
        access_token=runner._optional_string(credentials.get("access_token")),
        access_token_expires_at=runner._optional_string(credentials.get("access_token_expires_at")),
    )
    return True


def _oauth_access_token_expires_at(
    access_token: str,
    *,
    payload: dict[str, object],
    now: runner.datetime,
) -> str | None:
    claims = runner._decode_oauth_access_token_claims(access_token)
    exp = claims.get("exp")
    if isinstance(exp, (int, float)) and not isinstance(exp, bool) and float(exp) > 0:
        return runner.datetime.fromtimestamp(float(exp), tz=runner.timezone.utc).isoformat()
    expires_in = payload.get("expires_in")
    parsed_expires_in: int | None
    if isinstance(expires_in, (int, float)) and not isinstance(expires_in, bool):
        parsed_expires_in = int(expires_in)
    elif isinstance(expires_in, str):
        try:
            parsed_expires_in = int(expires_in)
        except ValueError:
            parsed_expires_in = None
    else:
        parsed_expires_in = None
    if parsed_expires_in is None or parsed_expires_in <= 0:
        return None
    return (now + runner.timedelta(seconds=parsed_expires_in)).isoformat()


def _cached_oauth_access_token(credentials: dict[str, object], *, now: runner.datetime) -> str | None:
    access_token = runner._optional_string(credentials.get("access_token"))
    access_token_expires_at = runner._optional_string(credentials.get("access_token_expires_at"))
    if access_token is None or access_token_expires_at is None:
        return None
    try:
        expires_at = runner.datetime.fromisoformat(access_token_expires_at)
    except ValueError:
        return None
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=runner.timezone.utc)
    expires_at = expires_at.astimezone(runner.timezone.utc)
    if expires_at <= now + runner.timedelta(seconds=runner._OAUTH_ACCESS_TOKEN_REFRESH_SKEW_SECONDS):
        return None
    return access_token


def _persist_rotated_oauth_refresh_token(
    *,
    store: runner.GuardStore,
    credentials: dict[str, object],
    package_firewall_entitlement: dict[str, object] | None = None,
    cloud_user_profile: dict[str, str] | None = None,
    refresh_token: str,
    access_token: str | None = None,
    access_token_expires_at: str | None = None,
    force_primary_secret_rewrite: bool = False,
) -> None:
    issuer = runner._optional_string(credentials.get("issuer"))
    client_id = runner._optional_string(credentials.get("client_id"))
    dpop_private_key_pem = runner._optional_string(credentials.get("dpop_private_key_pem"))
    dpop_public_jwk = credentials.get("dpop_public_jwk")
    dpop_public_jwk_thumbprint = runner._optional_string(credentials.get("dpop_public_jwk_thumbprint"))
    if (
        issuer is None
        or client_id is None
        or dpop_private_key_pem is None
        or not isinstance(dpop_public_jwk, dict)
        or dpop_public_jwk_thumbprint is None
    ):
        raise runner.GuardSyncAuthorizationExpiredError(runner._guard_oauth_reauthorization_message())
    supply_chain_firewall: bool | None
    if isinstance(package_firewall_entitlement, dict) and isinstance(
        package_firewall_entitlement.get("supply_chain_firewall"), bool
    ):
        supply_chain_firewall = bool(package_firewall_entitlement.get("supply_chain_firewall"))
    else:
        credentials_supply_chain_firewall = credentials.get("supply_chain_firewall")
        supply_chain_firewall = (
            credentials_supply_chain_firewall if isinstance(credentials_supply_chain_firewall, bool) else None
        )
    effective_access_token = access_token or runner._optional_string(credentials.get("access_token"))
    if access_token is not None:
        recovered_binding = runner.oauth_binding_metadata(access_token, issuer=issuer)
    else:
        recovered_binding = runner.oauth_binding_from_credentials(
            {**credentials, "access_token": effective_access_token}
        )
    effective_binding = runner.oauth_refresh_binding(
        credentials,
        recovered_binding,
        refreshed=access_token is not None,
    )
    store.set_oauth_local_credentials(
        issuer=issuer,
        client_id=client_id,
        refresh_token=refresh_token,
        dpop_private_key_pem=dpop_private_key_pem,
        dpop_public_jwk={str(key): str(value) for key, value in dpop_public_jwk.items()},
        dpop_public_jwk_thumbprint=dpop_public_jwk_thumbprint,
        grant_id=effective_binding["grant_id"],
        machine_id=effective_binding["machine_id"],
        device_id=effective_binding["device_id"],
        supply_chain_entitlement_expires_at=(
            runner._optional_string(package_firewall_entitlement.get("supply_chain_entitlement_expires_at"))
            if isinstance(package_firewall_entitlement, dict)
            else runner._optional_string(credentials.get("supply_chain_entitlement_expires_at"))
        ),
        supply_chain_firewall=supply_chain_firewall,
        supply_chain_plan_id=(
            runner._optional_string(package_firewall_entitlement.get("supply_chain_plan_id"))
            if isinstance(package_firewall_entitlement, dict)
            else runner._optional_string(credentials.get("supply_chain_plan_id"))
        ),
        workspace_id=effective_binding["workspace_id"],
        cloud_user_profile=cloud_user_profile,
        runtime_id=runner._optional_string(credentials.get("runtime_id")),
        runtime_label=runner._optional_string(credentials.get("runtime_label")),
        access_token=effective_access_token,
        access_token_expires_at=access_token_expires_at,
        now=runner._now(),
        force_primary_secret_rewrite=force_primary_secret_rewrite,
    )
