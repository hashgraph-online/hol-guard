"""Sign in and out of Cloud actions for one profile."""

from __future__ import annotations

import secrets
from collections.abc import Callable
from datetime import datetime, timezone
from typing import TextIO

from .cloud_actions_oauth import (
    CloudActionsServer,
    CloudActionsSignInError,
    LoopbackCallbackListener,
    build_authorize_url,
    discover_cloud_actions_server,
    exchange_authorization_code,
    read_cloud_actions_grant,
    register_cloud_actions_client,
    resolve_cloud_origin,
    revoke_cloud_actions_grant,
)
from .cloud_actions_session import (
    CloudActionsProfile,
    CloudActionsProfileBusyError,
    CloudActionsSecrets,
    CloudActionsSessionStore,
)
from .oauth_client import build_pkce_s256_challenge, generate_pkce_verifier


def sign_in(
    *,
    store: CloudActionsSessionStore,
    profile_name: str,
    cloud_url: str,
    workspace_id: str | None,
    timeout_seconds: float,
    open_browser: Callable[[str], bool] | None,
    notice: TextIO,
) -> CloudActionsProfile:
    """Run the browser sign-in and save the grant only after every check passes.

    Nothing is written for the profile until the grant is accepted, so a
    cancelled, refused or mismatched sign-in leaves the previous one in place.
    """

    server = discover_cloud_actions_server(resolve_cloud_origin(cloud_url))
    client_id = store.registered_client(server.issuer)
    if client_id is None:
        client_id = register_cloud_actions_client(server)
        store.remember_client(server.issuer, client_id)
    verifier = generate_pkce_verifier()
    state = secrets.token_urlsafe(32)
    listener = LoopbackCallbackListener(expected_state=state)
    try:
        url = build_authorize_url(
            server,
            client_id=client_id,
            redirect_uri=listener.redirect_uri,
            state=state,
            code_challenge=build_pkce_s256_challenge(verifier),
            workspace_id=workspace_id,
        )
        opened = open_browser(url) if open_browser is not None else False
        lead = "Finish signing in in your browser." if opened else "Open this link to sign in:"
        print(f"{lead}\n{url}", file=notice, flush=True)
        code = listener.wait(timeout_seconds, server=server)
    finally:
        listener.close()
    payload = exchange_authorization_code(
        server, client_id=client_id, code=code, redirect_uri=listener.redirect_uri, code_verifier=verifier
    )
    try:
        grant = read_cloud_actions_grant(
            payload, server=server, client_id=client_id, requested_workspace_id=workspace_id
        )
        profile = CloudActionsProfile(
            name=profile_name,
            issuer=server.issuer,
            resource=server.resource,
            client_id=client_id,
            workspace_id=grant.workspace_id,
            scopes=grant.scopes,
            expires_at=grant.expires_at,
            grant_id=grant.grant_id,
            signed_in_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        )
        with store.lock(profile_name):
            previous = store.load(profile_name)
            previous_secrets = store.load_secrets(profile_name)
            replaced_ref = store.save(
                profile, CloudActionsSecrets(access_token=grant.access_token, refresh_token=grant.refresh_token)
            )
    except CloudActionsProfileBusyError:
        _revoke_answer(server, client_id=client_id, payload=payload)
        raise CloudActionsSignInError(
            "profile_busy", f"Another hol-guard command is changing profile {profile_name}; try again."
        ) from None
    except BaseException:
        _revoke_answer(server, client_id=client_id, payload=payload)
        raise
    # Committed. End the sign-in this one replaced, on whichever Guard Cloud issued it.
    store.discard_secret(replaced_ref)
    if previous is not None and previous_secrets is not None:
        _ = _revoke_saved(previous, previous_secrets, known=server)
    return profile


def sign_out(*, store: CloudActionsSessionStore, profile_name: str) -> tuple[bool, bool]:
    """Remove the profile; returns (was signed in, Guard Cloud confirmed the revocation)."""

    try:
        with store.lock(profile_name):
            profile = store.load(profile_name)
            saved = store.load_secrets(profile_name)
            was_signed_in = store.delete(profile_name)
    except CloudActionsProfileBusyError:
        raise CloudActionsSignInError(
            "profile_busy", f"Another hol-guard command is changing profile {profile_name}; try again."
        ) from None
    revoked = False
    if profile is not None and saved is not None:
        revoked = _revoke_saved(profile, saved)
    return was_signed_in, revoked


def _revoke_saved(
    profile: CloudActionsProfile, saved: CloudActionsSecrets, *, known: CloudActionsServer | None = None
) -> bool:
    """End a saved sign-in on the Guard Cloud that issued it; best effort."""

    server = known if known is not None and known.issuer == profile.issuer else None
    if server is None:
        try:
            server = discover_cloud_actions_server(resolve_cloud_origin(profile.issuer))
        except CloudActionsSignInError:
            return False
        if server.issuer != profile.issuer:
            return False
    revoked = False
    if saved.refresh_token is not None:
        revoked = revoke_cloud_actions_grant(
            server, client_id=profile.client_id, token=saved.refresh_token, hint="refresh_token"
        )
    access_revoked = revoke_cloud_actions_grant(
        server, client_id=profile.client_id, token=saved.access_token, hint="access_token"
    )
    return revoked or access_revoked


def _revoke_answer(server: CloudActionsServer, *, client_id: str, payload: dict[str, object]) -> None:
    for hint in ("refresh_token", "access_token"):
        token = payload.get(hint)
        if isinstance(token, str) and token:
            try:
                _ = revoke_cloud_actions_grant(server, client_id=client_id, token=token, hint=hint)
            except Exception:
                continue


__all__ = ["sign_in", "sign_out"]
