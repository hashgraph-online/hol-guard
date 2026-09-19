"""Connected routing fixtures with real local credential authority."""

from __future__ import annotations

from codex_plugin_scanner.guard.cli.connect_completion import CONNECT_CONNECTION_KEY
from codex_plugin_scanner.guard.cli.connect_flow import CONNECT_SYNC_AUTH_CONTEXT_KEY, _build_sync_auth_context
from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.runtime.runner import GuardSyncNotConfiguredError
from codex_plugin_scanner.guard.store import GuardStore


def bound_connected_result(store: GuardStore, payload: dict[str, object]) -> dict[str, object]:
    """Replace only the provider exchange; preserve persistence and completion."""
    key = generate_dpop_key_pair()
    committed = store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="synthetic-connect-refresh",
        dpop_private_key_pem=key.private_key_pem,
        dpop_public_jwk=key.public_jwk,
        dpop_public_jwk_thumbprint=key.public_jwk_thumbprint,
        workspace_id=str(payload.get("workspace_id") or "synthetic-connect-workspace"),
        grant_id=str(payload.get("grant_id") or "synthetic-connect-grant"),
        machine_id=str(payload.get("machine_id") or "synthetic-connect-machine"),
        expected_attempt=store.begin_oauth_connect_attempt(),
        now="2026-06-04T18:30:00+00:00",
    )
    assert committed is not None
    return {
        **payload,
        CONNECT_CONNECTION_KEY: committed,
        CONNECT_SYNC_AUTH_CONTEXT_KEY: _build_sync_auth_context(
            access_token="synthetic-connect-access",
            dpop_key_material=key,
            sync_url="https://hol.org/api/guard/receipts/sync",
        ),
    }


def unavailable_first_sync(*_args: object, **_kwargs: object) -> dict[str, object]:
    """Exercise the actual retry UI without contacting a provider."""
    raise GuardSyncNotConfiguredError("Synthetic first sync is unavailable.")
