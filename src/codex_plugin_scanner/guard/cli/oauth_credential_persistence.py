"""Durable OAuth credential persistence shared by Guard connect flows."""

from __future__ import annotations

from collections.abc import Callable

from ..store import GuardStore
from .oauth_client import GuardDpopKeyMaterial


def persist_oauth_local_credentials(
    *,
    store: GuardStore,
    issuer: str,
    client_id: str,
    refresh_token: str,
    dpop_key_material: GuardDpopKeyMaterial,
    now: str,
    grant_id: str | None = None,
    machine_id: str | None = None,
    device_id: str | None = None,
    supply_chain_entitlement: dict[str, object] | None = None,
    workspace_id: str | None = None,
    cloud_user_profile: dict[str, str] | None = None,
    runtime_id: str | None = None,
    runtime_label: str | None = None,
    access_token: str | None = None,
    access_token_expires_at: str | None = None,
    reconcile: Callable[[GuardStore], object],
) -> None:
    entitlement = supply_chain_entitlement if isinstance(supply_chain_entitlement, dict) else {}
    expires_at = entitlement.get("supply_chain_entitlement_expires_at")
    firewall = entitlement.get("supply_chain_firewall")
    plan_id = entitlement.get("supply_chain_plan_id")
    with store.hold_oauth_refresh_lock():
        store.set_oauth_local_credentials(
            issuer=issuer,
            client_id=client_id,
            refresh_token=refresh_token,
            dpop_private_key_pem=dpop_key_material.private_key_pem,
            dpop_public_jwk=dpop_key_material.public_jwk,
            dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
            grant_id=grant_id,
            machine_id=machine_id,
            device_id=device_id,
            supply_chain_entitlement_expires_at=expires_at if isinstance(expires_at, str) else None,
            supply_chain_firewall=firewall if isinstance(firewall, bool) else None,
            supply_chain_plan_id=plan_id if isinstance(plan_id, str) else None,
            workspace_id=workspace_id,
            cloud_user_profile=cloud_user_profile,
            runtime_id=runtime_id,
            runtime_label=runtime_label,
            access_token=access_token,
            access_token_expires_at=access_token_expires_at,
            now=now,
        )
        reconcile(store)


__all__ = ["persist_oauth_local_credentials"]
