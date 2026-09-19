"""Actual stored authority for legacy inventory transport and freshness fixtures."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard import aibom_cli
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.aibom_operation_authority import (
    AibomOperation,
    capture_aibom_operation,
    commit_aibom_results,
)
from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.store import GuardStore

_FIXTURE_NOW = "2026-06-01T00:00:00+00:00"


def seed_aibom_credentials(store: GuardStore, *, workspace_id: str) -> None:
    key = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="synthetic-aibom-refresh",
        access_token="synthetic-aibom-access",
        access_token_expires_at="2099-01-01T00:00:00+00:00",
        dpop_private_key_pem=key.private_key_pem,
        dpop_public_jwk=key.public_jwk,
        dpop_public_jwk_thumbprint=key.public_jwk_thumbprint,
        grant_id="synthetic-aibom-grant",
        workspace_id=workspace_id,
        now=_FIXTURE_NOW,
    )


def capture_aibom_fixture_operation(
    store: GuardStore, *, context: HarnessContext | None = None, now: str = _FIXTURE_NOW
) -> AibomOperation:
    selected = (
        context
        if context is not None
        else HarnessContext(
            home_dir=aibom_cli._resolve_operator_home_dir(),
            workspace_dir=None,
            guard_home=store.guard_home,
        )
    )
    operation = capture_aibom_operation(
        store, selected, now=now, bind_installation=aibom_cli.trust_attestation_v2_enabled()
    )
    assert operation is not None
    return operation


def commit_aibom_fixture_result(
    store: GuardStore,
    key: str,
    payload: dict[str, object],
    now: str,
    *,
    context: HarnessContext | None = None,
) -> None:
    with store.hold_aibom_sync_lock():
        operation = capture_aibom_fixture_operation(store, context=context, now=now)
        assert commit_aibom_results(store, operation, {key: payload}, now=now)


def content_aibom_authority(
    tmp_path: Path, *, context: HarnessContext | None = None
) -> tuple[GuardStore, AibomOperation]:
    selected = (
        context
        if context is not None
        else HarnessContext(home_dir=tmp_path, workspace_dir=None, guard_home=tmp_path / "guard-home")
    )
    store = GuardStore(selected.guard_home, allow_system_keyring=False)
    seed_aibom_credentials(store, workspace_id="workspace-1")
    return store, capture_aibom_fixture_operation(store, context=selected)
