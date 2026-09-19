"""Shared fixtures for Guard Cloud local sync contract tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.policy_bundle_parser import (
    computed_policy_bundle_hash,
    payload_hash_for_policy_bundle,
)
from tests.cloud_exception_bundle_fixtures import build_cloud_exception_policy_bundle
from tests.policy_bundle_signing_helpers import sign_policy_bundle


def _seed_guard_cloud(store, *, workspace_id=None, sync_url=None, token="demo-token", now="2026-05-19T00:00:00Z"):
    """Seed OAuth credentials (replaces legacy set_sync_credentials scaffolding).

    Also installs a test-only resolver override so sync-path exercises stay hermetic
    (no OAuth token refresh against the network). Tests that need real sync against a
    local server pass sync_url=<url>.
    """
    from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
    from codex_plugin_scanner.guard.runtime import runner as guard_runner_module

    dpop_key_material = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token=token,
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id=workspace_id,
        now=now,
    )
    effective_sync_url = sync_url if sync_url is not None else "https://hol.org/api/guard/receipts/sync"
    guard_runner_module._test_sync_auth_context_override = {
        "sync_url": effective_sync_url,
        "access_token": token,
        "dpop_key_material": None,
    }


def _signed_runtime_status_policy_bundle(*, workspace_id: str) -> dict[str, object]:
    policy_bundle = build_cloud_exception_policy_bundle(workspace_id=workspace_id)
    policy_bundle["bundleVersion"] = "policy-2026-05-01.3"
    policy_bundle["rolloutState"] = "enforcing"
    policy_bundle["acknowledgements"] = [
        {
            "deviceId": "device-alpha",
            "acknowledgedAt": "2026-06-01T12:00:00+00:00",
            "status": "synced",
        }
    ]
    return sign_policy_bundle(policy_bundle, workspace_id=workspace_id)


def _digest_only_runtime_status_policy_bundle(*, workspace_id: str) -> dict[str, object]:
    policy_bundle = _signed_runtime_status_policy_bundle(workspace_id=workspace_id)
    policy_bundle["verifier"] = {
        "algorithm": "sha256",
        "keyId": "attacker-recomputed-digest",
        "signature": None,
    }
    policy_bundle["bundleHash"] = computed_policy_bundle_hash(policy_bundle)
    policy_bundle["payloadHash"] = payload_hash_for_policy_bundle(policy_bundle)
    return policy_bundle


def _artifact(tmp_path: Path) -> GuardArtifact:
    return GuardArtifact(
        artifact_id="codex:project:workspace-tools",
        name="workspace-tools",
        harness="codex",
        artifact_type="mcp_server",
        source_scope="project",
        config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
        command="node",
        args=("workspace.js",),
        transport="stdio",
    )


def _detection(artifact: GuardArtifact) -> HarnessDetection:
    return HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(artifact.config_path,),
        artifacts=(artifact,),
    )
