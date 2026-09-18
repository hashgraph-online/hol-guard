from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.store import GuardStore
from tests.policy_bundle_signing_helpers import policy_bundle_test_keyring


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def seed_inventory(store: GuardStore, artifact: GuardArtifact, *, now: str) -> None:
    store.record_inventory_artifact(
        artifact=artifact,
        artifact_hash="hash-1",
        policy_action="allow",
        changed=False,
        now=now,
        approved=True,
    )


def seed_guard_cloud_with_keys(
    store, *, workspace_id=None, sync_url=None, token="demo-token", now="2026-05-19T00:00:00Z"
):
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
    if workspace_id is not None:
        store.set_sync_payload(
            "policy_bundle_keyring",
            policy_bundle_test_keyring(workspace_id=workspace_id),
            now,
        )
    effective_sync_url = sync_url if sync_url is not None else "https://hol.org/api/guard/receipts/sync"
    guard_runner_module._test_sync_auth_context_override = {
        "sync_url": effective_sync_url,
        "access_token": token,
        "dpop_key_material": None,
    }


def seed_sync_credentials(
    home_dir: Path,
    sync_url: str,
    token: str = "local-test-token",
    *,
    workspace_id: str | None = None,
) -> None:
    seed_guard_cloud_with_keys(
        GuardStore(home_dir),
        workspace_id=workspace_id,
        sync_url=sync_url,
        token=token,
    )


def seed_guard_cloud_without_keys(
    store, *, workspace_id=None, sync_url=None, token="demo-token", now="2026-05-19T00:00:00Z"
):
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


def build_codex_fixture(home_dir: Path, workspace_dir: Path) -> None:
    write_text(
        home_dir / ".codex" / "config.toml",
        """
[mcp_servers.global_tools]
command = "python"
args = ["-m", "http.server", "9000"]
""".strip()
        + "\n",
    )
    write_text(
        workspace_dir / ".codex" / "config.toml",
        """
[mcp_servers.workspace_skill]
command = "node"
args = ["workspace-skill.js"]
""".strip()
        + "\n",
    )
