"""Disclosure-reason tests for canonical supply-chain evaluation."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.local_supply_chain import evaluate_package_request_artifact
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_tier2_phase13_support import artifact_from_command_fixture
from tests.test_guard_supply_chain_evaluator import (
    WORKSPACE_ID,
    _artifact_for_targets,
    _bundle_response,
    _package,
)

pytestmark = pytest.mark.usefixtures("package_intent_native")


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


POLICY_HASH = "policy-hash-1"


def test_unsupported_ecosystem_disclosure_reason(tmp_path: Path) -> None:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    artifact = artifact_from_command_fixture(
        "helm install ingress ingress-nginx/ingress-nginx",
        workspace=workspace_dir,
    )
    result = evaluate_package_request_artifact(
        artifact=artifact,
        store=GuardStore(tmp_path / "home"),
        workspace_dir=workspace_dir,
    )

    assert result.packages[0]["reasons"][0]["code"] == "unsupported_ecosystem_monitor_only"


def test_unidentified_package_reason_fires_for_supported_ecosystem(tmp_path: Path) -> None:
    """A supported-ecosystem package with no registry match emits unidentified_package."""
    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("unresolved-npm-pkg@1.0.0"),
        store=GuardStore(tmp_path / "home"),
        workspace_dir=tmp_path / "workspace",
        now="2026-05-19T00:00:00Z",
    )
    assert result.decision == "ask"
    assert result.policy_action == "require-reapproval"
    assert "monitor" not in result.user_copy.summary.lower()
    assert len(result.packages) == 1
    codes = [reason["code"] for reason in result.packages[0]["reasons"]]
    assert "no_cached_match" in codes
    assert "unidentified_package" in codes
    unidentified = next(r for r in result.packages[0]["reasons"] if r["code"] == "unidentified_package")
    assert unidentified["severity"] == "medium"
    assert "Local Guard" not in result.user_copy.harness_message
    assert "HOL Guard on this device" in result.packages[0]["reasons"][0]["message"]


def _running_guard_release(name: str) -> str | None:
    if name in {"hol-guard", "plugin-scanner"}:
        return "3.0.182"
    return None


def test_non_registry_install_of_hol_guard_still_requires_review(tmp_path: Path) -> None:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    result = evaluate_package_request_artifact(
        artifact=artifact_from_command_fixture(
            "pip install 'hol-guard @ git+https://github.com/example/hol-guard.git'",
            workspace=workspace_dir,
        ),
        store=GuardStore(tmp_path / "home"),
        workspace_dir=workspace_dir,
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "ask"
    assert result.policy_action == "require-reapproval"
    assert result.packages[0]["reasons"][0]["code"] != "installed_release_reinstall"


def test_alternate_index_install_of_hol_guard_still_requires_review(tmp_path: Path) -> None:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    result = evaluate_package_request_artifact(
        artifact=artifact_from_command_fixture(
            "pipx install hol-guard --index-url https://example.invalid/simple",
            workspace=workspace_dir,
        ),
        store=GuardStore(tmp_path / "home"),
        workspace_dir=workspace_dir,
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "ask"
    assert result.policy_action == "require-reapproval"
    assert "installed_release_reinstall" not in {reason["code"] for reason in result.packages[0]["reasons"]}


@pytest.mark.parametrize(
    "command",
    [
        "pip install hol-guard -f https://example.invalid/simple",
        "PIP_INDEX_URL=https://example.invalid/simple pip install hol-guard",
        "uv pip install hol-guard --default-index https://example.invalid/simple",
    ],
)
def test_relocated_registry_install_of_hol_guard_still_requires_review(tmp_path: Path, command: str) -> None:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    result = evaluate_package_request_artifact(
        artifact=artifact_from_command_fixture(command, workspace=workspace_dir),
        store=GuardStore(tmp_path / "home"),
        workspace_dir=workspace_dir,
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision in {"ask", "block"}
    assert result.policy_action != "allow"
    assert "HOL Guard allowed" not in result.user_copy.harness_message


def test_unidentified_package_blocks_under_strict_policy(tmp_path: Path) -> None:
    """Strict policy fails closed when registry identity cannot be resolved."""

    guard_home = tmp_path / "home"
    guard_home.mkdir()
    (guard_home / "config.toml").write_text('security_level = "strict"\n', encoding="utf-8")

    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("unresolved-npm-pkg@1.0.0"),
        store=GuardStore(guard_home),
        workspace_dir=tmp_path / "workspace",
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "block"
    assert result.policy_action == "block"


def test_unidentified_package_reason_absent_for_unsupported_ecosystem(tmp_path: Path) -> None:
    """Unsupported-ecosystem packages get unsupported_ecosystem codes, not unidentified_package."""
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    artifact = artifact_from_command_fixture(
        "helm install ingress ingress-nginx/ingress-nginx",
        workspace=workspace_dir,
    )
    result = evaluate_package_request_artifact(
        artifact=artifact,
        store=GuardStore(tmp_path / "home"),
        workspace_dir=workspace_dir,
        now="2026-05-19T00:00:00Z",
    )
    assert all(reason["code"] != "unidentified_package" for package in result.packages for reason in package["reasons"])


def test_known_package_does_not_emit_unidentified_package(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A package with a bundle match should not emit unidentified_package."""
    monkeypatch.setattr(GuardStore, "_assert_oauth_secret_persisted", lambda self, secret_id, value: None)
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    bundle_response = _bundle_response(
        packages=[
            _package(
                ecosystem="npm",
                name="left-pad",
                version="1.0.0",
                default_action="monitor",
            )
        ]
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, bundle_response, "2026-05-19T00:00:00Z")
    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("left-pad@1.0.0"),
        store=store,
        workspace_dir=tmp_path / "workspace",
        now="2026-05-19T00:00:00Z",
    )
    assert all(reason["code"] != "unidentified_package" for package in result.packages for reason in package["reasons"])
