"""Disclosure-reason tests for canonical supply-chain evaluation."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.runtime.supply_chain_package_eval as evaluator_module
from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import (
    _build_request_payload,
    _cloud_fail_closed_decision,
    evaluate_package_request_artifact,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_tier2_phase13_support import artifact_from_command_fixture
from tests.test_guard_supply_chain_evaluator import (
    WORKSPACE_ID,
    _artifact_for_targets,
    _bundle_response,
    _force_cloud_fallback,
    _package,
)


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


def test_cloud_fail_closed_policy_config_maps_security_levels(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    (store.guard_home / "config.toml").write_text('security_level = "strict"\n', encoding="utf-8")
    assert _cloud_fail_closed_decision(store=store, workspace_dir=tmp_path / "workspace") == "block"

    (store.guard_home / "config.toml").write_text('security_level = "balanced"\n', encoding="utf-8")
    assert _cloud_fail_closed_decision(store=store, workspace_dir=tmp_path / "workspace") == "ask"


def test_strict_mode_timeout_blocks_with_cloud_validation_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    (store.guard_home / "config.toml").write_text('security_level = "strict"\n', encoding="utf-8")
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        _bundle_response(
            packages=[
                _package(
                    ecosystem="npm",
                    name="left-pad",
                    version="1.0.0",
                    default_action="monitor",
                )
            ]
        ),
        "2026-05-19T00:00:00Z",
    )

    def raise_timeout(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise TimeoutError("network unreachable")

    monkeypatch.setattr(evaluator_module, "_urlopen_json_with_timeout_retry", raise_timeout)
    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("left-pad@1.0.0"),
        store=store,
        workspace_dir=tmp_path / "workspace",
        now="2026-05-19T00:00:00Z",
    )

    assert result.decision == "block"
    assert any(reason["code"] == "cloud_validation_error" for reason in result.reasons)


def test_local_fallback_disclosure_reason_surfaces_after_cloud_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _force_cloud_fallback(monkeypatch)
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("unknown-pkg@1.0.0"),
        store=store,
        workspace_dir=tmp_path / "workspace",
        now="2026-05-19T00:00:00Z",
    )

    assert any(reason["code"] == "cloud_timeout" for reason in result.reasons)
    assert result.enforcement in {"local_fallback", "offline_cached", "free_local"}


def test_stale_bundle_disclosure_reason_surfaces_in_final_evaluation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _force_cloud_fallback(monkeypatch)
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    stale_response = _bundle_response(
        packages=[
            _package(
                ecosystem="npm",
                name="left-pad",
                version="1.0.0",
                default_action="monitor",
            )
        ],
        generated_at=datetime(2026, 5, 18, tzinfo=timezone.utc),
        expires_at=datetime(2026, 5, 18, 1, tzinfo=timezone.utc),
    )
    store.cache_supply_chain_bundle(WORKSPACE_ID, stale_response, "2026-05-18T01:00:00Z")

    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("left-pad@1.0.0"),
        store=store,
        workspace_dir=tmp_path / "workspace",
        now="2026-05-19T00:00:00Z",
    )

    assert result.refresh_required is True
    assert any(reason["code"] == "stale_low_confidence" for reason in result.reasons)


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


def test_unknown_package_disclosure_reason(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _force_cloud_fallback(monkeypatch)
    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("totally-unknown-pkg@9.9.9"),
        store=GuardStore(tmp_path / "home"),
        workspace_dir=tmp_path / "workspace",
        now="2026-05-19T00:00:00Z",
    )

    assert any(reason["code"] == "no_cached_match" for package in result.packages for reason in package["reasons"])
    assert any(reason["code"] == "unidentified_package" for package in result.packages for reason in package["reasons"])


def test_unidentified_package_reason_fires_for_supported_ecosystem(tmp_path: Path) -> None:
    """A supported-ecosystem package with no registry match emits unidentified_package."""
    result = evaluate_package_request_artifact(
        artifact=_artifact_for_targets("unresolved-npm-pkg@1.0.0"),
        store=GuardStore(tmp_path / "home"),
        workspace_dir=tmp_path / "workspace",
        now="2026-05-19T00:00:00Z",
    )
    assert result.decision == "monitor"
    assert len(result.packages) == 1
    codes = [reason["code"] for reason in result.packages[0]["reasons"]]
    assert "no_cached_match" in codes
    assert "unidentified_package" in codes
    unidentified = next(r for r in result.packages[0]["reasons"] if r["code"] == "unidentified_package")
    assert unidentified["severity"] == "medium"


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


def test_unknown_package_result_directly_skips_unidentified_for_unsupported() -> None:
    """Directly test _unknown_package_result does not emit unidentified_package for unsupported ecosystem."""
    from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import _unknown_package_result

    target = {"ecosystem": "unsupported", "name": "some-pkg", "namespace": None}
    result = _unknown_package_result(target)
    codes = [reason["code"] for reason in result["reasons"]]
    assert "no_cached_match" in codes
    assert "unidentified_package" not in codes


def test_unknown_package_result_directly_skips_unidentified_for_system() -> None:
    """Directly test _unknown_package_result does not emit unidentified_package for system ecosystem."""
    from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import _unknown_package_result

    target = {"ecosystem": "system", "name": "some-pkg", "namespace": None}
    result = _unknown_package_result(target)
    codes = [reason["code"] for reason in result["reasons"]]
    assert "unidentified_package" not in codes


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


def test_policy_version_hash_consistency_between_cloud_request_and_local_evaluation(
    tmp_path: Path,
) -> None:
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
    artifact = _artifact_for_targets("left-pad@1.0.0")
    targets = evaluator_module._targets_from_artifact(artifact)
    workspace_fingerprint = evaluator_module._workspace_fingerprint(
        WORKSPACE_ID,
        workspace_dir=tmp_path / "workspace",
        artifact=artifact,
        bundle_meta={"policy_hash": POLICY_HASH},
    )
    assert workspace_fingerprint is not None
    request_payload = _build_request_payload(
        artifact=artifact,
        targets=targets,
        workspace_dir=tmp_path / "workspace",
        workspace_fingerprint=workspace_fingerprint,
        policy_version=POLICY_HASH,
    )

    assert request_payload["policyVersion"] == POLICY_HASH
    assert "lockfileContext" not in request_payload
