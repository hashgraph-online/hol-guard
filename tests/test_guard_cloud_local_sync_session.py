"""Guard Cloud local runtime session sync contract tests."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.shims import install_package_shims
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_cloud_local_sync_helpers import _seed_guard_cloud


def test_runtime_session_sync_skips_v1_event_when_ingest_was_recently_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-alpha")
    store.set_sync_payload(
        "guard_events_v1_summary",
        {
            "synced_at": datetime.now(timezone.utc).isoformat(),
            "sync_skipped": True,
            "sync_reason": "guard_events_endpoint_unavailable",
        },
        datetime.now(timezone.utc).isoformat(),
    )

    def _runtime_sync_response(**_kwargs):
        return {"syncedAt": "2026-04-24T00:01:00+00:00", "items": []}

    monkeypatch.setattr(
        guard_runner_module,
        "_urlopen_json_with_timeout_retry",
        _runtime_sync_response,
    )

    result = guard_runner_module.sync_runtime_session(
        store,
        session={
            "harness": "codex",
            "surface": "cli",
            "status": "active",
        },
    )

    assert result["runtime_session_synced_at"] == "2026-04-24T00:01:00+00:00"
    assert store.list_guard_events_v1(uploaded=False, limit=10) == []


def test_sync_runtime_session_emits_package_manager_coverage_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("HOL_GUARD_POLICY_YAML_IMPORT", raising=False)
    monkeypatch.delenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", raising=False)
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-alpha")
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    context = HarnessContext(
        home_dir=store.guard_home,
        workspace_dir=workspace_dir,
        guard_home=store.guard_home,
    )
    install_payload = install_package_shims(context, managers=("npm",))
    shim_dir = Path(str(install_payload["shim_dir"]))
    original_path = os.environ.get("PATH", "")
    monkeypatch.setenv("PATH", f"{shim_dir}{os.pathsep}{original_path}")
    store.set_sync_payload(
        "supply_chain_bundle_summary",
        {
            "synced_at": "2026-04-24T00:00:00+00:00",
        },
        "2026-04-24T00:00:00+00:00",
    )

    captured_body: dict[str, object] = {}

    def _runtime_sync_response(**kwargs):
        request = kwargs["request"]
        captured_body.update(json.loads(request.data.decode("utf-8")))
        return {"syncedAt": "2026-04-24T00:01:00+00:00", "items": []}

    monkeypatch.setattr(
        guard_runner_module,
        "_urlopen_json_with_timeout_retry",
        _runtime_sync_response,
    )

    guard_runner_module.sync_runtime_session(
        store,
        session={
            **guard_runner_module._local_guard_runtime_session(),
            "updatedAt": "2026-04-24T00:01:00+00:00",
            "workspace": str(workspace_dir),
        },
    )

    session_payload = captured_body["session"]
    assert isinstance(session_payload, dict)
    assert session_payload["deviceId"] == store.get_or_create_installation_id()
    assert session_payload["deviceName"] == store.get_device_metadata()["device_label"]
    assert session_payload["localIdentity"]["lastSyncedAt"] == "2026-04-24T00:01:00+00:00"
    assert session_payload["localIdentitySource"]["daemonId"] == "local-guard"
    assert session_payload["localIdentitySource"]["daemonVersion"] == "local-guard"
    assert session_payload["localIdentitySource"]["daemonStatus"] == "local-guard"
    assert session_payload["localIdentitySource"]["relayState"] == "local-guard"
    assert session_payload["packageManagerCoverage"] == {
        "generatedAt": "2026-04-24T00:01:00+00:00",
        "configuredManagers": ["npm"],
        "protectedManagers": ["npm"],
        "missingManagers": [],
        "pathActive": True,
        "bypasses": [],
        "staleIntel": {
            "status": "fresh",
            "lastSyncedAt": "2026-04-24T00:00:00+00:00",
            "nextRefreshAt": "2026-04-24T00:15:00+00:00",
        },
    }
    assert session_payload["policyDocumentVersions"] == ["guard.hashgraphonline.com/v1alpha1"]
    assert session_payload["policyBundleVersions"] == [
        "guard-policy-bundle.v1",
        "guard-policy-bundle.v2",
    ]
    assert session_payload["policyContracts"] == [
        "guard-policy-bundle/v1",
        "guard-policy-bundle/v2",
    ]
    assert session_payload["yamlImport"] is False
    assert "canonicalPolicyEnforcement" not in session_payload
    assert session_payload["selectedEnforcementLane"] == "legacy"
    assert "canonicalIncompatibilityReason" not in session_payload
    assert session_payload["canonicalRolloutPercentage"] == 0


def test_local_runtime_session_advertises_enabled_policy_capabilities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOL_GUARD_POLICY_YAML_IMPORT", "1")
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")

    session = guard_runner_module._local_guard_runtime_session()

    assert session["policy_document_versions"] == ["guard.hashgraphonline.com/v1alpha1"]
    assert session["policy_bundle_versions"] == [
        "guard-policy-bundle.v1",
        "guard-policy-bundle.v2",
    ]
    assert session["policy_contracts"] == [
        "guard-policy-bundle/v1",
        "guard-policy-bundle/v2",
    ]
    assert session["yaml_import"] is True
    assert session["canonical_policy_enforcement"] is True
    assert session["selected_enforcement_lane"] == "legacy"
    assert session["canonical_rollout_percentage"] == 100
    assert "advertised_canonical_capabilities" in session


def test_local_runtime_session_without_bundle_reports_legacy_when_canonical_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", raising=False)

    session = guard_runner_module._local_guard_runtime_session()

    assert session["selected_enforcement_lane"] == "legacy"
    assert "canonical_incompatibility_reason" not in session
    assert session["canonical_rollout_percentage"] == 0


def test_local_runtime_session_applies_stable_policy_rollout_cohorts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "25")

    cohort = [
        guard_runner_module._canonical_policy_enforcement_enabled(
            device_id=f"device-{index}",
            workspace_id="workspace-alpha",
        )
        for index in range(100)
    ]

    assert any(cohort)
    assert not all(cohort)
    assert cohort == [
        guard_runner_module._canonical_policy_enforcement_enabled(
            device_id=f"device-{index}",
            workspace_id="workspace-alpha",
        )
        for index in range(100)
    ]


def test_sync_runtime_session_prefers_latest_sync_summary_for_package_manager_coverage_freshness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-alpha")
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    context = HarnessContext(
        home_dir=store.guard_home,
        workspace_dir=workspace_dir,
        guard_home=store.guard_home,
    )
    install_payload = install_package_shims(context, managers=("npm",))
    shim_dir = Path(str(install_payload["shim_dir"]))
    original_path = os.environ.get("PATH", "")
    monkeypatch.setenv("PATH", f"{shim_dir}{os.pathsep}{original_path}")
    store.set_sync_payload(
        "supply_chain_bundle_summary",
        {
            "synced_at": "2026-04-24T00:00:00+00:00",
        },
        "2026-04-24T00:00:00+00:00",
    )
    store.set_sync_payload(
        "sync_summary",
        {
            "synced_at": "2026-04-24T00:20:00+00:00",
        },
        "2026-04-24T00:20:00+00:00",
    )

    captured_body: dict[str, object] = {}

    def _runtime_sync_response(**kwargs):
        request = kwargs["request"]
        captured_body.update(json.loads(request.data.decode("utf-8")))
        return {"syncedAt": "2026-04-24T00:21:00+00:00", "items": []}

    monkeypatch.setattr(
        guard_runner_module,
        "_urlopen_json_with_timeout_retry",
        _runtime_sync_response,
    )

    guard_runner_module.sync_runtime_session(
        store,
        session={
            "harness": "codex",
            "surface": "cli",
            "status": "active",
            "updatedAt": "2026-04-24T00:21:00+00:00",
            "workspace": str(workspace_dir),
        },
    )

    session_payload = captured_body["session"]
    assert isinstance(session_payload, dict)
    assert session_payload["packageManagerCoverage"]["staleIntel"] == {
        "status": "fresh",
        "lastSyncedAt": "2026-04-24T00:20:00+00:00",
        "nextRefreshAt": "2026-04-24T00:35:00+00:00",
    }


def test_sync_runtime_session_prefers_ipv6_private_identity_when_ipv4_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-alpha")
    monkeypatch.setattr(guard_runner_module, "_safe_private_ip", lambda: None)
    monkeypatch.setattr(guard_runner_module, "_safe_private_ipv6", lambda: "fd00::42")
    captured_body: dict[str, object] = {}

    def _runtime_sync_response(**kwargs):
        request = kwargs["request"]
        captured_body.update(json.loads(request.data.decode("utf-8")))
        return {"syncedAt": "2026-04-24T00:01:00+00:00", "items": []}

    monkeypatch.setattr(
        guard_runner_module,
        "_urlopen_json_with_timeout_retry",
        _runtime_sync_response,
    )

    guard_runner_module.sync_runtime_session(
        store,
        session={
            "harness": "codex",
            "surface": "cli",
            "status": "active",
            "updatedAt": "2026-04-24T00:01:00+00:00",
            "workspace": str(tmp_path / "workspace"),
        },
    )

    session_payload = captured_body["session"]
    assert isinstance(session_payload, dict)
    assert session_payload["localIdentity"]["ipAddress"] == "fd00::42"
    assert session_payload["localIdentity"]["privateIpAddress"] == "fd00::42"
    assert session_payload["localIdentitySource"]["privateIpAddress"] == "local-guard"


def test_sync_runtime_session_keeps_local_identity_when_package_coverage_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-alpha")
    monkeypatch.setattr(
        guard_runner_module,
        "package_shim_cloud_coverage",
        lambda *_args, **_kwargs: {
            "generatedAt": "2026-04-24T00:01:00+00:00",
            "configuredManagers": [],
            "protectedManagers": [],
            "missingManagers": [],
            "pathActive": False,
            "bypasses": [],
            "staleIntel": {
                "status": "unknown",
                "lastSyncedAt": None,
                "nextRefreshAt": None,
            },
        },
    )
    captured_body: dict[str, object] = {}

    def _runtime_sync_response(**kwargs):
        request = kwargs["request"]
        captured_body.update(json.loads(request.data.decode("utf-8")))
        return {"syncedAt": "2026-04-24T00:01:00+00:00", "items": []}

    monkeypatch.setattr(
        guard_runner_module,
        "_urlopen_json_with_timeout_retry",
        _runtime_sync_response,
    )

    guard_runner_module.sync_runtime_session(
        store,
        session={
            "harness": "codex",
            "surface": "cli",
            "status": "active",
            "updatedAt": "2026-04-24T00:01:00+00:00",
            "workspace": str(tmp_path / "workspace"),
        },
    )

    session_payload = captured_body["session"]
    assert isinstance(session_payload, dict)
    assert "daemonId" not in session_payload["localIdentity"]
    assert session_payload["localIdentitySource"]["daemonId"] == "local-guard"
