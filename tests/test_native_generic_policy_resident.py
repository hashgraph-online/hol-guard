"""Loaded generic origins and signed controls reach the actual bundled auto runtime.

Only the explicit MDM test path, initial enrollment and staged capability names
are supplied; canonical enforcement is enabled only for this component test.
This does not certify an installed release or default rollout.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard import config as config_module
from codex_plugin_scanner.guard import native_hook_edge
from codex_plugin_scanner.guard.config import GuardConfig, load_guard_config
from codex_plugin_scanner.guard.mdm.policy import load_managed_policy
from codex_plugin_scanner.guard.native_managed_capture import compile_configuration_origins
from codex_plugin_scanner.guard.native_managed_configuration import MANAGED_CONFIGURATION_FEATURE
from codex_plugin_scanner.guard.native_mode import python_oracle_surface_enabled
from codex_plugin_scanner.guard.native_policy_authority_read import read_native_policy_authority_inputs
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_policy import effective_native_policy_v3
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeStatus
from codex_plugin_scanner.guard.store import GuardStore
from scripts.native_slo_session import stop_native_resident
from tests.native_generic_policy_vectors import generate_vectors
from tests.native_managed_source_support import managed_store
from tests.native_scoped_resident_fixtures import prepare_store
from tests.native_sensitive_resident_fixtures import sensitive_test_status as source_built_auto_status
from tests.test_generic_managed_origin_outer import _toml
from tests.test_native_sensitive_policy_resident import _clean_mode


def _cases(tmp_path: Path) -> list[dict[str, Any]]:
    result = cast(list[dict[str, Any]], generate_vectors(tmp_path / "generated-vectors")["cases"])
    assert len(result) == 260 and len({case["name"] for case in result}) == 260
    return result


@dataclass(frozen=True)
class GenericSource:
    store: GuardStore
    workspace: Path
    home: Path
    profile: Path

    def select(self, case: dict[str, Any]) -> GuardConfig:
        self.profile.write_text(json.dumps(case["configInputs"]["managed"]))
        (self.store.guard_home / "config.toml").write_text(_toml(case["configInputs"]["local"]))
        loaded = load_guard_config(self.store.guard_home, workspace=self.workspace)
        assert loaded.managed_policy_status == "active" and loaded.managed_policy is not None
        assert loaded.local_policy_origin is not None
        assert dict(loaded.managed_policy.settings) == case["configInputs"]["managed"]["settings"]
        assert effective_native_policy_v3(loaded.local_policy_origin) == case["localEffectivePolicy"]
        compiled = compile_configuration_origins((loaded,))
        assert compiled.get("_managed_config") == case["managedConfiguration"]
        return loaded


def _source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> GenericSource:
    store, workspace = prepare_store(tmp_path)
    profile = tmp_path / "synthetic-managed-policy.json"
    monkeypatch.setattr(
        config_module, "load_managed_policy", lambda: load_managed_policy(policy_path=profile, write_cache=False)
    )
    return GenericSource(store, workspace, tmp_path, profile)


def _edge(
    publisher: NativePolicySnapshotPublisher,
    status: NativeRuntimeStatus,
    workspace: Path,
    home: Path,
    payload: dict[str, Any],
    *,
    observe: bool,
    case_name: str,
) -> dict[str, Any]:
    result = native_hook_edge.review_raw_hook_native(
        payload=payload,
        harness="codex",
        event="PreToolUse",
        guard_home=publisher.store.guard_home,
        home_dir=home,
        cwd=workspace,
        source_ref_external_allowed=False,
        observe_mode=observe,
        deadline=time.monotonic() + 5,
        policy_snapshot=publisher.current_snapshot_binding(),
    )
    assert result is not None, f"{case_name}: actual resident response is required"
    assert result["schema"] == "guard-hook-edge-result.v3" and result["authority"] == "rust"
    assert publisher.result_binding_is_current(result["policy_binding"])
    assert result["policy_binding"]["selected_decision_id"] is None
    assert status.capabilities is not None
    assert result["receipt"]["rule_digest"] == status.capabilities.rule_digest
    return result


def test_generic_resident_fixture_preserves_all_actual_origin_projections(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clean_mode(monkeypatch)
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    before = dict(os.environ)
    assert not python_oracle_surface_enabled()
    source = _source(tmp_path, monkeypatch)
    cases = _cases(tmp_path)
    assert dict(os.environ) == before
    assert not python_oracle_surface_enabled()
    for case in cases:
        _ = source.select(case)


def test_generic_vector_failure_restores_clean_native_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clean_mode(monkeypatch)
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    before = dict(os.environ)

    def fail_renderer(*_args: object, **_kwargs: object) -> int:
        assert python_oracle_surface_enabled()
        raise RuntimeError("synthetic vector generation failure")

    monkeypatch.setattr("tests.native_generic_policy_vectors._run_guard_hook_command", fail_renderer)
    with pytest.raises(RuntimeError, match="synthetic vector generation failure"):
        _cases(tmp_path)
    assert dict(os.environ) == before
    assert not python_oracle_surface_enabled()


@pytest.mark.slow
def test_generic_origins_reach_actual_auto_resident(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _clean_mode(monkeypatch)
    status = source_built_auto_status()
    assert status.identity is not None and status.capabilities is not None
    executable = status.identity.path
    monkeypatch.setattr(native_hook_edge, "native_runtime_status", lambda: status)
    source = _source(tmp_path, monkeypatch)
    publisher = NativePolicySnapshotPublisher(store=source.store, status_provider=lambda: status)
    completed: list[str] = []
    previous_binding = None
    try:
        for case in _cases(tmp_path):
            _ = source.select(case)
            publisher.request_publish()
            assert publisher.current_snapshot_binding() is None
            publisher._publish_once()
            assert publisher.is_ready(), (case["name"], publisher.last_error)
            result = _edge(
                publisher,
                status,
                source.workspace,
                source.home,
                case["payload"],
                observe=case["mode"] == "observe",
                case_name=case["name"],
            )
            expected = case["expected"]
            assert result["result"]["policy_action"] == expected["finalPolicyAction"], case["name"]
            assert result["result"]["decision"] == ("allow" if expected["exitCode"] == 0 else "deny")
            assert result["observed_policy_action"] == expected["observedPolicyAction"]
            assert result["receipt"]["policy_action"] == expected["finalPolicyAction"]
            assert result["receipt"]["observed_policy_action"] == expected["observedPolicyAction"]
            if previous_binding is not None:
                assert not publisher.result_binding_is_current(previous_binding)
            previous_binding = result["policy_binding"]
            completed.append(case["name"])
        assert len(completed) == len(set(completed)) == 260
        assert previous_binding is not None
        status = replace(
            status,
            capabilities=replace(
                status.capabilities,
                features=tuple(
                    feature for feature in status.capabilities.features if feature != MANAGED_CONFIGURATION_FEATURE
                ),
            ),
        )
        publisher.request_publish()
        publisher._publish_once()
        assert not publisher.is_ready() and publisher.current_snapshot_binding() is None
        assert publisher.last_error == "native_policy_authority_capability_unsupported"
        assert not publisher.result_binding_is_current(previous_binding)
    finally:
        publisher.close()
        assert stop_native_resident(executable, source.store.guard_home, write_diagnostic=False).contained


@pytest.mark.slow
def test_generic_signed_lockdown_and_withdrawal_reach_actual_auto_resident(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clean_mode(monkeypatch)
    status = source_built_auto_status()
    assert status.identity is not None
    monkeypatch.setattr(native_hook_edge, "native_runtime_status", lambda: status)
    store = managed_store(tmp_path, monkeypatch, lockdown=True)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    publisher = NativePolicySnapshotPublisher(store=store, status_provider=lambda: status)
    payload: dict[str, Any] = {"tool_name": "Shell", "tool_input": {"command": "printf Synthetic"}}
    try:
        for mode in ("enforce", "observe"):
            (store.guard_home / "config.toml").write_text(f'mode="{mode}"\ndefault_action="allow"\n')
            inputs = read_native_policy_authority_inputs(store, now=time.time())
            assert inputs.authority.managed is not None and inputs.authority.managed.global_lockdown
            publisher.request_publish()
            publisher._publish_once()
            assert publisher.is_ready(), publisher.last_error
            result = _edge(
                publisher, status, workspace, tmp_path, payload, observe=mode == "observe", case_name=f"lockdown-{mode}"
            )
            assert result["result"]["policy_action"] == "block" and result["result"]["decision"] == "deny"
            assert result["observed_policy_action"] is None
        keyring = store.get_sync_payload("policy_bundle_keyring")
        assert isinstance(keyring, dict)
        keys = keyring["keys"]
        assert isinstance(keys, list) and isinstance(keys[0], dict)
        keys[0]["state"] = "revoked"
        now = datetime.now(timezone.utc).isoformat()
        store.set_sync_payload("policy_bundle_keyring", keyring, now)
        publisher.request_publish()
        publisher._publish_once()
        assert not publisher.is_ready() and publisher.current_snapshot_binding() is None
        assert not publisher.result_binding_is_current(result["policy_binding"])
        store.clear_policy_bundle_authority(now, policy_bundle_last_error={"reason": "synthetic-clear"})
        publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
        cleared = _edge(
            publisher, status, workspace, tmp_path, payload, observe=True, case_name="explicit-clear-observe"
        )
        assert cleared["result"]["policy_action"] == "allow" and cleared["result"]["decision"] == "allow"
        assert cleared["policy_binding"]["source_input_digest"] != result["policy_binding"]["source_input_digest"]
    finally:
        publisher.close()
        assert stop_native_resident(status.identity.path, store.guard_home, write_diagnostic=False).contained
