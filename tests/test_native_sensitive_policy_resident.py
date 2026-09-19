"""Exact source-built auto resident decisions after real source publication.

Only initial trust enrollment, the explicit MDM test path and capability names
are staged. No installed release or production support claim is made.
"""

from __future__ import annotations

import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_hook_edge
from codex_plugin_scanner.guard.native_managed_capture import compile_configuration_origins
from codex_plugin_scanner.guard.native_managed_configuration import MANAGED_CONFIGURATION_FEATURE
from codex_plugin_scanner.guard.native_policy_authority_read import read_native_policy_authority_inputs
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeStatus
from scripts.native_slo_session import stop_native_resident
from tests import native_sensitive_read_policy_vectors as vectors
from tests.native_managed_source_support import managed_store
from tests.native_sensitive_resident_fixtures import origin_cases, sensitive_source, sensitive_test_status


def _clean_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("HOL_GUARD_TEST_MODE", "HOL_GUARD_PYTHON_ORACLE", "HOL_GUARD_NATIVE_DIAGNOSTIC"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")


def _edge(
    publisher: NativePolicySnapshotPublisher,
    status: NativeRuntimeStatus,
    workspace: Path,
    home: Path,
    *,
    observe: bool = False,
) -> dict[str, Any]:
    result = native_hook_edge.review_raw_hook_native(
        payload={"tool_name": "Read", "tool_input": {"file_path": str(workspace / ".npmrc")}},
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
    assert result is not None, "the actual resident must return an authenticated decision"
    assert result["schema"] == "guard-hook-edge-result.v3" and result["authority"] == "rust"
    assert publisher.result_binding_is_current(result["policy_binding"])
    assert result["policy_binding"]["selected_decision_id"] is None
    assert status.capabilities is not None
    assert result["receipt"]["rule_digest"] == status.capabilities.rule_digest
    return result


def test_sensitive_resident_fixture_uses_actual_loaded_origins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = sensitive_source(tmp_path, monkeypatch)
    cases = origin_cases(source.artifact_id)
    assert len(cases) == 7 and len({case.name for case in cases}) == 7
    projected = []
    for case in cases:
        loaded = source.select(case)
        compiled = compile_configuration_origins((loaded,))
        origin = compiled["_managed_config"]
        assert isinstance(origin, dict) and loaded.managed_policy is not None
        assert origin["source_digest"] == loaded.managed_policy.content_hash
        assert origin["default_action_present"] is ("default_action" in case.managed)
        projected.append(origin)
        with monkeypatch.context() as context:
            context.setattr(vectors, "config_for", lambda *args, _loaded=loaded, **kwargs: _loaded)
            evaluated = vectors.evaluate_case(
                {
                    "harness": "codex",
                    "payload": source.payload(),
                    "source": {
                        "home_dir": str(source.home),
                        "cwd": str(source.workspace),
                        "guard_home": str(source.store.guard_home),
                    },
                },
                vectors.Configuration(case.name),
                "observe" if case.mode == "observe" else "enforce",
                source.store.guard_home,
            )
        expected = evaluated["expected"]
        assert isinstance(expected, dict)
        assert expected["finalPolicyAction" if case.mode == "observe" else "evaluatedPolicyAction"] == case.expected
        if case.observed is not None:
            assert expected["observedPolicyAction"] == case.observed
    assert projected[-2]["effective_policy"] == projected[-1]["effective_policy"]
    assert projected[-2]["default_action_present"] is False
    assert projected[-1]["default_action_present"] is True


@pytest.mark.slow
def test_sensitive_read_origins_reach_actual_auto_resident(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _clean_mode(monkeypatch)
    status = sensitive_test_status()
    assert status.identity is not None and status.capabilities is not None
    executable = status.identity.path
    monkeypatch.setattr(native_hook_edge, "native_runtime_status", lambda: status)
    source = sensitive_source(tmp_path, monkeypatch)
    publisher = NativePolicySnapshotPublisher(store=source.store, status_provider=lambda: status)
    bindings = []
    try:
        for case in origin_cases(source.artifact_id):
            source.select(case)
            publisher.request_publish()
            assert publisher.current_snapshot_binding() is None
            publisher._publish_once()
            assert publisher.is_ready(), (case.name, publisher.last_error)
            result = _edge(publisher, status, source.workspace, source.home, observe=case.mode == "observe")
            assert result["result"]["policy_action"] == case.expected, case.name
            assert result["result"]["decision"] == ("allow" if case.expected in {"allow", "warn"} else "deny")
            if case.observed is not None:
                assert result["observed_policy_action"] == case.observed
            if bindings:
                assert not publisher.result_binding_is_current(bindings[-1])
                assert result["policy_binding"]["source_input_digest"] != bindings[-1]["source_input_digest"]
            bindings.append(result["policy_binding"])
        # Removing required negotiated support must close the next publication.
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
        assert not publisher.result_binding_is_current(bindings[-1])
        assert publisher.last_error == "native_policy_authority_capability_unsupported"
    finally:
        publisher.close()
        assert stop_native_resident(executable, source.store.guard_home, write_diagnostic=False).contained


@pytest.mark.slow
def test_sensitive_read_signed_lockdown_and_withdrawal_reach_actual_auto_resident(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clean_mode(monkeypatch)
    status = sensitive_test_status()
    assert status.identity is not None
    monkeypatch.setattr(native_hook_edge, "native_runtime_status", lambda: status)
    store = managed_store(tmp_path, monkeypatch, lockdown=True)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    publisher = NativePolicySnapshotPublisher(store=store, status_provider=lambda: status)
    try:
        for mode in ("enforce", "observe"):
            (store.guard_home / "config.toml").write_text(
                f'mode="{mode}"\ndefault_action="allow"\n[risk_actions]\nlocal_secret_read="allow"\n',
                encoding="utf-8",
            )
            inputs = read_native_policy_authority_inputs(store, now=time.time())
            assert inputs.authority.managed is not None and inputs.authority.managed.global_lockdown
            publisher.request_publish()
            publisher._publish_once()
            assert publisher.is_ready(), publisher.last_error
            result = _edge(publisher, status, workspace, tmp_path, observe=mode == "observe")
            assert result["result"]["policy_action"] == "block" and result["result"]["decision"] == "deny"
            if mode == "observe":
                assert result["observed_policy_action"] == "block"
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
        cleared = _edge(publisher, status, workspace, tmp_path, observe=True)
        assert cleared["result"]["policy_action"] == "allow" and cleared["result"]["decision"] == "allow"
        assert cleared["policy_binding"]["source_input_digest"] != result["policy_binding"]["source_input_digest"]
    finally:
        publisher.close()
        assert stop_native_resident(status.identity.path, store.guard_home, write_diagnostic=False).contained
