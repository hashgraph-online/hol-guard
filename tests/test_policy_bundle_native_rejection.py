"""A deterministic native rejection is a verdict, not an outage: it must not read or behave like one."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import synced_policy
from codex_plugin_scanner.guard.native_policy_bundle import (
    NATIVE_UNAVAILABLE_REJECTION,
    PolicyBundleNativeError,
    PolicyBundleNativeUnavailableError,
)
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.store import GuardStore
from tests.cloud_exception_bundle_fixtures import build_cloud_exception_policy_bundle
from tests.support.network import stub_authenticated_urlopen
from tests.test_cloud_exception_sync_proof import _JsonResponse
from tests.test_cloud_exception_sync_proof import _seed_guard_cloud as _seed_sync_cloud
from tests.test_policy_bundle_parser import computed_policy_bundle_hash


def _raising(error: PolicyBundleNativeError):
    def _raise(*_args: object, **_kwargs: object) -> object:
        raise error

    return _raise


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (PolicyBundleNativeError("limit_bytes"), "limit_bytes"),
        (PolicyBundleNativeUnavailableError("down"), NATIVE_UNAVAILABLE_REJECTION),
    ],
)
def test_cached_validation_keeps_the_native_rejection_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: PolicyBundleNativeError, expected: str
) -> None:
    bundle = build_cloud_exception_policy_bundle()
    monkeypatch.setattr(synced_policy, "validate_synced_policy_bundle", lambda *_a, **_k: (bundle, None, ()))
    monkeypatch.setattr(synced_policy, "policy_bundle_is_enforceable", _raising(error))

    validated, reason = synced_policy.cached_policy_bundle_validation(GuardStore(tmp_path / "guard-home"), bundle)

    assert validated is None
    assert reason == expected


def _sync_response(bundle: dict[str, object]):
    def fake_urlopen(request, timeout):
        if request.full_url.endswith("/api/v1/guard/events"):
            return _JsonResponse({"accepted": 0, "rejected": 0, "statuses": []})
        return _JsonResponse({"syncedAt": "2026-06-14T12:00:01+00:00", "receiptsStored": 0, "policyBundle": bundle})

    return fake_urlopen


@pytest.mark.parametrize(
    ("error", "keeps_prior", "reason"),
    [
        (PolicyBundleNativeUnavailableError("down"), True, NATIVE_UNAVAILABLE_REJECTION),
        (PolicyBundleNativeError("limit_bytes"), False, "limit_bytes"),
    ],
)
def test_runner_only_keeps_prior_authority_for_an_outage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error: PolicyBundleNativeError,
    keeps_prior: bool,
    reason: str,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_sync_cloud(store, workspace_id="workspace-sync-proof")
    bundle = build_cloud_exception_policy_bundle()
    bundle["bundleHash"] = computed_policy_bundle_hash(bundle)
    stub_authenticated_urlopen(monkeypatch, _sync_response(bundle))
    monkeypatch.setattr(guard_runner_module, "sync_pain_signals", lambda _store, auth_context=None: 0)
    guard_runner_module.sync_receipts(store)
    accepted = store.get_sync_payload("policy_bundle")
    assert isinstance(accepted, dict)
    decisions_before = store.list_policy_decisions()
    assert decisions_before

    monkeypatch.setattr(guard_runner_module, "effective_policy_bundle_acknowledgement", _raising(error))
    guard_runner_module.sync_receipts(store)

    rejections = store.list_events(event_name="policy_bundle/rejected")
    assert rejections
    payload = rejections[0]["payload"]
    assert isinstance(payload, dict)
    assert payload["reason"] == reason
    assert (store.list_policy_decisions() == decisions_before) is keeps_prior
