"""The daemon's policy sync answers the v2 screens the CLI sync already applies.

Cloud sends a v2 bundle only when v1 cannot carry the policy, so the daemon now
compiles one on every device rather than discarding it outside the canonical
rollout. Compiling it is what makes these screens the daemon's business too: a
document that does not compile has to come back as a verdict instead of
dropping the request, and a candidate the resident cannot hold against the
legacy shadow must not be activated here when ``sync_receipts`` would refuse it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_policy_bundle import NATIVE_UNAVAILABLE_REJECTION
from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError
from codex_plugin_scanner.guard.policy_document_types import PolicyCompilationError
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.runtime import runner_native_authority as authority
from codex_plugin_scanner.guard.runtime import runner_native_sync as native_sync
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_headless_daemon_api import _seed_guard_cloud
from tests.test_policy_bundle_delivery_daemon import _enable, _fixture, _sync


def _store(tmp_path: Path) -> GuardStore:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-managed-controls")
    return store


def test_daemon_answers_a_compile_rejection_with_its_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable(monkeypatch)
    store = _store(tmp_path)
    bundle, delivery = _fixture(store)

    def _uncompilable(*_args: object, **_kwargs: object) -> object:
        raise PolicyCompilationError("unsupported_rule_action", "rule-7")

    monkeypatch.setattr(runner, "compile_policy_bundle_document", _uncompilable)
    status, response = _sync(store, bundle=bundle, delivery=delivery)

    assert status == 400, response
    assert response["error"] == "canonical_compile_unsupported_rule_action"
    assert store.get_sync_payload("policy_bundle") is None
    assert store.get_sync_payload("policy_bundle_ack") is None


def test_daemon_refuses_a_candidate_the_resident_cannot_shadow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable(monkeypatch)
    store = _store(tmp_path)
    bundle, delivery = _fixture(store)

    def _no_verdict(*_args: object, **_kwargs: object) -> tuple[str, ...]:
        raise NativeRunnerAuthorityError("unavailable")

    monkeypatch.setattr(authority, "policy_shadow_mismatch", _no_verdict)
    status, response = _sync(store, bundle=bundle, delivery=delivery)

    assert status == 400, response
    assert response["error"] == "native_shadow_unavailable"
    assert store.get_sync_payload("policy_bundle") is None
    assert store.get_sync_payload("policy_bundle_ack") is None


def test_daemon_refuses_a_shadow_mismatch_on_a_rollout_device(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable(monkeypatch)
    store = _store(tmp_path)
    bundle, delivery = _fixture(store)
    monkeypatch.setattr(
        authority,
        "policy_shadow_mismatch",
        lambda *_args, **_kwargs: ("decision_rows_differ",),
    )
    monkeypatch.setattr(native_sync, "canonical_policy_enforcement_enabled", lambda **_kwargs: True)
    status, response = _sync(store, bundle=bundle, delivery=delivery)

    assert status == 400, response
    assert response["error"] == "canonical_shadow_mismatch"
    assert store.get_sync_payload("policy_bundle") is None
    assert store.get_sync_payload("policy_bundle_ack") is None


def test_daemon_still_activates_a_candidate_that_agrees_with_the_shadow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable(monkeypatch)
    store = _store(tmp_path)
    bundle, delivery = _fixture(store)
    monkeypatch.setattr(native_sync, "canonical_policy_enforcement_enabled", lambda **_kwargs: True)
    status, response = _sync(store, bundle=bundle, delivery=delivery)

    assert status == 200, response
    acknowledgement = store.get_sync_payload("policy_bundle_ack")
    assert isinstance(acknowledgement, dict)
    assert all(acknowledgement[key] == value for key, value in delivery.items())


def test_daemon_answers_a_rollout_lookup_outage_with_503(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable(monkeypatch)
    store = _store(tmp_path)
    bundle, delivery = _fixture(store)

    def _resident_down(**_kwargs: object) -> bool:
        raise NativeRunnerAuthorityError("unavailable")

    monkeypatch.setattr(native_sync, "canonical_policy_enforcement_enabled", _resident_down)
    status, response = _sync(store, bundle=bundle, delivery=delivery)

    assert status == 503, response
    assert response["error"] == NATIVE_UNAVAILABLE_REJECTION
    assert store.get_sync_payload("policy_bundle") is None
    assert store.get_sync_payload("policy_bundle_ack") is None
