"""The daemon's policy sync answers the v2 screens the CLI sync already applies.

Cloud sends a v2 bundle only when v1 cannot carry the policy, so the daemon now
compiles one on every device rather than discarding it outside the canonical
rollout. Compiling it is what makes these screens the daemon's business too: a
document that does not compile has to come back as a verdict instead of
dropping the request, and a candidate the resident cannot hold against the
legacy shadow must not be activated here when ``sync_receipts`` would refuse it.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_policy_bundle import NATIVE_UNAVAILABLE_REJECTION
from codex_plugin_scanner.guard.native_policy_document import NativePolicyDocumentError
from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError
from codex_plugin_scanner.guard.runtime import runner_native_sync as native_sync
from codex_plugin_scanner.guard.runtime import runner_policy_shadow as shadow
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_headless_daemon_api import _seed_guard_cloud
from tests.test_policy_bundle_delivery_daemon import _enable, _fixture, _sync


def _store(tmp_path: Path) -> GuardStore:
    store = GuardStore(tmp_path / "guard-home")
    _seed_guard_cloud(store, workspace_id="workspace-managed-controls")
    return store


def _answer(asked: list[str] | None = None, **fields: object) -> Callable[..., object]:
    answer: dict[str, object] = {"decisions": [], "rejection": None, "rule_id": None, "mismatch": None, **fields}

    def _query(query: str, _body: dict[str, object], **_kwargs: object) -> object:
        if asked is not None:
            asked.append(query)
        return answer

    return _query


def test_daemon_answers_a_compile_rejection_with_its_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable(monkeypatch)
    store = _store(tmp_path)
    bundle, delivery = _fixture(store)
    asked: list[str] = []
    query = _answer(asked, rejection="canonical_compile_unsupported_rule_action", rule_id="rule-7")
    monkeypatch.setattr(shadow, "policy_query", query)
    status, response = _sync(store, bundle=bundle, delivery=delivery)

    assert status == 400, response
    assert response["error"] == "canonical_compile_unsupported_rule_action"
    assert asked == ["bundle_candidate"]
    assert store.get_sync_payload("policy_bundle") is None
    assert store.get_sync_payload("policy_bundle_ack") is None


def test_daemon_refuses_a_candidate_the_resident_cannot_shadow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable(monkeypatch)
    store = _store(tmp_path)
    bundle, delivery = _fixture(store)
    mismatch = {"canonicalRows": 1, "legacyRows": 0, "reasonCodes": ["native_shadow_unavailable"], "status": "mismatch"}
    monkeypatch.setattr(shadow, "policy_query", _answer(rejection="native_shadow_unavailable", mismatch=mismatch))
    status, response = _sync(store, bundle=bundle, delivery=delivery)

    assert status == 400, response
    assert response["error"] == "native_shadow_unavailable"
    assert store.list_events(event_name="policy_bundle/shadow_mismatch")[-1]["payload"] == mismatch
    assert store.get_sync_payload("policy_bundle") is None
    assert store.get_sync_payload("policy_bundle_ack") is None


@pytest.mark.parametrize(
    "failure",
    [
        NativePolicyDocumentError("native_policy_document_unavailable"),
        ValueError("policy_document_query_invalid"),
    ],
)
def test_daemon_answers_an_unreachable_candidate_query_with_503(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
) -> None:
    # An outage, or a runtime that predates the query, is no verdict about the
    # bundle: the device keeps its policy and the daemon reports the outage.
    _enable(monkeypatch)
    store = _store(tmp_path)
    bundle, delivery = _fixture(store)

    def _down(*_args: object, **_kwargs: object) -> object:
        raise failure

    monkeypatch.setattr(shadow, "policy_query", _down)
    status, response = _sync(store, bundle=bundle, delivery=delivery)

    assert status == 503, response
    assert response["error"] == NATIVE_UNAVAILABLE_REJECTION
    assert store.get_sync_payload("policy_bundle") is None
    assert store.get_sync_payload("policy_bundle_ack") is None


@pytest.mark.parametrize(
    "answer",
    [
        None,
        {"decisions": [], "rejection": None},
        {"decisions": [{"harness": "codex"}], "rejection": None, "rule_id": None, "mismatch": None},
        {"decisions": [], "rejection": None, "rule_id": None, "mismatch": {"status": "mismatch"}},
    ],
)
def test_daemon_refuses_a_malformed_candidate_answer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    answer: object,
) -> None:
    _enable(monkeypatch)
    store = _store(tmp_path)
    bundle, delivery = _fixture(store)
    monkeypatch.setattr(shadow, "policy_query", lambda *_args, **_kwargs: answer)
    status, response = _sync(store, bundle=bundle, delivery=delivery)

    assert status == 503, response
    assert store.get_sync_payload("policy_bundle") is None


def test_daemon_refuses_a_shadow_mismatch_on_a_rollout_device(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable(monkeypatch)
    store = _store(tmp_path)
    bundle, delivery = _fixture(store)
    monkeypatch.setattr(native_sync, "canonical_policy_enforcement_enabled", lambda **_kwargs: True)
    mismatch = {"canonicalRows": 1, "legacyRows": 1, "reasonCodes": ["action"], "status": "mismatch"}
    monkeypatch.setattr(
        shadow,
        "policy_query",
        _answer(rejection="canonical_shadow_mismatch", mismatch=mismatch),
    )
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
