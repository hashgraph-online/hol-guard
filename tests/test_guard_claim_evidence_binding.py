"""Saved-allow claim evidence is re-verified by the resident under its write lock.

The integrity state, key and signed-bundle identities that decide a claim are
gathered by the Python transport before the claim's write transaction. None of
them is covered by the authority-revision triggers, so each can move in the
window between gathering and claiming. The claim must refuse, and a missing
diagnosis must fail closed instead of raising.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Callable
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_store_policy, store_policy
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_approval_reuse import _install_signed_exact_policies

_NOW = "2026-07-17T12:00:00+00:00"
_LOOKUP = "2026-07-17T12:01:00+00:00"
_CLAIM = "2026-07-17T12:02:00+00:00"
_RACED = "2026-07-17T12:01:30+00:00"
_ARTIFACT_ID = "codex:project:tool-action:binding-race"
_ARTIFACT_HASH = "sha256:binding-race"

_BUNDLE_SYNC_KEYS = (
    "policy_bundle",
    "policy_bundle_keyring",
    "supply_chain_bundle_keyring",
    "managed_policy_bundle_keyring_provenance",
    "policy_bundle_acceptance_checkpoint",
)


def _bundle_store(tmp_path: Path) -> tuple[GuardStore, dict[str, object]]:
    store = GuardStore(tmp_path / "guard-home")
    _install_signed_exact_policies(
        store,
        [(_ARTIFACT_ID, "allow", "Signed remote allow")],
        now=_NOW,
        bundle_version="policy-2026-07-17.binding-race",
    )
    selected = store.resolve_policy_decision("codex", _ARTIFACT_ID, _ARTIFACT_HASH, now=_LOOKUP, consume_one_shot=False)
    assert selected is not None
    assert selected["source"] == "policy-bundle"
    return store, selected


def _local_store(tmp_path: Path) -> tuple[GuardStore, dict[str, object]]:
    store = GuardStore(tmp_path / "guard-home")
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=_ARTIFACT_ID,
            artifact_hash=_ARTIFACT_HASH,
            source="approval-gate",
        ),
        _NOW,
    )
    selected = store.resolve_policy_decision("codex", _ARTIFACT_ID, _ARTIFACT_HASH, now=_LOOKUP, consume_one_shot=False)
    assert selected is not None
    return store, selected


def _race(
    monkeypatch: pytest.MonkeyPatch,
    mutate: Callable[[], None] | None,
    *,
    strip_binding: bool = False,
) -> None:
    """Run ``mutate`` after the evidence is gathered, right before dispatch."""

    real = store_policy.native_claim_approval_reuse_decisions

    def racing(**kwargs: object) -> bool:
        if mutate is not None:
            mutate()
        if strip_binding:
            evidence = dict(kwargs["evidence"])  # type: ignore[arg-type]
            evidence.pop("evidence_binding")
            kwargs["evidence"] = evidence
        return real(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(store_policy, "native_claim_approval_reuse_decisions", racing)


def _touch_sync_state(store: GuardStore, key: str) -> Callable[[], None]:
    def mutate() -> None:
        payload = store.get_sync_payload(key)
        store.set_sync_payload(key, {**(payload if isinstance(payload, dict) else {}), "raced": True}, _RACED)

    return mutate


def _set_workspace(store: GuardStore) -> Callable[[], None]:
    return lambda: store.set_sync_payload("oauth_local_credentials", {"workspace_id": "workspace-2"}, _RACED)


def _swap_device(store: GuardStore) -> Callable[[], None]:
    def mutate() -> None:
        with sqlite3.connect(store.path) as connection:
            connection.execute("update guard_devices set installation_id = 'raced-install'")

    return mutate


def _claim_events(store: GuardStore) -> int:
    return len(store.list_events(event_name="approval.policy_reuse_applied"))


def test_unchanged_bundle_evidence_still_claims(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store, selected = _bundle_store(tmp_path)
    _race(monkeypatch, None)

    assert store.claim_approval_reuse_decision(selected, now=_CLAIM) is True
    assert _claim_events(store) == 1


@pytest.mark.parametrize("sync_key", _BUNDLE_SYNC_KEYS)
def test_claim_refuses_bundle_source_changed_between_gather_and_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sync_key: str
) -> None:
    store, selected = _bundle_store(tmp_path)
    _race(monkeypatch, _touch_sync_state(store, sync_key))

    assert store.claim_approval_reuse_decision(selected, now=_CLAIM) is False
    assert _claim_events(store) == 0


def test_claim_refuses_workspace_changed_between_gather_and_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, selected = _bundle_store(tmp_path)
    _race(monkeypatch, _set_workspace(store))

    assert store.claim_approval_reuse_decision(selected, now=_CLAIM) is False
    assert _claim_events(store) == 0


def test_claim_refuses_device_changed_between_gather_and_claim(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store, selected = _bundle_store(tmp_path)
    _race(monkeypatch, _swap_device(store))

    assert store.claim_approval_reuse_decision(selected, now=_CLAIM) is False
    assert _claim_events(store) == 0


def test_claim_refuses_bundle_evidence_shipped_without_a_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, selected = _bundle_store(tmp_path)
    _race(monkeypatch, None, strip_binding=True)

    assert store.claim_approval_reuse_decision(selected, now=_CLAIM) is False
    assert _claim_events(store) == 0


def test_unchanged_local_evidence_still_claims(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store, selected = _local_store(tmp_path)
    _race(monkeypatch, None)

    assert store.claim_approval_reuse_decision(selected, now=_CLAIM) is True


def test_claim_refuses_integrity_state_changed_between_gather_and_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, selected = _local_store(tmp_path)
    _race(monkeypatch, _touch_sync_state(store, "policy_integrity"))

    assert store.claim_approval_reuse_decision(selected, now=_CLAIM) is False


def test_claim_refuses_local_evidence_shipped_without_a_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, selected = _local_store(tmp_path)
    _race(monkeypatch, None, strip_binding=True)

    assert store.claim_approval_reuse_decision(selected, now=_CLAIM) is False


def test_bundle_binding_is_read_before_the_identities_it_binds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A source that moves while the identities are derived must differ from the binding."""

    store, selected = _bundle_store(tmp_path)
    real = store._cached_policy_bundle_decision_identities

    def moving(**kwargs: object) -> frozenset[tuple[object, ...]]:
        identities = real(**kwargs)
        _set_workspace(store)()
        return identities

    monkeypatch.setattr(store, "_cached_policy_bundle_decision_identities", moving)

    assert store.claim_approval_reuse_decision(selected, now=_CLAIM) is False
    assert _claim_events(store) == 0


def _record_saved_rows(store: GuardStore) -> None:
    store.record_local_once_approval(
        request_id="req-diagnostic",
        harness="codex",
        artifact_id=_ARTIFACT_ID,
        artifact_hash=_ARTIFACT_HASH,
        workspace="/workspace/a",
        publisher=None,
        action="allow",
        created_at=_NOW,
        expires_at="2026-07-17T13:00:00+00:00",
    )


def test_native_diagnostic_without_a_resident_raises_the_typed_value_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(native_store_policy, "_resident_request", lambda **_kwargs: None)

    with pytest.raises(ValueError, match="native_approval_reuse_diagnostic_unavailable") as raised:
        native_store_policy.native_approval_reuse_diagnostic(
            store_path=tmp_path / "guard.db",
            guard_home=tmp_path,
            harness="codex",
            artifact_id=_ARTIFACT_ID,
            artifact_hash=_ARTIFACT_HASH,
            workspace=None,
            publisher=None,
            now=_NOW,
            evidence_provider=lambda _policy, _local_once: {},
        )
    assert isinstance(raised.value, native_store_policy.ApprovalReuseDiagnosticUnavailableError)


def test_diagnostic_fails_closed_with_a_typed_warning_when_the_resident_gives_no_answer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _record_saved_rows(store)
    monkeypatch.setattr(native_store_policy, "_resident_request", lambda **_kwargs: None)

    with caplog.at_level(logging.WARNING, logger=store_policy.__name__):
        result = store.approval_reuse_diagnostic(
            "codex", _ARTIFACT_ID, _ARTIFACT_HASH, "/workspace/a", None, now=_CLAIM
        )
        reason = store.approval_reuse_validation_reason(
            "codex", _ARTIFACT_ID, _ARTIFACT_HASH, "/workspace/a", None, now=_CLAIM
        )

    assert result == ("approval_reuse_integrity_failure", None)
    assert reason == "approval_reuse_integrity_failure"
    messages = [record.getMessage() for record in caplog.records if record.name == store_policy.__name__]
    assert len(messages) == 2
    assert all("native_approval_reuse_diagnostic_unavailable" in message for message in messages)
    assert all(record.exc_info is None for record in caplog.records)


def test_fresh_home_diagnostic_needs_no_resident(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")

    def forbidden(**_kwargs: object) -> None:
        raise AssertionError("a store with no saved rows must not need the resident")

    monkeypatch.setattr(native_store_policy, "_resident_request", forbidden)

    assert store.approval_reuse_diagnostic("codex", _ARTIFACT_ID, _ARTIFACT_HASH, "/workspace/a", None) == (None, None)
    assert store.approval_reuse_validation_reason("codex", _ARTIFACT_ID, _ARTIFACT_HASH, None, None) is None
