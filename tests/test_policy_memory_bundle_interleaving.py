"""Real SQLite decisions through independent signed bundle and memory updates."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.review_contracts import REVIEW_VERIFICATION_KEYRING_SYNC_KEY
from codex_plugin_scanner.guard.store import GuardStore
from tests.policy_bundle_signing_helpers import sign_policy_bundle
from tests.test_guard_review_policy_memory_command import _bundle, _resign_bundle, _store
from tests.test_policy_bundle_activation_atomicity import _activate_bundle, _signed_bundle
from tests.test_policy_memory_authority_binding import _apply, _decision, _now


def _policy(version: str, at: str) -> dict[str, object]:
    bundle = _signed_bundle(rollout_state="enforcing", bundle_version=version, issued_at=at)
    bundle["rules"][0].update(action="block", artifactId="codex:bundle-check")
    return sign_policy_bundle(bundle)


def _assert_authority(store: GuardStore, memory: str | None) -> None:
    assert store.resolve_policy("codex", "codex:bundle-check", now=_now()) == "block"
    assert store.resolve_policy("codex", "codex:local-check", now=_now()) == "block"
    assert _decision(store) == memory
    sources = {row["source"] for row in store.list_policy_decisions()}
    assert {"policy-bundle", "local"} <= sources
    assert ("cloud-signed-memory" in sources) == (memory is not None)


def test_bundle_memory_bundle_restart_revoke_replay_preserves_actual_decisions(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.set_sync_payload(
        REVIEW_VERIFICATION_KEYRING_SYNC_KEY, store.get_sync_payload("policy_bundle_keyring"), _now()
    )
    store.upsert_policy(
        PolicyDecision(harness="codex", scope="artifact", action="block", artifact_id="codex:local-check"), _now()
    )
    bundle_a = _policy("bundle-a", "2026-09-01T00:00:00Z")
    bundle_b = _policy("bundle-b", "2026-09-02T00:00:00Z")
    _activate_bundle(store, bundle_a, _now())
    _assert_authority(store, None)
    memory = _bundle(store)
    memory["policyVersion"] = "memory-1"
    assert _apply(store, _resign_bundle(memory))["status"] == "accepted"
    _assert_authority(store, "allow")
    _activate_bundle(store, bundle_b, _now())
    _assert_authority(store, "allow")
    store = GuardStore(store.guard_home)
    _assert_authority(store, "allow")
    revoked = _bundle(store)
    revoked.update(policyVersion="memory-2", memoryRules=[], revocations=["review-memory:receipt-1"])
    assert _apply(store, _resign_bundle(revoked))["status"] == "accepted"
    _assert_authority(store, None)
    _activate_bundle(store, bundle_a, _now())
    assert store.get_sync_payload("policy_bundle")["bundleVersion"] == "bundle-b"
    _assert_authority(store, None)
    assert _apply(store, memory)["status"] == "stale"
    _assert_authority(store, None)
