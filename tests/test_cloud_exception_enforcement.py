"""An approved Cloud exception lifts the Cloud policy block it was approved against."""

from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa

from codex_plugin_scanner.guard.consumer.native_decision_projection import (
    _ConsumerAuthorityInputs,
    _native_runtime_decision,
)
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.runtime.runner_native_sync import cloud_exceptions
from codex_plugin_scanner.guard.store import GuardStore
from tests.cloud_exception_bundle_fixtures import (
    build_cloud_exception_bundle_entry,
    build_cloud_exception_policy_bundle,
)
from tests.policy_bundle_signing_helpers import policy_bundle_test_keyring
from tests.policy_store_support import replace_remote_policies
from tests.test_policy_bundle_v2 import _signed_bundle as _signed_v2_bundle
from tests.test_policy_bundle_v2 import _verification_key as _v2_verification_key

WORKSPACE_ID = "workspace-sync-proof"
NOW = "2026-10-29T12:00:00+00:00"
PACKAGE_ARTIFACT_ID = "codex:project:package-request:left-pad"
# The workspace `_signed_v2_bundle` signs for.
V2_WORKSPACE_ID = "workspace-alpha"


def test_exception_without_a_harness_is_listed_for_every_harness() -> None:
    entry = build_cloud_exception_bundle_entry()
    del entry["harness"]
    active = cloud_exceptions({"cloudExceptions": [entry]}, device_id=None, harness="claude-code", active_at=NOW)
    assert [(item["id"], item["harness"]) for item in active] == [(entry["exceptionId"], None)]


def _store_with_bundle(
    tmp_path: Path,
    cloud_exceptions: list[dict[str, object]],
    local_rules: tuple[PolicyDecision, ...] = (),
) -> GuardStore:
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_payload("oauth_local_credentials", {"workspace_id": WORKSPACE_ID}, NOW)
    store.set_sync_payload("policy_bundle_keyring", policy_bundle_test_keyring(workspace_id=WORKSPACE_ID), NOW)
    store.set_sync_payload(
        "policy_bundle",
        build_cloud_exception_policy_bundle(cloud_exceptions=cloud_exceptions, workspace_id=WORKSPACE_ID),
        NOW,
    )
    replace_remote_policies(
        store,
        [
            PolicyDecision(
                harness="codex",
                scope="harness",
                action="block",
                artifact_id="family:package-request",
                source="policy-bundle",
                owner="pkg-block",
                reason="Block risky package installs before execution.",
            )
        ],
        NOW,
        remote_write_authorized=True,
    )
    for rule in local_rules:
        store.upsert_policy(rule, NOW)
    return store


def _saved_decision_sent_to_composer(store: GuardStore) -> object:
    sent: dict[str, object] = {}

    def composer(operation: str, payload: dict[str, object], **_kwargs: object) -> dict[str, object]:
        assert operation == "runtime_authoritative"
        runtime = payload["runtime"]
        assert isinstance(runtime, dict)
        sent["saved_decision"] = runtime["saved_decision"]
        return {"append_pending_claim": False}

    inputs = _ConsumerAuthorityInputs(
        store=store,
        harness="codex",
        workspace=None,
        now=NOW,
        trusted_request_overrides={},
        claimed_saved_approval_overrides={},
        retained_saved_approval_overrides={},
        saved_approval_qualification_overrides={},
        runtime_detector_composition=None,
        runtime_detector_block_reason=None,
        runtime_signals=[],
        pending_approval_claims=None,
    )
    _ = _native_runtime_decision(
        inputs,
        artifact_id=PACKAGE_ARTIFACT_ID,
        approval_context_hash="sha256:artifact",
        publisher=None,
        memory_command=None,
        memory_artifact_type=None,
        memory_artifact_name=None,
        current_action="warn",
        configured_action=None,
        scanner_action="allow",
        raw_scoring_recommendation="allow",
        skill_directory_identity_reusable=None,
        composer=composer,
    )
    return sent["saved_decision"]


def test_evaluation_drops_the_cloud_block_an_approved_exception_lifts(tmp_path: Path) -> None:
    store = _store_with_bundle(
        tmp_path,
        [{**build_cloud_exception_bundle_entry(), "artifactId": PACKAGE_ARTIFACT_ID}],
    )

    assert _saved_decision_sent_to_composer(store) is None


def test_evaluation_keeps_the_cloud_block_once_the_exception_is_gone(tmp_path: Path) -> None:
    store = _store_with_bundle(
        tmp_path,
        [
            {
                **build_cloud_exception_bundle_entry(expires_at="2026-10-29T11:00:00+00:00"),
                "artifactId": PACKAGE_ARTIFACT_ID,
            }
        ],
    )

    saved = _saved_decision_sent_to_composer(store)
    assert isinstance(saved, dict)
    assert saved["action"] == "block"


def test_lifted_cloud_block_does_not_hide_a_local_block(tmp_path: Path) -> None:
    exception = {**build_cloud_exception_bundle_entry(), "artifactId": PACKAGE_ARTIFACT_ID}
    local_block = PolicyDecision(harness="codex", scope="harness", action="block", reason="Local rule.")

    def lookup(store: GuardStore) -> dict[str, object]:
        decision = store.resolve_policy_decision_lookup("codex", PACKAGE_ARTIFACT_ID, now=NOW, consume_one_shot=False)[
            "decision"
        ]
        assert isinstance(decision, dict)
        return decision

    shadowed = lookup(_store_with_bundle(tmp_path / "without-exception", [], (local_block,)))
    lifted = lookup(_store_with_bundle(tmp_path / "with-exception", [exception], (local_block,)))

    assert shadowed["source"] == "policy-bundle"
    assert (lifted["action"], lifted["source"]) == ("block", "local")


def _store_with_v2_bundle(
    tmp_path: Path,
    cloud_exceptions: list[dict[str, object]],
    local_rules: tuple[PolicyDecision, ...] = (),
) -> GuardStore:
    """A store holding a signed v2 bundle and the canonical rule it compiled to on sync."""

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _v2_verification_key(private_key)
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_payload("oauth_local_credentials", {"workspace_id": V2_WORKSPACE_ID}, NOW)
    store.set_sync_payload("policy_bundle_keyring", {"keys": [verification_key.to_dict()]}, NOW)
    store.set_sync_payload(
        "policy_bundle",
        _signed_v2_bundle(
            private_key,
            verification_key,
            cloud_exceptions=cloud_exceptions,
            cloud_exceptions_issued_at="2026-10-29T09:00:00Z",
        ),
        NOW,
    )
    replace_remote_policies(
        store,
        [
            PolicyDecision(
                harness="codex",
                scope="harness",
                action="block",
                artifact_id="family:package-request",
                source="policy-bundle-canonical",
                owner="pkg-block",
                reason="Block risky package installs before execution.",
            )
        ],
        NOW,
        remote_write_authorized=True,
    )
    for rule in local_rules:
        store.upsert_policy(rule, NOW)
    return store


def _v2_exception(**fields: object) -> dict[str, object]:
    return {**build_cloud_exception_bundle_entry(), "artifactId": PACKAGE_ARTIFACT_ID, **fields}


def test_v2_bundle_exception_lifts_its_canonical_block(tmp_path: Path) -> None:
    store = _store_with_v2_bundle(tmp_path, [_v2_exception()])

    assert _saved_decision_sent_to_composer(store) is None


def test_v2_bundle_keeps_its_canonical_block_once_the_exception_expires(tmp_path: Path) -> None:
    store = _store_with_v2_bundle(tmp_path, [_v2_exception(expiresAt="2026-10-29T11:00:00+00:00")])

    saved = _saved_decision_sent_to_composer(store)
    assert isinstance(saved, dict)
    assert saved["action"] == "block"


def test_v2_lifted_canonical_block_does_not_hide_a_local_block(tmp_path: Path) -> None:
    local_block = PolicyDecision(harness="codex", scope="harness", action="block", reason="Local rule.")

    decision = store_lookup(_store_with_v2_bundle(tmp_path, [_v2_exception()], (local_block,)))

    assert (decision["action"], decision["source"]) == ("block", "local")


def store_lookup(store: GuardStore) -> dict[str, object]:
    decision = store.resolve_policy_decision_lookup("codex", PACKAGE_ARTIFACT_ID, now=NOW, consume_one_shot=False)[
        "decision"
    ]
    assert isinstance(decision, dict)
    return decision
