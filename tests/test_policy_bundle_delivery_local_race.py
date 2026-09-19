from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_gate import ApprovalGateInput, update_settings
from codex_plugin_scanner.guard.managed_controls_policy_bundle import signed_cloud_extension_projection_digest
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.policy_bundle_delivery import effective_projection_digest
from codex_plugin_scanner.guard.policy_bundle_parser import policy_bundle_acceptance_checkpoint
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.extension_control_proof import (
    ExtensionControlMutation,
    issue_extension_control_proof,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntime
from codex_plugin_scanner.guard.store import GuardStore
from tests.managed_controls_activation_support import CAPABILITIES, parse_managed_bundle

_PASSWORD = "correct horse battery staple"
_VECTOR_PATH = (
    Path(__file__).resolve().parents[1]
    / "contracts/managed-controls/v1/policy-bundle-v2-extension-signature-vector.json"
)


def _bundle() -> dict[str, object]:
    value = json.loads(_VECTOR_PATH.read_text())["bundle"]
    assert isinstance(value, dict)
    return value


def test_atomic_activation_rejects_stale_delivery_after_concurrent_local_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    update_settings(
        guard_home,
        {
            "enabled": True,
            "new_password": _PASSWORD,
            "confirm_password": _PASSWORD,
            "cooldown_seconds": 0,
        },
    )
    stale_store = GuardStore(guard_home)
    local_store = GuardStore(guard_home)
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    stale_store._bootstrap_extension_control_authority(registry.catalog_digest, key=None)
    base = stale_store.read_extension_control_authority_for_registry(registry)
    runtime = ExtensionControlRuntime(base)
    bundle = _bundle()
    wire_digest = runner.build_builtin_extension_catalog_wire(
        guard_version="test",
        generated_at="2026-08-25T12:00:00Z",
    )["catalogDigest"]
    device_id, _ = runner._guard_device_metadata(stale_store)
    rollback = bundle["rollback"]
    assert isinstance(rollback, dict)
    delivery = {
        "bundleId": "policy-managed-controls",
        "bundleHash": bundle["bundleHash"],
        "bundleVersion": bundle["bundleVersion"],
        "workspaceId": bundle["workspaceId"],
        "deviceId": device_id,
        "runtimeSessionId": "runtime-managed-controls",
        "deliveryId": "00000000-0000-4000-8000-000000000003",
        "policyRevision": 7,
        "extensionAuthorityRevision": base.revision,
        "catalogDigest": wire_digest,
        "effectiveProjectionDigest": effective_projection_digest(base),
        "payloadHash": bundle["payloadHash"],
        "extensionProjectionDigest": signed_cloud_extension_projection_digest(
            parse_managed_bundle(bundle),
            catalog_digest=wire_digest,
        ),
        "lastKnownGoodBundleHash": rollback["lastGoodBundleHash"],
    }

    stale_waiting = threading.Event()
    release_stale = threading.Event()
    original_prepare = stale_store._prepared_remote_policy_rows

    def gated_prepare(*args, **kwargs):
        result = original_prepare(*args, **kwargs)
        stale_waiting.set()
        assert release_stale.wait(timeout=5)
        return result

    monkeypatch.setattr(stale_store, "_prepared_remote_policy_rows", gated_prepare)
    stale_result: list[dict[str, object] | None] = []
    stale_thread = threading.Thread(
        target=lambda: stale_result.append(
            stale_store.apply_policy_bundle_authority(
                [],
                "2026-08-25T12:00:01Z",
                policy_bundle=bundle,
                policy_bundle_keyring={"keys": []},
                cloud_exceptions=[],
                policy_bundle_ack={},
                policy_bundle_checkpoint=policy_bundle_acceptance_checkpoint(bundle),
                update_last_good=True,
                managed_controls_policy=parse_managed_bundle(bundle),
                managed_controls_negotiated_capabilities=CAPABILITIES,
                managed_controls_delivery=delivery,
                managed_controls_publish=runtime.publish_after_commit,
                remote_write_authorized=True,
            )
        ),
        name="stale-local-authority-delivery",
    )
    stale_thread.start()
    assert stale_waiting.wait(timeout=5)

    extension = registry.extensions[0]
    local_layer = ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=registry.catalog_digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(
                ControlTarget(ControlTargetKind.EXTENSION, extension.extension_id),
                ControlState.DISABLED,
            ),
        ),
    )
    mutation = ExtensionControlMutation(
        previous_revision=0,
        catalog_digest=registry.catalog_digest,
        layers=(local_layer,),
        actor_id="local-admin",
        idempotency_key="local-authority-race",
        nonce="local-authority-race-nonce",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._require_local_terminal_confirmation",
        lambda _mutation: None,
    )
    proof = issue_extension_control_proof(
        guard_home,
        mutation,
        approval_gate_input=ApprovalGateInput(password=_PASSWORD),
        session_nonce="local-authority-race-session",
    )
    committed_local = local_store.commit_extension_control_layers(
        (local_layer,),
        catalog_digest=registry.catalog_digest,
        actor_id="local-admin",
        expected_revision=0,
        idempotency_key="local-authority-race",
        nonce="local-authority-race-nonce",
        proof=proof,
    )
    runtime.refresh(committed_local)
    release_stale.set()
    stale_thread.join(timeout=5)

    durable = local_store.read_extension_control_authority(catalog_digest=registry.catalog_digest)
    assert not stale_thread.is_alive()
    assert stale_result == [None]
    assert durable.revision == 1
    assert durable.layers == (local_layer,)
    assert runtime.current().revision == durable.revision
    assert runtime.current().layers == durable.layers
    assert stale_store.get_sync_payload("policy_bundle") is None


def test_two_bundle_replacements_commit_one_consistent_authority_set(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    first = [
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="block",
            artifact_id="command:one",
            source="policy-bundle",
        )
    ]
    second = [
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id="command:two",
            source="policy-bundle",
        )
    ]
    errors: list[BaseException] = []

    def write(rows: list[PolicyDecision], now: str) -> None:
        try:
            store.replace_remote_policies(rows, now, remote_write_authorized=True)
        except BaseException as error:
            errors.append(error)

    threads = [
        threading.Thread(target=write, args=(first, "2026-08-25T12:00:01Z")),
        threading.Thread(target=write, args=(second, "2026-08-25T12:00:02Z")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
    assert errors == []
    remaining = store.list_policy_decisions()
    ids = {row["artifact_id"] for row in remaining if row["source"] == "policy-bundle"}
    assert ids in ({"command:one"}, {"command:two"})
    assert len(ids) == 1


def test_concurrent_memory_and_bundle_writes_keep_one_family_each(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.runtime.review_policy_memory_executor import execute_review_policy_memory
    from tests.test_guard_review_policy_memory_command import _bundle as memory_bundle
    from tests.test_guard_review_policy_memory_command import _store

    store = _store(tmp_path)
    errors: list[BaseException] = []

    def write_bundle() -> None:
        try:
            store.replace_remote_policies(
                [
                    PolicyDecision(
                        harness="codex",
                        scope="artifact",
                        action="block",
                        artifact_id="command:bundle",
                        source="policy-bundle",
                    )
                ],
                "2026-08-25T12:00:01Z",
                remote_write_authorized=True,
            )
        except BaseException as error:
            errors.append(error)

    def write_memory() -> None:
        try:
            execute_review_policy_memory(
                {"decisionMemoryBundle": memory_bundle(store)},
                store=store,
                generated_at="2026-08-25T12:00:02Z",
            )
        except BaseException as error:
            errors.append(error)

    threads = [threading.Thread(target=write_bundle), threading.Thread(target=write_memory)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
    assert errors == []
    remaining = store.list_policy_decisions()
    bundle_ids = {row["artifact_id"] for row in remaining if row["source"] == "policy-bundle"}
    memory_ids = {row["artifact_id"] for row in remaining if row["source"] == "cloud-signed-memory"}
    assert bundle_ids == {"command:bundle"}
    assert memory_ids == {"plugin:hol/deploy"}
    assert len(remaining) == 2
