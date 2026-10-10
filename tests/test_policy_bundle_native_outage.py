"""A resident outage is never a policy verdict: it fails closed with its own code."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_policy_bundle as bridge
from codex_plugin_scanner.guard import policy_bundle_parser as parser
from codex_plugin_scanner.guard import policy_bundle_trusted_keys as trusted_keys
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.native_policy_bundle import (
    NATIVE_UNAVAILABLE_REJECTION,
    PolicyBundleNativeError,
    PolicyBundleNativeUnavailableError,
)
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.synced_policy import cached_policy_bundle_validation
from tests.cloud_exception_bundle_fixtures import build_cloud_exception_policy_bundle
from tests.policy_bundle_signing_helpers import (
    policy_bundle_test_keyring,
    policy_bundle_test_verification_key,
    sign_policy_bundle,
)
from tests.support.network import stub_authenticated_urlopen
from tests.test_cloud_exception_sync_proof import _JsonResponse
from tests.test_cloud_exception_sync_proof import _seed_guard_cloud as _seed_sync_cloud
from tests.test_guard_headless_daemon_api import (
    _dashboard_token_for,
    _read_json_response,
    _request,
)
from tests.test_guard_headless_daemon_api import _seed_guard_cloud as _seed_daemon_cloud
from tests.test_policy_bundle_parser import computed_policy_bundle_hash


def _unavailable(*_args: object, **_kwargs: object) -> dict[str, object]:
    raise PolicyBundleNativeUnavailableError(bridge.UNAVAILABLE)


@contextmanager
def _resident_outage(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for module in (bridge, parser, trusted_keys):
        monkeypatch.setattr(module, "native_policy_bundle", _unavailable)
    yield


# -- request transport -------------------------------------------------------


def test_request_ids_are_unique_across_threads() -> None:
    seen: list[str] = []
    guard = threading.Lock()

    def worker() -> None:
        ids = [bridge._next_request_id() for _ in range(500)]
        with guard:
            seen.extend(ids)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(seen) == 4000
    assert len(set(seen)) == 4000


def test_self_referential_input_is_rejected_not_followed() -> None:
    cyclic_list: list[object] = []
    cyclic_list.append(cyclic_list)
    cyclic_dict: dict[str, object] = {}
    cyclic_dict["self"] = {"inner": [cyclic_dict]}

    for value in (cyclic_list, cyclic_dict):
        with pytest.raises(PolicyBundleNativeError) as raised:
            bridge._reject_non_json(value)
        assert raised.value.code == "invalid_json_value"
        with pytest.raises(PolicyBundleNativeError) as raised:
            bridge.policy_bundle_chunks(value)
        assert raised.value.code == "invalid_json_value"


def test_nesting_depth_is_bounded() -> None:
    deep: object = []
    for _ in range(bridge.MAX_INPUT_DEPTH + 40):
        deep = [deep]
    with pytest.raises(PolicyBundleNativeError) as raised:
        bridge._reject_non_json(deep)
    assert raised.value.code == "limit_depth"

    shallow: object = []
    for _ in range(50):
        shallow = [shallow]
    bridge._reject_non_json(shallow)


def test_shared_acyclic_containers_remain_valid() -> None:
    shared = {"k": [1, 2, 3]}
    bridge._reject_non_json({"a": shared, "b": shared, "c": [shared, shared]})


@pytest.mark.parametrize("number", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_numbers_keep_their_code(number: float) -> None:
    with pytest.raises(PolicyBundleNativeError) as raised:
        bridge._reject_non_json({"a": [number]})
    assert raised.value.code == "non_finite_number"


# -- paged results -------------------------------------------------------------


def _fake_pages(monkeypatch: pytest.MonkeyPatch, pages: list[dict[str, object]]) -> list[object]:
    offsets: list[object] = []

    def fake(kind: str, request_input: dict[str, object]) -> dict[str, object]:
        offsets.append(request_input["offset"])
        return pages[len(offsets) - 1]

    monkeypatch.setattr(bridge, "policy_bundle_verdict", fake)
    return offsets


def test_paged_rows_follow_next_offsets_and_check_the_total(monkeypatch: pytest.MonkeyPatch) -> None:
    offsets = _fake_pages(
        monkeypatch,
        [
            {"decisions": [{"a": 1}, {"a": 2}], "total": 3, "next": 2},
            {"decisions": [{"a": 3}], "total": 3, "next": None},
        ],
    )

    assert bridge.policy_bundle_paged_rows("build_decisions", {}) == [{"a": 1}, {"a": 2}, {"a": 3}]
    assert offsets == [0, 2]


@pytest.mark.parametrize(
    "pages",
    [
        [{"decisions": [{"a": 1}], "total": 2, "next": None}],
        [{"decisions": [{"a": 1}], "total": 2, "next": 1}, {"decisions": [{"a": 2}], "total": 3, "next": None}],
        [{"decisions": [{"a": 1}], "total": 1, "next": 0}],
        [{"decisions": "nope", "total": 0, "next": None}],
    ],
)
def test_inconsistent_row_pages_are_an_outage(monkeypatch: pytest.MonkeyPatch, pages: list[dict[str, object]]) -> None:
    _fake_pages(monkeypatch, pages * 2)
    with pytest.raises(PolicyBundleNativeUnavailableError):
        bridge.policy_bundle_paged_rows("build_decisions", {})


def test_paged_text_is_verified_against_its_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    text = "héllo wörld"
    encoded = text.encode()
    digest = hashlib.sha256(encoded).hexdigest()
    _fake_pages(
        monkeypatch,
        [
            {"value": "héllo ", "total": len(encoded), "sha256": digest, "next": 7},
            {"value": "wörld", "total": len(encoded), "sha256": digest, "next": None},
        ],
    )
    assert bridge.policy_bundle_paged_text("v1_canonical_payload", {}) == text

    _fake_pages(
        monkeypatch,
        [{"value": "tampered", "total": len(encoded), "sha256": digest, "next": None}],
    )
    with pytest.raises(PolicyBundleNativeUnavailableError):
        bridge.policy_bundle_paged_text("v1_canonical_payload", {})


# -- verdict helpers -----------------------------------------------------------


def test_flag_propagates_an_outage_but_not_a_rejection(monkeypatch: pytest.MonkeyPatch) -> None:
    bundle: dict[str, object] = {"contractVersion": "guard-policy-bundle.v1", "rolloutState": "enforcing"}
    with _resident_outage(monkeypatch), pytest.raises(PolicyBundleNativeUnavailableError):
        parser.policy_bundle_is_enforceable(bundle)

    def rejected(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {"error": "unsupported_contract"}

    monkeypatch.setattr(parser, "native_policy_bundle", rejected)
    assert parser.policy_bundle_is_enforceable(bundle) is False


def test_key_helpers_report_an_outage_not_an_expired_key(monkeypatch: pytest.MonkeyPatch) -> None:
    key = policy_bundle_test_verification_key()
    with _resident_outage(monkeypatch):
        with pytest.raises(PolicyBundleNativeUnavailableError):
            trusted_keys.signing_key_is_current(key)
        with pytest.raises(PolicyBundleNativeUnavailableError):
            trusted_keys.safe_load_policy_bundle_verification_keys(policy_bundle_test_keyring())
        assert bridge.native_rejection_code(PolicyBundleNativeUnavailableError("x")) == NATIVE_UNAVAILABLE_REJECTION
        assert bridge.native_rejection_code(PolicyBundleNativeError("limit_bytes")) == "limit_bytes"


def test_synced_validation_reports_the_unavailable_code(monkeypatch: pytest.MonkeyPatch) -> None:
    bundle = sign_policy_bundle(build_cloud_exception_policy_bundle(workspace_id="workspace-1"))
    with _resident_outage(monkeypatch):
        validated, reason, _keys = trusted_keys.validate_synced_policy_bundle(
            bundle,
            stored_keyring=policy_bundle_test_keyring(workspace_id="workspace-1"),
            expected_workspace_id="workspace-1",
        )
    assert validated is None
    assert reason == NATIVE_UNAVAILABLE_REJECTION


def test_non_finite_number_codes_follow_the_bundle_contract() -> None:
    v1: dict[str, object] = {"contractVersion": "guard-policy-bundle.v1"}
    v2: dict[str, object] = {"contractVersion": "guard-policy-bundle.v2"}
    error = PolicyBundleNativeError("non_finite_number")
    assert trusted_keys._synced_rejection_code(v1, error) == "invalid_json_value"
    assert trusted_keys._synced_rejection_code(v2, error) == "unsupported_number"


def test_cached_validation_distinguishes_an_outage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_sync_cloud(store, workspace_id="workspace-sync-proof")
    bundle = build_cloud_exception_policy_bundle()
    bundle["bundleHash"] = computed_policy_bundle_hash(bundle)

    with _resident_outage(monkeypatch):
        validated, reason = cached_policy_bundle_validation(store, bundle)

    assert validated is None
    assert reason == NATIVE_UNAVAILABLE_REJECTION


# -- runner and daemon ---------------------------------------------------------


def _sync_response(bundle: dict[str, object]):
    def fake_urlopen(request, timeout):
        if request.full_url.endswith("/api/v1/guard/events"):
            return _JsonResponse({"accepted": 0, "rejected": 0, "statuses": []})
        return _JsonResponse({"syncedAt": "2026-06-14T12:00:01+00:00", "receiptsStored": 0, "policyBundle": bundle})

    return fake_urlopen


def test_runner_sync_fails_closed_and_keeps_prior_authority_during_an_outage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
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

    newer = build_cloud_exception_policy_bundle()
    newer["bundleVersion"] = "policy-2099-01-01.1"
    newer["bundleHash"] = computed_policy_bundle_hash(newer)
    stub_authenticated_urlopen(monkeypatch, _sync_response(newer))
    with _resident_outage(monkeypatch):
        guard_runner_module.sync_receipts(store)

    rejections = store.list_events(event_name="policy_bundle/rejected")
    assert rejections
    payload = rejections[0]["payload"]
    assert isinstance(payload, dict)
    assert payload["reason"] == NATIVE_UNAVAILABLE_REJECTION
    assert "native runtime" in str(payload["message"])
    assert store.get_sync_payload("policy_bundle") == accepted
    assert store.list_policy_decisions() == decisions_before


def test_runner_downgrade_check_raises_on_an_unavailable_transition(monkeypatch: pytest.MonkeyPatch) -> None:
    v2: dict[str, object] = {
        "contractVersion": "guard-policy-bundle.v2",
        "bundleVersion": 3,
        "bundleHash": "sha256:" + "a" * 64,
    }
    monkeypatch.setattr(
        guard_runner_module,
        "validate_policy_bundle_v2_transition",
        lambda *_args, **_kwargs: NATIVE_UNAVAILABLE_REJECTION,
    )
    with pytest.raises(PolicyBundleNativeUnavailableError):
        guard_runner_module._policy_bundle_is_version_downgrade(None, v2)


def test_daemon_policy_sync_answers_503_when_the_resident_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_daemon_cloud(store, workspace_id="workspace-1")
    store.set_sync_payload("policy_bundle_keyring", policy_bundle_test_keyring(), "2026-05-19T00:00:00Z")
    bundle = sign_policy_bundle(build_cloud_exception_policy_bundle(workspace_id="workspace-1"))

    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        with _resident_outage(monkeypatch):
            status, payload = _read_json_response(
                _request(
                    daemon.port,
                    "/v1/policy/sync",
                    token=token,
                    payload={"harness": "codex", "operation": "policy_sync", "policy_bundle": json.dumps(bundle)},
                )
            )
    finally:
        daemon.stop()

    assert status == 503
    assert payload["error"] == NATIVE_UNAVAILABLE_REJECTION
    assert "native runtime" in str(payload["message"])
    assert store.get_sync_payload("policy_bundle") is None
    assert store.list_policy_decisions() == []


# -- the resident never runs under the authority lock ---------------------------


def _managed_activation(store: GuardStore):
    from codex_plugin_scanner.guard.managed_controls_policy_bundle import signed_cloud_extension_projection_digest
    from codex_plugin_scanner.guard.policy_bundle_delivery import effective_projection_digest
    from codex_plugin_scanner.guard.policy_bundle_parser import policy_bundle_acceptance_checkpoint
    from codex_plugin_scanner.guard.runtime import runner
    from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
    from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntime
    from tests.managed_controls_activation_support import CAPABILITIES, parse_managed_bundle
    from tests.test_policy_bundle_delivery_runtime import _bundle

    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    store._bootstrap_extension_control_authority(registry.catalog_digest, key=None)
    base = store.read_extension_control_authority_for_registry(registry)
    runtime = ExtensionControlRuntime(base)
    device_id, _ = runner._guard_device_metadata(store)
    wire_digest = runner.build_builtin_extension_catalog_wire(
        guard_version="test", generated_at="2026-08-25T12:00:00Z"
    )["catalogDigest"]
    bundle = _bundle()
    rollback = bundle["rollback"]
    assert isinstance(rollback, dict)
    delivery = {
        "bundleId": f"policy-{bundle['bundleVersion']}",
        "bundleHash": bundle["bundleHash"],
        "bundleVersion": bundle["bundleVersion"],
        "workspaceId": bundle["workspaceId"],
        "deviceId": device_id,
        "runtimeSessionId": "runtime-managed-controls",
        "deliveryId": "00000000-0000-4000-8000-000000000001",
        "policyRevision": 7,
        "extensionAuthorityRevision": base.revision,
        "catalogDigest": wire_digest,
        "effectiveProjectionDigest": effective_projection_digest(base),
        "payloadHash": bundle["payloadHash"],
        "extensionProjectionDigest": signed_cloud_extension_projection_digest(
            parse_managed_bundle(bundle), catalog_digest=wire_digest
        ),
        "lastKnownGoodBundleHash": rollback["lastGoodBundleHash"],
    }

    def activate():
        return store.apply_policy_bundle_authority(
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

    return activate


def test_activation_computes_resident_verdicts_outside_the_authority_lock_and_write_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard import policy_bundle_activation as activation_module

    store = GuardStore(tmp_path / "guard-home")
    activate = _managed_activation(store)
    held = 0
    original_lock = store._extension_control_authority_lock

    @contextmanager
    def counting_lock(*args: object, **kwargs: object) -> Iterator[None]:
        nonlocal held
        with original_lock(*args, **kwargs):
            held += 1
            try:
                yield
            finally:
                held -= 1

    monkeypatch.setattr(store, "_extension_control_authority_lock", counting_lock)
    original_ack = activation_module.policy_bundle_acknowledgement_payload
    observations: list[tuple[int, bool]] = []

    def observing_ack(**kwargs: Any) -> dict[str, object]:
        writer_free = True
        probe = sqlite3.connect(store.path, timeout=0.05)
        try:
            probe.execute("begin immediate")
            probe.rollback()
        except sqlite3.OperationalError:
            writer_free = False
        finally:
            probe.close()
        observations.append((held, writer_free))
        return original_ack(**kwargs)

    monkeypatch.setattr(activation_module, "policy_bundle_acknowledgement_payload", observing_ack)

    committed = activate()

    assert committed is not None
    assert store.get_sync_payload("policy_bundle_ack")
    assert observations
    assert all(lock_depth == 0 and writer_free for lock_depth, writer_free in observations)


def test_activation_recomputes_when_the_acknowledgement_state_changes_between_attempts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard import policy_bundle_activation as activation_module

    store = GuardStore(tmp_path / "guard-home")
    activate = _managed_activation(store)
    original_ack = activation_module.policy_bundle_acknowledgement_payload
    previous_values: list[object] = []

    def racing_ack(**kwargs: Any) -> dict[str, object]:
        previous_values.append(kwargs.get("previous"))
        if len(previous_values) == 1:
            # A concurrent writer stores an acknowledgement after the first
            # verdict was computed for the empty state.
            store.set_sync_payload(
                "policy_bundle_ack", {"sequence": 41, "bundleHash": "sha256:" + "d" * 64}, "2026-08-25T12:00:00Z"
            )
        return original_ack(**kwargs)

    monkeypatch.setattr(activation_module, "policy_bundle_acknowledgement_payload", racing_ack)

    activate()

    assert len(previous_values) >= 2
    assert previous_values[0] is None
    assert isinstance(previous_values[-1], dict)
    assert previous_values[-1]["sequence"] == 41
