"""``POST /v1/policy/sync``: accept a signed Guard Cloud policy bundle.

Runs in the resident library process behind ``desktop library-call`` so an
accepted bundle republishes the extension-control runtime that process holds.
Returns ``{"status": int, "body": {...}, "no_store": bool}``.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, cast

from ..store import GuardStore


class _RejectedError(Exception):
    def __init__(self, reply: dict[str, object]) -> None:
        super().__init__(reply.get("status"))
        self.reply = reply


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _reply(body: Mapping[str, object], status: int = 200) -> dict[str, object]:
    return {"status": status, "body": dict(body), "no_store": False}


def _rejection(code: str, status: int = 400) -> dict[str, object]:
    from ..policy_bundle_parser import policy_bundle_rejection_message

    body: dict[str, object] = {"error": code}
    message = policy_bundle_rejection_message(code)
    if message is not None:
        body["message"] = message
    return _reply(body, status)


def _unavailable() -> dict[str, object]:
    from ..native_policy_bundle import NATIVE_UNAVAILABLE_REJECTION

    return _rejection(NATIVE_UNAVAILABLE_REJECTION, 503)


def _optional_string(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _policy_memory_payload(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _managed_controls_publish(store: GuardStore) -> Any:
    from ..extension_control_host import existing_host

    host = existing_host(store)
    return None if host is None else host.runtime.publish_after_commit


def policy_sync(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Validate, activate and acknowledge a policy bundle, behind the approval gate."""

    from ..library_calls import LibraryCallError
    from ..native_policy_bundle import (
        PolicyBundleNativeError,
        PolicyBundleNativeUnavailableError,
        native_rejection_code,
    )

    payload = args.get("payload")
    if not isinstance(payload, dict):
        raise LibraryCallError("invalid_arguments")
    try:
        return _policy_sync(store, payload)
    except _RejectedError as rejected:
        return rejected.reply
    except PolicyBundleNativeUnavailableError:
        # Without the resident's verdict nothing is accepted, activated, or
        # acknowledged; the caller gets a retryable outage.
        return _unavailable()
    except PolicyBundleNativeError as error:
        # A native verdict or input rejection is final for this bundle.
        return _rejection(native_rejection_code(error))


def _validated_bundle(store: GuardStore, payload: dict[str, object], policy_bundle: dict[str, object]) -> Any:
    from ..native_policy_bundle import NATIVE_UNAVAILABLE_REJECTION
    from ..policy_bundle_parser import policy_bundle_is_enforceable
    from ..policy_bundle_trusted_keys import (
        MANAGED_POLICY_BUNDLE_KEYRING_PROVENANCE_STATE_KEY,
        validate_synced_policy_bundle,
    )
    from ..runtime.runner import (
        _daemon_version_supported,
        _policy_bundle_downgrade_reference,
        _policy_bundle_is_version_downgrade,
        _validate_cached_policy_bundle,
    )

    validated, rejection_reason, trusted_keys = validate_synced_policy_bundle(
        policy_bundle,
        stored_keyring=store.get_sync_payload("policy_bundle_keyring"),
        sync_payload=payload,
        supply_chain_keyring=store.get_sync_payload("supply_chain_bundle_keyring"),
        managed_keyring_provenance=store.get_sync_payload(MANAGED_POLICY_BUNDLE_KEYRING_PROVENANCE_STATE_KEY),
        expected_workspace_id=store.get_cloud_workspace_id(),
    )
    existing, existing_error = _validate_cached_policy_bundle(store, store.get_sync_payload("policy_bundle"))
    if NATIVE_UNAVAILABLE_REJECTION in (rejection_reason, existing_error):
        raise _RejectedError(_unavailable())
    if validated is None:
        raise _RejectedError(_rejection(rejection_reason or "invalid_policy_bundle"))
    if not _daemon_version_supported(validated):
        raise _RejectedError(_reply({"error": "unsupported_daemon_version"}, 400))
    if not policy_bundle_is_enforceable(validated):
        raise _RejectedError(_rejection("inactive_rollout_state"))
    if _policy_bundle_is_version_downgrade(_policy_bundle_downgrade_reference(store, existing), validated):
        raise _RejectedError(_rejection("bundle_version_downgrade"))
    return validated, trusted_keys, existing


def _policy_sync(store: GuardStore, payload: dict[str, object]) -> dict[str, object]:
    from ..adapters import get_adapter
    from ..approval_gate import ApprovalGateError, require_high_risk
    from ..approval_gate import input_from_mapping as gate_input_from_mapping
    from ..config import VALID_RECEIPT_REDACTION_LEVELS
    from ..native_policy_bundle import (
        NATIVE_UNAVAILABLE_REJECTION,
        PolicyBundleNativeError,
        PolicyBundleNativeUnavailableError,
    )
    from ..native_runner_authority import NativeRunnerAuthorityError
    from ..policy_bundle_activation import activate_with_reason
    from ..policy_bundle_delivery import policy_bundle_acknowledgement_payload
    from ..policy_bundle_trusted_keys import policy_bundle_keyring_payload
    from ..policy_bundle_v2 import POLICY_BUNDLE_V2_CONTRACT
    from ..runtime import runner_native_sync as _sync
    from ..runtime.extension_control_authority import ExtensionControlAuthorityError
    from ..runtime.managed_policy_delivery import daemon_managed_controls_candidate
    from ..runtime.runner import (
        _guard_device_metadata,
        _persist_cloud_receipt_redaction_level,
        _policy_bundle_acceptance_checkpoint,
        _policy_bundle_cloud_exception_items,
        _reset_cloud_receipt_redaction_authority,
        policy_bundle_candidate_decisions,
    )

    harness = _optional_string(payload.get("harness"))
    if harness is None:
        return _reply({"error": "missing_harness"}, 400)
    try:
        adapter = get_adapter(harness)
    except ValueError:
        return _reply({"error": "unknown_harness"}, 404)
    try:
        grant = require_high_risk(
            store.guard_home,
            purpose="policy_write",
            approval_gate_input=gate_input_from_mapping(payload),
        )
    except ApprovalGateError as error:
        return _reply(error.to_payload(), error.status)
    policy_memory = _policy_memory_payload(payload.get("policy_memory"))
    policy_bundle = _policy_memory_payload(payload.get("policy_bundle") or payload.get("policyBundle"))
    if not policy_memory and not policy_bundle:
        return _reply({"error": "missing_policy_memory"}, 400)
    if policy_memory:
        return _reply({"error": "unsupported_policy_memory_contract"}, 400)
    validated, trusted_keys, existing = _validated_bundle(store, payload, policy_bundle)
    device_id, device_name = _guard_device_metadata(store)
    is_v2 = validated.get("contractVersion") == POLICY_BUNDLE_V2_CONTRACT
    managed_policy = None
    managed_capabilities = frozenset[str]()
    delivery: dict[str, object] | None = None
    if is_v2:
        managed_policy, managed_capabilities, delivery, managed_error = daemon_managed_controls_candidate(
            store=store,
            payload=payload,
            policy_bundle=validated,
            device_id=device_id,
        )
        if managed_error is not None:
            return _reply({"error": managed_error}, 400)
    applied_at = _now()
    # Only a v2 bundle reads the rollout, and a resident that cannot answer is
    # an outage, not a refusal of the bundle.
    try:
        canonical_enforcement = is_v2 and _sync.canonical_policy_enforcement_enabled(
            device_id=device_id,
            workspace_id=store.get_cloud_workspace_id(),
        )
    except NativeRunnerAuthorityError:
        return _unavailable()
    decisions, candidate_rejection, _rule_id = policy_bundle_candidate_decisions(
        store,
        validated,
        is_v2=is_v2,
        device_id=device_id,
        device_name=device_name,
        canonical_enforcement=canonical_enforcement,
        existing_policy_bundle=existing,
        now=applied_at,
    )
    if candidate_rejection == NATIVE_UNAVAILABLE_REJECTION:
        return _unavailable()
    if candidate_rejection is not None:
        return _rejection(candidate_rejection)
    stored_ack = store.get_sync_payload("policy_bundle_ack")
    ack = policy_bundle_acknowledgement_payload(
        device_id=device_id,
        device_name=device_name,
        policy_bundle=validated,
        synced_at=applied_at,
        previous=stored_ack if isinstance(stored_ack, dict) else None,
        delivery=delivery,
    )
    try:
        cloud_exceptions = _policy_bundle_cloud_exception_items(
            store,
            sync_exceptions=[],
            policy_bundle=validated,
            policy_bundle_ack=ack,
            device_id=device_id,
        )
    except PolicyBundleNativeUnavailableError:
        return _unavailable()
    try:
        activated, activation_rejection = activate_with_reason(
            store.apply_policy_bundle_authority,
            decisions,
            applied_at,
            policy_bundle=validated,
            policy_bundle_keyring=policy_bundle_keyring_payload(
                trusted_keys,
                workspace_id=store.get_cloud_workspace_id(),
            ),
            cloud_exceptions=cloud_exceptions,
            policy_bundle_ack=ack,
            policy_bundle_checkpoint=_policy_bundle_acceptance_checkpoint(validated),
            update_last_good=True,
            policy_bundle_last_error={},
            managed_controls_policy=managed_policy,
            managed_controls_negotiated_capabilities=managed_capabilities,
            managed_controls_delivery=delivery,
            managed_controls_publish=_managed_controls_publish(store),
            approval_gate_grant=grant,
            remote_write_authorized=True,
        )
    except PolicyBundleNativeError:
        raise
    except (ExtensionControlAuthorityError, ValueError):
        return _reply({"error": "managed_runtime_publish_failed"}, 503)
    if activated is None:
        return _reply({"error": activation_rejection}, 400)
    level = validated.get("receiptRedactionLevel")
    if isinstance(level, str) and level in VALID_RECEIPT_REDACTION_LEVELS:
        _persist_cloud_receipt_redaction_level(store, level=level, synced_at=applied_at)
    else:
        _reset_cloud_receipt_redaction_authority(store, synced_at=applied_at)  # type: ignore[arg-type]
    return _reply(
        {
            "bundle_hash": str(validated["bundleHash"]),
            "bundle_version": str(validated["bundleVersion"]),
            "harness": adapter.harness,
            "operation": "policy_sync",
            "status": "completed",
        }
    )


POLICY_SYNC_CALLS = {"route.policy_sync": cast(Any, policy_sync)}
